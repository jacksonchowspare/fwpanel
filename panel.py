#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fwpanel — 自研防火墙控制面板（适配 Debian 13 / nftables）
================================================================
零第三方依赖：仅使用 Python 标准库 + 系统 nft 命令。

功能：
  * Web 管理界面（浏览器访问）
  * 端口放行/拒绝、IP 白名单/黑名单
  * 服务模板快捷开关（SSH/HTTP/HTTPS/DNS/Mail）
  * 宽松/严格两种模式（严格模式默认拒绝，需显式放行）
  * 防锁死：SSH 放行规则永远存在且不可删除
  * 登录认证：pbkdf2 密码哈希 + session token + 失败锁定
  * nftables 规则原子应用，失败自动回滚

目录结构：
  /etc/fwpanel/config.json     配置（含密码哈希，权限 600）
  /etc/fwpanel/rules.json      规则清单
  /etc/fwpanel/firewall.nft    生成的 nftables 规则文件
  /etc/fwpanel/firewall.nft.bak 上次成功应用的备份

用法：
  fwpanel serve [--port N] [--bind IP]    启动面板（默认）
  fwpanel reset-password                  重置面板密码（交互式）
  fwpanel apply                           仅应用规则（供 systemd 启动时调用）
"""

import argparse
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# ------------------------------- 常量与路径 -------------------------------
# 测试时用环境变量覆盖配置目录（单测/冒烟测试）
BASE_DIR = os.environ.get("FW_TEST_DIR", "/etc/fwpanel")
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
RULES_FILE = os.path.join(BASE_DIR, "rules.json")
NFT_FILE = os.path.join(BASE_DIR, "firewall.nft")
NFT_BACKUP = os.path.join(BASE_DIR, "firewall.nft.bak")
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

DRY_RUN = "--dry-run" in sys.argv or os.environ.get("FW_DRY_RUN") == "1"

DEFAULT_PORT = 17890
SSH_PORT_DEFAULT = 22
TOKEN_TTL = 24 * 3600          # token 有效期 24 小时
LOCK_MAX_FAIL = 5              # 连续失败次数
LOCK_SECONDS = 300             # 锁定 5 分钟

# 服务模板：名称 -> (协议, 端口)
SERVICES = {
    "ssh":   ("tcp", 22),
    "http":  ("tcp", 80),
    "https": ("tcp", 443),
    "dns":   ("udp", 53),
    "mail":  ("tcp", 25),
    "imap":  ("tcp", 143),
    "smtps": ("tcp", 465),
}

# ------------------------------- 基础工具 -------------------------------

def log(msg):
    print(f"[fwpanel] {time.strftime('%F %T')} {msg}", flush=True)


def sha256_hex(s):
    return hashlib.sha256(s.encode()).hexdigest()


def hash_password(password, salt=None):
    """pbkdf2 哈希；返回 salt$hash 字符串"""
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 120_000)
    return f"{salt}${dk.hex()}"


def verify_password(password, stored):
    try:
        salt, _ = stored.split("$", 1)
    except ValueError:
        return False
    return hmac.compare_digest(hash_password(password, salt), stored)


def is_ipv6(ip):
    return ":" in ip


# ------------------------------- 配置管理 -------------------------------

class Config:
    def __init__(self):
        self.data = self._load()

    def _load(self):
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE) as f:
                return json.load(f)
        return {}

    def save(self):
        os.makedirs(BASE_DIR, exist_ok=True)
        tmp = CONFIG_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.data, f, indent=2, ensure_ascii=False)
        os.chmod(tmp, 0o600)
        os.replace(tmp, CONFIG_FILE)

    def get(self, key, default=None):
        return self.data.get(key, default)

    def set(self, key, value):
        self.data[key] = value
        self.save()


# ------------------------------- 规则存储与渲染 -------------------------------

class RuleStore:
    """规则清单持久化 + nftables 规则渲染"""

    RULE_TYPES = ("port_allow", "port_deny", "ip_allow", "ip_deny")

    def __init__(self):
        self.rules = self._load()

    def _load(self):
        if os.path.exists(RULES_FILE):
            try:
                with open(RULES_FILE) as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                return []
        return []

    def save(self):
        os.makedirs(BASE_DIR, exist_ok=True)
        tmp = RULES_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.rules, f, indent=2, ensure_ascii=False)
        os.replace(tmp, RULES_FILE)

    def add(self, rule):
        rule = dict(rule)
        rule["id"] = secrets.token_hex(6)
        rule.setdefault("comment", "")
        self.rules.append(rule)
        self.save()
        return rule

    def remove(self, rule_id):
        for r in self.rules:
            if r["id"] == rule_id:
                if r.get("protected"):
                    return False, "SSH 保护规则不可删除（可在配置中修改 ssh_port 后重建）"
                self.rules.remove(r)
                self.save()
                return True, "ok"
        return False, "规则不存在"

    def render(self, config):
        """生成 nftables 规则文本。config 提供模式与 ssh_port"""
        mode = config.get("mode", "permissive")   # permissive 宽松 / strict 严格
        ssh_port = int(config.get("ssh_port", SSH_PORT_DEFAULT))
        lines = []
        lines.append("#!/usr/sbin/nft -f")
        lines.append("table inet fwpanel {")
        lines.append("    chain input {")
        if mode == "strict":
            lines.append("        type filter hook input priority filter; policy drop;")
        else:
            lines.append("        type filter hook input priority filter; policy accept;")
        # 基础放行：已建立连接 + 本机回环 + ICMP
        lines.append("        ct state established,related accept")
        lines.append('        iifname "lo" accept')
        lines.append("        ip protocol icmp accept")
        lines.append("        ip6 nexthdr icmpv6 accept")
        # SSH 保护规则（永远存在，防锁死）
        lines.append(f"        tcp dport {ssh_port} accept   # SSH 保护(不可删除)")
        # 用户规则
        for r in self.rules:
            lines.append(self._render_one(r, config))
        lines.append("    }")
        lines.append("}")
        return "\n".join(lines) + "\n"

    @staticmethod
    def _render_one(r, config):
        t = r.get("type")
        comment = r.get("comment", "")
        tag = f"  # {comment}" if comment else ""
        if t == "port_allow":
            proto = r.get("proto", "tcp")
            return f"        {proto} dport {r['port']} accept{tag}"
        if t == "port_deny":
            proto = r.get("proto", "tcp")
            return f"        {proto} dport {r['port']} drop{tag}"
        if t == "ip_allow":
            ip = r["ip"]
            key = "ip6 saddr" if is_ipv6(ip) else "ip saddr"
            return f"        {key} {ip} accept{tag}"
        if t == "ip_deny":
            ip = r["ip"]
            key = "ip6 saddr" if is_ipv6(ip) else "ip saddr"
            return f"        {key} {ip} drop{tag}"
        return ""


# ------------------------------- nftables 执行 -------------------------------

class NFTManager:
    """应用规则：备份 -> 原子加载 -> 失败回滚"""

    def __init__(self, store, config):
        self.store = store
        self.config = config

    def apply(self):
        text = self.store.render(self.config)
        os.makedirs(BASE_DIR, exist_ok=True)
        with open(NFT_FILE, "w") as f:
            f.write(text)
        if DRY_RUN:
            log("[dry-run] 生成规则文件，跳过 nft -f 执行")
            log("---- 规则内容 ----")
            for line in text.splitlines():
                print("  " + line)
            log("---- 规则内容结束 ----")
            return True, "dry-run"

        # 备份当前生效规则
        try:
            subprocess.run(["nft", "list", "ruleset"], capture_output=True, text=True, check=True)
            with open(NFT_BACKUP, "w") as f:
                subprocess.run(["nft", "list", "ruleset"], stdout=f, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            log("无法读取当前规则集（可能为空），跳过备份")

        # 原子应用
        try:
            result = subprocess.run(
                ["nft", "-f", NFT_FILE], capture_output=True, text=True, timeout=15
            )
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            return False, f"nft 执行失败: {e}"
        if result.returncode != 0:
            # 回滚
            if os.path.exists(NFT_BACKUP):
                subprocess.run(["nft", "-f", NFT_BACKUP], capture_output=True, text=True)
                log("规则加载失败，已回滚备份")
            return False, f"nft 报错: {result.stderr.strip()[:300]}"
        log(f"规则已应用（{len(self.store.rules)} 条用户规则，模式 {self.config.get('mode', 'permissive')}）")
        return True, "ok"

    def status(self):
        """返回面板管理的规则是否已加载"""
        try:
            r = subprocess.run(["nft", "list", "table", "inet", "fwpanel"],
                               capture_output=True, text=True, timeout=10)
            return r.returncode == 0
        except FileNotFoundError:
            return False


# ------------------------------- 认证管理 -------------------------------

class Auth:
    def __init__(self, config):
        self.config = config
        self.tokens = {}            # token -> expiry
        self.lock = threading.Lock()
        self.fail_count = 0
        self.lock_until = 0

    def check_locked(self):
        if time.time() < self.lock_until:
            return True
        return False

    def login(self, username, password):
        with self.lock:
            if self.check_locked():
                return None, "尝试过于频繁，请稍后再试"
            stored_user = self.config.get("username")
            stored_pass = self.config.get("password_hash")
            if not stored_user or not stored_pass:
                return None, "面板未初始化，请运行安装脚本"
            if hmac.compare_digest(username, stored_user) and verify_password(password, stored_pass):
                self.fail_count = 0
                token = secrets.token_urlsafe(32)
                self.tokens[token] = time.time() + TOKEN_TTL
                return token, "ok"
            self.fail_count += 1
            if self.fail_count >= LOCK_MAX_FAIL:
                self.lock_until = time.time() + LOCK_SECONDS
                self.fail_count = 0
                log(f"登录失败次数过多，IP 已锁定 {LOCK_SECONDS}s")
            return None, "用户名或密码错误"

    def check(self, token):
        expiry = self.tokens.get(token, 0)
        if expiry > time.time():
            return True
        self.tokens.pop(token, None)
        return False

    def logout(self, token):
        self.tokens.pop(token, None)


# ------------------------------- HTTP 服务 -------------------------------

class PanelHandler(BaseHTTPRequestHandler):
    server_version = "fwpanel/1.0"

    def log_message(self, fmt, *args):   # 静默默认日志，避免刷屏
        pass

    # ---------- 基础 ----------
    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length <= 0:
                return {}
            return json.loads(self.rfile.read(length))
        except (ValueError, json.JSONDecodeError):
            return {}

    def _token(self):
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:].strip()
        return ""

    def _require_auth(self):
        token = self._token()
        if not token or not self.server.auth.check(token):
            self._send(401, {"error": "未登录或登录已过期"})
            return None
        return token

    # ---------- 路由 ----------
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/" or path == "/index.html":
            self._serve_static()
        elif path == "/api/status":
            self._api_status()
        elif path == "/api/rules":
            self._api_list_rules()
        elif path == "/api/logout":
            token = self._token()
            if token:
                self.server.auth.logout(token)
            self._send(200, {"ok": True})
        else:
            self._send(404, {"error": "Not Found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/api/login":
            self._api_login()
        elif path == "/api/rules":
            self._api_add_rule()
        elif path == "/api/service":
            self._api_service()
        elif path == "/api/open-port":
            self._api_open_port()
        elif path == "/api/mode":
            self._api_mode()
        elif path == "/api/password":
            self._api_password()
        else:
            self._send(404, {"error": "Not Found"})

    def do_DELETE(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path.startswith("/api/rules/"):
            self._api_delete_rule(path.rsplit("/", 1)[1])
        else:
            self._send(404, {"error": "Not Found"})

    # ---------- 静态页面 ----------
    def _serve_static(self):
        index = os.path.join(STATIC_DIR, "index.html")
        try:
            with open(index, "rb") as f:
                self._send(200, f.read(), "text/html; charset=utf-8")
        except FileNotFoundError:
            self._send(500, {"error": "前端页面缺失，请检查安装完整性"})

    # ---------- API ----------
    def _api_login(self):
        data = self._read_json()
        token, msg = self.server.auth.login(data.get("username", ""), data.get("password", ""))
        if token:
            self._send(200, {"token": token})
        else:
            self._send(401, {"error": msg})

    def _api_status(self):
        token = self._require_auth()
        if token is None:
            return
        nft = self.server.nft
        cfg = self.server.config
        hostname = os.uname().nodename
        try:
            mem = subprocess.run(["awk", "/^MemTotal:/{print int($2/1024)}", "/proc/meminfo"],
                                 capture_output=True, text=True).stdout.strip()
        except FileNotFoundError:
            mem = ""
        self._send(200, {
            "hostname": hostname,
            "mode": cfg.get("mode", "permissive"),
            "ssh_port": int(cfg.get("ssh_port", SSH_PORT_DEFAULT)),
            "loaded": nft.status(),
            "rule_count": len(self.server.store.rules),
            "version": "1.1.0",
        })

    def _api_list_rules(self):
        token = self._require_auth()
        if token is None:
            return
        self._send(200, {"rules": self.server.store.rules})

    def _api_add_rule(self):
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        rtype = data.get("type")
        if rtype not in RuleStore.RULE_TYPES:
            self._send(400, {"error": f"type 必须是 {RuleStore.RULE_TYPES} 之一"})
            return
        rule = {"type": rtype, "comment": str(data.get("comment", ""))[:60]}
        if rtype.startswith("port"):
            proto = data.get("proto", "tcp")
            if proto not in ("tcp", "udp"):
                self._send(400, {"error": "proto 必须是 tcp 或 udp"})
                return
            try:
                port = int(data.get("port", 0))
            except (TypeError, ValueError):
                self._send(400, {"error": "端口必须是数字"})
                return
            if not (1 <= port <= 65535):
                self._send(400, {"error": "端口范围 1-65535"})
                return
            rule["proto"] = proto
            rule["port"] = port
        else:
            ip = str(data.get("ip", "")).strip()
            if not ip:
                self._send(400, {"error": "IP 不能为空"})
                return
            rule["ip"] = ip
        self.server.store.add(rule)
        ok, msg = self.server.nft.apply()
        if not ok:
            # 应用失败：回滚规则清单
            self.server.store.remove(rule["id"])
            self._send(500, {"error": f"规则应用失败，已回滚: {msg}"})
            return
        self._send(200, {"ok": True, "rule": rule, "msg": msg})

    def _api_delete_rule(self, rule_id):
        token = self._require_auth()
        if token is None:
            return
        ok, msg = self.server.store.remove(rule_id)
        if not ok:
            self._send(400, {"error": msg})
            return
        nft_ok, nft_msg = self.server.nft.apply()
        if not nft_ok:
            self._send(500, {"error": f"规则应用失败: {nft_msg}"})
            return
        self._send(200, {"ok": True, "msg": nft_msg})

    def _api_service(self):
        """服务模板开关：{name: 'http', enabled: true}"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        name = data.get("name")
        enabled = bool(data.get("enabled"))
        if name not in SERVICES:
            self._send(400, {"error": f"服务必须是 {list(SERVICES)} 之一"})
            return
        proto, port = SERVICES[name]
        # 找同名规则
        existing = [r for r in self.server.store.rules
                    if r.get("type") == "port_allow" and r.get("port") == port]
        if enabled and not existing:
            self.server.store.add({"type": "port_allow", "proto": proto, "port": port,
                                   "comment": f"服务:{name}"})
        elif not enabled:
            for r in existing:
                if r.get("comment") == f"服务:{name}":
                    self.server.store.remove(r["id"])
        ok, msg = self.server.nft.apply()
        if not ok:
            self._send(500, {"error": msg})
            return
        self._send(200, {"ok": True, "msg": msg})

    def _api_open_port(self):
        """一键开放端口给公网：{port, proto?}（等价于添加放行规则，幂等）"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        try:
            port = int(data.get("port", 0))
        except (TypeError, ValueError):
            self._send(400, {"error": "端口必须是数字"})
            return
        proto = data.get("proto", "tcp")
        if proto not in ("tcp", "udp"):
            self._send(400, {"error": "proto 必须是 tcp 或 udp"})
            return
        if not (1 <= port <= 65535):
            self._send(400, {"error": "端口范围 1-65535"})
            return
        # 已放行则直接返回成功（幂等）
        for r in self.server.store.rules:
            if r.get("type") == "port_allow" and r.get("port") == port and r.get("proto") == proto:
                self._send(200, {"ok": True, "msg": f"端口 {port}/{proto} 已在放行列表中", "id": r["id"]})
                return
        rule = self.server.store.add({"type": "port_allow", "proto": proto, "port": port,
                                      "comment": "面板开放"})
        ok, msg = self.server.nft.apply()
        if not ok:
            self.server.store.remove(rule["id"])
            self._send(500, {"error": f"规则应用失败，已回滚: {msg}"})
            return
        self._send(200, {"ok": True, "msg": f"端口 {port}/{proto} 已开放给公网", "rule": rule})

    def _api_mode(self):
        """切换宽松/严格模式：{mode: 'permissive'|'strict'}"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        mode = data.get("mode")
        if mode not in ("permissive", "strict"):
            self._send(400, {"error": "mode 必须是 permissive 或 strict"})
            return
        self.server.config.set("mode", mode)
        ok, msg = self.server.nft.apply()
        if not ok:
            self._send(500, {"error": msg})
            return
        self._send(200, {"ok": True, "msg": msg})

    def _api_password(self):
        """修改密码：{old_password, new_password}"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        old = data.get("old_password", "")
        new = data.get("new_password", "")
        stored = self.server.config.get("password_hash", "")
        if not verify_password(old, stored):
            self._send(400, {"error": "原密码错误"})
            return
        if len(new) < 8:
            self._send(400, {"error": "新密码至少 8 位"})
            return
        self.server.config.set("password_hash", hash_password(new))
        self._send(200, {"ok": True, "msg": "密码已修改"})


# ------------------------------- 服务启动 -------------------------------

class PanelServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, handler, config, store, nft, auth):
        super().__init__(addr, handler)
        self.config = config
        self.store = store
        self.nft = nft
        self.auth = auth


def cmd_reset_password():
    """交互式重置密码（安装脚本 --change-password 调用）"""
    if not os.path.exists(CONFIG_FILE):
        print("面板未初始化，请先运行安装脚本", file=sys.stderr)
        sys.exit(1)
    cfg = Config()
    import getpass
    while True:
        p1 = getpass.getpass("输入新密码（至少 8 位）: ")
        if len(p1) < 8:
            print("密码太短")
            continue
        p2 = getpass.getpass("再次输入: ")
        if p1 != p2:
            print("两次输入不一致")
            continue
        break
    cfg.set("password_hash", hash_password(p1))
    print("密码已更新")


def cmd_apply(config):
    """应用规则（systemd ExecStartPre 或手动）"""
    store = RuleStore()
    nft = NFTManager(store, config)
    ok, msg = nft.apply()
    if not ok:
        print(f"规则应用失败: {msg}", file=sys.stderr)
        sys.exit(1)
    print(f"规则已应用: {msg}")


def cmd_open_port(port, proto="tcp"):
    """CLI 一键开放端口给公网：fwpanel open-port 8080 [tcp|udp]"""
    config = Config()
    store = RuleStore()
    if not (1 <= port <= 65535) or proto not in ("tcp", "udp"):
        print("用法: fwpanel open-port <端口(1-65535)> [tcp|udp]", file=sys.stderr)
        sys.exit(1)
    for r in store.rules:
        if r.get("type") == "port_allow" and r.get("port") == port and r.get("proto") == proto:
            print(f"端口 {port}/{proto} 已在放行列表中")
            return
    rule = store.add({"type": "port_allow", "proto": proto, "port": port, "comment": "CLI 开放"})
    nft = NFTManager(store, config)
    ok, msg = nft.apply()
    if not ok:
        store.remove(rule["id"])
        print(f"规则应用失败，已回滚: {msg}", file=sys.stderr)
        sys.exit(1)
    print(f"✓ 端口 {port}/{proto} 已开放给公网")
    print(f"  当前放行端口: " + ", ".join(
        f"{r['port']}/{r['proto']}" for r in store.rules
        if r.get("type") == "port_allow") or "（无）")


def main():
    parser = argparse.ArgumentParser(description="fwpanel 防火墙控制面板")
    parser.add_argument("cmd", nargs="?", default="serve",
                        choices=["serve", "reset-password", "apply", "open-port"])
    parser.add_argument("arg1", nargs="?", help="open-port 的端口（如 8080 或 8080/udp）")
    parser.add_argument("arg2", nargs="?", help="open-port 的协议（tcp/udp，默认 tcp）")
    parser.add_argument("--port", type=int, default=int(os.environ.get("FW_PORT", DEFAULT_PORT)))
    parser.add_argument("--bind", default=os.environ.get("FW_BIND", "127.0.0.1"))
    args = parser.parse_args()

    config = Config()
    if args.cmd == "reset-password":
        cmd_reset_password()
        return
    if args.cmd == "apply":
        cmd_apply(config)
        return
    if args.cmd == "open-port":
        arg = args.arg1 or ""
        proto = args.arg2 or "tcp"
        if "/" in arg:
            arg, proto = arg.split("/", 1)
        if not arg.isdigit():
            print("用法: fwpanel open-port <端口(1-65535)> [tcp|udp]  （如: fwpanel open-port 8080）",
                  file=sys.stderr)
            sys.exit(1)
        cmd_open_port(int(arg), proto)
        return

    # serve
    store = RuleStore()
    nft = NFTManager(store, config)
    auth = Auth(config)
    server = PanelServer((args.bind, args.port), PanelHandler, config, store, nft, auth)

    # 启动时应用一次规则（保证面板规则生效）
    ok, msg = nft.apply()
    if not ok:
        log(f"警告：启动时规则应用失败: {msg}")

    log(f"面板已启动: http://{args.bind}:{args.port}  (dry-run={DRY_RUN})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log("收到退出信号")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
