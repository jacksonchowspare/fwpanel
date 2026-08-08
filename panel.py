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
import datetime
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# ------------------------------- 常量与路径 -------------------------------
CURRENT_VERSION = "1.15.0"
# 测试时用环境变量覆盖配置目录（单测/冒烟测试）
BASE_DIR = os.environ.get("FW_TEST_DIR", "/etc/fwpanel")
APP_DIR = os.environ.get("FW_APP_DIR", "/usr/local/lib/fwpanel")
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

# 升级源（国内友好优先）：jsDelivr → GitHub raw → ghproxy
UPGRADE_SOURCES = [
    "https://cdn.jsdelivr.net/gh/jacksonchowspare/fwpanel@{tag}/{path}",
    "https://raw.githubusercontent.com/jacksonchowspare/fwpanel/{tag}/{path}",
    "https://ghproxy.com/https://raw.githubusercontent.com/jacksonchowspare/fwpanel/{tag}/{path}",
]

# 服务模板：名称 -> (协议, 端口)
SERVICES = {
    "ssh":   ("tcp", 22),
    "http":  ("tcp", 80),
    "https": ("tcp", 443),
    "dns":   ("udp", 53),
}

VALID_PROTOS = ("tcp", "udp", "both")

# SSH 端口切换时的临时放行规则注释（确认新端口可用后手动删除）
SSH_OLD_PORT_COMMENT = "旧SSH端口-切换保护"

# 严格模式下面板端口自动放行规则的注释（防止面板自身被锁死）
PANEL_PORT_COMMENT = "面板端口-严格模式"

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


def detect_distro():
    """自动识别系统发行版（读 /etc/os-release），如 'Debian 13'、'Ubuntu 26.04'、'Arch Linux'"""
    try:
        info = {}
        with open("/etc/os-release") as f:
            for line in f:
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    info[k] = v.strip('"')
        name = info.get("NAME", "").split()[0] if info.get("NAME") else info.get("ID", "Linux")
        ver = info.get("VERSION_ID", "").strip()
        return f"{name} {ver}".strip() if ver else name
    except Exception:
        return "Linux"


def is_valid_ip_or_net(s):
    """校验 IP 目标：单个 IP / CIDR 网段 / 范围，如 1.2.3.4、1.2.3.0/24、
    1.2.3.1-1.2.3.50、2001:db8::/32（IPv4/IPv6 均可）"""
    s = str(s).strip()
    # 范围格式：start-end（两端同版本且 start <= end）
    if "-" in s:
        if s.count("-") != 1:
            return False
        a, b = (x.strip() for x in s.split("-", 1))
        try:
            ia, ib = ipaddress.ip_address(a), ipaddress.ip_address(b)
        except ValueError:
            return False
        return ia.version == ib.version and int(ia) <= int(ib)
    # 单个 IP 或 CIDR
    try:
        ipaddress.ip_network(s, strict=False)
        return True
    except ValueError:
        return False


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

    def get(self, rule_id):
        for r in self.rules:
            if r["id"] == rule_id:
                return r
        return None

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
        # ⚠ 黑名单规则优先：拒绝类规则（ip_deny/port_deny）必须放在所有 accept 之前，
        #   否则 SSH 保护等 accept 规则会先命中，封禁对 SSH 端口失效
        for r in self.rules:
            if r.get("type") in ("ip_deny", "port_deny"):
                for line in self._render_one(r):
                    lines.append(line)
        # SSH 保护规则（永远存在，防锁死）
        lines.append(f"        tcp dport {ssh_port} accept   # SSH 保护(不可删除)")
        # 用户规则（放行/拒绝之外的部分）
        for r in self.rules:
            if r.get("type") not in ("ip_deny", "port_deny"):
                for line in self._render_one(r):
                    lines.append(line)
        lines.append("    }")
        lines.append("}")
        return "\n".join(lines) + "\n"

    @staticmethod
    def _render_one(r):
        """单条规则 → nft 规则行列表（proto=both 生成 TCP+UDP 两行）"""
        t = r.get("type")
        comment = r.get("comment", "")
        tag = f"  # {comment}" if comment else ""
        if t in ("port_allow", "port_deny"):
            action = "accept" if t == "port_allow" else "drop"
            if r.get("proto") == "both":
                return [f"        tcp dport {r['port']} {action}{tag}",
                        f"        udp dport {r['port']} {action}{tag}"]
            proto = r.get("proto", "tcp")
            return [f"        {proto} dport {r['port']} {action}{tag}"]
        if t in ("ip_allow", "ip_deny"):
            action = "accept" if t == "ip_allow" else "drop"
            ip = r["ip"]
            key = "ip6 saddr" if is_ipv6(ip) else "ip saddr"
            return [f"        {key} {ip} {action}{tag}"]
        return []


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

        # 幂等重建：先删除旧表再加载。
        # ⚠ nft -f 对已存在的 chain 是追加语义（规则累积），不删表会导致规则爆炸 + 旧端口残留
        subprocess.run(["nft", "delete", "table", "inet", "fwpanel"],
                       capture_output=True, text=True)

        # 加载
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

    def disable(self):
        """关闭防火墙：删除 fwpanel 表（rules.json 保留，重新开启时恢复）"""
        if DRY_RUN:
            log("[dry-run] 删除 fwpanel 表（跳过 nft 执行）")
            return True, "dry-run"
        try:
            r = subprocess.run(["nft", "delete", "table", "inet", "fwpanel"],
                               capture_output=True, text=True, timeout=10)
            if r.returncode != 0:
                return False, r.stderr.strip()[:200]
            return True, "ok"
        except FileNotFoundError:
            return False, "nft 不可用"

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


# ------------------------------- 升级功能 -------------------------------

def restart_service():
    """重启 fwpanel 服务（由修改端口/升级等操作延迟调用）"""
    subprocess.run(["systemctl", "restart", "fwpanel"], capture_output=True)


def port_in_use_py(port):
    """Python 侧端口占用检测（bind 测试）"""
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("0.0.0.0", port))
        return False
    except OSError:
        return True
    finally:
        s.close()


def http_get_json(url, timeout=8):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return json.loads(r.read())
    except Exception:
        return None


def http_download(url, dest, timeout=15):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            data = r.read()
        if not data:
            return False
        with open(dest, "wb") as f:
            f.write(data)
        return True
    except Exception:
        return False


def version_tuple(v):
    return tuple(int(x) for x in str(v).split("."))


def version_gt(a, b):
    """a > b（语义化版本比较，处理 1.10.0 > 1.9.0）"""
    return version_tuple(a) > version_tuple(b)


def get_latest_version():
    """查询 GitHub 最新版本号（GitHub API → jsDelivr data API 双源）"""
    d = http_get_json("https://api.github.com/repos/jacksonchowspare/fwpanel/releases/latest")
    if d and d.get("tag_name"):
        return d["tag_name"].lstrip("v")
    d = http_get_json("https://data.jsdelivr.com/v1/package/gh/jacksonchowspare/fwpanel")
    if d and d.get("versions"):
        return d["versions"][0]
    return None


def download_panel_files(tag, tmpdir):
    """按版本号下载 panel.py / index.html / favicon.ico 到临时目录；
    返回 (py_path, html_path, ico_path 或 None) 或 None"""
    ok, py_path = False, os.path.join(tmpdir, "panel.py")
    for tpl in UPGRADE_SOURCES:
        if http_download(tpl.format(tag=tag, path="panel.py"), py_path):
            ok = True
            break
    if not ok:
        return None
    ok, html_path = False, os.path.join(tmpdir, "index.html")
    for tpl in UPGRADE_SOURCES:
        if http_download(tpl.format(tag=tag, path="static/index.html"), html_path):
            ok = True
            break
    if not ok:
        return None
    ico_path = os.path.join(tmpdir, "favicon.ico")
    ok = False
    for tpl in UPGRADE_SOURCES:
        if http_download(tpl.format(tag=tag, path="static/favicon.ico"), ico_path):
            ok = True
            break
    return py_path, html_path, (ico_path if ok else None)


def perform_upgrade():
    """一键升级：检查版本 → 下载 → 校验 → 备份 → 替换 → 延迟重启。返回 (ok, msg)"""
    latest = get_latest_version()
    if not latest:
        return False, "无法获取最新版本（网络问题），请稍后再试"
    if not version_gt(latest, CURRENT_VERSION):
        return False, f"已是最新版本 v{CURRENT_VERSION}"

    tmpdir = tempfile.mkdtemp(prefix="fwpanel-upgrade-")
    backup_py = os.path.join(APP_DIR, "panel.py.bak")
    backup_html = os.path.join(APP_DIR, "static", "index.html.bak")
    backup_ico = os.path.join(APP_DIR, "static", "favicon.ico.bak")
    panel_py = os.path.join(APP_DIR, "panel.py")
    panel_html = os.path.join(APP_DIR, "static", "index.html")
    panel_ico = os.path.join(APP_DIR, "static", "favicon.ico")
    try:
        files = download_panel_files(latest, tmpdir)
        if not files:
            return False, "下载新版文件失败，请检查网络"
        new_py, new_html, new_ico = files
        # 校验：新版 panel.py 必须语法通过，且版本号确实更新
        try:
            import py_compile
            py_compile.compile(new_py, doraise=True)
        except Exception as e:
            return False, f"新版文件校验失败，已中止: {e}"
        try:
            with open(new_py, encoding="utf-8") as f:
                src = f.read()
            m = __import__("re").search(r'CURRENT_VERSION\s*=\s*"([\d.]+)"', src)
            if m and m.group(1) == CURRENT_VERSION:
                return False, "下载到的版本与当前相同，请稍后重试"
        except Exception:
            pass
        # 备份当前文件
        shutil.copy2(panel_py, backup_py)
        shutil.copy2(panel_html, backup_html)
        if os.path.exists(panel_ico):
            shutil.copy2(panel_ico, backup_ico)
        # 替换
        os.chmod(new_py, 0o755)
        shutil.copy2(new_py, panel_py)
        shutil.copy2(new_html, panel_html)
        if new_ico and os.path.exists(new_ico):
            shutil.copy2(new_ico, panel_ico)
    except Exception as e:
        # 失败回滚
        try:
            if os.path.exists(backup_py):
                shutil.copy2(backup_py, panel_py)
            if os.path.exists(backup_html):
                shutil.copy2(backup_html, panel_html)
            if os.path.exists(backup_ico):
                shutil.copy2(backup_ico, panel_ico)
        except Exception:
            pass
        return False, f"升级失败，已自动回滚: {e}"
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    # 延迟重启，确保响应先送达浏览器
    threading.Timer(1.5, restart_service).start()
    return True, f"已升级到 v{latest}，服务重启中，请稍候重新登录"


# ------------------------------- SSH 端口管理 -------------------------------

SSHD_CONFIG_D = os.environ.get("FW_SSHD_DIR", "/etc/ssh/sshd_config.d")


def get_sshd_port():
    """检测系统 SSH 服务实际监听端口（sshd -T 优先，root 下可用）"""
    try:
        r = subprocess.run(["sshd", "-T"], capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            if line.startswith("port "):
                return int(line.split()[1])
    except Exception:
        pass
    return SSH_PORT_DEFAULT


def sync_ssh_port(config):
    """自动同步 SSH 保护端口到系统实际端口（仅当处于自动模式，手动设置后不再覆盖）"""
    if not config.get("ssh_port_auto", True):
        return False
    try:
        detected = get_sshd_port()
        current = int(config.get("ssh_port", SSH_PORT_DEFAULT))
        if detected != current:
            config.set("ssh_port", detected)
            log(f"SSH 保护端口已自动同步为系统实际端口 {detected}")
            return True
    except Exception:
        pass
    return False


def has_established_on_port(port):
    """检测端口上是否存在已建立的 TCP 连接（SSH 连接会保持 ESTABLISHED）"""
    try:
        r = subprocess.run(["ss", "-tn", "state", "established", f"( sport = :{port} )"],
                           capture_output=True, text=True, timeout=5)
        return r.returncode == 0 and bool(r.stdout.strip())
    except Exception:
        return False


def cleanup_old_ssh_rules(old_port):
    """删除指向旧 SSH 端口的全部放行规则（切换保护/服务开关/手动开放等），
    仅保留面板端口规则（避免面板自身被锁死）"""
    store = RuleStore()
    before = len(store.rules)
    store.rules = [r for r in store.rules
                   if not (r.get("type") == "port_allow" and r.get("port") == old_port
                           and r.get("comment") != PANEL_PORT_COMMENT)]
    if len(store.rules) != before:
        store.save()
        nft = NFTManager(store, Config())
        nft.apply()
        return True
    return False


def watch_ssh_switch(old_port, new_port, confirm_delay=600, wait_timeout=3600):
    """后台监控：检测到新 SSH 端口连接后，延迟 confirm_delay 秒（10 分钟倒计时）再删除旧端口规则。
    等待连接上限 wait_timeout=3600：期间新端口始终无连接则放弃，保留旧规则保住 SSH 通道"""
    deadline = time.time() + wait_timeout
    while time.time() < deadline:
        if has_established_on_port(new_port):
            log(f"检测到新 SSH 端口 {new_port} 已有连接，开始 10 分钟倒计时，倒计时结束自动删除旧端口 {old_port} 放行规则")
            time.sleep(confirm_delay)
            if cleanup_old_ssh_rules(old_port):
                log(f"已自动删除旧端口 {old_port} 放行规则")
            else:
                log(f"无旧端口规则需清理")
            return
        time.sleep(30)
    log(f"等待新 SSH 端口 {new_port} 连接超时（{wait_timeout}s），保留旧端口 {old_port} 规则，保住 SSH 通道")


def ssh_service_name():
    """检测系统 SSH 服务名：Debian/Ubuntu 是 ssh，Arch/Fedora 等是 sshd"""
    try:
        r = subprocess.run(["systemctl", "list-unit-files"],
                           capture_output=True, text=True, timeout=5)
        if re.search(r"^ssh\.service\s", r.stdout, re.M):
            return "ssh"
    except Exception:
        pass
    return "sshd"


def apply_sshd_port(port):
    """修改系统 SSH 服务端口：写入 sshd_config.d 并重启 ssh。返回 (ok, msg)"""
    if not (1 <= port <= 65535):
        return False, "端口范围 1-65535"
    try:
        os.makedirs(SSHD_CONFIG_D, exist_ok=True)
        conf = os.path.join(SSHD_CONFIG_D, "99-fwpanel-port.conf")
        with open(conf, "w") as f:
            f.write(f"# Managed by fwpanel — SSH port\nPort {port}\n")
        svc = ssh_service_name()
        r = subprocess.run(["systemctl", "restart", svc],
                           capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            return False, f"重启 {svc} 服务失败: {r.stderr.strip()[:200]}"
        if get_sshd_port() != port:
            return False, "sshd 未监听新端口，请检查配置"
        return True, f"系统 SSH 端口已切换为 {port}"
    except Exception as e:
        return False, f"修改失败: {e}"


# ------------------------------- SSH 防爆破 -------------------------------

BANS_FILE = os.path.join(BASE_DIR, "bans.json")
BAN_COMMENT = "SSH防爆破-自动封禁"
BF_DEFAULTS = {"enabled": False, "max_fails": 5, "ban_seconds": 3600, "fail_window": 300}


def bf_cfg(config):
    """读取防爆破配置（合并默认值）"""
    bf = config.get("bruteforce")
    if not isinstance(bf, dict):
        bf = {}
    return {k: bf.get(k, v) for k, v in BF_DEFAULTS.items()}


def load_bans():
    try:
        with open(BANS_FILE) as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_bans(bans):
    try:
        os.makedirs(BASE_DIR, exist_ok=True)
        tmp = BANS_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(bans, f, ensure_ascii=False)
        os.replace(tmp, BANS_FILE)
    except Exception:
        pass


def get_failed_ssh_attempts(window_seconds):
    """从 journal 读取最近窗口内的 SSH 认证失败记录，返回 {ip: 次数}"""
    svc = ssh_service_name()
    try:
        r = subprocess.run(["journalctl", "-u", svc, "--since", f"-{int(window_seconds)}s",
                            "-o", "cat", "--no-pager"],
                           capture_output=True, text=True, timeout=10)
    except Exception:
        return {}
    counts = {}
    pat = re.compile(r"Failed password for .*? from ([0-9a-fA-F:.]+) port")
    for line in r.stdout.splitlines():
        m = pat.search(line)
        if m:
            ip = m.group(1)
            counts[ip] = counts.get(ip, 0) + 1
    return counts


def get_established_ips(port):
    """端口上已建立连接的远端 IP 集合（豁免封禁，防把自己锁死）"""
    ips = set()
    try:
        r = subprocess.run(["ss", "-tn", "state", "established", f"( sport = :{port} )"],
                           capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 5:
                remote = parts[4]
                ip = remote.rsplit(":", 1)[0].strip("[]")
                if ip and ip != "*":
                    ips.add(ip)
    except Exception:
        pass
    return ips


def bruteforce_cycle(config, store, now=None):
    """执行一轮防爆破扫描：解封到期 IP + 检测并封禁新 IP。返回动作日志列表"""
    logs = []
    bf = bf_cfg(config)
    if not bf["enabled"]:
        return logs
    if not config.get("firewall_enabled", True):
        # 防火墙已关闭：无拦截可言，跳过扫描（开启后自动恢复）
        return logs
    now = time.time() if now is None else now
    bans = load_bans()
    changed = False
    # 1) 到期解封
    expired = [ip for ip, until in bans.items() if until <= now]
    recently_unbanned = set()
    for ip in expired:
        store.rules = [r for r in store.rules
                       if not (r.get("type") == "ip_deny" and r.get("ip") == ip
                               and r.get("comment") == BAN_COMMENT)]
        del bans[ip]
        recently_unbanned.add(ip)
        changed = True
        logs.append(f"SSH 防爆破: {ip} 封禁到期，已自动解封")
    # 2) 检测新失败并封禁
    exempt = get_established_ips(int(config.get("ssh_port", SSH_PORT_DEFAULT)))
    exempt.add("127.0.0.1")
    exempt.add("::1")
    counts = get_failed_ssh_attempts(bf["fail_window"])
    for ip, n in counts.items():
        # 当前连接 IP / 已封禁 / 本轮回避（刚解封）都不重复处理
        if ip in exempt or ip in bans or ip in recently_unbanned:
            continue
        if n >= bf["max_fails"]:
            if not any(r.get("type") == "ip_deny" and r.get("ip") == ip
                       and r.get("comment") == BAN_COMMENT for r in store.rules):
                store.add({"type": "ip_deny", "ip": ip, "comment": BAN_COMMENT})
            bans[ip] = now + bf["ban_seconds"]
            changed = True
            logs.append(f"SSH 防爆破: {ip} 失败 {n} 次，已封禁 {bf['ban_seconds']} 秒")
    if changed:
        store.save()
        save_bans(bans)
        nft = NFTManager(store, config)
        nft.apply()
    return logs


def bruteforce_loop(config, store, interval=30):
    """后台监控线程：每 interval 秒执行一轮防爆破扫描"""
    while True:
        try:
            for msg in bruteforce_cycle(config, store):
                log(msg)
        except Exception as e:
            log(f"SSH 防爆破扫描异常: {e}")
        time.sleep(interval)


# ------------------------------- 反向代理（Nginx） -------------------------------

PROXIES_FILE = os.path.join(BASE_DIR, "proxies.json")
ACME_WEBROOT = "/var/www/fwpanel-acme"
LE_LIVE = "/etc/letsencrypt/live"


class ProxyStore:
    def __init__(self):
        self.proxies = self._load()

    def _load(self):
        try:
            with open(PROXIES_FILE) as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except Exception:
            return []

    def save(self):
        os.makedirs(BASE_DIR, exist_ok=True)
        tmp = PROXIES_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.proxies, f, indent=2, ensure_ascii=False)
        os.replace(tmp, PROXIES_FILE)

    def add(self, p):
        p = dict(p)
        p["id"] = secrets.token_hex(6)
        p.setdefault("scheme", "http")
        p.setdefault("websocket", False)
        p.setdefault("ssl", False)
        p.setdefault("enabled", True)
        p["created"] = int(time.time())
        self.proxies.append(p)
        self.save()
        return p

    def get(self, pid):
        for p in self.proxies:
            if p["id"] == pid:
                return p
        return None

    def remove(self, pid):
        for i, p in enumerate(self.proxies):
            if p["id"] == pid:
                self.proxies.pop(i)
                self.save()
                return True
        return False


def nginx_conf_dir():
    """检测 nginx 配置目录（Debian: sites-enabled，Arch/Fedora: conf.d）"""
    for d in ("/etc/nginx/sites-enabled", "/etc/nginx/conf.d"):
        if os.path.isdir(d):
            return d
    return None


def nginx_available():
    return shutil.which("nginx") is not None


def nginx_active():
    try:
        r = subprocess.run(["systemctl", "is-active", "nginx"],
                           capture_output=True, text=True, timeout=5)
        return r.stdout.strip() == "active"
    except Exception:
        return False


def certbot_available():
    return shutil.which("certbot") is not None


def cert_files_exist(domain):
    return os.path.isfile(os.path.join(LE_LIVE, domain, "fullchain.pem"))


def cert_status(domain):
    """返回证书到期时间戳（无证书返回 None）"""
    pem = os.path.join(LE_LIVE, domain, "fullchain.pem")
    if not os.path.isfile(pem):
        return None
    try:
        r = subprocess.run(["openssl", "x509", "-enddate", "-noout", "-in", pem],
                           capture_output=True, text=True, timeout=10)
        m = re.search(r"notAfter=(.+)", r.stdout)
        if m:
            dt = datetime.datetime.strptime(m.group(1).strip(), "%b %d %H:%M:%S %Y %Z")
            return int(dt.timestamp())
    except Exception:
        pass
    return None


def host_guard(domain):
    """生成 nginx host 守卫：只允许通过域名访问，IP/其他 Host 直连返回 444"""
    if domain.startswith("*."):
        base = re.escape(domain[2:])
        return f'    if ($host !~ ^(.+\\.)?{base}$) {{ return 444; }}\n'
    return f'    if ($host != "{domain}") {{ return 444; }}\n'


def render_proxy_conf(p):
    """生成 nginx server block 配置（含 ACME 挑战路径、HTTP→HTTPS 跳转、WebSocket 支持）"""
    ssl_on = bool(p.get("ssl")) and cert_files_exist(p["domain"])
    ws = bool(p.get("websocket"))
    block_ip = bool(p.get("block_ip"))
    upstream = f"{p.get('scheme', 'http')}://{p['target_host']}:{p['target_port']}"
    guard = host_guard(p["domain"]) if block_ip else ""
    ws_extra = ("        proxy_http_version 1.1;\n"
                "        proxy_set_header Upgrade $http_upgrade;\n"
                '        proxy_set_header Connection "upgrade";\n')
    hdr = ("        proxy_set_header Host $host;\n"
           "        proxy_set_header X-Real-IP $remote_addr;\n"
           "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n"
           "        proxy_set_header X-Forwarded-Proto $scheme;\n")
    lines = [f"# FW-Panel 管理: {p['domain']}"]
    # HTTP server（ACME 挑战；有证书时跳转 HTTPS）
    lines.append("server {")
    lines.append("    listen 80;")
    lines.append(f"    server_name {p['domain']};")
    lines.append(f"    location /.well-known/acme-challenge/ {{ root {ACME_WEBROOT}; }}")
    if guard:
        lines.extend(x for x in guard.splitlines() if x)
    if ssl_on:
        lines.append("    location / { return 301 https://$host$request_uri; }")
    else:
        lines.append("    location / {")
        lines.append(f"        proxy_pass {upstream};")
        lines.extend(x for x in hdr.splitlines() if x)
        if ws:
            lines.extend(x for x in ws_extra.splitlines() if x)
        lines.append("    }")
    lines.append("}")
    if ssl_on:
        lines.append("server {")
        lines.append("    listen 443 ssl;")
        lines.append(f"    server_name {p['domain']};")
        lines.append(f"    ssl_certificate {LE_LIVE}/{p['domain']}/fullchain.pem;")
        lines.append(f"    ssl_certificate_key {LE_LIVE}/{p['domain']}/privkey.pem;")
        if guard:
            lines.extend(x for x in guard.splitlines() if x)
        lines.append("    location / {")
        lines.append(f"        proxy_pass {upstream};")
        lines.extend(x for x in hdr.splitlines() if x)
        if ws:
            lines.extend(x for x in ws_extra.splitlines() if x)
        lines.append("    }")
        lines.append("}")
    return "\n".join(lines) + "\n"


def apply_proxies(store):
    """生成所有启用代理的 nginx 配置 → nginx -t 校验 → reload"""
    if DRY_RUN:
        log("[dry-run] 生成 nginx 反代配置（跳过写入/reload）")
        return True, "dry-run"
    conf_dir = nginx_conf_dir()
    if not conf_dir:
        return False, "未找到 nginx 配置目录（未安装 nginx？）"
    try:
        # 写入/删除各代理配置
        for p in store.proxies:
            conf = os.path.join(conf_dir, f"fwpanel-{p['id']}.conf")
            if p.get("enabled", True):
                with open(conf, "w") as f:
                    f.write(render_proxy_conf(p))
            elif os.path.exists(conf):
                os.remove(conf)
        # 清理失效配置（代理已删除或已禁用）
        for fn in os.listdir(conf_dir):
            if fn.startswith("fwpanel-") and fn.endswith(".conf"):
                pid = fn[len("fwpanel-"):-len(".conf")]
                if not any(p["id"] == pid and p.get("enabled", True) for p in store.proxies):
                    os.remove(os.path.join(conf_dir, fn))
    except OSError as e:
        return False, f"写入配置失败: {e}"
    # 校验
    try:
        r = subprocess.run(["nginx", "-t"], capture_output=True, text=True, timeout=15)
    except FileNotFoundError:
        return False, "nginx 不可用（未安装）"
    if r.returncode != 0:
        return False, f"nginx 配置校验失败: {(r.stderr or r.stdout).strip()[:300]}"
    subprocess.run(["nginx", "-s", "reload"], capture_output=True, text=True, timeout=15)
    return True, "nginx 已重载"


def issue_cert(domain, email):
    """certbot 申请证书（webroot 方式，需 80 端口公网可达）"""
    if not certbot_available():
        return False, "未安装 certbot，请先安装（apt install certbot / pacman -S certbot / dnf install certbot）"
    try:
        os.makedirs(ACME_WEBROOT, exist_ok=True)
        cmd = ["certbot", "certonly", "--webroot", "-w", ACME_WEBROOT,
               "-d", domain, "--non-interactive", "--agree-tos", "--keep-until-expiring"]
        if email:
            cmd += ["-m", email]
        else:
            cmd += ["--register-unsafely-without-email"]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except FileNotFoundError:
        return False, "certbot 不可用"
    except subprocess.TimeoutExpired:
        return False, "证书申请超时（180 秒），请确认 80 端口公网可达"
    if r.returncode != 0:
        return False, f"证书申请失败: {(r.stderr or r.stdout).strip()[:300]}"
    return True, "证书已签发"


def renew_cert(domain):
    """手动续期证书（强制 renewal）并重载 nginx"""
    if not certbot_available():
        return False, "未安装 certbot"
    try:
        r = subprocess.run(["certbot", "renew", "--cert-name", domain, "--force-renewal",
                            "--non-interactive"], capture_output=True, text=True, timeout=300)
    except FileNotFoundError:
        return False, "certbot 不可用"
    except subprocess.TimeoutExpired:
        return False, "续期超时（5 分钟）"
    if r.returncode != 0:
        return False, f"续期失败: {(r.stderr or r.stdout).strip()[:300]}"
    if nginx_available():
        subprocess.run(["nginx", "-s", "reload"], capture_output=True, text=True, timeout=15)
    return True, "证书已续期，nginx 已重载"


def pkg_mgr():
    """检测系统包管理器：apt / pacman / dnf"""
    try:
        info = {}
        with open("/etc/os-release") as f:
            for line in f:
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    info[k] = v.strip('"')
        did = info.get("ID", "")
        if did in ("debian", "ubuntu"):
            return "apt"
        if did in ("arch", "manjaro", "endeavouros"):
            return "pacman"
        if did in ("fedora", "centos", "rocky", "alma", "rhel"):
            return "dnf"
    except Exception:
        pass
    for m in ("apt-get", "pacman", "dnf"):
        if shutil.which(m):
            return m
    return None


def install_pkgs(pkgs):
    """按发行版自动安装系统包（apt-get / pacman / dnf）"""
    mgr = pkg_mgr()
    if not mgr:
        return False, "无法识别包管理器，请手动安装: " + " ".join(pkgs)
    try:
        if mgr == "apt":
            r = subprocess.run(["apt-get", "update"], capture_output=True, text=True, timeout=300)
            if r.returncode != 0:
                return False, f"apt-get update 失败: {(r.stderr or r.stdout).strip()[:200]}"
            r = subprocess.run(["apt-get", "install", "-y"] + pkgs,
                               capture_output=True, text=True, timeout=600)
        elif mgr == "pacman":
            r = subprocess.run(["pacman", "-Sy", "--noconfirm"] + pkgs,
                               capture_output=True, text=True, timeout=600)
        else:  # dnf
            r = subprocess.run(["dnf", "install", "-y"] + pkgs,
                               capture_output=True, text=True, timeout=600)
    except FileNotFoundError:
        return False, f"{mgr} 不可用"
    except subprocess.TimeoutExpired:
        return False, "安装超时（10 分钟）"
    if r.returncode != 0:
        return False, f"安装失败: {(r.stderr or r.stdout).strip()[:300]}"
    return True, f"已安装: {' '.join(pkgs)}"


def ensure_nginx_default():
    """写入 nginx 默认兜底配置（ACME 挑战路径 + 未匹配域名返回 444），保证 nginx 可直接启动"""
    conf_dir = nginx_conf_dir()
    if not conf_dir or DRY_RUN:
        return
    conf = os.path.join(conf_dir, "fwpanel-default.conf")
    content = ("# FW-Panel 默认兜底\n"
               "server {\n"
               "    listen 80;\n"
               "    server_name _;\n"
               f"    location /.well-known/acme-challenge/ {{ root {ACME_WEBROOT}; }}\n"
               "    location / { return 444; }\n"
               "}\n")
    try:
        with open(conf, "w") as f:
            f.write(content)
    except OSError:
        pass


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
            self._serve_static("index.html")
        elif path == "/favicon.ico":
            self._serve_static("favicon.ico")
        elif path == "/api/status":
            self._api_status()
        elif path == "/api/upgrade/check":
            self._api_upgrade_check()
        elif path == "/api/ssh":
            self._api_ssh()
        elif path == "/api/bruteforce":
            self._api_bruteforce()
        elif path == "/api/proxy":
            self._api_proxy()
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
        elif path.startswith("/api/rules/"):
            self._api_edit_rule(path.rsplit("/", 1)[1])
        elif path == "/api/service":
            self._api_service()
        elif path == "/api/open-port":
            self._api_open_port()
        elif path == "/api/mode":
            self._api_mode()
        elif path == "/api/password":
            self._api_password()
        elif path == "/api/upgrade":
            self._api_upgrade()
        elif path == "/api/ssh/apply":
            self._api_ssh_apply()
        elif path == "/api/ssh":
            self._api_ssh_set()
        elif path == "/api/panel/port":
            self._api_panel_port()
        elif path == "/api/bruteforce":
            self._api_bruteforce_set()
        elif path.startswith("/api/bruteforce/"):
            self._api_bruteforce_unban(path.rsplit("/", 1)[1])
        elif path == "/api/firewall":
            self._api_firewall()
        elif path == "/api/proxy":
            self._api_proxy_add()
        elif path == "/api/proxy/install":
            self._api_proxy_install()
        elif path.startswith("/api/proxy/"):
            self._api_proxy_action(path[len("/api/proxy/"):])
        elif path == "/api/username":
            self._api_username()
        else:
            self._send(404, {"error": "Not Found"})

    def do_DELETE(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path.startswith("/api/rules/"):
            self._api_delete_rule(path.rsplit("/", 1)[1])
        elif path.startswith("/api/bruteforce/"):
            self._api_bruteforce_unban(path.rsplit("/", 1)[1])
        elif path.startswith("/api/proxy/"):
            self._api_proxy_delete(path.rsplit("/", 1)[1])
        else:
            self._send(404, {"error": "Not Found"})

    # ---------- 静态页面 ----------
    def _serve_static(self, name):
        path = os.path.join(STATIC_DIR, name)
        try:
            with open(path, "rb") as f:
                data = f.read()
        except FileNotFoundError:
            self._send(404, {"error": "Not Found"})
            return
        if name.endswith(".html"):
            ctype = "text/html; charset=utf-8"
        elif name.endswith(".ico"):
            ctype = "image/x-icon"
        else:
            ctype = "application/octet-stream"
        self._send(200, data, ctype)

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
            "distro": detect_distro(),
            "mode": cfg.get("mode", "permissive"),
            "ssh_port": int(cfg.get("ssh_port", SSH_PORT_DEFAULT)),
            "loaded": nft.status(),
            "rule_count": len(self.server.store.rules),
            "version": CURRENT_VERSION,
            "panel_port": int(cfg.get("port", DEFAULT_PORT)),
            "username": cfg.get("username", ""),
        })

    def _api_upgrade_check(self):
        token = self._require_auth()
        if token is None:
            return
        latest = get_latest_version()
        if latest is None:
            self._send(502, {"error": "无法连接版本服务器，请稍后再试"})
            return
        self._send(200, {
            "current": CURRENT_VERSION,
            "latest": latest,
            "update_available": version_gt(latest, CURRENT_VERSION),
        })

    def _api_upgrade(self):
        token = self._require_auth()
        if token is None:
            return
        ok, msg = perform_upgrade()
        if not ok:
            self._send(500, {"error": msg})
            return
        self._send(200, {"ok": True, "msg": msg})

    def _api_ssh(self):
        """查询 SSH 端口状态：面板保护端口 vs 系统实际端口"""
        token = self._require_auth()
        if token is None:
            return
        self._send(200, {
            "protected_port": int(self.server.config.get("ssh_port", SSH_PORT_DEFAULT)),
            "sshd_port": get_sshd_port(),
        })

    def _api_ssh_set(self):
        """仅更新防火墙 SSH 保护端口（不动系统 sshd）"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        try:
            port = int(data.get("ssh_port", 0))
        except (TypeError, ValueError):
            self._send(400, {"error": "端口必须是数字"})
            return
        if not (1 <= port <= 65535):
            self._send(400, {"error": "端口范围 1-65535"})
            return
        self.server.config.set("ssh_port", port)
        self.server.config.set("ssh_port_auto", False)   # 手动设置后停止自动同步
        ok, msg = self.server.nft.apply()
        if not ok:
            self._send(500, {"error": f"规则应用失败: {msg}"})
            return
        self._send(200, {"ok": True, "msg": f"SSH 保护端口已更新为 {port}（防火墙规则已生效）"})

    def _api_ssh_apply(self):
        """同步修改系统 SSH 端口（防锁死流程：旧端口临时放行 → 更新保护 → 改 sshd → 重启）"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        try:
            port = int(data.get("ssh_port", 0))
        except (TypeError, ValueError):
            self._send(400, {"error": "端口必须是数字"})
            return
        if not (1 <= port <= 65535):
            self._send(400, {"error": "端口范围 1-65535"})
            return
        old = int(self.server.config.get("ssh_port", SSH_PORT_DEFAULT))
        store = self.server.store
        # 1) 端口变化时先临时放行旧端口（切换期间旧连接不断）
        if port != old:
            exists = any(r.get("type") == "port_allow" and r.get("port") == old
                         and r.get("comment") == SSH_OLD_PORT_COMMENT for r in store.rules)
            if not exists:
                store.add({"type": "port_allow", "proto": "tcp", "port": old,
                           "comment": SSH_OLD_PORT_COMMENT})
        # 2) 更新保护端口并应用规则
        self.server.config.set("ssh_port", port)
        self.server.config.set("ssh_port_auto", False)   # 手动设置后停止自动同步
        ok, msg = self.server.nft.apply()
        if not ok:
            self._send(500, {"error": f"防火墙规则应用失败: {msg}"})
            return
        # 3) 修改系统 sshd 端口
        sok, smsg = apply_sshd_port(port)
        if not sok:
            self._send(500, {"error": smsg + "（防火墙已更新，请用 ssh -p 原端口 登录排查）"})
            return
        hint = ""
        if port != old:
            threading.Thread(target=watch_ssh_switch, args=(old, port), daemon=True).start()
            hint = (f"。已启动自动检测：新端口 {port} 出现连接后自动删除旧端口 {old} 的放行规则"
                    f"（规则备注「{SSH_OLD_PORT_COMMENT}」）")
        self._send(200, {"ok": True, "msg": smsg + hint})

    def _api_panel_port(self):
        """修改面板端口：更新配置 + 同步防火墙规则 + 重启服务"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        try:
            port = int(data.get("port", 0))
        except (TypeError, ValueError):
            self._send(400, {"error": "端口必须是数字"})
            return
        if not (1 <= port <= 65535):
            self._send(400, {"error": "端口范围 1-65535"})
            return
        old = int(self.server.config.get("port", DEFAULT_PORT))
        if port == old:
            self._send(200, {"ok": True, "msg": f"面板端口已是 {port}"})
            return
        if port_in_use_py(port):
            self._send(400, {"error": f"端口 {port} 已被占用，请换一个"})
            return
        # 更新配置
        self.server.config.set("port", port)
        # 防火墙规则：删除旧面板端口的全部放行规则（不留残留攻击面），并确保新端口放行
        store = self.server.store
        store.rules = [r for r in store.rules
                       if not (r.get("type") == "port_allow" and r.get("port") == old)]
        exists = any(r.get("type") == "port_allow" and r.get("port") == port
                     and r.get("comment") == PANEL_PORT_COMMENT for r in store.rules)
        if not exists:
            store.add({"type": "port_allow", "proto": "tcp", "port": port,
                       "comment": PANEL_PORT_COMMENT})
        store.save()
        self.server.nft.apply()
        # 延迟重启，响应先送达
        threading.Timer(1.5, restart_service).start()
        self._send(200, {"ok": True, "msg": f"面板端口已修改为 {port}，服务重启中，"
                                            f"请用 http://<服务器IP>:{port} 访问"})

    def _api_username(self):
        """修改面板登录用户名"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        name = str(data.get("username", "")).strip()
        import re
        if not re.match(r"^[A-Za-z0-9_]{3,32}$", name):
            self._send(400, {"error": "用户名需为 3-32 位字母、数字或下划线"})
            return
        self.server.config.set("username", name)
        self._send(200, {"ok": True, "msg": f"登录用户名已修改为 {name}，下次登录请用新用户名"})

    def _api_bruteforce(self):
        """查询防爆破配置与当前封禁列表"""
        token = self._require_auth()
        if token is None:
            return
        bf = bf_cfg(self.server.config)
        bans = load_bans()
        now = time.time()
        items = [{"ip": ip, "until": int(u), "remaining": max(0, int(u - now))}
                 for ip, u in sorted(bans.items())]
        self._send(200, {
            "enabled": bool(bf["enabled"]),
            "max_fails": bf["max_fails"],
            "ban_seconds": bf["ban_seconds"],
            "fail_window": bf["fail_window"],
            "bans": items,
        })

    def _api_bruteforce_set(self):
        """更新防爆破配置：{enabled?, max_fails?, ban_seconds?, fail_window?}"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        bf = bf_cfg(self.server.config)
        if "enabled" in data:
            bf["enabled"] = bool(data["enabled"])
        for key, lo, hi in (("max_fails", 1, 100), ("ban_seconds", 60, 604800),
                            ("fail_window", 60, 86400)):
            if key in data:
                try:
                    v = int(data[key])
                except (TypeError, ValueError):
                    self._send(400, {"error": f"{key} 必须是数字"})
                    return
                if not (lo <= v <= hi):
                    self._send(400, {"error": f"{key} 范围 {lo}-{hi}"})
                    return
                bf[key] = v
        self.server.config.set("bruteforce", bf)
        state = "已启用" if bf["enabled"] else "已停用"
        self._send(200, {"ok": True, "msg": f"SSH 防爆破{state}（失败 {bf['max_fails']} 次封禁 {bf['ban_seconds']} 秒）"})

    def _api_bruteforce_unban(self, ip):
        """手动解封 IP"""
        token = self._require_auth()
        if token is None:
            return
        store = self.server.store
        store.rules = [r for r in store.rules
                       if not (r.get("type") == "ip_deny" and r.get("ip") == ip
                               and r.get("comment") == BAN_COMMENT)]
        bans = load_bans()
        removed = ip in bans
        if removed:
            del bans[ip]
            save_bans(bans)
        store.save()
        self.server.nft.apply()
        self._send(200, {"ok": True, "msg": f"{ip} 已解封" if removed else f"{ip} 不在封禁列表"})

    def _api_firewall(self):
        """一键开启/关闭防火墙：{enabled: true|false}
        关闭=删除 nftables 表（规则配置保留，开启时恢复）；开启=重新加载规则"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        enabled = bool(data.get("enabled"))
        if enabled:
            ok, msg = self.server.nft.apply()
            if not ok:
                self._send(500, {"error": f"开启失败: {msg}"})
                return
            self.server.config.set("firewall_enabled", True)
            self._send(200, {"ok": True, "msg": "防火墙已开启（规则已加载生效）"})
        else:
            ok, msg = self.server.nft.disable()
            if not ok:
                self._send(500, {"error": f"关闭失败: {msg}"})
                return
            self.server.config.set("firewall_enabled", False)
            self._send(200, {"ok": True, "msg": "防火墙已关闭（所有端口放行，规则配置已保留，重新开启恢复）"})

    def _api_proxy_install(self):
        """一键安装 nginx + certbot（按发行版 apt/pacman/dnf），并自动写入 nginx 配置"""
        token = self._require_auth()
        if token is None:
            return
        todo = []
        if not nginx_available():
            todo.append("nginx")
        if not certbot_available():
            todo.append("certbot")
        if todo:
            ok, msg = install_pkgs(todo)
            if not ok:
                self._send(500, {"error": msg})
                return
        # 启动 nginx 服务
        if nginx_available() and not nginx_active():
            try:
                subprocess.run(["systemctl", "enable", "--now", "nginx"],
                               capture_output=True, text=True, timeout=30)
            except Exception:
                pass
        # 自动写入 nginx 配置：ACME webroot + 默认兜底 + 已有代理配置
        try:
            os.makedirs(ACME_WEBROOT, exist_ok=True)
        except OSError:
            pass
        ensure_nginx_default()
        ok2, msg2 = apply_proxies(ProxyStore())
        if not ok2:
            self._send(500, {"error": f"nginx 配置写入失败: {msg2}"})
            return
        self._send(200, {"ok": True, "msg": f"安装完成（{', '.join(todo) or '已是最新'}）；{msg2}"})

    def _api_proxy(self):
        """查询反向代理列表与 nginx/certbot 状态"""
        token = self._require_auth()
        if token is None:
            return
        items = []
        for p in ProxyStore().proxies:
            item = {**p, "cert_expiry": cert_status(p["domain"]),
                    "cert_exists": cert_files_exist(p["domain"])}
            if item["cert_exists"]:
                item["cert_path"] = f"{LE_LIVE}/{p['domain']}/fullchain.pem"
                item["key_path"] = f"{LE_LIVE}/{p['domain']}/privkey.pem"
            items.append(item)
        self._send(200, {
            "installed": nginx_available(),
            "active": nginx_active(),
            "certbot": certbot_available(),
            "proxies": items,
        })

    def _api_proxy_add(self):
        """添加反向代理：{domain, target_host, target_port, scheme?, websocket?, ssl?}"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        domain = str(data.get("domain", "")).strip().lower()
        host = str(data.get("target_host", "")).strip()
        try:
            port = int(data.get("target_port", 0))
        except (TypeError, ValueError):
            self._send(400, {"error": "目标端口必须是数字"})
            return
        if not re.match(r"^[a-zA-Z0-9.\-*]+$", domain) or not domain:
            self._send(400, {"error": "域名格式无效（支持域名 / IP / 通配符 *.example.com）"})
            return
        if not host:
            self._send(400, {"error": "目标主机不能为空"})
            return
        if not (1 <= port <= 65535):
            self._send(400, {"error": "目标端口范围 1-65535"})
            return
        scheme = data.get("scheme", "http")
        if scheme not in ("http", "https"):
            self._send(400, {"error": "scheme 必须是 http 或 https"})
            return
        pstore = ProxyStore()
        if any(p["domain"] == domain for p in pstore.proxies):
            self._send(400, {"error": f"域名 {domain} 已存在代理"})
            return
        p = pstore.add({
            "domain": domain, "target_host": host, "target_port": port,
            "scheme": scheme, "websocket": bool(data.get("websocket")),
            "ssl": bool(data.get("ssl")),
        })
        # 防火墙放行 443（幂等）；80 不放行，如需证书申请请自行放行 80
        store = self.server.store
        changed = False
        for p443 in (443,):
            if not any(r.get("type") == "port_allow" and r.get("port") == p443
                       for r in store.rules):
                store.add({"type": "port_allow", "proto": "tcp", "port": p443,
                           "comment": "反代:HTTPS"})
                changed = True
        if changed:
            store.save()
        self.server.nft.apply()
        ok, msg = apply_proxies(pstore)
        self._send(200, {"ok": True, "msg": f"代理 {domain} 已添加（{msg}）", "proxy": p})

    def _api_proxy_action(self, suffix):
        """代理操作：POST /api/proxy/<id>  {action: enable|ssl, ...}
        或 POST /api/proxy/<id>/enable  /ssl"""
        token = self._require_auth()
        if token is None:
            return
        parts = suffix.split("/")
        pid = parts[0]
        path_action = parts[1] if len(parts) > 1 else None
        data = self._read_json()
        action = path_action or str(data.get("action", ""))
        pstore = ProxyStore()
        p = pstore.get(pid)
        if not p:
            self._send(400, {"error": "代理不存在"})
            return
        if action == "enable":
            p["enabled"] = bool(data.get("enabled", True))
            pstore.save()
            ok, msg = apply_proxies(pstore)
            self._send(200, {"ok": True, "msg": f"代理 {p['domain']} 已{'启用' if p['enabled'] else '停用'}（{msg}）"})
        elif action == "ssl":
            ok, msg = issue_cert(p["domain"], str(data.get("email", "")).strip())
            if not ok:
                self._send(500, {"error": msg})
                return
            p["ssl"] = True
            pstore.save()
            ok2, msg2 = apply_proxies(pstore)
            tail = f"；{msg2}" if ok2 else f"；配置应用失败: {msg2}"
            self._send(200, {"ok": True, "msg": msg + tail})
        elif action == "renew":
            ok, msg = renew_cert(p["domain"])
            if not ok:
                self._send(500, {"error": msg})
                return
            self._send(200, {"ok": True, "msg": msg})
        elif action == "blockip":
            p["block_ip"] = bool(data.get("enabled", True))
            pstore.save()
            ok, msg = apply_proxies(pstore)
            state = "已开启" if p["block_ip"] else "已关闭"
            self._send(200, {"ok": True, "msg": f"{p['domain']} 禁止 IP+端口访问{state}（{msg}）"})
        else:
            self._send(400, {"error": f"未知操作: {action}（支持 enable / ssl / renew / blockip）"})

    def _api_proxy_delete(self, pid):
        """删除代理"""
        token = self._require_auth()
        if token is None:
            return
        pstore = ProxyStore()
        p = pstore.get(pid)
        if not p:
            self._send(400, {"error": "代理不存在"})
            return
        domain = p["domain"]
        pstore.remove(pid)
        ok, msg = apply_proxies(pstore)
        self._send(200, {"ok": True, "msg": f"代理 {domain} 已删除（{msg}）"})

    def _api_list_rules(self):
        token = self._require_auth()
        if token is None:
            return
        self._send(200, {"rules": self.server.store.rules})

    def _api_edit_rule(self, rid):
        """修改规则备注：{comment}"""
        token = self._require_auth()
        if token is None:
            return
        store = self.server.store
        r = store.get(rid)
        if not r:
            self._send(400, {"error": "规则不存在"})
            return
        data = self._read_json()
        if "comment" not in data:
            self._send(400, {"error": "未提供备注内容"})
            return
        r["comment"] = str(data.get("comment", "")).strip()[:100]
        store.save()
        ok, msg = self.server.nft.apply()
        if not ok:
            self._send(500, {"error": msg})
            return
        self._send(200, {"ok": True, "msg": "备注已修改"})

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
            if proto not in VALID_PROTOS:
                self._send(400, {"error": f"proto 必须是 {VALID_PROTOS} 之一"})
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
            if not is_valid_ip_or_net(ip):
                self._send(400, {"error": "IP 格式无效（支持 1.2.3.4 / 1.2.3.0/24 / 1.2.3.1-1.2.3.50 / IPv6）"})
                return
            rule["ip"] = ip
        rule = self.server.store.add(rule)
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
        """服务模板开关：{name: 'http', enabled: true}
        SSH 服务端口跟随当前保护端口（不固定 22），其余服务固定"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        name = data.get("name")
        enabled = bool(data.get("enabled"))
        if name not in SERVICES:
            self._send(400, {"error": f"服务必须是 {list(SERVICES)} 之一"})
            return
        if name == "ssh":
            proto, port = "tcp", int(self.server.config.get("ssh_port", SSH_PORT_DEFAULT))
        else:
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
        if proto not in VALID_PROTOS:
            self._send(400, {"error": f"proto 必须是 {VALID_PROTOS} 之一"})
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
        """切换宽松/严格模式：{mode: 'permissive'|'strict'}
        切严格模式时自动放行面板端口，防止面板自身被锁死"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        mode = data.get("mode")
        if mode not in ("permissive", "strict"):
            self._send(400, {"error": "mode 必须是 permissive 或 strict"})
            return
        store = self.server.store
        if mode == "strict":
            # 严格模式：确保面板端口已放行（防锁死）
            panel_port = int(self.server.config.get("port", DEFAULT_PORT))
            exists = any(r.get("type") == "port_allow" and r.get("port") == panel_port
                         and r.get("comment") == PANEL_PORT_COMMENT for r in store.rules)
            if not exists:
                store.add({"type": "port_allow", "proto": "tcp", "port": panel_port,
                           "comment": PANEL_PORT_COMMENT})
        self.server.config.set("mode", mode)
        ok, msg = self.server.nft.apply()
        if not ok:
            self._send(500, {"error": msg})
            return
        extra = ""
        if mode == "strict":
            extra = f"（已自动放行面板端口 {panel_port}，防止面板被锁死）"
        self._send(200, {"ok": True, "msg": f"模式已切换为 {'严格' if mode == 'strict' else '宽松'}{extra}"})

    def _api_password(self):
        """修改密码/用户名：{old_password, new_password?, username?}
        新密码/新用户名至少提供一项（可只改其一）"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        old = data.get("old_password", "")
        stored = self.server.config.get("password_hash", "")
        if not verify_password(old, stored):
            self._send(400, {"error": "原密码错误"})
            return
        new = data.get("new_password")
        if new is not None:
            new = str(new)
            if len(new) < 8:
                self._send(400, {"error": "新密码至少 8 位"})
                return
            self.server.config.set("password_hash", hash_password(new))
        name = data.get("username")
        if name is not None:
            name = str(name).strip()
            if not re.match(r"^[A-Za-z0-9_]{3,32}$", name):
                self._send(400, {"error": "用户名需为 3-32 位字母、数字或下划线"})
                return
            self.server.config.set("username", name)
        if new is None and name is None:
            self._send(400, {"error": "未提供要修改的新密码或新用户名"})
            return
        self._send(200, {"ok": True, "msg": "账户设置已更新，下次登录生效"})


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
    """CLI 一键开放端口给公网：fwpanel open-port 8080 [tcp|udp|both]"""
    config = Config()
    store = RuleStore()
    if not (1 <= port <= 65535) or proto not in VALID_PROTOS:
        print("用法: fwpanel open-port <端口(1-65535)> [tcp|udp|both]  （默认 tcp）", file=sys.stderr)
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
    parser.add_argument("--port", type=int, default=None,
                        help="面板端口（默认读 /etc/fwpanel/config.json，安装参数 --port 写入）")
    parser.add_argument("--bind", default=None,
                        help="监听地址（默认读 /etc/fwpanel/config.json，安装参数 --bind 写入）")
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

    # serve：端口/监听地址以 config.json 为权威（安装时写入），CLI 显式参数可覆盖
    bind = args.bind or config.get("bind", "127.0.0.1")
    port = args.port or int(config.get("port", DEFAULT_PORT))
    # 自动同步 SSH 保护端口到系统实际端口（防锁死保护跟随当前 SSH 端口，手动设置后停止）
    sync_ssh_port(config)
    store = RuleStore()
    nft = NFTManager(store, config)
    auth = Auth(config)
    server = PanelServer((bind, port), PanelHandler, config, store, nft, auth)
    # SSH 防爆破后台监控（配置启用后生效）
    threading.Thread(target=bruteforce_loop, args=(config, store), daemon=True).start()
    log("SSH 防爆破监控线程已启动")

    # 启动时应用一次规则（保证面板规则生效）
    ok, msg = nft.apply()
    if not ok:
        log(f"警告：启动时规则应用失败: {msg}")

    log(f"面板已启动: http://{bind}:{port}  (dry-run={DRY_RUN})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log("收到退出信号")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
