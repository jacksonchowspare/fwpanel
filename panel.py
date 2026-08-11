#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fwpanel — 简易VPS控制面板（适配 Debian 13 / nftables）
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
CURRENT_VERSION = "1.24.38"
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
        # SSH 保护规则（永远存在，防锁死；支持白名单模式：仅允许列表 IP 访问）
        allow_ips = config.get("ssh_allow_ips") or []
        if allow_ips:
            v4 = [ip for ip in allow_ips if ":" not in ip]
            v6 = [ip for ip in allow_ips if ":" in ip]
            if v4:
                lines.append(f"        ip saddr {{{', '.join(v4)}}} tcp dport {ssh_port} accept   # SSH 白名单")
            if v6:
                lines.append(f"        ip6 saddr {{{', '.join(v6)}}} tcp dport {ssh_port} accept   # SSH 白名单")
            lines.append(f"        tcp dport {ssh_port} drop   # SSH 保护(仅白名单 IP 可访问)")
        else:
            lines.append(f"        tcp dport {ssh_port} accept   # SSH 保护(不可删除)")
        # 用户规则（放行/拒绝之外的部分）
        for r in self.rules:
            if r.get("type") not in ("ip_deny", "port_deny"):
                for line in self._render_one(r):
                    lines.append(line)
        lines.append("    }")
        # ⚠ v1.24.27：PREROUTING 拦截链（priority -200，在 Docker DNAT 之前）——
        #   Docker 端口映射（-p 8807:8080）的流量在 PREROUTING 被 DNAT 后走 FORWARD 链进容器，
        #   永远不会经过 input 链，input 链的 port_deny drop 对 Docker 端口完全无效。
        #   这里用 filter hook prerouting priority -200（早于 Docker 的 dstnat -100），
        #   公网直连目标端口在 DNAT 前直接 drop；iifname != "lo" 保证 nginx 本机反代不受影响。
        deny_ports = [r for r in self.rules if r.get("type") == "port_deny"]
        if deny_ports:
            lines.append("    chain prerouting_drop {")
            lines.append("        type filter hook prerouting priority -200; policy accept;")
            for r in deny_ports:
                if r.get("proto") == "both":
                    lines.append(f'        iifname != "lo" tcp dport {r["port"]} drop   # 禁止公网直连(Docker端口)')
                    lines.append(f'        iifname != "lo" udp dport {r["port"]} drop   # 禁止公网直连(Docker端口)')
                else:
                    proto = r.get("proto", "tcp")
                    lines.append(f'        iifname != "lo" {proto} dport {r["port"]} drop   # 禁止公网直连(Docker端口)')
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
            # 拒绝类规则排除本机回环：只挡外部流量，不挡 nginx 本机转发（反代目标端口场景）
            prefix = 'iifname != "lo" ' if t == "port_deny" else ""
            if r.get("proto") == "both":
                return [f"        {prefix}tcp dport {r['port']} {action}{tag}",
                        f"        {prefix}udp dport {r['port']} {action}{tag}"]
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
    """查询 GitHub 最新版本号（GitHub API 带重试 → jsDelivr data API 兜底）"""
    # GitHub API 主源：失败重试 2 次（服务器网络波动/限流时常见）
    for attempt in (1, 2, 3):
        d = http_get_json("https://api.github.com/repos/jacksonchowspare/fwpanel/releases/latest", timeout=20)
        if d and d.get("tag_name"):
            return d["tag_name"].lstrip("v")
        if attempt < 3:
            time.sleep(2)
    # 兜底：jsDelivr（可能有缓存滞后，比 GitHub 慢一拍）
    d = http_get_json("https://data.jsdelivr.com/v1/package/gh/jacksonchowspare/fwpanel", timeout=20)
    if d and d.get("versions"):
        return d["versions"][0]
    return None


def download_panel_files(tag, tmpdir):
    """按版本号下载 panel.py / index.html / github-logo.png / favicon.ico 到临时目录；
    返回 (py_path, html_path, logo_path 或 None, ico_path 或 None) 或 None"""
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
    logo_path = os.path.join(tmpdir, "github-logo.png")
    ok = False
    for tpl in UPGRADE_SOURCES:
        if http_download(tpl.format(tag=tag, path="static/github-logo.png"), logo_path):
            ok = True
            break
    ico_path = os.path.join(tmpdir, "favicon.ico")
    ok2 = False
    for tpl in UPGRADE_SOURCES:
        if http_download(tpl.format(tag=tag, path="static/favicon.ico"), ico_path):
            ok2 = True
            break
    return py_path, html_path, (logo_path if ok else None), (ico_path if ok2 else None)


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
    backup_logo = os.path.join(APP_DIR, "static", "github-logo.png.bak")
    panel_py = os.path.join(APP_DIR, "panel.py")
    panel_html = os.path.join(APP_DIR, "static", "index.html")
    panel_ico = os.path.join(APP_DIR, "static", "favicon.ico")
    panel_logo = os.path.join(APP_DIR, "static", "github-logo.png")
    try:
        files = download_panel_files(latest, tmpdir)
        if not files:
            return False, "下载新版文件失败，请检查网络"
        new_py, new_html, new_logo, new_ico = files
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
        if os.path.exists(panel_logo):
            shutil.copy2(panel_logo, backup_logo)
        # 替换
        os.chmod(new_py, 0o755)
        shutil.copy2(new_py, panel_py)
        shutil.copy2(new_html, panel_html)
        if new_logo and os.path.exists(new_logo):
            shutil.copy2(new_logo, panel_logo)
        if new_ico and os.path.exists(new_ico):
            shutil.copy2(new_ico, panel_ico)
    except Exception as e:
        # 失败回滚
        try:
            if os.path.exists(backup_py):
                shutil.copy2(backup_py, panel_py)
            if os.path.exists(backup_html):
                shutil.copy2(backup_html, panel_html)
            if os.path.exists(backup_logo):
                shutil.copy2(backup_logo, panel_logo)
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
MANUAL_BAN_COMMENT = "手动封禁"
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
        # 删除该 IP 的防爆破相关规则（自动封禁 + 手动封禁都到期解封）
        store.rules = [r for r in store.rules
                       if not (r.get("type") == "ip_deny" and r.get("ip") == ip
                               and r.get("comment") in (BAN_COMMENT, MANUAL_BAN_COMMENT))]
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


# ------------------------------- 网卡流量统计 -------------------------------

TRAFFIC_FILE = os.environ.get("FW_TRAFFIC_FILE", os.path.join(BASE_DIR, "traffic.json"))
TRAFFIC_INTERVAL = 60  # 采样间隔（秒）


def read_net_dev():
    """读取 /proc/net/dev 各网卡累计字节，返回 {iface: {"rx": int, "tx": int}}（排除 lo）"""
    result = {}
    try:
        with open("/proc/net/dev", "r", encoding="utf-8") as f:
            lines = f.readlines()[2:]  # 跳过表头两行
    except OSError:
        return result
    for line in lines:
        if ":" not in line:
            continue
        name, data = line.split(":", 1)
        name = name.strip()
        if not name or name == "lo":
            continue
        parts = data.split()
        if len(parts) >= 9:
            # /proc/net/dev 行格式: rx_bytes rx_packets ... tx_bytes(第9列) ...
            result[name] = {"rx": int(parts[0]), "tx": int(parts[8])}
    return result


def primary_iface():
    """识别主网卡：/proc/net/route 的默认路由网卡，兜底第一个非 lo 有数据网卡"""
    try:
        with open("/proc/net/route", "r", encoding="utf-8") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 2 and parts[1] == "00000000" and parts[0] != "lo":
                    return parts[0]
    except OSError:
        pass
    devs = read_net_dev()
    if devs:
        return sorted(devs.keys())[0]
    return "eth0"


class TrafficStore:
    """按天聚合的网卡流量存储：traffic.json = {"since": "YYYY-MM-DD", "days": {"YYYY-MM-DD": {"iface": {"rx":, "tx":}}}}"""

    def __init__(self, path=None):
        self.path = path or TRAFFIC_FILE
        self.data = {"since": None, "days": {}}
        self._last = None  # {iface: {"rx":, "tx":, "ts":}} 上次采样快照
        self._rates = {}   # {iface: {"rx_bps":, "tx_bps":}} 最近一次采样速率
        self.load()

    def load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                self.data = json.load(f)
        except (OSError, ValueError):
            self.data = {"since": None, "days": {}}
        if not isinstance(self.data.get("days"), dict):
            self.data["days"] = {}
        if "since" not in self.data:
            self.data["since"] = None

    def save(self):
        tmp = self.path + ".tmp"
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.data, f, ensure_ascii=False)
            os.replace(tmp, self.path)
        except OSError:
            pass  # 磁盘不可写不阻断面板

    def record(self, counters=None, now=None):
        """采样一次：当前累计值与上次快照的差值累加到当天；首次采样只建基线（防重启跳变）"""
        counters = counters if counters is not None else read_net_dev()
        now = now if now is not None else time.time()
        today = datetime.date.today().isoformat()
        day = self.data["days"].setdefault(today, {})
        self._rates = {}
        if self._last is None:
            self._last = {name: {"rx": c["rx"], "tx": c["tx"], "ts": now}
                          for name, c in counters.items()}
            if self.data["since"] is None:
                self.data["since"] = today
                self.save()
            return
        for name, c in counters.items():
            prev = self._last.get(name)
            if prev is None:
                self._last[name] = {"rx": c["rx"], "tx": c["tx"], "ts": now}
                continue
            dt = now - prev["ts"]
            if dt <= 0:
                dt = 1
            drx = max(0, c["rx"] - prev["rx"])
            dtx = max(0, c["tx"] - prev["tx"])
            self._rates[name] = {"rx_bps": drx / dt, "tx_bps": dtx / dt}
            if drx > 0 or dtx > 0:
                slot = day.setdefault(name, {"rx": 0, "tx": 0})
                slot["rx"] += drx
                slot["tx"] += dtx
            self._last[name] = {"rx": c["rx"], "tx": c["tx"], "ts": now}
        if self.data["since"] is None:
            self.data["since"] = today
        self.save()

    def totals_for(self, iface, start=None, end=None):
        """按日期范围累加某网卡流量；start/end 为 'YYYY-MM-DD' 或 None"""
        rx = tx = 0
        for date_str, day in self.data["days"].items():
            if start and date_str < start:
                continue
            if end and date_str > end:
                continue
            slot = day.get(iface)
            if slot:
                rx += slot.get("rx", 0)
                tx += slot.get("tx", 0)
        return {"rx": rx, "tx": tx}

    def daily(self, iface, days=7):
        """近 days 天每日流量（无记录的天补 0）"""
        out = []
        today = datetime.date.today()
        for i in range(days - 1, -1, -1):
            d = today - datetime.timedelta(days=i)
            ds = d.isoformat()
            slot = self.data["days"].get(ds, {}).get(iface, {})
            out.append({"date": ds, "rx": slot.get("rx", 0), "tx": slot.get("tx", 0)})
        return out

    def ifaces(self):
        """全部出现过的网卡（含速率表）"""
        ifaces = set()
        for day in self.data["days"].values():
            ifaces.update(day.keys())
        ifaces.update(self._rates.keys())
        return sorted(ifaces)


def traffic_active_iface(store):
    """自动选择当前有流量的网卡：最近采样速率非零 > 今日有流量记录 > 主网卡兜底"""
    # 1. 最近采样速率非零（正在跑流量）
    for name, r in sorted(store._rates.items()):
        if r.get("rx_bps", 0) > 0 or r.get("tx_bps", 0) > 0:
            return name
    # 2. 今日有流量记录
    today = datetime.date.today().isoformat()
    day = store.data.get("days", {}).get(today, {})
    for name, slot in sorted(day.items()):
        if slot.get("rx", 0) > 0 or slot.get("tx", 0) > 0:
            return name
    # 3. 主网卡兜底
    return primary_iface()


def traffic_loop(store, interval=TRAFFIC_INTERVAL):
    """后台线程：定期采样网卡流量并按天聚合"""
    while True:
        try:
            store.record()
        except Exception as e:
            log(f"网卡流量采样异常: {e}")
        time.sleep(interval)


# ------------------------------- 反向代理（Nginx） -------------------------------

PROXIES_FILE = os.path.join(BASE_DIR, "proxies.json")
CERT_FILE = os.path.join(BASE_DIR, "certificates.json")
ACME_WEBROOT = "/var/www/fwpanel-acme"
LE_LIVE = "/etc/letsencrypt/live"
PROXY_TARGET_DENY_COMMENT = "反代目标端口-禁止公网直连"


def load_cert_store():
    """独立申请的证书记录：{domain: email}"""
    try:
        with open(CERT_FILE) as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_cert_store(store):
    try:
        os.makedirs(BASE_DIR, exist_ok=True)
        tmp = CERT_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(store, f, indent=2, ensure_ascii=False)
        os.replace(tmp, CERT_FILE)
    except OSError:
        pass


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


def reload_nginx():
    """nginx -t 校验后 reload；失败返回错误信息"""
    r = subprocess.run(["nginx", "-t"], capture_output=True, text=True, timeout=15)
    if r.returncode != 0:
        return False, f"nginx 配置校验失败: {(r.stderr or r.stdout).strip()[:300]}"
    subprocess.run(["nginx", "-s", "reload"], capture_output=True, text=True, timeout=15)
    return True, "nginx 已重载"


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


def _fmt_next_check(next_raw):
    """把下次检测时间格式化为「xxxx年xx月xx日 星期几」"""
    try:
        from datetime import datetime
        # systemctl show 输出的 epoch 微秒
        if next_raw and next_raw.isdigit():
            dt = datetime.fromtimestamp(int(next_raw) / 1e6)
            return f"{dt.year}年{dt.month}月{dt.day}日 星期{'一二三四五六日'[dt.weekday()]}"
    except Exception:
        pass
    return next_raw or ""


def cert_renew_status():
    """检测 certbot 自动续期状态：systemd timer / cron 任务"""
    if not certbot_available():
        return {"enabled": False, "via": "", "next": "", "reason": "certbot 未安装"}
    try:
        r = subprocess.run(["systemctl", "show", "certbot.timer",
                            "-p", "NextElapseUSecRealtime", "-p", "ActiveState"],
                           capture_output=True, text=True, timeout=10)
        if r.returncode == 0 and "certbot.timer" in r.stdout or "ActiveState=active" in r.stdout:
            usec = ""
            for line in r.stdout.splitlines():
                if line.startswith("NextElapseUSecRealtime="):
                    usec = line.split("=", 1)[1].strip()
            if usec and usec != "0":
                return {"enabled": True, "via": "systemd timer",
                        "next": _fmt_next_check(usec), "reason": ""}
    except Exception:
        pass
    try:
        r = subprocess.run(["systemctl", "list-timers", "certbot.timer", "--no-pager"],
                           capture_output=True, text=True, timeout=10)
        if r.returncode == 0 and "certbot.timer" in r.stdout:
            for line in r.stdout.splitlines():
                if "certbot.timer" in line:
                    parts = line.split()
                    return {"enabled": True, "via": "systemd timer",
                            "next": _fmt_next_check(" ".join(parts[0:2])), "reason": ""}
    except Exception:
        pass
    if os.path.exists("/etc/cron.d/certbot"):
        return {"enabled": True, "via": "cron", "next": "每天两次随机检查", "reason": ""}
    return {"enabled": False, "via": "", "next": "", "reason": "未找到 systemd timer 或 cron 续期任务"}


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
    hsts = bool(p.get("hsts"))
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
        if hsts:
            lines.append('        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;')
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
    # 确保默认兜底配置正确（default_server 接管未匹配请求，禁止 IP 直连）
    ensure_nginx_default()
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


# ---------- Docker 模块（v1.24.0）----------

def docker_available():
    """检测 docker CLI 是否存在（docker 命令本身可用）"""
    return shutil.which("docker") is not None


def docker_status():
    """Docker 状态：{installed, service_active, version, containers, running, data_root}"""
    if not docker_available():
        return {"installed": False, "service_active": False,
                "version": "", "containers": 0, "running": 0,
                "data_root": "", "compose_version": ""}
    version = ""
    try:
        r = subprocess.run(["docker", "--version"], capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            version = (r.stdout or r.stderr).strip()
    except Exception:
        pass
    service_active = False
    try:
        r = subprocess.run(["systemctl", "is-active", "docker"],
                           capture_output=True, text=True, timeout=10)
        service_active = (r.returncode == 0 and (r.stdout or "").strip() == "active")
    except Exception:
        pass
    containers = running = 0
    try:
        r = subprocess.run(["docker", "ps", "-aq"], capture_output=True, text=True, timeout=15)
        if r.returncode == 0:
            containers = len([x for x in r.stdout.splitlines() if x.strip()])
        r2 = subprocess.run(["docker", "ps", "-q"], capture_output=True, text=True, timeout=15)
        if r2.returncode == 0:
            running = len([x for x in r2.stdout.splitlines() if x.strip()])
    except Exception:
        pass
    # 读取当前 data-root（docker info）
    data_root = ""
    try:
        ri = subprocess.run(["docker", "info", "--format", "{{.DockerRootDir}}"],
                            capture_output=True, text=True, timeout=15)
        if ri.returncode == 0:
            data_root = ri.stdout.strip()
    except Exception:
        pass
    # compose 版本（docker compose version，提取 vX.Y.Z）
    compose_version = ""
    try:
        rc = subprocess.run(["docker", "compose", "version"],
                            capture_output=True, text=True, timeout=10)
        if rc.returncode == 0:
            compose_version = rc.stdout.strip()
            # 精简：只保留版本号部分（如 Docker Compose version v2.29.7 → v2.29.7）
            m = re.search(r"v?\d+\.\d+\.\d+", compose_version)
            if m:
                compose_version = m.group(0)
    except Exception:
        pass
    return {"installed": True, "service_active": service_active,
            "version": version, "containers": containers, "running": running,
            "data_root": data_root, "compose_version": compose_version}


def install_docker_pkgs(source="official"):
    """一键安装 docker + compose 插件。
    source="official"：发行版官方源（docker.io / docker）
    source="china"：国内镜像源（Debian/Ubuntu 用阿里云 docker-ce 源装 docker-ce 全家桶；
                     Arch 走 pacman 官方源；Fedora/CentOS 用阿里云 docker-ce 源）
    返回 (ok, msg)"""
    if DRY_RUN:
        return True, f"DRY_RUN: 跳过安装（source={source}）"
    mgr = pkg_mgr()
    if not mgr:
        return False, "无法识别包管理器，请手动安装 Docker"
    try:
        if mgr == "apt":
            if source == "china":
                ok, msg = _setup_aliyun_docker_apt()
                if not ok:
                    return False, msg
                r = subprocess.run(["apt-get", "install", "-y",
                                    "docker-ce", "docker-ce-cli", "containerd.io", "docker-compose-plugin"],
                                   capture_output=True, text=True, timeout=600)
            else:
                r = subprocess.run(["apt-get", "update"], capture_output=True, text=True, timeout=300)
                if r.returncode != 0:
                    return False, f"apt-get update 失败: {(r.stderr or r.stdout).strip()[:200]}"
                # 官方源没有 docker-compose-plugin（那是 docker-ce 仓库的包名）：
                # 先试 docker-compose-v2（Debian 12+/Ubuntu 22.10+），失败回退 docker-compose（老版 v1）
                r = subprocess.run(["apt-get", "install", "-y", "docker.io", "docker-compose-v2"],
                                   capture_output=True, text=True, timeout=600)
                if r.returncode != 0:
                    r = subprocess.run(["apt-get", "install", "-y", "docker.io", "docker-compose"],
                                       capture_output=True, text=True, timeout=600)
        elif mgr == "pacman":
            r = subprocess.run(["pacman", "-Sy", "--noconfirm", "docker", "docker-compose"],
                               capture_output=True, text=True, timeout=600)
        elif mgr == "dnf":
            if source == "china":
                ok, msg = _setup_aliyun_docker_dnf()
                if not ok:
                    return False, msg
                r = subprocess.run(["dnf", "install", "-y", "docker-ce", "docker-ce-cli",
                                    "containerd.io", "docker-compose-plugin"],
                                   capture_output=True, text=True, timeout=600)
            else:
                # Fedora/RHEL 官方源同样没有 docker-compose-plugin：先试 v2，失败回退 v1
                r = subprocess.run(["dnf", "install", "-y", "docker", "docker-compose-v2"],
                                   capture_output=True, text=True, timeout=600)
                if r.returncode != 0:
                    r = subprocess.run(["dnf", "install", "-y", "docker", "docker-compose"],
                                       capture_output=True, text=True, timeout=600)
        else:
            return False, f"不支持的包管理器: {mgr}"
    except subprocess.TimeoutExpired:
        return False, "安装超时（10 分钟）"
    if r.returncode != 0:
        return False, f"安装失败: {(r.stderr or r.stdout).strip()[:300]}"
    # 启动服务 + 开机自启
    try:
        subprocess.run(["systemctl", "enable", "--now", "docker"],
                       capture_output=True, text=True, timeout=60)
    except Exception:
        pass
    return True, "Docker 已安装并启动（国内镜像源）" if source == "china" else "Docker 已安装并启动"


def uninstall_docker_pkgs():
    """一键卸载 Docker：停止并禁用服务，移除两种来源安装的全部 docker 相关包
    （国内 docker-ce 系列 + 国外 docker.io/docker 系列 + compose），保留 /DockerData 数据目录。
    返回 (ok, msg)"""
    if DRY_RUN:
        return True, "DRY_RUN: 跳过卸载"
    mgr = pkg_mgr()
    if not mgr:
        return False, "无法识别包管理器，请手动卸载 Docker"
    # 1. 停止并禁用服务（两种常见服务名都试）
    for svc in ("docker", "docker.socket"):
        try:
            subprocess.run(["systemctl", "stop", svc], capture_output=True, text=True, timeout=60)
            subprocess.run(["systemctl", "disable", svc], capture_output=True, text=True, timeout=60)
        except Exception:
            pass
    # 2. 移除包（一次性覆盖国内 + 国外两种来源的包名）
    try:
        if mgr == "apt":
            pkgs = ["docker-ce", "docker-ce-cli", "containerd.io", "docker-compose-plugin",
                    "docker.io", "docker-compose-v2", "docker-compose",
                    "docker-buildx-plugin", "docker-ce-rootless-extras"]
            r = subprocess.run(["apt-get", "remove", "-y", "--purge"] + pkgs,
                               capture_output=True, text=True, timeout=300)
            if r.returncode != 0:
                return False, f"apt-get remove 失败: {(r.stderr or r.stdout).strip()[:300]}"
            r = subprocess.run(["apt-get", "autoremove", "-y", "--purge"],
                               capture_output=True, text=True, timeout=300)
        elif mgr == "pacman":
            r = subprocess.run(["pacman", "-Rns", "--noconfirm",
                                "docker", "docker-compose", "docker-compose-plugin",
                                "containerd", "docker-buildx"],
                               capture_output=True, text=True, timeout=300)
            # pacman -Rns 对不存在的包会失败，尝试移除已装的部分
            if r.returncode != 0:
                r2 = subprocess.run(["pacman", "-Rns", "--noconfirm", "docker", "docker-compose"],
                                    capture_output=True, text=True, timeout=300)
                if r2.returncode == 0:
                    r = r2
        elif mgr == "dnf":
            pkgs = ["docker-ce", "docker-ce-cli", "containerd.io", "docker-compose-plugin",
                    "docker", "docker-compose-v2", "docker-compose",
                    "docker-buildx-plugin", "docker-ce-rootless-extras"]
            r = subprocess.run(["dnf", "remove", "-y"] + pkgs,
                               capture_output=True, text=True, timeout=300)
            if r.returncode != 0:
                return False, f"dnf remove 失败: {(r.stderr or r.stdout).strip()[:300]}"
        else:
            return False, f"不支持的包管理器: {mgr}"
    except subprocess.TimeoutExpired:
        return False, "卸载超时（5 分钟）"
    if r.returncode != 0:
        return False, f"卸载失败: {(r.stderr or r.stdout).strip()[:300]}"
    return True, "Docker 已卸载（/DockerData 数据目录已保留）"


def _setup_aliyun_docker_apt():
    """Debian/Ubuntu 配置阿里云 docker-ce 源（自动检测 codename + 架构 + gpg key）"""
    import urllib.request
    # 检测 codename（bookworm / trixie / noble ...）和架构
    codename = ""
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("VERSION_CODENAME="):
                    codename = line.strip().split("=", 1)[1].strip('"')
                    break
    except Exception:
        pass
    if not codename:
        return False, "无法检测系统 codename，请使用国外直连安装"
    arch = "amd64"
    try:
        r = subprocess.run(["dpkg", "--print-architecture"], capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            arch = r.stdout.strip()
    except Exception:
        pass
    if arch not in ("amd64", "arm64", "armhf", "ppc64el", "riscv64", "s390x"):
        return False, f"不支持的架构: {arch}"
    # 安装 gpg + 配置阿里云 docker-ce 源（apt-key 已废弃，用 keyrings + signed-by）
    try:
        os.makedirs("/etc/apt/keyrings", exist_ok=True)
        gpg_url = "https://mirrors.aliyun.com/docker-ce/linux/debian/gpg"
        key_path = "/etc/apt/keyrings/docker.gpg"
        r = subprocess.run(["curl", "-fsSL", gpg_url, "-o", key_path],
                           capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            return False, f"下载阿里云 gpg key 失败: {(r.stderr or r.stdout).strip()[:200]}"
        # 区分 Debian / Ubuntu 的源路径
        dist = "debian"
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    if line.startswith("ID="):
                        if line.strip().split("=", 1)[1].strip('"') == "ubuntu":
                            dist = "ubuntu"
                        break
        except Exception:
            pass
        repo_line = (f"deb [arch={arch} signed-by={key_path}] "
                     f"https://mirrors.aliyun.com/docker-ce/linux/{dist} {codename} stable")
        with open("/etc/apt/sources.list.d/docker-ce.list", "w") as f:
            f.write(repo_line + "\n")
        r = subprocess.run(["apt-get", "update"], capture_output=True, text=True, timeout=300)
        if r.returncode != 0:
            return False, f"apt-get update 失败: {(r.stderr or r.stdout).strip()[:300]}"
    except Exception as e:
        return False, f"配置阿里云源失败: {e}"
    return True, ""


def _setup_aliyun_docker_dnf():
    """Fedora/CentOS/RHEL 配置阿里云 docker-ce 源（dnf config-manager）"""
    # 检测大版本
    ver = "9"
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("VERSION_ID="):
                    v = line.strip().split("=", 1)[1].strip('"')
                    ver = v.split(".")[0] if v else "9"
                    break
    except Exception:
        pass
    if ver not in ("7", "8", "9", "10"):
        return False, f"不支持的 CentOS/RHEL 版本: {ver}"
    try:
        r = subprocess.run(["dnf", "config-manager", "--add-repo",
                            f"https://mirrors.aliyun.com/docker-ce/linux/centos/docker-ce.repo"],
                           capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            return False, f"添加阿里云 docker-ce 源失败: {(r.stderr or r.stdout).strip()[:300]}"
        # 阿里云 repo 文件里的官方地址替换成镜像
        repo = "/etc/yum.repos.d/docker-ce.repo"
        if os.path.exists(repo):
            with open(repo) as f:
                content = f.read()
            content = content.replace("https://download.docker.com", "https://mirrors.aliyun.com/docker-ce")
            with open(repo, "w") as f:
                f.write(content)
    except Exception as e:
        return False, f"配置阿里云源失败: {e}"
    return True, ""


def docker_images():
    """镜像列表（docker images --format json），带 in_use 标记：
    对比 docker ps -a 所有容器（含停止）引用的镜像 ID，被引用 = 使用中"""
    if not docker_available():
        return []
    try:
        r = subprocess.run(["docker", "images", "--format",
                            "{{.ID}}\t{{.Repository}}\t{{.Tag}}\t{{.Size}}"],
                           capture_output=True, text=True, timeout=20)
        if r.returncode != 0:
            return []
        # 使用中的镜像 ID 集合（docker ps -aq 拿容器 ID → inspect 拿镜像 ID，兼容短 ID 前缀）
        used_ids = set()
        try:
            rp = subprocess.run(["docker", "ps", "-aq"], capture_output=True, text=True, timeout=15)
            if rp.returncode == 0:
                cids = [x.strip() for x in rp.stdout.splitlines() if x.strip()]
                if cids:
                    ri = subprocess.run(["docker", "inspect", "--format", "{{.Image}}"] + cids,
                                        capture_output=True, text=True, timeout=20)
                    if ri.returncode == 0:
                        for img in ri.stdout.splitlines():
                            img = img.strip()
                            if img.startswith("sha256:"):
                                img = img[7:]  # ⚠ inspect 返回 sha256:64位完整ID，必须去前缀再截断
                            if img:
                                used_ids.add(img[:12])
        except Exception:
            pass
        out = []
        for line in r.stdout.splitlines():
            p = line.split("\t")
            if len(p) >= 4:
                iid = p[0][:12]
                out.append({"id": iid, "repository": p[1],
                            "tag": p[2], "size": p[3],
                            "in_use": iid in used_ids})
        return out
    except Exception:
        return []


def docker_image_prune():
    """清理全部未使用镜像（docker image prune -f，悬空+未引用）"""
    if DRY_RUN:
        return True, "DRY_RUN: image prune"
    try:
        r = subprocess.run(["docker", "image", "prune", "-f"],
                           capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return False, "清理超时（5 分钟）"
    if r.returncode != 0:
        return False, (r.stderr or r.stdout).strip()[:300]
    # 提取清理摘要（Total reclaimed space）
    msg = (r.stdout or r.stderr or "").strip()
    return True, f"未使用镜像已清理{'：' + msg if msg else ''}"


def docker_containers(all_=True):
    """容器列表（docker ps -a --format json）"""
    if not docker_available():
        return []
    try:
        args = ["docker", "ps", "--format",
                "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"]
        if all_:
            args.insert(2, "-a")
        r = subprocess.run(args, capture_output=True, text=True, timeout=20)
        if r.returncode != 0:
            return []
        out = []
        for line in r.stdout.splitlines():
            p = line.split("\t")
            if len(p) >= 4:
                running = p[3].startswith("Up")
                out.append({"id": p[0][:12], "name": p[1], "image": p[2],
                            "status": p[3], "ports": p[4] if len(p) > 4 else "",
                            "running": running})
        return out
    except Exception:
        return []


def docker_stats():
    """资源监控（docker stats --no-stream）"""
    if not docker_available():
        return []
    try:
        r = subprocess.run(
            ["docker", "stats", "--no-stream", "--format",
             "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.NetIO}}\t{{.BlockIO}}"],
            capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            return []
        out = []
        for line in r.stdout.splitlines():
            p = line.split("\t")
            if len(p) >= 6:
                out.append({"name": p[0], "cpu": p[1], "mem": p[2],
                            "mem_pct": p[3], "net": p[4], "block": p[5]})
        return out
    except Exception:
        return []


def docker_action(act, cid):
    """容器操作：start/stop/restart/remove"""
    if DRY_RUN:
        return True, f"DRY_RUN: {act} {cid}"
    try:
        r = subprocess.run(["docker", act, cid], capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return False, "操作超时"
    if r.returncode != 0:
        return False, (r.stderr or r.stdout).strip()[:300]
    return True, f"容器 {act} 成功"


def docker_logs(cid, tail=200):
    """查看容器日志（最后 N 行）"""
    try:
        r = subprocess.run(["docker", "logs", "--tail", str(tail), cid],
                           capture_output=True, text=True, timeout=20)
        return r.stdout[-8000:] + (r.stderr[-2000:] if r.stderr else "")
    except Exception:
        return ""


def docker_pull(name):
    """拉取镜像"""
    if DRY_RUN:
        return True, f"DRY_RUN: pull {name}"
    try:
        r = subprocess.run(["docker", "pull", name], capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        return False, "拉取超时（10 分钟）"
    if r.returncode != 0:
        return False, (r.stderr or r.stdout).strip()[:300]
    return True, f"镜像 {name} 拉取成功"


def docker_rmi(image_id):
    """删除镜像"""
    if DRY_RUN:
        return True, f"DRY_RUN: rmi {image_id}"
    try:
        r = subprocess.run(["docker", "rmi", "-f", image_id],
                           capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return False, "删除超时"
    if r.returncode != 0:
        return False, (r.stderr or r.stdout).strip()[:300]
    return True, f"镜像 {image_id} 已删除"


def docker_create(name, image, ports="", envs=""):
    """创建容器：name/镜像/端口映射(宿:容,逗号分隔)/环境变量(KEY=V,逗号分隔)。
    自动创建 /DockerData/dockerrun/<容器名> 数据目录并挂载到容器 /data（v1.24.10）"""
    if DRY_RUN:
        return True, f"DRY_RUN: create {name} from {image}"
    args = ["docker", "run", "-d", "--name", name]
    # 自动数据卷：/DockerData/dockerrun/<name> → /data
    vol_dir = os.path.join(DOCKER_DATA_BASE, "dockerrun", name)
    try:
        os.makedirs(vol_dir, exist_ok=True)
    except Exception:
        pass
    args += ["-v", f"{vol_dir}:/data"]
    for kv in [x.strip() for x in ports.split(",") if x.strip()]:
        args += ["-p", kv]
    for kv in [x.strip() for x in envs.split(",") if x.strip()]:
        args += ["-e", kv]
    args.append(image)
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return False, "创建超时（5 分钟）"
    if r.returncode != 0:
        return False, (r.stderr or r.stdout).strip()[:300]
    return True, f"容器 {name} 创建成功（数据卷已挂载 {vol_dir}:/data）"


# Compose 文件根目录（/DockerData/dockercompose，env 可覆盖便于测试），
# 每个 compose 按 yml 里第一个镜像名建独立子目录
COMPOSE_FILE_LEGACY = "/etc/fwpanel/docker-compose.yml"


def _compose_dir_from_content(content):
    """从 docker-compose.yml 内容解析第一个服务镜像名，生成独立子目录名。
    找不到镜像名时回退 'default'；镜像名做安全净化（只留字母数字-_.）"""
    name = "default"
    try:
        # 匹配 services: 段内第一个 image: xxx（忽略注释行）
        for line in content.splitlines():
            s = line.strip()
            if s.startswith("#") or ":" not in s:
                continue
            key, _, val = s.partition(":")
            if key.strip() == "image":
                img = val.strip().strip('"\'')
                if img:
                    # 去掉 tag 和仓库前缀，如 docker.io/library/nginx:latest → nginx
                    img = img.rsplit("/", 1)[-1].split(":", 1)[0]
                    img = re.sub(r"[^A-Za-z0-9_.-]", "", img)
                    if img:
                        name = img
                break
    except Exception:
        pass
    return name


def _compose_dir_name(content, folder=""):
    """确定 compose 子目录名：用户指定 folder 优先（安全净化），留空取第一个镜像名"""
    folder = (folder or "").strip()
    if folder:
        folder = re.sub(r"[^A-Za-z0-9_.-]", "", folder)
        return folder or _compose_dir_from_content(content)
    return _compose_dir_from_content(content)


def _compose_file_for(content, folder=""):
    """compose 文件路径：/DockerData/dockercompose/<目录名>/docker-compose.yml"""
    return os.path.join(COMPOSE_BASE, _compose_dir_name(content, folder), "docker-compose.yml")


def docker_compose_up(content, folder=""):
    """保存 docker-compose.yml 到 /DockerData/dockercompose/<目录名>/ 并启动。
    folder 非空用用户指定目录名（安全净化），留空自动取 yml 第一个镜像名。兼容旧路径自动迁移"""
    if DRY_RUN:
        return True, "DRY_RUN: compose up"
    try:
        compose_file = _compose_file_for(content, folder)
        d = os.path.dirname(compose_file)
        os.makedirs(d, exist_ok=True)
        # 旧路径存在且新路径不存在 → 迁移（保留旧数据目录一致）
        if os.path.exists(COMPOSE_FILE_LEGACY) and not os.path.exists(compose_file):
            try:
                shutil.copy2(COMPOSE_FILE_LEGACY, compose_file)
            except Exception:
                pass
        with open(compose_file, "w") as f:
            f.write(content)
        r = subprocess.run(["docker", "compose", "-f", compose_file,
                            "up", "-d"],
                           capture_output=True, text=True, timeout=300)
        if r.returncode != 0:
            return False, (r.stderr or r.stdout).strip()[:400]
    except Exception as e:
        return False, f"Compose 启动失败: {e}"
    return True, f"Compose 启动成功（已保存到 {compose_file}）"


def docker_compose_list():
    """列出已保存的 compose 项目：扫描 /DockerData/dockercompose/*/docker-compose.yml，
    每条含 folder 名、文件路径、修改时间、运行状态（docker compose ps 是否有运行中容器）"""
    items = []
    try:
        if not os.path.isdir(COMPOSE_BASE):
            return items
        for name in sorted(os.listdir(COMPOSE_BASE)):
            f = os.path.join(COMPOSE_BASE, name, "docker-compose.yml")
            if not os.path.isfile(f):
                continue
            running = False
            try:
                r = subprocess.run(["docker", "compose", "-f", f, "ps", "-q"],
                                   capture_output=True, text=True, timeout=20)
                if r.returncode == 0 and r.stdout.strip():
                    running = True
            except Exception:
                pass
            items.append({"folder": name, "path": f,
                          "mtime": int(os.path.getmtime(f)),
                          "running": running})
    except Exception:
        pass
    return items


def docker_compose_start(folder):
    """重新启动已保存的 compose 项目（docker compose -f <项目目录>/docker-compose.yml up -d）"""
    if DRY_RUN:
        return True, f"DRY_RUN: compose start {folder}"
    folder = (folder or "").strip()
    if not folder:
        return False, "缺少项目文件夹名称"
    compose_file = os.path.join(COMPOSE_BASE, folder, "docker-compose.yml")
    if not os.path.exists(compose_file):
        return False, f"未找到项目 {folder}（{compose_file} 不存在）"
    try:
        r = subprocess.run(["docker", "compose", "-f", compose_file, "up", "-d"],
                           capture_output=True, text=True, timeout=300)
        if r.returncode != 0:
            return False, (r.stderr or r.stdout).strip()[:400]
    except subprocess.TimeoutExpired:
        return False, "启动超时（5 分钟）"
    except Exception as e:
        return False, f"启动失败: {e}"
    return True, f"项目 {folder} 已启动"


def docker_compose_upgrade(folder):
    """升级已保存的 compose 项目：先 docker compose pull 拉最新镜像，再 up -d 重建容器"""
    if DRY_RUN:
        return True, f"DRY_RUN: compose upgrade {folder}"
    folder = (folder or "").strip()
    if not folder:
        return False, "缺少项目文件夹名称"
    compose_file = os.path.join(COMPOSE_BASE, folder, "docker-compose.yml")
    if not os.path.exists(compose_file):
        return False, f"未找到项目 {folder}（{compose_file} 不存在）"
    try:
        # 1. 拉取最新镜像
        r = subprocess.run(["docker", "compose", "-f", compose_file, "pull"],
                           capture_output=True, text=True, timeout=600)
        if r.returncode != 0:
            return False, f"拉取最新镜像失败: {(r.stderr or r.stdout).strip()[:400]}"
        # 2. 重建容器（检测到镜像变化会自动 recreate）
        r = subprocess.run(["docker", "compose", "-f", compose_file, "up", "-d"],
                           capture_output=True, text=True, timeout=600)
        if r.returncode != 0:
            return False, f"重建容器失败: {(r.stderr or r.stdout).strip()[:400]}"
    except subprocess.TimeoutExpired:
        return False, "升级超时（10 分钟）"
    except Exception as e:
        return False, f"升级失败: {e}"
    return True, f"项目 {folder} 已升级（镜像已更新并重建）"


def docker_compose_down(folder=""):
    """停止并移除指定 compose 项目（folder 必填；兼容旧调用不带 folder 时取最新修改的）"""
    if DRY_RUN:
        return True, "DRY_RUN: compose down"
    target = ""
    folder = (folder or "").strip()
    if folder:
        candidate = os.path.join(COMPOSE_BASE, folder, "docker-compose.yml")
        if os.path.exists(candidate):
            target = candidate
    if not target:
        # 兼容：不带 folder 时扫描 /DockerData/dockercompose/*/（有多个就取最新修改的）
        try:
            if os.path.isdir(COMPOSE_BASE):
                candidates = []
                for root, dirs, files in os.walk(COMPOSE_BASE):
                    if "docker-compose.yml" in files:
                        candidates.append(os.path.join(root, "docker-compose.yml"))
                if candidates:
                    target = max(candidates, key=os.path.getmtime)
        except Exception:
            pass
    if not target:
        target = COMPOSE_FILE_LEGACY if os.path.exists(COMPOSE_FILE_LEGACY) else ""
    if not target:
        return False, "尚未保存 docker-compose.yml，请先执行「Compose 启动」"
    try:
        r = subprocess.run(["docker", "compose", "-f", target, "down"],
                           capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            return False, (r.stderr or r.stdout).strip()[:400]
    except Exception as e:
        return False, f"Compose 停止失败: {e}"
    return True, f"Compose 已停止{f'（{folder}）' if folder else ''}"


# Docker 数据目录基础路径（/DockerData，env 可覆盖便于测试）
DOCKER_DATA_BASE = os.environ.get("FW_DOCKER_DATA", "/DockerData")
# 三个核心目录（v1.24.10 精简，用户要求）：
#   dockerimage   → 镜像存储（daemon.json data-root）
#   dockercompose → compose 文件（按镜像名分子目录）
#   dockerrun     → 面板创建容器的数据卷（自动挂载 /data）
DOCKER_DATA_DIRS = ["dockerimage", "dockercompose", "dockerrun"]
# daemon.json 路径（env 可覆盖便于测试）
DOCKER_DAEMON_JSON = os.environ.get("FW_DOCKER_DAEMON_JSON", "/etc/docker/daemon.json")
# Compose 文件根目录（/DockerData/dockercompose，env 可覆盖便于测试），
# 每个 compose 按 yml 里第一个镜像名建独立子目录
COMPOSE_BASE = os.environ.get("FW_COMPOSE_BASE", os.path.join(DOCKER_DATA_BASE, "dockercompose"))


def create_docker_dirs():
    """在根目录创建 /DockerData 及三个核心子目录（幂等，已存在不报错）"""
    if DRY_RUN:
        return True, f"DRY_RUN: 创建目录（{DOCKER_DATA_BASE} + {len(DOCKER_DATA_DIRS)} 个子目录）"
    created = []
    try:
        base = DOCKER_DATA_BASE
        os.makedirs(base, exist_ok=True)
        created.append(base)
        for sub in DOCKER_DATA_DIRS:
            d = os.path.join(base, sub)
            os.makedirs(d, exist_ok=True)
            created.append(d)
    except Exception as e:
        return False, f"创建目录失败: {e}"
    return True, f"已创建 {len(created)} 个目录：{DOCKER_DATA_BASE}（含 {len(DOCKER_DATA_DIRS)} 个核心子目录）"


def set_docker_data_root():
    """配置 Docker 镜像存储目录 → daemon.json data-root=/DockerData/dockerimage。
    保留 daemon.json 已有配置项（合并写入），幂等。返回 (ok, msg)"""
    if DRY_RUN:
        return True, "DRY_RUN: 配置 data-root"
    target = os.path.join(DOCKER_DATA_BASE, "dockerimage")
    try:
        # 先确保目录存在
        os.makedirs(target, exist_ok=True)
        d = os.path.dirname(DOCKER_DAEMON_JSON)
        os.makedirs(d, exist_ok=True)
        # 读已有配置合并（保留其他字段如 registry-mirrors）
        conf = {}
        if os.path.exists(DOCKER_DAEMON_JSON):
            try:
                with open(DOCKER_DAEMON_JSON) as f:
                    conf = json.load(f)
            except Exception:
                conf = {}
        conf["data-root"] = target
        tmp = DOCKER_DAEMON_JSON + ".tmp"
        with open(tmp, "w") as f:
            json.dump(conf, f, indent=2)
            f.write("\n")
        os.replace(tmp, DOCKER_DAEMON_JSON)
        # 重启 docker 使配置生效
        subprocess.run(["systemctl", "restart", "docker"],
                       capture_output=True, text=True, timeout=120)
    except Exception as e:
        return False, f"配置失败: {e}"
    return True, f"镜像存储已指向 {target}（Docker 已重启）"


def nginx_supports_reject_handshake():
    """nginx >= 1.19.4 支持 ssl_reject_handshake（未匹配 SNI 直接拒绝 TLS 握手）"""
    try:
        r = subprocess.run(["nginx", "-v"], capture_output=True, text=True, timeout=10)
        m = re.search(r"nginx/(\d+)\.(\d+)", (r.stderr or "") + (r.stdout or ""))
        if m:
            return (int(m.group(1)), int(m.group(2))) >= (1, 19)
    except Exception:
        pass
    return False


def ensure_nginx_default():
    """写入 nginx 默认兜底配置（default_server：未匹配域名一律 444 / 拒绝 TLS 握手）
    确保公网 IP 直连 80/443 无法访问到任何反代内容（禁止 IP+端口访问的根基）"""
    conf_dir = nginx_conf_dir()
    if not conf_dir or DRY_RUN:
        return
    # 禁用发行版自带默认站点：必须移出 sites-enabled 目录
    # （Debian include sites-enabled/* 不限后缀，仅改名 .bak 仍会被加载 → duplicate default_server）
    for f in ("/etc/nginx/sites-enabled/default",
              "/etc/nginx/sites-enabled/000-default"):
        if os.path.exists(f):
            target = f.replace("/sites-enabled/", "/sites-available/") + ".fwpanel-bak"
            if not os.path.isdir(os.path.dirname(target)):
                target = "/etc/fwpanel/" + os.path.basename(f) + ".fwpanel-bak"
            if not os.path.exists(target):
                try:
                    os.rename(f, target)
                    log(f"已禁用系统默认站点: {f} → {target}")
                except OSError:
                    pass
    # 升级清理：移除旧版兜底文件名变体（避免 duplicate default server 冲突）
    for f in ("00-fwpanel.conf", "fwpanel.conf"):
        p = os.path.join(conf_dir, f)
        if os.path.isfile(p):
            try:
                os.remove(p)
                log(f"已清理旧版兜底配置: {p}")
            except OSError:
                pass
    conf = os.path.join(conf_dir, "fwpanel-default.conf")
    content = ("# FW-Panel 默认兜底\n"
               "server {\n"
               "    listen 80 default_server;\n"
               "    server_name _;\n"
               f"    location /.well-known/acme-challenge/ {{ root {ACME_WEBROOT}; }}\n"
               "    location / { return 444; }\n"
               "}\n")
    # nginx >= 1.19.4：443 未匹配 SNI 直接拒绝握手（IP 直连 443 无法访问）
    if nginx_supports_reject_handshake():
        content += ("server {\n"
                    "    listen 443 ssl default_server;\n"
                    "    ssl_reject_handshake on;\n"
                    "    server_name _;\n"
                    "}\n")
    try:
        existing = ""
        if os.path.exists(conf):
            with open(conf) as f:
                existing = f.read()
        if existing == content:
            return  # 幂等，无需重写
        with open(conf, "w") as f:
            f.write(content)
        log("nginx 默认兜底配置已更新（default_server 接管未匹配请求）")
    except OSError:
        pass


# ------------------------------- BBR -------------------------------

IPV6_SYSCTL = "/etc/sysctl.d/99-fwpanel-ipv6.conf"
GAI_CONF = "/etc/gai.conf"


def ipv6_status():
    """IPv6 状态：v4_first（IPv6 开+IPv4 优先）/ disabled / enabled"""
    try:
        with open("/proc/sys/net/ipv6/conf/all/disable_ipv6") as f:
            disabled = f.read().strip() == "1"
    except Exception:
        disabled = True
    v4_first = False
    try:
        with open(GAI_CONF) as f:
            for line in f:
                s = line.strip()
                if s.startswith("precedence ::ffff:0:0/96") and not s.startswith("#"):
                    v4_first = True
                    break
    except Exception:
        pass
    if disabled:
        return "disabled"
    return "v4_first" if v4_first else "enabled"


def set_ipv6_mode(mode):
    """设置 IPv6 模式：v4_first / disable / enable（写 sysctl.d + gai.conf，立即生效）"""
    if mode not in ("v4_first", "disable", "enable"):
        return False, "mode 必须是 v4_first / disable / enable"
    disable = "1" if mode == "disable" else "0"
    # 1. sysctl 持久化配置 + 立即生效
    content = (f"net.ipv6.conf.all.disable_ipv6={disable}\n"
               f"net.ipv6.conf.default.disable_ipv6={disable}\n")
    try:
        os.makedirs("/etc/sysctl.d", exist_ok=True)
        tmp = IPV6_SYSCTL + ".tmp"
        with open(tmp, "w") as f:
            f.write(content)
        os.replace(tmp, IPV6_SYSCTL)
        if not DRY_RUN:
            r = subprocess.run(["sysctl", "--system"], capture_output=True, text=True, timeout=30)
            if r.returncode != 0:
                return False, f"sysctl 应用失败: {(r.stderr or r.stdout).strip()[:200]}"
            for k in ("net.ipv6.conf.all.disable_ipv6",
                      "net.ipv6.conf.default.disable_ipv6"):
                subprocess.run(["sysctl", "-w", f"{k}={disable}"],
                               capture_output=True, text=True, timeout=10)
    except OSError as e:
        return False, f"写入 {IPV6_SYSCTL} 失败: {e}"
    # 2. gai.conf：IPv4 优先规则（v4_first 添加，其余注释掉）
    try:
        if mode == "v4_first":
            if not os.path.exists(GAI_CONF):
                with open(GAI_CONF, "w") as f:
                    f.write("")
            with open(GAI_CONF) as f:
                lines = f.read().splitlines()
            if not any(s.strip().startswith("precedence ::ffff:0:0/96")
                       and not s.strip().startswith("#") for s in lines):
                lines.append("precedence ::ffff:0:0/96 100")
                with open(GAI_CONF, "w") as f:
                    f.write("\n".join(lines) + "\n")
        else:
            if os.path.exists(GAI_CONF):
                with open(GAI_CONF) as f:
                    lines = f.read().splitlines()
                changed = False
                for i, s in enumerate(lines):
                    if s.strip().startswith("precedence ::ffff:0:0/96") \
                            and not s.strip().startswith("#"):
                        lines[i] = "# " + s.lstrip("# ")
                        changed = True
                if changed:
                    with open(GAI_CONF, "w") as f:
                        f.write("\n".join(lines) + "\n")
    except OSError as e:
        return False, f"gai.conf 修改失败: {e}"
    label = {"v4_first": "IPv4 优先（IPv6 保持开启）",
             "disable": "已禁用 IPv6",
             "enable": "已开启 IPv6（系统默认优先级）"}[mode]
    return True, f"设置完成：{label}"


def bbr_status():
    """BBR 是否已开启"""
    try:
        with open("/proc/sys/net/ipv4/tcp_congestion_control") as f:
            return f.read().strip() == "bbr"
    except Exception:
        return False


def bbr_module_exists():
    """内核是否带有 bbr 模块文件（Debian 等发行版 bbr 为模块化编译）"""
    try:
        rel = os.uname().release
        for ext in ("ko", "ko.xz", "ko.zst", "ko.gz"):
            if os.path.exists(f"/lib/modules/{rel}/kernel/net/ipv4/tcp_bbr.{ext}"):
                return True
        return False
    except Exception:
        return False


def bbr_available():
    """内核是否支持 BBR（含模块化：已加载/可加载/模块文件存在）"""
    try:
        with open("/proc/sys/net/ipv4/tcp_available_congestion_control") as f:
            if "bbr" in f.read():
                return True
    except Exception:
        pass
    # 尝试加载模块（Debian 系 bbr 是 tcp_bbr.ko，设置时本可自动加载，这里主动探测）
    try:
        r = subprocess.run(["modprobe", "tcp_bbr"], capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            return True
    except Exception:
        pass
    return bbr_module_exists()


def enable_bbr():
    """开启 BBR：写入 sysctl 配置（持久化）并立即生效，回读校验"""
    if DRY_RUN:
        log("[dry-run] 写入 BBR sysctl 配置（跳过）")
        return True, "dry-run"
    if not bbr_available():
        return False, "内核不支持 BBR（需 Linux 4.9+ 且内核包含 bbr 模块）"
    conf = os.environ.get("FW_BBR_CONF", "/etc/sysctl.d/99-fwpanel-bbr.conf")
    content = "net.core.default_qdisc = fq\nnet.ipv4.tcp_congestion_control = bbr\n"
    try:
        with open(conf, "w") as f:
            f.write(content)
    except OSError as e:
        return False, f"写入配置失败: {e}"
    try:
        r1 = subprocess.run(["sysctl", "-w", "net.core.default_qdisc=fq"],
                            capture_output=True, text=True, timeout=10)
        if r1.returncode != 0:
            return False, f"设置 qdisc 失败: {(r1.stderr or r1.stdout).strip()[:200]}"
        r2 = subprocess.run(["sysctl", "-w", "net.ipv4.tcp_congestion_control=bbr"],
                            capture_output=True, text=True, timeout=10)
        if r2.returncode != 0:
            return False, f"设置 BBR 失败: {(r2.stderr or r2.stdout).strip()[:200]}"
    except FileNotFoundError:
        return False, "sysctl 不可用（配置已写入，重启后生效）"
    except Exception:
        return False, "sysctl 应用失败（配置已写入，重启后生效）"
    # 回读校验：确认内核实际生效
    if not bbr_status():
        return False, "BBR 配置已写入但内核未生效（可能被其他 sysctl 配置覆盖），请重启后检查 /proc/sys/net/ipv4/tcp_congestion_control"
    return True, "BBR 已开启（回读校验通过）"


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
        elif path.startswith("/static/fonts/"):
            self._serve_static(path[len("/static/"):])
        elif path == "/api/bbr":
            self._api_bbr()
        elif path == "/api/traffic":
            self._api_traffic()
        elif path == "/api/ipv6":
            self._api_ipv6()
        elif path == "/api/cert":
            self._api_cert()
        elif path.startswith("/api/cert/"):
            self._api_cert_action(path.rsplit("/", 1)[1])
        elif path == "/api/status":
            self._api_status()
        elif path == "/api/upgrade/check":
            self._api_upgrade_check()
        elif path == "/api/ssh":
            self._api_ssh()
        elif path == "/api/ssh/allow-ips":
            self._api_ssh_allow_ips()
        elif path == "/api/bruteforce":
            self._api_bruteforce()
        elif path == "/api/proxy":
            self._api_proxy()
        elif path == "/api/docker":
            self._api_docker_status()
        elif path == "/api/docker/containers":
            self._api_docker_containers()
        elif path == "/api/docker/images":
            self._api_docker_images()
        elif path == "/api/docker/stats":
            self._api_docker_stats()
        elif path == "/api/docker/dirs":
            self._api_docker_dirs_status()
        elif path == "/api/docker/compose":
            self._api_docker_compose_list()
        elif path.startswith("/api/docker/logs/"):
            self._api_docker_logs(path[len("/api/docker/logs/"):])
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
        elif path == "/api/close-port":
            self._api_close_port()
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
        elif path == "/api/ssh/allow-ips":
            self._api_ssh_allow_ips_set()
        elif path == "/api/panel/port":
            self._api_panel_port()
        elif path == "/api/bbr":
            self._api_bbr_enable()
        elif path == "/api/ipv6":
            self._api_ipv6()
        elif path == "/api/restart":
            self._api_restart()
        elif path == "/api/bruteforce":
            self._api_bruteforce_set()
        elif path == "/api/bruteforce/ban":
            self._api_bruteforce_ban()
        elif path == "/api/bruteforce/unban":
            self._api_bruteforce_unban()
        elif path.startswith("/api/bruteforce/"):
            self._api_bruteforce_unban(path.rsplit("/", 1)[1])
        elif path == "/api/firewall":
            self._api_firewall()
        elif path == "/api/cert":
            self._api_cert_add()
        elif path.startswith("/api/cert/"):
            self._api_cert_action(path.rsplit("/", 1)[1])
        elif path == "/api/proxy":
            self._api_proxy_add()
        elif path == "/api/proxy/install":
            self._api_proxy_install()
        elif path.startswith("/api/proxy/"):
            self._api_proxy_action(path[len("/api/proxy/"):])
        elif path == "/api/username":
            self._api_username()
        elif path == "/api/docker/install":
            self._api_docker_install()
        elif path == "/api/docker/uninstall":
            self._api_docker_uninstall()
        elif path == "/api/docker/action":
            self._api_docker_action()
        elif path == "/api/docker/create":
            self._api_docker_create()
        elif path == "/api/docker/pull":
            self._api_docker_pull()
        elif path == "/api/docker/rmi":
            self._api_docker_rmi()
        elif path == "/api/docker/prune":
            self._api_docker_prune()
        elif path == "/api/docker/data-root":
            self._api_docker_data_root()
        elif path == "/api/docker/compose/up":
            self._api_docker_compose_up()
        elif path == "/api/docker/compose/start":
            self._api_docker_compose_start()
        elif path == "/api/docker/compose/upgrade":
            self._api_docker_compose_upgrade()
        elif path == "/api/docker/compose/down":
            self._api_docker_compose_down()
        elif path == "/api/docker/dirs":
            self._api_docker_dirs_create()
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
            # 注入当前版本号（登录页底部显示）
            data = data.replace(b"__VERSION__", CURRENT_VERSION.encode())
        elif name.endswith(".png"):
            ctype = "image/png"
        elif name.endswith(".ico"):
            ctype = "image/x-icon"
        elif name.endswith(".woff2"):
            ctype = "font/woff2"
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

    def _api_ssh_allow_ips(self):
        """GET：查询 SSH 白名单 + 当前访问面板的 IP"""
        token = self._require_auth()
        if token is None:
            return
        self._send(200, {
            "ips": self.server.config.get("ssh_allow_ips") or [],
            "client_ip": self.client_address[0] if self.client_address else "",
        })

    def _api_ssh_allow_ips_set(self):
        """POST：设置 SSH 白名单 {ips: "1.2.3.4,5.6.7.8" | ""}（空 = 恢复所有 IP）"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        raw = str(data.get("ips", "")).strip()
        ips = []
        if raw:
            for part in raw.replace("，", ",").split(","):
                ip = part.strip()
                if ip and not is_valid_ip_or_net(ip):
                    self._send(400, {"error": f"IP 格式无效: {ip}（支持 1.2.3.4 / CIDR）"})
                    return
                if ip:
                    ips.append(ip)
        self.server.config.set("ssh_allow_ips", ips)
        ok, msg = self.server.nft.apply()
        if not ok:
            self._send(500, {"error": f"规则应用失败: {msg}"})
            return
        tip = f"仅允许 {len(ips)} 个 IP/CIDR 访问 SSH" if ips else "所有 IP 均可访问 SSH"
        self._send(200, {"ok": True, "msg": f"SSH 白名单已保存：{tip}（{msg}）"})

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
        # 反代联动：有代理指向旧面板端口的，同步改为新端口（反代域名访问不受影响）
        proxy_hint = ""
        pstore = ProxyStore()
        synced = [p for p in pstore.proxies if p.get("target_port") == old]
        if synced:
            for p in pstore.proxies:
                if p.get("target_port") == old:
                    p["target_port"] = port
            pstore.save()
            apply_proxies(pstore)
            # 目标端口禁止规则迁移：旧端口 → 新端口
            store.rules = [r for r in store.rules
                           if not (r.get("type") == "port_deny" and r.get("port") == old
                                   and r.get("comment") == PROXY_TARGET_DENY_COMMENT)]
            if not any(r.get("type") == "port_deny" and r.get("port") == port
                       and r.get("comment") == PROXY_TARGET_DENY_COMMENT for r in store.rules):
                store.add({"type": "port_deny", "proto": "tcp", "port": port,
                           "comment": PROXY_TARGET_DENY_COMMENT})
            store.save()
            self.server.nft.apply()
            proxy_hint = f"；已同步 {len(synced)} 个反代目标端口到新端口，域名访问不受影响"
        # 延迟重启，响应先送达
        threading.Timer(1.5, restart_service).start()
        self._send(200, {"ok": True, "msg": f"面板端口已修改为 {port}，服务重启中，"
                                            f"请用 http://<服务器IP>:{port} 访问{proxy_hint}"})

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

    # ---------- Docker API（v1.24.0）----------

    def _api_docker_status(self):
        """GET /api/docker → 安装状态/版本/容器数"""
        token = self._require_auth()
        if token is None:
            return
        self._send(200, docker_status())

    def _api_docker_containers(self):
        """GET /api/docker/containers → 容器列表"""
        token = self._require_auth()
        if token is None:
            return
        self._send(200, {"containers": docker_containers(True)})

    def _api_docker_images(self):
        """GET /api/docker/images → 镜像列表"""
        token = self._require_auth()
        if token is None:
            return
        self._send(200, {"images": docker_images()})

    def _api_docker_stats(self):
        """GET /api/docker/stats → 资源监控"""
        token = self._require_auth()
        if token is None:
            return
        self._send(200, {"stats": docker_stats()})

    def _api_docker_logs(self, cid):
        """GET /api/docker/logs/<id> → 容器日志"""
        token = self._require_auth()
        if token is None:
            return
        self._send(200, {"logs": docker_logs(cid)})

    def _api_docker_install(self):
        """POST /api/docker/install {source: official|china} → 一键安装 docker + compose"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        source = str(data.get("source", "official"))
        if source not in ("official", "china"):
            source = "official"
        ok, msg = install_docker_pkgs(source)
        self._send(200 if ok else 500, {"ok": ok, "msg": msg})

    def _api_docker_uninstall(self):
        """POST /api/docker/uninstall → 一键卸载 docker（国内/国外源安装均可）"""
        token = self._require_auth()
        if token is None:
            return
        ok, msg = uninstall_docker_pkgs()
        self._send(200 if ok else 500, {"ok": ok, "msg": msg})

    def _api_docker_action(self):
        """POST /api/docker/action {action, id} → start/stop/restart/remove"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        act = str(data.get("action", ""))
        cid = str(data.get("id", "")).strip()
        if act not in ("start", "stop", "restart", "remove"):
            self._send(400, {"error": "无效操作，支持: start/stop/restart/remove"})
            return
        if not cid:
            self._send(400, {"error": "缺少容器 ID"})
            return
        ok, msg = docker_action(act, cid)
        self._send(200 if ok else 500, {"ok": ok, "msg": msg})

    def _api_docker_create(self):
        """POST /api/docker/create {name, image, ports, envs} → 创建容器"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        name = str(data.get("name", "")).strip()
        image = str(data.get("image", "")).strip()
        if not name or not image:
            self._send(400, {"error": "容器名称和镜像不能为空"})
            return
        ok, msg = docker_create(name, image,
                                str(data.get("ports", "")),
                                str(data.get("envs", "")))
        self._send(200 if ok else 500, {"ok": ok, "msg": msg})

    def _api_docker_pull(self):
        """POST /api/docker/pull {name} → 拉取镜像"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        name = str(data.get("name", "")).strip()
        if not name:
            self._send(400, {"error": "镜像名不能为空"})
            return
        ok, msg = docker_pull(name)
        self._send(200 if ok else 500, {"ok": ok, "msg": msg})

    def _api_docker_rmi(self):
        """POST /api/docker/rmi {id} → 删除镜像"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        image_id = str(data.get("id", "")).strip()
        if not image_id:
            self._send(400, {"error": "缺少镜像 ID"})
            return
        ok, msg = docker_rmi(image_id)
        self._send(200 if ok else 500, {"ok": ok, "msg": msg})

    def _api_docker_prune(self):
        """POST /api/docker/prune → 清理全部未使用镜像"""
        token = self._require_auth()
        if token is None:
            return
        ok, msg = docker_image_prune()
        self._send(200 if ok else 500, {"ok": ok, "msg": msg})

    def _api_docker_data_root(self):
        """POST /api/docker/data-root → 配置镜像存储目录为 /DockerData/dockerimage"""
        token = self._require_auth()
        if token is None:
            return
        ok, msg = set_docker_data_root()
        self._send(200 if ok else 500, {"ok": ok, "msg": msg})

    def _api_docker_compose_up(self):
        """POST /api/docker/compose/up {content, folder} → 保存并启动 compose"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        content = str(data.get("content", ""))
        if not content.strip():
            self._send(400, {"error": "docker-compose.yml 内容不能为空"})
            return
        ok, msg = docker_compose_up(content, str(data.get("folder", "")))
        self._send(200 if ok else 500, {"ok": ok, "msg": msg})

    def _api_docker_compose_list(self):
        """GET /api/docker/compose → 已保存的 compose 项目列表"""
        token = self._require_auth()
        if token is None:
            return
        self._send(200, {"projects": docker_compose_list()})

    def _api_docker_compose_start(self):
        """POST /api/docker/compose/start {folder} → 启动指定已保存项目"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        folder = str(data.get("folder", "")).strip()
        if not folder:
            self._send(400, {"error": "缺少项目文件夹名称"})
            return
        ok, msg = docker_compose_start(folder)
        self._send(200 if ok else 500, {"ok": ok, "msg": msg})

    def _api_docker_compose_upgrade(self):
        """POST /api/docker/compose/upgrade {folder} → 升级指定已保存项目（拉最新镜像+重建）"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        folder = str(data.get("folder", "")).strip()
        if not folder:
            self._send(400, {"error": "缺少项目文件夹名称"})
            return
        ok, msg = docker_compose_upgrade(folder)
        self._send(200 if ok else 500, {"ok": ok, "msg": msg})

    def _api_docker_compose_down(self):
        """POST /api/docker/compose/down {folder} → 停止指定 compose 项目"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        folder = str(data.get("folder", ""))
        ok, msg = docker_compose_down(folder)
        self._send(200 if ok else 500, {"ok": ok, "msg": msg})

    def _api_docker_dirs_create(self):
        """POST /api/docker/dirs → 一键创建 /DockerData 及常用子目录"""
        token = self._require_auth()
        if token is None:
            return
        ok, msg = create_docker_dirs()
        self._send(200 if ok else 500, {"ok": ok, "msg": msg})

    def _api_docker_dirs_status(self):
        """GET /api/docker/dirs → 目录创建状态（是否存在/子目录数）"""
        token = self._require_auth()
        if token is None:
            return
        base = DOCKER_DATA_BASE
        exists = os.path.isdir(base)
        sub_count = 0
        if exists:
            try:
                sub_count = sum(1 for d in DOCKER_DATA_DIRS if os.path.isdir(os.path.join(base, d)))
            except Exception:
                pass
        self._send(200, {"exists": exists, "base": base,
                         "sub_dirs": sub_count, "total": len(DOCKER_DATA_DIRS)})

    def _api_bruteforce_ban(self):
        """手动封禁 IP：{ip} → 添加拒绝规则 + 写入封禁记录（使用配置的封禁时长）"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        ip = str(data.get("ip", "")).strip()
        if not is_valid_ip_or_net(ip) or "/" in ip or "-" in ip:
            self._send(400, {"error": "请输入单个 IP 地址（IPv4/IPv6）"})
            return
        store = self.server.store
        if any(r.get("type") == "ip_deny" and r.get("ip") == ip for r in store.rules):
            self._send(400, {"error": f"{ip} 已在封禁列表"})
            return
        store.add({"type": "ip_deny", "ip": ip, "comment": MANUAL_BAN_COMMENT})
        # 写入封禁记录（显示在防爆破模块，带剩余时间）
        bans = load_bans()
        bans[ip] = int(time.time()) + bf_cfg(self.server.config)["ban_seconds"]
        save_bans(bans)
        ok, msg = self.server.nft.apply()
        if not ok:
            self._send(500, {"error": msg})
            return
        self._send(200, {"ok": True, "msg": f"已封禁 {ip}"})

    def _api_bruteforce_unban(self, ip=None):
        """手动解封 IP：{ip} → 删除该 IP 的全部拒绝规则与封禁记录"""
        token = self._require_auth()
        if token is None:
            return
        if ip is None:
            data = self._read_json()
            ip = str(data.get("ip", "")).strip()
        if not ip:
            self._send(400, {"error": "请输入 IP 地址"})
            return
        store = self.server.store
        before = len(store.rules)
        store.rules = [r for r in store.rules
                       if not (r.get("type") == "ip_deny" and r.get("ip") == ip)]
        removed = len(store.rules) < before
        bans = load_bans()
        if ip in bans:
            del bans[ip]
            save_bans(bans)
        if removed:
            store.save()
            ok, msg = self.server.nft.apply()
            if not ok:
                self._send(500, {"error": msg})
                return
        self._send(200, {"ok": True,
                         "msg": f"{ip} 已解封" if removed else f"{ip} 不在封禁列表"})

    def _api_traffic(self):
        """网卡流量统计：GET /api/traffic?iface=eth0&from=YYYY-MM-DD&to=YYYY-MM-DD
        返回 网卡列表/实时速率/今日/昨日/近7天/总累计/自定义日期范围累计"""
        token = self._require_auth()
        if token is None:
            return
        traffic = getattr(self.server, "traffic", None)
        if traffic is None:
            traffic = TrafficStore()  # 兜底（未挂载时独立实例）
        try:
            traffic.record()  # 顺手补一次采样，让今日与速率最新
        except Exception:
            pass
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        iface = (qs.get("iface") or [""])[0].strip()
        if not iface:
            iface = traffic_active_iface(traffic)  # 默认选中当前有流量的网卡
        from_date = (qs.get("from") or [""])[0].strip()
        to_date = (qs.get("to") or [""])[0].strip()
        for name, val in (("开始日期", from_date), ("结束日期", to_date)):
            if val:
                try:
                    datetime.date.fromisoformat(val)
                except ValueError:
                    self._send(400, {"error": f"{name}格式应为 YYYY-MM-DD"})
                    return
        if from_date and to_date and to_date < from_date:
            self._send(400, {"error": "结束日期不能早于开始日期"})
            return
        today = datetime.date.today().isoformat()
        yesterday = (datetime.date.today() - datetime.timedelta(days=1)).isoformat()
        resp = {
            "ifaces": traffic.ifaces(),
            "primary": primary_iface(),
            "current": iface,
            "rates": traffic._rates,
            "today": traffic.totals_for(iface, start=today),
            "yesterday": traffic.totals_for(iface, start=yesterday, end=yesterday),
            "week": traffic.daily(iface, 7),
            "total": traffic.totals_for(iface),
            "since": traffic.data.get("since"),
        }
        if from_date:
            end = to_date or today
            d0 = datetime.date.fromisoformat(from_date)
            d1 = datetime.date.fromisoformat(end)
            resp["custom"] = {
                "rx": traffic.totals_for(iface, start=from_date, end=end)["rx"],
                "tx": traffic.totals_for(iface, start=from_date, end=end)["tx"],
                "from": from_date,
                "to": end,
                "days": max(0, (d1 - d0).days + 1),
            }
        self._send(200, resp)

    def _api_bbr(self):
        """查询 BBR 状态与内核版本"""
        token = self._require_auth()
        if token is None:
            return
        self._send(200, {
            "enabled": bbr_status(),
            "supported": bbr_available(),
            "kernel": os.uname().release,
        })

    def _api_bbr_enable(self):
        """一键开启 BBR"""
        token = self._require_auth()
        if token is None:
            return
        ok, msg = enable_bbr()
        if not ok:
            self._send(500, {"error": msg})
            return
        self._send(200, {"ok": True, "msg": msg, "enabled": bbr_status()})

    def _api_ipv6(self):
        """GET：查询 IPv6 状态；POST {mode}：设置 v4_first / disable / enable"""
        token = self._require_auth()
        if token is None:
            return
        if self.command == "GET":
            self._send(200, {"status": ipv6_status()})
            return
        data = self._read_json()
        mode = str(data.get("mode", ""))
        ok, msg = set_ipv6_mode(mode)
        if not ok:
            self._send(400, {"error": msg})
            return
        self._send(200, {"ok": True, "msg": msg, "status": ipv6_status()})

    def _api_restart(self):
        """重启面板服务（先响应，再延迟重启，前端收到反馈后自动重连）"""
        token = self._require_auth()
        if token is None:
            return
        if DRY_RUN:
            log("[dry-run] 重启面板服务（跳过）")
            self._send(200, {"ok": True, "msg": "dry-run: 重启面板（跳过）"})
            return
        threading.Timer(1.0, restart_service).start()
        self._send(200, {"ok": True, "msg": "面板重启中，约 5 秒后自动重新连接..."})

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

    def _api_cert(self):
        """独立证书列表：域名、邮箱、有效期、路径"""
        token = self._require_auth()
        if token is None:
            return
        store = load_cert_store()
        items = []
        for domain, email in store.items():
            item = {"domain": domain, "email": email,
                    "cert_exists": cert_files_exist(domain),
                    "cert_expiry": cert_status(domain)}
            if item["cert_exists"]:
                item["cert_path"] = f"{LE_LIVE}/{domain}/fullchain.pem"
                item["key_path"] = f"{LE_LIVE}/{domain}/privkey.pem"
            items.append(item)
        self._send(200, {
            "installed": nginx_available(),
            "certbot": certbot_available(),
            "renew": cert_renew_status(),
            "certs": items,
        })

    def _api_cert_add(self):
        """单独申请 SSL 证书：{domain, email?}（certbot webroot，需 80 可达）"""
        token = self._require_auth()
        if token is None:
            return
        data = self._read_json()
        domain = str(data.get("domain", "")).strip().lower()
        email = str(data.get("email", "")).strip()
        if not re.match(r"^[a-zA-Z0-9.\-*]+$", domain) or not domain:
            self._send(400, {"error": "域名格式无效（如 example.com 或 *.example.com）"})
            return
        if not nginx_available():
            self._send(400, {"error": "未安装 nginx，请先在反向代理模块一键安装（ACME 挑战需要）"})
            return
        ensure_nginx_default()   # 确保 80 挑战路径兜底配置存在
        ok, msg = reload_nginx()  # 新配置必须立即生效，否则挑战仍 404
        if not ok:
            self._send(500, {"error": msg})
            return
        ok, msg = issue_cert(domain, email)
        if not ok:
            self._send(500, {"error": msg})
            return
        store = load_cert_store()
        store[domain] = email
        save_cert_store(store)
        self._send(200, {"ok": True, "msg": f"{domain} 证书已签发"})

    def _api_cert_action(self, suffix):
        """证书操作：POST /api/cert/<domain> {action: renew|delete}"""
        token = self._require_auth()
        if token is None:
            return
        domain = suffix.strip().lower()
        data = self._read_json()
        action = str(data.get("action", ""))
        store = load_cert_store()
        if domain not in store:
            self._send(400, {"error": "该域名不在独立证书列表中"})
            return
        if action == "renew":
            ok, msg = renew_cert(domain)
            if not ok:
                self._send(500, {"error": msg})
                return
            self._send(200, {"ok": True, "msg": f"{domain} 证书已续期"})
        elif action == "delete":
            del store[domain]
            save_cert_store(store)
            self._send(200, {"ok": True, "msg": f"{domain} 已从列表移除（证书文件保留，供服务引用）"})
        else:
            self._send(400, {"error": "action 必须是 renew 或 delete"})

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
            "renew": cert_renew_status(),
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
            "hsts": bool(data.get("hsts")),
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
        # 禁止公网直连目标端口（80/443 除外——入口端口由 nginx 兜底 444 控制）
        # 拒绝规则含回环豁免，不影响 nginx 本机转发
        if port not in (80, 443) and not any(
                r.get("type") == "port_deny" and r.get("port") == port
                and r.get("comment") == PROXY_TARGET_DENY_COMMENT for r in store.rules):
            store.add({"type": "port_deny", "proto": "tcp", "port": port,
                       "comment": PROXY_TARGET_DENY_COMMENT})
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
            # 规则联动（v1.24.28 用户明确要求"总开关"心智）：
            # 开启 → 幂等补建目标端口拒绝规则（缺失自动重建）
            # 关闭 → 删除该端口的拒绝规则（nginx 入口 + 防火墙保护同时放开）
            # ⚠ 用户已知悉：关闭后目标端口（含 Docker 发布端口）公网直连不再受防火墙保护
            tail = ""
            tport = p.get("target_port")
            if tport and tport not in (80, 443):
                store = self.server.store
                if p["block_ip"]:
                    # 开启：补建（幂等）
                    if not any(r.get("type") == "port_deny" and r.get("port") == tport
                               and r.get("comment") == PROXY_TARGET_DENY_COMMENT
                               for r in store.rules):
                        store.add({"type": "port_deny", "proto": "tcp", "port": tport,
                                   "comment": PROXY_TARGET_DENY_COMMENT})
                        store.save()
                        self.server.nft.apply()
                        tail = "；已重建目标端口拒绝规则"
                else:
                    # 关闭：删除（联动）
                    before = len(store.rules)
                    store.rules = [r for r in store.rules
                                   if not (r.get("type") == "port_deny" and r.get("port") == tport
                                           and r.get("comment") == PROXY_TARGET_DENY_COMMENT)]
                    if len(store.rules) != before:
                        store.save()
                        self.server.nft.apply()
                        tail = "；已删除目标端口拒绝规则"
            self._send(200, {"ok": True, "msg": f"{p['domain']} 禁止 IP+端口访问{state}（{msg}）{tail}"})
        elif action == "edit":
            if "scheme" in data:
                sc = str(data.get("scheme"))
                if sc not in ("http", "https"):
                    self._send(400, {"error": "scheme 必须是 http 或 https"})
                    return
                p["scheme"] = sc
            p["websocket"] = bool(data.get("websocket", p.get("websocket", False)))
            p["hsts"] = bool(data.get("hsts", p.get("hsts", False)))
            pstore.save()
            ok, msg = apply_proxies(pstore)
            tail = "" if ok else f"；配置应用失败: {msg}"
            self._send(200, {"ok": True, "msg": f"{p['domain']} 已更新（WebSocket: {'开' if p['websocket'] else '关'} / HSTS: {'开' if p['hsts'] else '关'}）{tail}"})
        else:
            self._send(400, {"error": f"未知操作: {action}（支持 enable / ssl / renew / blockip / edit）"})

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
        target_port = p.get("target_port")
        pstore.remove(pid)
        # 清理目标端口禁止规则（若没有其他代理仍指向该端口）
        if target_port and target_port not in (80, 443):
            store = self.server.store
            if not any(q.get("target_port") == target_port for q in pstore.proxies):
                store.rules = [r for r in store.rules
                               if not (r.get("type") == "port_deny" and r.get("port") == target_port
                                       and r.get("comment") == PROXY_TARGET_DENY_COMMENT)]
                store.save()
                self.server.nft.apply()
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
            # 关闭服务：删除该端口全部非保护放行规则（含手动开放的「面板开放」注释规则）
            for r in existing:
                if not r.get("protected"):
                    self.server.store.remove(r["id"])
        ok, msg = self.server.nft.apply()
        if not ok:
            self._send(500, {"error": msg})
            return
        self._send(200, {"ok": True, "msg": msg})

    def _api_close_port(self):
        """一键删除端口放行规则：{port, proto?} proto ∈ tcp|udp|both
        tcp 删 tcp+both，udp 删 udp+both，both 删该端口全部放行"""
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
        proto = data.get("proto", "tcp")
        if proto not in VALID_PROTOS:
            self._send(400, {"error": f"proto 必须是 {VALID_PROTOS} 之一"})
            return
        store = self.server.store
        before = len(store.rules)
        store.rules = [r for r in store.rules
                       if not (r.get("type") == "port_allow" and r.get("port") == port
                               and (r.get("proto") == proto or r.get("proto") == "both"
                                    or proto == "both"))]
        removed = before - len(store.rules)
        if removed == 0:
            self._send(200, {"ok": True, "msg": f"端口 {port} 没有可删除的放行规则", "removed": 0})
            return
        store.save()
        ok, msg = self.server.nft.apply()
        if not ok:
            self._send(500, {"error": msg})
            return
        self._send(200, {"ok": True, "msg": f"已删除端口 {port} 的 {removed} 条放行规则", "removed": removed})

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
        # 已放行则直接返回成功（幂等）；传入 comment 时更新注释便于识别
        comment = str(data.get("comment", "")).strip() or "面板开放"
        for r in self.server.store.rules:
            if r.get("type") == "port_allow" and r.get("port") == port and r.get("proto") == proto:
                if comment and r.get("comment") != comment:
                    r["comment"] = comment
                    self.server.store.save()
                self._send(200, {"ok": True, "msg": f"端口 {port}/{proto} 已在放行列表中", "id": r["id"]})
                return
        rule = self.server.store.add({"type": "port_allow", "proto": proto, "port": port,
                                      "comment": comment})
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
    parser = argparse.ArgumentParser(description="fwpanel 简易VPS控制面板")
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
    # 网卡流量统计后台线程（按天聚合）
    traffic = TrafficStore()
    traffic.record()  # 启动建立采样基线
    server.traffic = traffic
    threading.Thread(target=traffic_loop, args=(traffic,), daemon=True).start()
    log("网卡流量统计线程已启动")

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
