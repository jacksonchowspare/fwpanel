#!/usr/bin/env bash
# =============================================================================
# fwpanel — 自研防火墙控制面板 一键安装包（Debian/Ubuntu/Arch/Fedora 多发行版）
# -----------------------------------------------------------------------------
# 零第三方依赖：Python 标准库 + 系统 nftables，不装 firewalld/ufw。
#
# 用法：
#   sudo bash install.sh                         一键安装（随机端口/用户名/密码，一并打印）
#   sudo bash install.sh -p 17890                指定面板端口
#   sudo bash install.sh --bind 127.0.0.1        仅本机访问（默认 0.0.0.0 开放远程）
#   sudo bash install.sh --user admin --password MyPass123  指定凭据
#   sudo bash install.sh --check                 仅体检环境
#   sudo bash install.sh --change-password       重置面板密码（交互式）
#   sudo bash install.sh --uninstall             卸载（停服务+删文件）
#
# 环境变量（与参数等效，参数优先）：
#   FW_PORT FW_BIND FW_USER FW_PASS
# =============================================================================

set -Eeuo pipefail

# ------------------------------ 常量 ------------------------------
readonly SCRIPT_NAME="FW-Panel 防火墙面板安装包"
readonly SCRIPT_VERSION="1.23.23"
readonly LOG_FILE="/var/log/fwpanel-install.log"
readonly APP_DIR="/usr/local/lib/fwpanel"
readonly ETC_DIR="/etc/fwpanel"
readonly SERVICE_NAME="fwpanel.service"
readonly MIN_DEBIAN_VERSION=11
readonly SUPPORTED_DISTROS="debian ubuntu arch fedora centos rocky alma rhel manjaro endeavouros"

# 发行版与包管理器（check_os 中填充）
DISTRO_ID="unknown"
DISTRO_NAME=""
PKG_MGR=""
PY_PKG="python3"

# ------------------------------ 变量 ------------------------------
ACTION="install"
FORCE=0
PANEL_PORT=""
PANEL_BIND=""
PANEL_USER=""
PANEL_PASS=""
OPEN_PORTS=""

# ------------------------------ 颜色 ------------------------------
if [ -t 1 ]; then
    C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
    C_BOLD=$'\033[1m'; C_RESET=$'\033[0m'
else
    C_RED=""; C_GREEN=""; C_YELLOW=""; C_BOLD=""; C_RESET=""
fi

log_info()  { printf '%s[INFO ]%s %s\n' "$C_GREEN" "$C_RESET" "$1"; }
log_warn()  { printf '%s[WARN ]%s %s\n' "$C_YELLOW" "$C_RESET" "$1"; }
log_error() { printf '%s[ERROR]%s %s\n' "$C_RED" "$C_RESET" "$1"; }

error() { log_error "$1"; exit 1; }

err_trap() {
    local rc=$?
    log_error "脚本异常退出（退出码 $rc），请查看日志: $LOG_FILE"
}
trap err_trap ERR

# ============================== 环境检测 ==============================

check_root() {
    if [ "$(id -u)" -eq 0 ]; then
        # root 用户：确保 sudo 可用（便于其他用户提权），缺失则自动安装
        if ! command -v sudo >/dev/null 2>&1; then
            log_warn "未检测到 sudo，自动安装（root 可直接使用，其他用户可借此提权）..."
            install_pkgs "sudo" || log_warn "sudo 安装失败（root 直接使用不受影响）"
        fi
        log_info "权限检查通过（root）"
        return 0
    fi
    # 非 root 用户
    if ! command -v sudo >/dev/null 2>&1; then
        error "当前用户非 root 且未安装 sudo，无法提权安装。请先切换到 root（su -）后重新执行"
    fi
    if [ ! -f "$0" ]; then
        error "检测到管道安装模式（curl | bash）且当前非 root，请改用：curl -sSL <安装地址> | sudo bash"
    fi
    # 有 sudo：自动提权重跑自身（保留原参数）
    log_warn "非 root 用户运行，自动通过 sudo 提权执行 ..."
    exec sudo bash "$0" "${SCRIPT_ARGS[@]}"
}

check_os() {
    [ -r /etc/os-release ] || error "无法读取 /etc/os-release"
    # shellcheck disable=SC1091
    . /etc/os-release
    DISTRO_ID="${ID:-unknown}"
    DISTRO_NAME="${NAME:-$DISTRO_ID}"
    case "$DISTRO_ID" in
        debian|ubuntu)            PKG_MGR="apt";    PY_PKG="python3" ;;
        arch|manjaro|endeavouros) PKG_MGR="pacman"; PY_PKG="python"  ;;
        fedora|centos|rocky|alma|rhel) PKG_MGR="dnf"; PY_PKG="python3" ;;
        *)
            [ "$FORCE" = "1" ] && log_warn "未知发行版 $DISTRO_ID（--force 跳过，风险自负）" \
                || error "不支持的系统: $DISTRO_ID（支持: $SUPPORTED_DISTROS，确认兼容可加 --force）"
            ;;
    esac
    log_info "系统: $DISTRO_NAME ($DISTRO_ID)"
    case "$DISTRO_ID" in
        debian)
            local ver="${VERSION_ID:-0}"; ver="${ver%%.*}"
            if [[ "$ver" =~ ^[0-9]+$ ]] && [ "$ver" -lt "$MIN_DEBIAN_VERSION" ]; then
                [ "$FORCE" = "1" ] && log_warn "Debian $ver 低于推荐版本（--force 跳过）" \
                    || error "Debian $ver 版本过低，要求 $MIN_DEBIAN_VERSION 及以上"
            fi
            if [ "$ver" = "13" ]; then log_info "Debian 13 (Trixie) ✓ 完全适配"
            else log_info "Debian $ver（兼容模式）"; fi
            ;;
        ubuntu)                    log_info "Ubuntu ${VERSION_ID:-}（兼容模式）" ;;
        arch|manjaro|endeavouros)  log_info "Arch 系（滚动更新，兼容模式）" ;;
        fedora|centos|rocky|alma|rhel) log_info "$DISTRO_NAME ${VERSION_ID:-}（兼容模式）" ;;
    esac
}

check_arch() {
    case "$(uname -m)" in
        x86_64|aarch64|arm64) log_info "架构: $(uname -m) ✓" ;;
        *) error "不支持的架构: $(uname -m)（仅支持 x86_64 / aarch64）" ;;
    esac
}

check_tools() {
    if command -v python3 >/dev/null 2>&1; then
        local pyver
        pyver="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
        log_info "Python: $pyver ✓"
    else
        log_warn "未安装 python3，将在安装依赖时自动安装"
    fi
    if command -v nft >/dev/null 2>&1; then
        log_info "nftables: $(nft --version 2>/dev/null | head -1) ✓"
    else
        log_warn "未安装 nftables，将在安装依赖时自动安装"
    fi
}

check_existing() {
    if [ -f "$APP_DIR/panel.py" ] || systemctl list-unit-files 2>/dev/null | grep -q "$SERVICE_NAME"; then
        if [ "${1:-}" = "check" ]; then
            log_warn "检测到 fwpanel 已安装（体检模式跳过安装）。"
            log_info "重跑安装脚本可升级到最新版: curl -sSL https://raw.githubusercontent.com/jacksonchowspare/fwpanel/main/install.sh | sudo bash"
            exit 0
        fi
        log_info "检测到 fwpanel 已安装，执行升级（保留配置/规则/代理）..."
        do_upgrade
        exit 0
    fi
}

do_upgrade() {
    local tmpdir base_url
    tmpdir=$(mktemp -d)
    base_url="https://raw.githubusercontent.com/jacksonchowspare/fwpanel/main"
    log_info "下载最新版本..."
    if ! curl -fsSL "$base_url/panel.py" -o "$tmpdir/panel.py" 2>/dev/null || [ ! -s "$tmpdir/panel.py" ]; then
        log_err "下载 panel.py 失败，请检查服务器网络后重试"
        rm -rf "$tmpdir"
        exit 1
    fi
    # 防降级：当前版本 ≥ 下载版本时跳过（例如服务器已是更高版本）
    local cur_ver new_ver
    cur_ver=$(grep -oP 'CURRENT_VERSION\s*=\s*"\K[\d.]+' "$APP_DIR/panel.py" 2>/dev/null | head -1)
    new_ver=$(grep -oP 'CURRENT_VERSION\s*=\s*"\K[\d.]+' "$tmpdir/panel.py" 2>/dev/null | head -1)
    if [ -n "$cur_ver" ] && [ -n "$new_ver" ]; then
        if [ "$(printf '%s\n' "$cur_ver" "$new_ver" | sort -V | tail -1)" = "$cur_ver" ]; then
            log_info "当前版本 v$cur_ver ≥ 下载版本 v$new_ver，跳过升级（不降级）"
            rm -rf "$tmpdir"
            exit 0
        fi
        log_info "升级 v$cur_ver → v$new_ver"
    fi
    curl -fsSL "$base_url/static/index.html" -o "$tmpdir/index.html" 2>/dev/null || true
    curl -fsSL "$base_url/static/github-logo.png" -o "$tmpdir/github-logo.png" 2>/dev/null || true
    curl -fsSL "$base_url/install.sh" -o "$tmpdir/install.sh" 2>/dev/null || true
    # 备份当前版本（保留最近 3 份）
    local bak
    bak="$APP_DIR/panel.py.bak.$(date +%Y%m%d%H%M%S)"
    cp "$APP_DIR/panel.py" "$bak" 2>/dev/null && log_info "已备份旧版本: $bak"
    ls -t "$APP_DIR"/panel.py.bak.* 2>/dev/null | tail -n +4 | xargs -r rm -f
    # 覆盖安装
    cp "$tmpdir/panel.py" "$APP_DIR/panel.py"
    if [ -s "$tmpdir/index.html" ]; then
        mkdir -p "$APP_DIR/static"
        cp "$tmpdir/index.html" "$APP_DIR/static/index.html"
    fi
    if [ -s "$tmpdir/github-logo.png" ]; then
        mkdir -p "$APP_DIR/static"
        cp "$tmpdir/github-logo.png" "$APP_DIR/static/github-logo.png"
    fi
    if [ -s "$tmpdir/install.sh" ]; then
        cp "$tmpdir/install.sh" "$0" 2>/dev/null || true
    fi
    rm -rf "$tmpdir"
    # 语法校验
    if ! python3 -m py_compile "$APP_DIR/panel.py" 2>/dev/null; then
        log_err "新版本语法错误，正在回滚备份..."
        cp "$bak" "$APP_DIR/panel.py" 2>/dev/null
        exit 1
    fi
    # 重启服务（尝试常见服务名，兼容旧版安装的命名差异）
    if systemctl restart fwpanel 2>/dev/null || systemctl restart fwpanel.service 2>/dev/null; then
        log_info "服务已重启: fwpanel"
    else
        log_warn "未能自动重启面板服务，请手动执行: systemctl restart fwpanel"
        log_warn "（若服务名不同，可先查看: systemctl list-unit-files | grep -i fw）"
    fi
    log_info "升级完成 ✓ 配置/规则已保留；页面请强制刷新（Ctrl+F5）"
}

do_check() {
    echo "================== $SCRIPT_NAME v$SCRIPT_VERSION 环境体检 =================="
    check_os; check_root; check_arch; check_tools; check_existing check
    echo "==========================================================================="
    echo "体检通过，可执行: sudo bash $0"
}

# ============================== 参数解析 ==============================

usage() {
    cat <<EOF
$SCRIPT_NAME v$SCRIPT_VERSION —— 自研防火墙控制面板（Debian 13 · nftables）

用法:
  sudo bash $0                           一键安装（随机端口/用户名/密码，安装结束一并打印）
  sudo bash $0 -p 17890                  指定面板端口
  sudo bash $0 --bind 127.0.0.1          仅本机访问（默认 0.0.0.0 开放远程）
  sudo bash $0 --user admin --password x  指定登录凭据
  sudo bash $0 --check                   仅体检环境
  sudo bash $0 --change-password         重置面板密码（交互式）
  sudo bash $0 --uninstall               卸载（停服务 + 删文件）

选项:
  -p, --port PORT     面板端口（默认随机 17000-19999）
      --bind IP       监听地址（默认 0.0.0.0 开放远程访问）
      --user NAME     登录用户名（默认随机 8 位）
      --password PASS 登录密码，≥8 位（默认随机 16 位强密码）
      --open-port P   安装后立即开放端口给公网（逗号分隔，如 80,443 或 53/udp）
      --force         跳过系统检测
  -h, --help          帮助

环境变量（参数优先）: FW_PORT FW_BIND FW_USER FW_PASS
EOF
}

init_params() {
    PANEL_PORT="${FW_PORT:-}"
    PANEL_BIND="${FW_BIND:-}"
    PANEL_USER="${FW_USER:-}"
    PANEL_PASS="${FW_PASS:-}"
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -p|--port)     PANEL_PORT="$2"; shift 2 ;;
            --bind)        PANEL_BIND="$2"; shift 2 ;;
            --user)        PANEL_USER="$2"; shift 2 ;;
            --password)    PANEL_PASS="$2"; shift 2 ;;
            --open-port)   OPEN_PORTS="$2"; shift 2 ;;
            --check)       ACTION="check"; shift ;;
            --change-password) ACTION="change-password"; shift ;;
            -u|--uninstall) ACTION="uninstall"; shift ;;
            --force)       FORCE=1; shift ;;
            -h|--help)     usage; exit 0 ;;
            *) error "未知参数: $1（用 -h 查看帮助）" ;;
        esac
    done
}

gen_password() {
    local pw
    pw="$(head -c 1 /dev/urandom | tr -dc 'A-Z')"
    pw+="$(head -c 1 /dev/urandom | tr -dc 'a-z')"
    pw+="$(head -c 1 /dev/urandom | tr -dc '0-9')"
    pw+="$(head -c 128 /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 13)"
    while [ "${#pw}" -lt 16 ]; do pw+="$((RANDOM % 10))"; done
    printf '%s' "${pw:0:16}" | fold -w1 | shuf | tr -d '\n'
}

gen_user() {
    local u
    u="$(head -c 32 /dev/urandom | tr -dc 'a-z0-9' | head -c 8)"
    while [ "${#u}" -lt 8 ]; do
        u+="$((RANDOM % 10))"
    done
    printf '%s' "${u:0:8}"
}

port_in_use() {
    ss -tlnH 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${1}$"
}

resolve_params() {
    [ -n "$PANEL_BIND" ] || PANEL_BIND="0.0.0.0"
    if [ -z "$PANEL_PORT" ]; then
        # 默认随机端口 17000-19999（每次安装不同，安装结束一并打印）
        local p
        while :; do
            p=$((RANDOM % 3000 + 17000))
            port_in_use "$p" || { PANEL_PORT="$p"; break; }
        done
    fi
    [[ "$PANEL_PORT" =~ ^[0-9]{1,5}$ ]] || error "端口必须为数字: $PANEL_PORT"
    port_in_use "$PANEL_PORT" && error "端口 $PANEL_PORT 已被占用，请换一个"
    [ -n "$PANEL_USER" ] || PANEL_USER="$(gen_user)"
    [ -n "$PANEL_PASS" ] || PANEL_PASS="$(gen_password)"
    [ "${#PANEL_PASS}" -ge 8 ] || error "密码至少 8 位"
    [[ "$PANEL_USER" =~ ^[A-Za-z0-9_]{3,32}$ ]] || error "用户名需为 3-32 位字母数字"
}

# ============================== 安装 ==============================

install_deps() {
    # 缺什么装什么（最小化安装可能没有 python3/nftables/curl/wget），按发行版选择包管理器
    local pkgs=()
    if ! command -v python3 >/dev/null 2>&1 && ! command -v python >/dev/null 2>&1; then
        pkgs+=("$PY_PKG")
    fi
    command -v nft >/dev/null 2>&1 || pkgs+=("nftables")
    command -v curl >/dev/null 2>&1 || pkgs+=("curl")
    command -v wget >/dev/null 2>&1 || pkgs+=("wget")
    if [ "${#pkgs[@]}" -gt 0 ]; then
        log_info "安装依赖（$PKG_MGR）: ${pkgs[*]} ..."
        case "$PKG_MGR" in
            apt)
                apt-get update -y
                DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs[@]}"
                ;;
            pacman)
                pacman -Sy --noconfirm "${pkgs[@]}"
                ;;
            dnf)
                dnf install -y "${pkgs[@]}"
                ;;
            *)
                error "未检测到支持的包管理器，请手动安装: ${pkgs[*]}"
                ;;
        esac
    fi
    log_info "依赖就绪（python3 + nftables）"
}

download_file() {
    local dest="$1" url="$2"
    curl -fsSL --connect-timeout 10 --retry 2 -o "$dest" "$url" || return 1
    [ -s "$dest" ] || return 1
}

fetch_source() {
    # 三级源自动回退：GitHub raw → jsDelivr CDN → ghproxy 镜像（国内友好）
    local dest="$1" path="$2"
    download_file "$dest" "https://raw.githubusercontent.com/jacksonchowspare/fwpanel/main/$path" && return 0
    log_warn "GitHub 直连失败，切换 jsDelivr CDN ..."
    download_file "$dest" "https://cdn.jsdelivr.net/gh/jacksonchowspare/fwpanel@main/$path" && return 0
    log_warn "jsDelivr 失败，切换 ghproxy 镜像 ..."
    download_file "$dest" "https://ghproxy.com/https://raw.githubusercontent.com/jacksonchowspare/fwpanel/main/$path" && return 0
    return 1
}

deploy_files() {
    log_info "部署程序文件到 $APP_DIR ..."
    local script_dir src_py src_html src_ico tmp_src=""
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)"
    src_py="$script_dir/panel.py"
    src_html="$script_dir/static/index.html"
    src_ico="$script_dir/static/favicon.ico"

    # 管道一键安装（curl | sudo bash）时只有 install.sh 自身，配套文件需自动下载
    if [ ! -f "$src_py" ] || [ ! -f "$src_html" ]; then
        log_warn "未找到配套文件（管道安装模式），自动下载 panel.py / index.html / favicon.ico ..."
        tmp_src="$(mktemp -d)"
        fetch_source "$tmp_src/panel.py" "panel.py" \
            || error "下载 panel.py 失败，请检查网络，或改用 tar 包安装"
        fetch_source "$tmp_src/index.html" "static/index.html" \
            || error "下载 index.html 失败，请检查网络"
        fetch_source "$tmp_src/favicon.ico" "static/favicon.ico" \
            || log_warn "下载 favicon.ico 失败（不影响安装，将使用默认图标）"
        src_py="$tmp_src/panel.py"
        src_html="$tmp_src/index.html"
        src_ico="$tmp_src/favicon.ico"
    fi

    mkdir -p "$APP_DIR/static"
    install -m 755 "$src_py" "$APP_DIR/panel.py"
    install -m 644 "$src_html" "$APP_DIR/static/index.html"
    if [ -f "$src_ico" ]; then
        install -m 644 "$src_ico" "$APP_DIR/static/favicon.ico"
    fi
    [ -n "$tmp_src" ] && rm -rf "$tmp_src"
    log_info "文件部署完成"
}

write_config() {
    log_info "初始化配置 /etc/fwpanel ..."
    mkdir -p "$ETC_DIR"
    # 由 Python 生成密码哈希，明文密码只打印一次，绝不落盘；
    # ssh_port 自动检测系统实际 SSH 端口（防锁死保护跟随真实端口，不固定 22）
    local ssh_detected
    ssh_detected="$(python3 - "$PANEL_USER" "$PANEL_PASS" "$PANEL_PORT" "$PANEL_BIND" <<'EOF'
import sys, json, hashlib, secrets, os, subprocess
user, pwd, port, bind = sys.argv[1:5]
salt = secrets.token_hex(16)
dk = hashlib.pbkdf2_hmac("sha256", pwd.encode(), bytes.fromhex(salt), 120_000)

def detect_ssh_port():
    try:
        r = subprocess.run(["sshd", "-T"], capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            if line.startswith("port "):
                return int(line.split()[1])
    except Exception:
        pass
    return 22

ssh_port = detect_ssh_port()
cfg = {
    "username": user,
    "password_hash": f"{salt}${dk.hex()}",
    "port": int(port),
    "bind": bind,
    "mode": "strict",
    "ssh_port": ssh_port,
    "ssh_port_auto": True,      # 自动跟随系统 SSH 端口；面板手动设置后关闭
}
path = "/etc/fwpanel/config.json"
tmp = path + ".tmp"
with open(tmp, "w") as f:
    json.dump(cfg, f, indent=2, ensure_ascii=False)
os.chmod(tmp, 0o600)
os.replace(tmp, path)
print(ssh_port)
EOF
)"
    [[ "$ssh_detected" =~ ^[0-9]{1,5}$ ]] || ssh_detected=22
    # 初始规则：自动放行实际 SSH 端口 + 面板端口（防锁死，装完即可访问，不覆盖已有规则）
    gen_initial_rules "$ssh_detected" "$PANEL_PORT" "$ETC_DIR/rules.json"
}

# 生成初始放行规则：SSH 端口 + 面板端口（均 protected 不可删除，防锁死）
gen_initial_rules() {
    local ssh_port="$1" panel_port="$2" rules_file="$3"
    [ -f "$rules_file" ] && return 0
    local id1 id2
    id1="$(printf '%04x%04x%04x' $((RANDOM % 65536)) $((RANDOM % 65536)) $((RANDOM % 65536)))"
    id2="$(printf '%04x%04x%04x' $((RANDOM % 65536)) $((RANDOM % 65536)) $((RANDOM % 65536)))"
    cat > "$rules_file" <<EOF
[
  {"id": "$id1", "type": "port_allow", "proto": "tcp", "port": $ssh_port, "comment": "SSH保护(安装自动放行)", "protected": true},
  {"id": "$id2", "type": "port_allow", "proto": "tcp", "port": $panel_port, "comment": "面板端口(安装自动放行)", "protected": true}
]
EOF
    chmod 600 "$rules_file"
    log_info "已自动放行 SSH($ssh_port) 与面板端口($panel_port)"
}

install_service() {
    cat > "/etc/systemd/system/$SERVICE_NAME" <<EOF
[Unit]
Description=fwpanel Firewall Panel (nftables)
After=network.target

[Service]
Type=simple
# 端口/监听地址以 /etc/fwpanel/config.json 为准（面板内/改配置后重启即生效）
ExecStart=/usr/bin/python3 $APP_DIR/panel.py serve
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now "$SERVICE_NAME" >/dev/null 2>&1
    sleep 1
    if ! systemctl is-active --quiet "$SERVICE_NAME"; then
        log_error "服务启动失败，日志如下："
        journalctl -u "$SERVICE_NAME" -n 20 --no-pager 2>/dev/null | tail -20 || true
        error "fwpanel 服务启动失败"
    fi
    log_info "服务已启动并设为开机自启（$SERVICE_NAME）"

    # 安装时顺带开放端口（--open-port "80,443,53/udp"）
    if [ -n "$OPEN_PORTS" ]; then
        log_info "开放指定端口给公网: $OPEN_PORTS"
        local item
        IFS=',' read -ra items <<< "$OPEN_PORTS"
        for item in "${items[@]}"; do
            python3 "$APP_DIR/panel.py" open-port "$item" || log_warn "端口 $item 开放失败"
        done
    fi
}

print_summary() {
    local ip
    ip="$(ip route get 1.1.1.1 2>/dev/null | sed -n 's/.*src \([0-9.]*\).*/\1/p' | head -1)"
    [ -n "$ip" ] || ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
    [ -n "$ip" ] || ip="<服务器IP>"

    echo ""
    echo "=================================================================="
    echo "${C_GREEN}  🎉 fwpanel 防火墙面板安装完成！${C_RESET}"
    echo "=================================================================="
    if [ "$PANEL_BIND" = "0.0.0.0" ]; then
        echo "  面板地址 : ${C_BOLD}http://${ip}:${PANEL_PORT}${C_RESET}"
    else
        echo "  面板地址 : ${C_BOLD}http://127.0.0.1:${PANEL_PORT}${C_RESET}  （仅本机）"
        echo "  远程访问 : 在本机执行 ssh -L ${PANEL_PORT}:127.0.0.1:${PANEL_PORT} root@${ip}"
        echo "             然后浏览器打开 http://127.0.0.1:${PANEL_PORT}"
    fi
    echo "  登录用户 : ${PANEL_USER}"
    echo "  登录密码 : ${PANEL_PASS}"
    echo "------------------------------------------------------------------"
    echo "  ${C_RED}⚠ 凭据仅显示这一次，不会写入任何文件，请立即记下！${C_RESET}"
    echo "  忘记密码: sudo bash $0 --change-password"
    echo "  面板内可修改密码；SSH(22) 始终放行防锁死"
    echo "  查看日志: journalctl -u fwpanel -f"
    echo "=================================================================="
}

do_install() {
    echo "================== $SCRIPT_NAME v$SCRIPT_VERSION =================="
    check_os; check_root; check_arch; check_tools; check_existing
    resolve_params
    install_deps
    deploy_files
    write_config
    install_service
    print_summary
}

# ============================== 卸载 ==============================

do_uninstall() {
    echo "================== $SCRIPT_NAME 卸载模式 =================="
    check_root
    if systemctl list-unit-files 2>/dev/null | grep -q "$SERVICE_NAME"; then
        log_info "停止并禁用服务..."
        systemctl stop "$SERVICE_NAME" 2>/dev/null || true
        systemctl disable "$SERVICE_NAME" 2>/dev/null || true
        rm -f "/etc/systemd/system/$SERVICE_NAME"
        systemctl daemon-reload
    fi
    log_info "删除程序文件 $APP_DIR ..."
    rm -rf "$APP_DIR"
    echo "------------------------------------------------------------------"
    log_warn "配置与规则位于 $ETC_DIR，删除即丢失面板账号和防火墙规则:"
    echo "  rm -rf $ETC_DIR"
    echo "  （若面板已添加规则，卸载前请先在面板中恢复，或手动整理 nft 规则）"
    echo "------------------------------------------------------------------"
    log_info "卸载完成"
}

# ============================== 改密 ==============================

do_change_password() {
    check_root
    [ -f "$ETC_DIR/config.json" ] || error "面板未安装，无法修改密码"
    log_info "交互式重置面板密码（至少 8 位）..."
    python3 "$APP_DIR/panel.py" reset-password
}

# ============================== 入口 ==============================

main() {
    SCRIPT_ARGS=("$@")
    init_params
    parse_args "$@"
    case "$ACTION" in
        check)   do_check ;;
        uninstall) exec > >(tee -a "$LOG_FILE") 2>&1; do_uninstall ;;
        change-password) do_change_password ;;
        *)       exec > >(tee -a "$LOG_FILE") 2>&1; do_install ;;
    esac
}

main "$@"
