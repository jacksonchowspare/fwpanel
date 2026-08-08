#!/usr/bin/env bash
# =============================================================================
# fwpanel — 自研防火墙控制面板 一键安装包（适配 Debian 13 Trixie / 兼容 11、12）
# -----------------------------------------------------------------------------
# 零第三方依赖：Python 标准库 + 系统 nftables，不装 firewalld/ufw。
#
# 用法：
#   sudo bash install.sh                         一键安装（随机凭据，打印一次）
#   sudo bash install.sh -p 17890 --bind 0.0.0.0 指定端口 / 开放远程访问
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
readonly SCRIPT_NAME="fwpanel 防火墙面板安装包"
readonly SCRIPT_VERSION="1.4.0"
readonly LOG_FILE="/var/log/fwpanel-install.log"
readonly APP_DIR="/usr/local/lib/fwpanel"
readonly ETC_DIR="/etc/fwpanel"
readonly SERVICE_NAME="fwpanel.service"
readonly MIN_DEBIAN_VERSION=11

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
    [ "$(id -u)" -eq 0 ] || error "请使用 root 权限运行（sudo bash $0）"
    log_info "权限检查通过（root）"
}

check_os() {
    [ -r /etc/os-release ] || error "无法读取 /etc/os-release"
    # shellcheck disable=SC1091
    . /etc/os-release
    if [ "${ID:-}" != "debian" ]; then
        [ "$FORCE" = "1" ] && log_warn "非 Debian 系统（--force 跳过，风险自负）" \
            || error "当前系统不是 Debian。仅适配 Debian 11/12/13，确认兼容可加 --force"
    fi
    local ver="${VERSION_ID:-0}"; ver="${ver%%.*}"
    if [[ "$ver" =~ ^[0-9]+$ ]] && [ "$ver" -lt "$MIN_DEBIAN_VERSION" ]; then
        [ "$FORCE" = "1" ] && log_warn "Debian $ver 低于推荐版本（--force 跳过）" \
            || error "Debian $ver 版本过低，要求 $MIN_DEBIAN_VERSION 及以上"
    fi
    if [ "$ver" = "13" ]; then log_info "系统: Debian 13 (Trixie) ✓ 完全适配"
    else log_info "系统: Debian $ver（兼容模式）"; fi
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
        log_warn "检测到 fwpanel 已安装，跳过安装。"
        log_info "查看服务: systemctl status $SERVICE_NAME"
        log_info "重置密码: sudo bash $0 --change-password"
        exit 0
    fi
}

do_check() {
    echo "================== $SCRIPT_NAME v$SCRIPT_VERSION 环境体检 =================="
    check_root; check_os; check_arch; check_tools; check_existing
    echo "==========================================================================="
    echo "体检通过，可执行: sudo bash $0"
}

# ============================== 参数解析 ==============================

usage() {
    cat <<EOF
$SCRIPT_NAME v$SCRIPT_VERSION —— 自研防火墙控制面板（Debian 13 · nftables）

用法:
  sudo bash $0                           一键安装（随机端口/用户名/密码，凭据只打印一次）
  sudo bash $0 -p 17890                  指定面板端口
  sudo bash $0 --bind 0.0.0.0            开放局域网/远程访问（默认仅本机 127.0.0.1）
  sudo bash $0 --user admin --password x  指定登录凭据
  sudo bash $0 --check                   仅体检环境
  sudo bash $0 --change-password         重置面板密码（交互式）
  sudo bash $0 --uninstall               卸载（停服务 + 删文件）

选项:
  -p, --port PORT     面板端口（默认 17890，被占用自动随机 17000-19999）
      --bind IP       监听地址（默认 127.0.0.1 仅本机；远程访问用 0.0.0.0）
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
    [ -n "$PANEL_BIND" ] || PANEL_BIND="127.0.0.1"
    if [ -z "$PANEL_PORT" ]; then
        PANEL_PORT="17890"
        if port_in_use "$PANEL_PORT"; then
            log_warn "端口 17890 被占用，自动分配新端口"
            local p
            while :; do
                p=$((RANDOM % 3000 + 17000))
                port_in_use "$p" || { PANEL_PORT="$p"; break; }
            done
        fi
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
    # 缺什么装什么（Debian 最小化安装可能没有 python3/nftables）
    local pkgs=()
    command -v python3 >/dev/null 2>&1 || pkgs+=(python3)
    command -v nft >/dev/null 2>&1 || pkgs+=(nftables)
    if [ "${#pkgs[@]}" -gt 0 ]; then
        log_info "安装依赖: ${pkgs[*]} ..."
        apt-get update -y
        DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs[@]}"
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
    local script_dir src_py src_html tmp_src=""
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)"
    src_py="$script_dir/panel.py"
    src_html="$script_dir/static/index.html"

    # 管道一键安装（curl | sudo bash）时只有 install.sh 自身，配套文件需自动下载
    if [ ! -f "$src_py" ] || [ ! -f "$src_html" ]; then
        log_warn "未找到配套文件（管道安装模式），自动下载 panel.py / index.html ..."
        tmp_src="$(mktemp -d)"
        fetch_source "$tmp_src/panel.py" "panel.py" \
            || error "下载 panel.py 失败，请检查网络，或改用 tar 包安装"
        fetch_source "$tmp_src/index.html" "static/index.html" \
            || error "下载 index.html 失败，请检查网络"
        src_py="$tmp_src/panel.py"
        src_html="$tmp_src/index.html"
    fi

    mkdir -p "$APP_DIR/static"
    install -m 755 "$src_py" "$APP_DIR/panel.py"
    install -m 644 "$src_html" "$APP_DIR/static/index.html"
    [ -n "$tmp_src" ] && rm -rf "$tmp_src"
    log_info "文件部署完成"
}

write_config() {
    log_info "初始化配置 /etc/fwpanel ..."
    mkdir -p "$ETC_DIR"
    # 由 Python 生成密码哈希，明文密码只打印一次，绝不落盘
    python3 - "$PANEL_USER" "$PANEL_PASS" "$PANEL_PORT" "$PANEL_BIND" <<'EOF'
import sys, json, hashlib, secrets, os
user, pwd, port, bind = sys.argv[1:5]
salt = secrets.token_hex(16)
dk = hashlib.pbkdf2_hmac("sha256", pwd.encode(), bytes.fromhex(salt), 120_000)
cfg = {
    "username": user,
    "password_hash": f"{salt}${dk.hex()}",
    "port": int(port),
    "bind": bind,
    "mode": "permissive",
    "ssh_port": 22,
}
path = "/etc/fwpanel/config.json"
tmp = path + ".tmp"
with open(tmp, "w") as f:
    json.dump(cfg, f, indent=2, ensure_ascii=False)
os.chmod(tmp, 0o600)
os.replace(tmp, path)
print("config.json 已生成（含密码哈希，权限 600）")
EOF
    # 初始空规则
    if [ ! -f "$ETC_DIR/rules.json" ]; then
        printf '[]\n' > "$ETC_DIR/rules.json"
        chmod 600 "$ETC_DIR/rules.json"
    fi
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
    check_root; check_os; check_arch; check_tools; check_existing
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
