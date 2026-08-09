#!/usr/bin/env bash
# install.sh 函数级单元测试（提取函数源码后 source，不触发 main）
set -u
SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/install.sh"
TMPF=$(mktemp)
head -n -1 "$SCRIPT" > "$TMPF"      # 去掉最后一行 main "$@"
# shellcheck disable=SC1090
source "$TMPF"
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  ✓ $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  ✗ $1"; }

echo "== gen_password：16位且含大写/小写/数字 =="
for i in 1 2 3; do
    pw=$(gen_password)
    [ "${#pw}" -eq 16 ] && echo "$pw" | grep -qE '[A-Z]' && echo "$pw" | grep -qE '[a-z]' \
        && echo "$pw" | grep -qE '[0-9]' && ok "第${i}个密码格式正确" || bad "第${i}个密码异常: $pw"
done

echo "== gen_user：8位小写字母数字 =="
u=$(gen_user)
[ "${#u}" -eq 8 ] && echo "$u" | grep -qE '^[a-z0-9]+$' && ok "用户名: $u" || bad "用户名异常: $u"

echo "== resolve_params 默认值 =="
PANEL_PORT=""; PANEL_BIND=""; PANEL_USER=""; PANEL_PASS=""
resolve_params
[ -n "$PANEL_PORT" ] && [ "$PANEL_BIND" = "0.0.0.0" ] && [ -n "$PANEL_USER" ] \
    && [ "${#PANEL_PASS}" -ge 8 ] && ok "默认参数齐全 PORT=$PANEL_PORT BIND=$PANEL_BIND" || bad "默认参数缺失"

echo "== resolve_params 非法端口应报错（子shell） =="
PANEL_PORT="abc"; PANEL_BIND=""; PANEL_USER="x"; PANEL_PASS="12345678"
( resolve_params >/dev/null 2>&1 ) && bad "非法端口未拦截" || ok "非法端口已拦截"

echo "== resolve_params 短密码应报错（子shell） =="
PANEL_PORT="17890"; PANEL_BIND=""; PANEL_USER="xx"; PANEL_PASS="short"
( resolve_params >/dev/null 2>&1 ) && bad "短密码未拦截" || ok "短密码已拦截"

echo "== 环境变量读取（FW_* 普通名，\${VAR:-} 直接可用） =="
head -n -1 "$SCRIPT" > /tmp/install_funcs_fw.sh
FW_PORT=18888 FW_BIND=0.0.0.0 FW_USER=envuser FW_PASS=EnvPass123 \
    bash -c 'source /tmp/install_funcs_fw.sh
    init_params
    [ "$PANEL_PORT" = "18888" ] && [ "$PANEL_BIND" = "0.0.0.0" ] && [ "$PANEL_USER" = "envuser" ] \
        && [ "$PANEL_PASS" = "EnvPass123" ] && echo "  ✓ 环境变量读取正确" || echo "  ✗ 失败: $PANEL_PORT/$PANEL_BIND"'

echo "== 命令行参数优先级 =="
PANEL_PORT="17890"
parse_args -p 19001
[ "$PANEL_PORT" = "19001" ] && ok "参数覆盖环境变量" || bad "参数未生效"

echo "== check_root 非root无sudo应报错（子shell） =="
if [ "$(id -u)" -ne 0 ]; then
    ( PATH=/nonexistent bash -c "source '$TMPF'; check_root" >/dev/null 2>&1 ) \
        && bad "非root无sudo未拦截" || ok "已拦截（提示切换root）"
else
    echo "  （root 环境跳过）"
fi

echo "== check_existing 已安装时进入升级（不跳过） =="
head -n -1 "$SCRIPT" > /tmp/install_funcs_up.sh
bash -c 'source /tmp/install_funcs_up.sh
APP_DIR=/tmp/fwpanel-test-installed
mkdir -p "$APP_DIR"; touch "$APP_DIR/panel.py"
do_upgrade() { echo "UPGRADE_CALLED"; exit 0; }
out=$(check_existing)
echo "$out" | grep -q UPGRADE_CALLED && ok "已安装 → 进入升级流程" || bad "未进入升级: $out"
rm -rf /tmp/fwpanel-test-installed'

echo "== check_existing 体检模式已安装不升级 =="
bash -c 'source /tmp/install_funcs_up.sh
APP_DIR=/tmp/fwpanel-test-installed
mkdir -p "$APP_DIR"; touch "$APP_DIR/panel.py"
do_upgrade() { echo "UPGRADE_CALLED"; exit 0; }
out=$(check_existing check)
echo "$out" | grep -q UPGRADE_CALLED && bad "体检模式不应升级" || ok "体检模式跳过升级"
rm -rf /tmp/fwpanel-test-installed'
rm -f /tmp/install_funcs_up.sh

echo "== gen_initial_rules 生成 SSH+面板端口放行 =="
RULES_TMP="$(mktemp -u)"
rm -f "$RULES_TMP"
gen_initial_rules 2222 17890 "$RULES_TMP"
python3 - "$RULES_TMP" <<'PYEOF'
import json, sys
rules = json.load(open(sys.argv[1]))
assert len(rules) == 2, f"规则数 {len(rules)} != 2"
ports = {r["port"]: r for r in rules}
assert 2222 in ports and ports[2222]["protected"] is True, "SSH 保护规则缺失或未保护"
assert 17890 in ports and ports[17890]["protected"] is True, "面板端口规则缺失或未保护"
print("  ✓ 初始规则正确（SSH 2222 + 面板 17890，均 protected）")
PYEOF
gen_initial_rules 2222 17890 "$RULES_TMP" && echo "  ✓ 已存在不覆盖" || bad "已存在规则被覆盖"
rm -f "$RULES_TMP"

echo "== check_os 发行版识别（本机） =="
DISTRO_ID="unknown"; PKG_MGR=""
check_os
[ -n "$DISTRO_ID" ] && [ -n "$PKG_MGR" ] \
    && ok "识别发行版: $DISTRO_ID (包管理器: $PKG_MGR, python包: $PY_PKG)" \
    || bad "发行版识别失败"

echo "============================================"
echo "结果: $PASS 通过, $FAIL 失败"
rm -f "$TMPF" /tmp/install_funcs_fw.sh
exit $FAIL
