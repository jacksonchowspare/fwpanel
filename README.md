# fwpanel — 自研防火墙控制面板（Debian 13）

> 完全自研的 Web 防火墙管理面板：Python 标准库 + nftables，零第三方依赖，
> 不依赖 firewalld/ufw/1Panel 等任何外部面板。适配 Debian 13 (Trixie)，兼容 11/12。

## 特性

- ✅ **自研零依赖**：后端 Python 标准库（http.server + subprocess），前端原生 HTML/JS
- ✅ **nftables 原生管理**：直接生成并原子应用 nft 规则（Debian 13 默认防火墙后端）
- ✅ **防锁死保护**：SSH(22) 放行规则永远存在且不可删除，改端口只需改配置
- ✅ **一键开放端口**：面板 ⚡ 快捷区 / CLI `fwpanel open-port 8080` / 安装参数 `--open-port` 三入口
- ✅ 两种模式：宽松（默认放行，按需拒绝）/ 严格（默认拒绝，白名单放行）
- ✅ 端口放行/拒绝、IP 白名单/黑名单（支持 IPv6）
- ✅ 服务模板快捷开关：SSH/HTTP/HTTPS/DNS/Mail/IMAP/SMTPS
- ✅ 登录认证：pbkdf2 密码哈希 + session token + 连续失败锁定 5 分钟
- ✅ 规则原子应用失败自动回滚，不会把自己锁在门外
- ✅ 凭据只打印一次，不落盘；忘记密码可命令行重置
- ✅ systemd 服务 + 开机自启；一键安装 / 一键卸载

## 系统要求

| 项目 | 要求 |
|------|------|
| 系统 | Debian 13 (Trixie) 推荐，11/12 兼容 |
| 权限 | root（安装时） |
| 依赖 | python3（Debian 自带）、nftables（脚本自动安装） |
| 内存 | ≥ 256MB 即可 |

## 一键安装

```bash
# 本机已有安装包目录时
sudo bash install.sh

# 或指定端口 / 开放远程访问
sudo bash install.sh -p 17890 --bind 0.0.0.0
```

安装结束终端一次性打印面板地址、用户名、密码——**只显示这一次，请立即记下**。

默认只监听 127.0.0.1（最安全），远程访问两种方式任选：

```bash
# 方式一：SSH 隧道（推荐，无需开放端口）
ssh -L 17890:127.0.0.1:17890 root@服务器IP
# 然后浏览器打开 http://127.0.0.1:17890

# 方式二：面板直接监听公网（安装时指定）
sudo bash install.sh --bind 0.0.0.0
```

## 参数说明

| 参数 | 说明 | 默认 |
|------|------|------|
| `-p, --port` | 面板端口 | 17890（占用则随机 17000-19999） |
| `--bind` | 监听地址 | 127.0.0.1（仅本机） |
| `--user` | 登录用户名 | 随机 8 位 |
| `--password` | 登录密码（≥8 位） | 随机 16 位强密码 |
| `--open-port` | 安装后立即开放端口（如 80,443 或 53/udp） | - |
| `--check` | 环境体检 | - |
| `--change-password` | 重置面板密码（交互式） | - |
| `--uninstall` | 卸载（停服务+删文件） | - |
| `--force` | 跳过系统检测 | - |

环境变量（参数优先）：`FW_PORT` `FW_BIND` `FW_USER` `FW_PASS`

## 一键开放端口（三种方式）

```bash
# 1. 面板：登录后 ⚡「一键开放端口」输入端口号即可，立即生效
# 2. CLI（SSH 到服务器直接执行，无需登录面板）：
sudo python3 /usr/local/lib/fwpanel/panel.py open-port 8080        # TCP 8080
sudo python3 /usr/local/lib/fwpanel/panel.py open-port 53/udp      # UDP 53
# 3. 安装时顺带开放：
sudo bash install.sh --open-port 80,443
```

重复开放同一端口不会报错（幂等）。

## 面板功能

- 状态总览：防火墙是否生效、模式、规则数、SSH 保护端口
- 模式切换：宽松（默认放行）/ 严格（默认拒绝）
- 服务快捷开关：一键放行/关闭常用服务端口
- 规则管理：添加/删除放行或拒绝的端口、IP（支持 IPv6 和备注）
- 修改密码：面板内随时可改

## 规则文件位置

| 文件 | 说明 |
|------|------|
| /etc/fwpanel/config.json | 配置 + 密码哈希（权限 600） |
| /etc/fwpanel/rules.json | 规则清单（权限 600） |
| /etc/fwpanel/firewall.nft | 生成的 nft 规则（`nft -f` 应用） |
| /usr/local/lib/fwpanel/ | 程序文件（panel.py + static/） |

手动查看当前生效规则：`nft list ruleset`

## 常见问题

**Q: 面板打不开？**
A: 检查服务状态 `systemctl status fwpanel`、日志 `journalctl -u fwpanel -f`。
默认只监听本机，请确认用 SSH 隧道访问或安装时指定了 --bind。

**Q: 密码忘了？**
A: `sudo bash install.sh --change-password` 命令行直接重置，不用重装。

**Q: SSH 端口不是 22？**
A: 编辑 /etc/fwpanel/config.json 改 ssh_port 后重启服务：
`systemctl restart fwpanel`（SSH 保护规则自动更新）

**Q: 严格模式下把自己规则搞乱了？**
A: 规则应用失败会自动回滚备份；SSH 保护规则永不被删除，SSH 始终可连。

## 卸载

```bash
sudo bash install.sh --uninstall
# 如需连配置和规则一起删：
rm -rf /etc/fwpanel
```

## 文件清单

```
fwpanel/
├── panel.py                # 面板后端（Python 标准库，零依赖）
├── static/index.html       # Web 前端（单页深色界面）
├── install.sh              # 一键安装/卸载/改密
├── test/
│   ├── test_panel.py       # Python 单测 + HTTP API 冒烟（10 项）
│   └── unit_test.sh        # 安装脚本函数测试（8 项）
└── README.md               # 本说明
```
