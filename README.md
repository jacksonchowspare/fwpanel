# FW-Panel · 自研防火墙控制面板

完全自研的 Linux 防火墙管理面板：**Python 标准库 + nftables**，零第三方 Python 依赖，不依赖 firewalld / ufw / 1Panel 等任何外部面板。

## 支持系统

| 发行版 | 包管理器 | 说明 |
|--------|---------|------|
| Debian 11 / 12 / 13 | apt | 13 (Trixie) 完全适配 |
| Ubuntu 20.04+ | apt | |
| Arch / Manjaro | pacman | |
| Fedora / CentOS / Rocky / Alma / RHEL | dnf | |

架构支持 x86_64 / aarch64。

## 一键安装

```bash
curl -sSL https://raw.githubusercontent.com/jacksonchowspare/fwpanel/main/install.sh | sudo bash
```

> root 用户可直接去掉 `sudo`。

安装过程全自动：
- 自动识别发行版并安装依赖（python3 / nftables，缺什么装什么）
- 自动检测系统实际 SSH 端口并写入保护规则
- 面板端口、用户名、密码全部随机生成，**安装结束一次性打印**（凭据不落盘，忘记密码可用 `--change-password` 重置）
- 默认监听 `0.0.0.0`（公网可访问），安装完成后用打印的地址登录：
  `http://服务器IP:随机端口`

### 可选参数

| 参数 | 说明 |
|------|------|
| `-p, --port PORT` | 指定面板端口（默认随机 17000-19999） |
| `--bind IP` | 监听地址（默认 0.0.0.0；仅本机访问用 127.0.0.1） |
| `--user NAME` | 指定用户名（默认随机 8 位） |
| `--password PASS` | 指定密码，≥8 位（默认随机 16 位强密码） |
| `--open-port P` | 安装后立即放行端口（逗号分隔，如 `80,443` 或 `53/udp`） |
| `--check` | 仅体检环境 |
| `--change-password` | 重置面板密码（交互式） |
| `--uninstall` | 卸载（停服务 + 删文件） |

示例：

```bash
# 指定端口 + 仅本机访问
curl -sSL https://raw.githubusercontent.com/jacksonchowspare/fwpanel/main/install.sh | sudo bash -s -- -p 17890 --bind 127.0.0.1

# 指定凭据 + 安装后放行 80/443
curl -sSL https://raw.githubusercontent.com/jacksonchowspare/fwpanel/main/install.sh | sudo bash -s -- --user admin --password MyPass123 --open-port 80,443
```

## 功能特性

- **防火墙规则管理**：放行/拒绝端口（TCP/UDP/TCP+UDP）、IP 规则支持单 IP / CIDR 网段 / IP 范围（IPv4/IPv6），实时搜索 + 分页
- **宽松 / 严格模式**：严格模式默认拒绝、白名单放行，自动放行面板端口防锁死
- **SSH 防锁死保护**：保护规则跟随实际 SSH 端口，一键同步修改系统 SSH 端口，切换后自动清理旧端口规则
- **SSH 防爆破**：失败次数 / 统计窗口 / 封禁时长可配置，到期自动解封，手动封禁/解封 IP，实时倒计时 + 搜索分页
- **一键开放 / 删除端口**：公网放行与收回，二次确认
- **一键开启 BBR**：官方原版方案（fq + bbr），写配置持久化、立即生效、回读校验，显示内核版本
- **反向代理（Nginx）**：域名绑定反代、ACME 证书一键申请/手动续期/路径查看、WebSocket、HTTP→HTTPS 跳转、禁止 IP+端口访问、一键安装 nginx+certbot（自动识别包管理器）
- **防火墙一键开关**：关闭=删除 nftables 表（规则保留），开启=一键恢复
- **面板设置**：修改面板端口（自动删旧放新并跳转）、账户设置（用户名+密码，双次确认）
- **系统更新**：自动检测新版本 + 一键升级（下载→校验→备份→替换→失败回滚）
- **多发行版**：安装、依赖、SSH 服务名全自动适配

## 升级

面板内「🔄 系统更新」→ 一键升级，或重新执行一键安装命令（幂等）。

## 卸载

```bash
curl -sSL https://raw.githubusercontent.com/jacksonchowspare/fwpanel/main/install.sh | sudo bash -s -- --uninstall
```

## 安全说明

- 凭据只打印一次不落盘；忘记密码用 `--change-password` 重置
- SSH 保护规则不可删除（防锁死）
- 封禁 IP 前确认不会封到自己的出口 IP；关闭防火墙 = 完全暴露，仅建议排查问题时短暂使用
- 申请证书需要 80 端口公网可达（ACME 挑战）
