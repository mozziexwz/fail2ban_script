# fail2ban_script

fail2ban 一键部署 / 管理脚本，用来保护 SSH。中文菜单，自动识别 SSH 实际端口。

支持使用 systemd 的 Debian / Ubuntu 和 RHEL 系（Rocky / AlmaLinux / CentOS / Fedora）。

## 使用

```bash
curl -fsSL https://raw.githubusercontent.com/mozziexwz/fail2ban_script/main/fail2ban.sh -o fail2ban.sh
```

```bash
sudo bash fail2ban.sh
```

不想进菜单，直接部署（全部使用默认值，不提问）：

```bash
sudo bash fail2ban.sh install -y
```

其他子命令：

| 命令 | 作用 |
|---|---|
| `status` | 服务状态、jail 状态、封禁列表及到期时间 |
| `unban <IP>` / `unban --all` | 解封 |
| `ban <IP>` | 手动封禁 |
| `ports` | 只显示检测到的 SSH 端口 |
| `uninstall [-y]` | 卸载 |

## 菜单

```
 1) 一键部署（安装 + 配置 + 启动）
 2) 查看状态 / 封禁列表
 3) 解封 IP
 4) 手动封禁 IP
 5) 白名单管理
 6) 修改参数
 7) 重新识别 SSH 端口
 8) 日志
 9) 服务管理
10) 卸载
```

## 一键部署做了什么

1. 安装 `fail2ban`、`nftables`，以及读 systemd 日志需要的 `python3-systemd`（Debian/Ubuntu）或 `fail2ban-systemd`（RHEL 系，会先启用 EPEL）。
2. 检测 SSH 实际端口，写入 `/etc/fail2ban/jail.local`。已有的 `jail.local` 会先备份为 `jail.local.bak.<时间>`。
3. 写入 `/etc/fail2ban/fail2ban.local`，把封禁历史保留期调到 30 天。
4. 用 `fail2ban-client -t` 校验配置，校验失败自动还原；通过后重启服务并设为开机自启。

生成的 `jail.local`：

```ini
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1
banaction = nftables-multiport
banaction_allports = nftables-allports

bantime = 1d
findtime = 15m
maxretry = 5
bantime.increment = true
bantime.factor = 1
bantime.maxtime = 1w

[sshd]
enabled = true
mode = normal
backend = systemd
port = 22
```

## 参数说明

- **`port`**：fail2ban 里的 `port = ssh` 并不会自动识别端口，它只是按 `/etc/services` 解析成 22。脚本会取「正在监听的 sshd」「`ssh.socket`」「`sshd -T` 的生效配置」三者的并集，写成具体数字。改了 SSH 端口后用菜单 7 更新。
- **`bantime.factor`**：默认公式本身每次翻倍，首次封禁不套公式，factor 是额外乘数。
  - `factor = 1`：1 天 → 2 天 → 4 天 → 1 周
  - `factor = 2`：1 天 → 4 天 → 1 周
- **`dbpurgeage`**：fail2ban 默认只把封禁历史保留 1 天左右，过期后同一个 IP 再来会从头算。脚本设为 30 天。
- **`backend = systemd`**：放在 `[sshd]` 而不是 `[DEFAULT]`，以后加读日志文件的 jail（如 nginx）不受影响。
- **`mode`**：`normal`（默认）只匹配明确的认证失败；`aggressive` 还会抓预认证阶段的扫描和异常断开，误伤风险略高。菜单 6 可切换。
- **nftables 不可用时**（缺少 `nft` 或内核不支持）自动改用 `iptables-multiport` / `iptables-allports`。
- **fail2ban 低于 0.11** 不支持递增封禁，脚本会自动关闭该项。

## 注意

- 自己输错 5 次密码同样会被封 1 天。固定 IP 可以在部署时或菜单 5 里加入白名单。
- 被封后可以从别的 IP 登录，执行 `bash fail2ban.sh unban <IP>` 解封。
- 脚本只安装 `nft` 命令，不会启用 `nftables.service`（那个服务会加载带 `flush ruleset` 的 `/etc/nftables.conf`，可能冲掉 ufw / docker 的规则）。
- 生成的配置文件请通过脚本菜单修改，手动改动会在下次脚本写配置时被覆盖。
