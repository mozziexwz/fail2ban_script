# fail2ban_script

fail2ban 一键部署 / 管理脚本，用来保护 SSH。中文菜单，自动识别 SSH 实际端口。

支持使用 systemd 的 Debian / Ubuntu 和 RHEL 系（Rocky / AlmaLinux / CentOS / Fedora）。兼容 MSBOOST 部署节点时配置的 fail2ban，见[与 MSBOOST 一起使用](#与-msboost-一起使用)。

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
2. 检测 SSH 实际端口，写入 `/etc/fail2ban/jail.local`。已有的 `jail.local` 会先备份为 `jail.local.bak.<时间>`；服务器上有 MSBOOST 的配置时，沿用它的白名单和参数。
3. 写入 `/etc/fail2ban/fail2ban.local`，把封禁历史保留期调到 30 天。
4. 用 `fail2ban-client -t` 校验配置，校验失败自动还原；通过后重启服务并设为开机自启。

生成的 `jail.local`：

```ini
[DEFAULT]
banaction = nftables-multiport
banaction_allports = nftables-allports

[sshd]
enabled = true
mode = normal
backend = systemd
port = 22
banaction = nftables-multiport
ignoreip = 127.0.0.1/8 ::1
bantime = 1d
findtime = 15m
maxretry = 5
bantime.increment = true
bantime.factor = 1
bantime.maxtime = 1w
```

## 参数说明

- **`port`**：fail2ban 里的 `port = ssh` 并不会自动识别端口，它只是按 `/etc/services` 解析成 22。脚本会取「正在监听的 sshd」「`ssh.socket`」「`sshd -T` 的生效配置」三者的并集，写成具体数字。改了 SSH 端口后用菜单 7 更新。
- **`bantime.factor`**：默认公式本身每次翻倍，首次封禁不套公式，factor 是额外乘数。
  - `factor = 1`：1 天 → 2 天 → 4 天 → 1 周
  - `factor = 2`：1 天 → 4 天 → 1 周
- **`dbpurgeage`**：fail2ban 默认只把封禁历史保留 1 天左右，过期后同一个 IP 再来会从头算。脚本设为 30 天。
- **SSH 的设置都写在 `[sshd]`**：`jail.d/*.conf` 虽然比 `jail.local` 先读，但它们 `[sshd]` 段里的值比 `jail.local` 的 `[DEFAULT]` 优先。MSBOOST 的 `zz-msboost.conf` 就把设置写在 `[sshd]` 里，所以只有写在 `[sshd]` 才能盖过它。`[DEFAULT]` 只留封禁动作，给以后添加的其他 jail 用。v1.0 生成的 `jail.local`（参数在 `[DEFAULT]`）照样能读，下次保存时改成新格式。
- **`mode`**：`normal`（默认）只匹配明确的认证失败；`aggressive` 还会抓预认证阶段的扫描和异常断开，误伤风险略高。菜单 6 可切换。
- **nftables 不可用时**（缺少 `nft` 或内核不支持）自动改用 `iptables-multiport` / `iptables-allports`。
- **fail2ban 低于 0.11** 不支持递增封禁，脚本会自动关闭该项。

## 注意

- 自己输错 5 次密码同样会被封 1 天。固定 IP 可以在部署时或菜单 5 里加入白名单。
- 被封后可以从别的 IP 登录，执行 `bash fail2ban.sh unban <IP>` 解封。
- 手动解封会同时清掉该 IP 的封禁历史，它下次再犯会从首次封禁时长重新算；只有封禁自然到期的 IP 才会递增。
- 脚本只安装 `nft` 命令，不会启用 `nftables.service`（那个服务会加载带 `flush ruleset` 的 `/etc/nftables.conf`，可能冲掉 ufw / docker 的规则）。
- 生成的配置文件请通过脚本菜单修改，手动改动会在下次脚本写配置时被覆盖。

## 与 MSBOOST 一起使用

MSBOOST（网站 v2.12.0 起、本地版 v1.2.0 起）部署和升级节点时会自动配置 fail2ban，只写两个带标记的文件：`/etc/fail2ban/jail.d/zz-msboost.conf` 和 `/etc/fail2ban/fail2ban.d/zz-msboost.conf`。白名单里是回环地址、网站执行机的 IP 和部署时的来源地址（本地版是电脑所在的 /16），参数和本脚本的默认值相同。

**在 MSBOOST 配置过的服务器上运行本脚本**

- 菜单顶部显示「配置: MSBOOST」。查看状态、解封、封禁、日志、服务管理直接可用，显示的是 MSBOOST 的配置。
- 修改白名单、参数、端口（菜单 5/6/7），或者执行一键部署时，会先询问是否由本脚本接管。接管时 MSBOOST 的白名单和参数原样带过来，写进 `jail.local` 的 `[sshd]` 段。MSBOOST 的两个文件不改不删，只是被 `jail.local` 覆盖。
- 白名单菜单里标着「MSBOOST」的条目是 MSBOOST 写入的，删除前会提示：删掉执行机的 IP 后，有人输错几次密码就会把执行机封掉，MSBOOST 的任务就连不上这台服务器了。
- 接管后，MSBOOST「升级节点」会显示「已有 fail2ban 配置，未改动」，不再更新白名单。网站新增或更换执行机后，要在菜单 5 手动加入新执行机的 IP。

**交还给 MSBOOST**：菜单 10 卸载。本脚本只删除自己的 `jail.local` 和 `fail2ban.local`，fail2ban 不停，马上改回按 MSBOOST 的配置运行，软件包也保留。之后在网站或本地版上「升级节点」一次，白名单就按当前执行机刷新。

**先用本脚本、后部署 MSBOOST 节点**：MSBOOST 看到已有配置就不改动，执行机不在白名单里。用网站管理这台服务器的话，在菜单 5 加入执行机的 IP；或者按上面的方法交还给 MSBOOST。

**用 v1.0 部署在 MSBOOST 之后的服务器**：v1.0 把白名单和参数写在 `[DEFAULT]`，被 MSBOOST 的 `[sshd]` 盖住，实际生效的是 MSBOOST 的设置。查看状态时会提示；执行一次菜单 1（保留现有参数），或在菜单 5/6 保存一次，就会改成新格式，原来的白名单和 MSBOOST 的条目都会保留。

## 开发

函数级测试不需要 root，也不需要安装 fail2ban：

```bash
bash tests/run.sh
```

装了 fail2ban 的机器上，可以用真实的 fail2ban 解析配置，确认 `jail.local` 能盖过 MSBOOST 的文件（不需要 root，不改动系统）：

```bash
bash tests/f2b_parse.sh
```

每次推送会由 GitHub Actions 自动跑语法检查、ShellCheck 和这两组测试（`.github/workflows/ci.yml`）。安装、防火墙规则、服务启停这些只能在真机上验证，测试不覆盖。
