#!/usr/bin/env bash
#
# 用真实的 fail2ban 解析配置（fail2ban-client -d），确认本脚本生成的 jail.local
# 能盖过 MSBOOST 的 jail.d/zz-msboost.conf。
# 需要装好 fail2ban；不需要 root，也不改动系统：配置复制到临时目录里解析。
# 用法: bash tests/f2b_parse.sh [发行版的 fail2ban 配置目录，默认 /etc/fail2ban]

# CFG_* 变量在这里赋值，由被 source 进来的 fail2ban.sh 读取
# shellcheck disable=SC2034
set -u

src=${1:-/etc/fail2ban}
if ! command -v fail2ban-client >/dev/null 2>&1 || [ ! -f "$src/jail.conf" ]; then
  echo "SKIP: 没有安装 fail2ban"
  exit 0
fi

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# 只要发行版自带的配置：去掉本机已有的 *.local 和 MSBOOST 的文件
cp -R "$src" "$tmp/fail2ban"
find "$tmp/fail2ban" -name '*.local' -delete
rm -f "$tmp/fail2ban/jail.d/zz-msboost.conf" "$tmp/fail2ban/fail2ban.d/zz-msboost.conf"
mkdir -p "$tmp/fail2ban/jail.d"

export F2B_DIR="$tmp/fail2ban"
export MSB_NODE_STATE="$tmp/msboost-install.env"
# shellcheck source=../fail2ban.sh
source "$here/../fail2ban.sh"

pass=0
fail=0
dump=""

# load_dump 名称   解析临时目录里的配置，结果放在 dump
load_dump() {
  if ! dump=$(fail2ban-client -c "$F2B_DIR" -d 2>"$tmp/err"); then
    fail=$((fail + 1))
    echo "FAIL $1: fail2ban-client -d failed: $(head -c 600 "$tmp/err")"
    dump=""
  fi
}

# sees 名称 正则     生效的配置里有这一项
sees() {
  if grep -Eq -- "$2" <<<"$dump"; then
    pass=$((pass + 1))
  else
    fail=$((fail + 1))
    echo "FAIL $1: not in the dump: $2"
    grep -F "'sshd'" <<<"$dump" | cut -c1-200 | head -n 40
  fi
}

# misses 名称 正则   生效的配置里没有这一项
misses() {
  if grep -Eq -- "$2" <<<"$dump"; then
    fail=$((fail + 1))
    echo "FAIL $1: unexpectedly in the dump: $2"
  else
    pass=$((pass + 1))
  fi
}

echo "$(fail2ban-client --version 2>/dev/null | head -n 1), $src"

# MSBOOST v2.12.0 写的文件（node 仓库 internal/executor/fail2ban.go 的 f2b_render）：
# 执行机 198.51.100.10 / 2001:db8::10，本地版电脑所在的 /16
cat >"$MSB_JAIL" <<'EOF'
# Managed by MSBOOST (msboost-fail2ban-v1)
# Defaults for a server without its own fail2ban configuration. Anything in
# jail.local or jail.d/*.local takes precedence over this file.
[sshd]
enabled = true
mode = normal
backend = systemd
port = 22022
ignoreip = 127.0.0.1/8 ::1 198.51.100.10 2001:db8::10 203.0.0.0/16
banaction = nftables-multiport
bantime = 1d
findtime = 15m
maxretry = 5
bantime.increment = true
bantime.factor = 1
bantime.maxtime = 1w
EOF

# 1. 只有 MSBOOST 的配置
load_dump msboost_only
sees msb_maxretry "'sshd', 'maxretry', '?5'?\]"
sees msb_executor "'sshd', 'addignoreip'.*'198\.51\.100\.10'"
sees msb_port     "'port', '22022'"

# 2. v1.0 的布局（参数在 [DEFAULT]）被 MSBOOST 的 [sshd] 盖住：这就是 v1.1 改布局的原因
cat >"$JAIL_LOCAL" <<EOF
$MARKER
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1 192.0.2.7
banaction = nftables-multiport
banaction_allports = nftables-allports
bantime = 2h
findtime = 10m
maxretry = 3

[sshd]
enabled = true
mode = normal
backend = systemd
port = 2222
EOF
load_dump v10_layout
sees   v10_shadowed_maxretry "'sshd', 'maxretry', '?5'?\]"
misses v10_lost_whitelist    "'sshd', 'addignoreip'.*'192\.0\.2\.7'"

# 3. 接管：带上 MSBOOST 的设置，再改参数、白名单、端口和动作，全部要生效
load_msboost_config
CFG_MAXRETRY=3
CFG_BANTIME=2h
CFG_FINDTIME=10m
CFG_INCREMENT=false
CFG_PORT=2222
CFG_BANACTION=iptables-multiport
CFG_BANACTION_ALL=iptables-allports
merge_ignoreip 192.0.2.7
render_config >"$JAIL_LOCAL"
load_dump takeover
sees   own_maxretry      "'sshd', 'maxretry', '?3'?\]"
sees   own_bantime       "'sshd', 'bantime', '?2h'?\]"
sees   own_findtime      "'sshd', 'findtime', '?10m'?\]"
misses own_no_increment  "'sshd', 'bantime\.increment', '?[Tt]rue'?\]"
sees   own_port          "'port', '2222'"
misses own_not_msb_port  "'port', '22022'"
sees   own_action        "'sshd', 'addaction', 'iptables-multiport'"
misses own_not_msb_action "'sshd', 'addaction', 'nftables"
sees   own_whitelist     "'sshd', 'addignoreip'.*'192\.0\.2\.7'"
sees   kept_executor     "'sshd', 'addignoreip'.*'198\.51\.100\.10'"
sees   kept_executor_v6  "'sshd', 'addignoreip'.*'2001:db8::10'"
sees   kept_local_net    "'sshd', 'addignoreip'.*'203\.0\.0\.0/16'"

# 4. 从白名单删掉 MSBOOST 的条目后，它确实不在了
CFG_IGNOREIP="127.0.0.1/8 ::1 192.0.2.7"
CFG_INCREMENT=true
render_config >"$JAIL_LOCAL"
load_dump whitelist_removed
misses removed_executor "'sshd', 'addignoreip'.*'198\.51\.100\.10'"
sees   increment_on     "'sshd', 'bantime\.increment', '?[Tt]rue'?\]"

# 5. 没有 MSBOOST 时一样；fail2ban.local 的封禁历史保留期
rm -f "$MSB_JAIL"
write_f2b_local
load_dump no_msboost
sees plain_maxretry "'sshd', 'maxretry', '?3'?\]"
sees plain_purgeage "'dbpurgeage', '?2592000'?\]"

echo "pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
