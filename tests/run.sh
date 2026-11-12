#!/usr/bin/env bash
#
# 函数级测试：不需要 root，不需要安装 fail2ban，也不会改动系统。
# 用法: bash tests/run.sh

# CFG_* 变量在这里赋值，由被 source 进来的 fail2ban.sh 读取
# shellcheck disable=SC2034
set -u

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

export F2B_DIR="$tmp/fail2ban"
export MSB_NODE_STATE="$tmp/msboost-install.env"
mkdir -p "$F2B_DIR/jail.d"

# shellcheck source=../fail2ban.sh
source "$here/../fail2ban.sh"

pass=0
fail=0

# eq 名称 实际值 期望值
eq() {
  if [ "$2" = "$3" ]; then
    pass=$((pass + 1))
  else
    fail=$((fail + 1))
    echo "FAIL $1: got [$2] want [$3]"
  fi
}

# pass_if 名称 命令...   命令应当成功
pass_if() {
  local name=$1
  shift
  if "$@" 2>/dev/null; then
    pass=$((pass + 1))
  else
    fail=$((fail + 1))
    echo "FAIL $name: expected success: $*"
  fi
}

# fail_if 名称 命令...    命令应当失败
fail_if() {
  local name=$1
  shift
  if "$@" 2>/dev/null; then
    fail=$((fail + 1))
    echo "FAIL $name: expected failure: $*"
  else
    pass=$((pass + 1))
  fi
}

ascii_only() { ! LC_ALL=C grep -q '[^[:print:][:space:]]' "$1"; }

# ---------------------------------------------------------------- SSH 端口解析

ss_out='State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
LISTEN 0      128          0.0.0.0:2222      0.0.0.0:*     users:(("sshd",pid=812,fd=3))
LISTEN 0      128             [::]:2222         [::]:*     users:(("sshd",pid=812,fd=4))
LISTEN 0      4096       127.0.0.1:5432      0.0.0.0:*     users:(("postgres",pid=1,fd=5))
LISTEN 0      4096               *:22              *:*     users:(("sshd",pid=900,fd=3),("systemd",pid=1,fd=93))'
eq ss_ports     "$(printf '%s\n' "$ss_out" | parse_ss_sshd_ports | join_ports)" "22,2222"
eq socket_ports "$(printf 'Listen=[::]:2200 (Stream)\nListen=0.0.0.0:22 (Stream)\n' | parse_socket_ports | join_ports)" "22,2200"
eq sshd_T_ports "$(printf 'port 22\nport 60022\naddressfamily any\npermitrootlogin yes\n' | parse_sshd_T_ports | join_ports)" "22,60022"
eq no_ports     "$(printf '\n\n' | join_ports)" ""

# ---------------------------------------------------------------- IP 校验

pass_if v4            is_ip_or_cidr 1.2.3.4
pass_if v4_cidr       is_ip_or_cidr 10.0.0.0/8
pass_if v4_cidr0      is_ip_or_cidr 0.0.0.0/0
fail_if  v4_octet      is_ip_or_cidr 256.1.1.1
fail_if  v4_short      is_ip_or_cidr 1.2.3
fail_if  v4_mask       is_ip_or_cidr 1.2.3.4/33
fail_if  v4_lead_zero  is_ip_or_cidr 010.0.0.1
fail_if  v4_mask_zero  is_ip_or_cidr 10.0.0.0/08
fail_if  v4_trailing   is_ip_or_cidr 1.2.3.4:
fail_if  word          is_ip_or_cidr abc
fail_if  empty         is_ip_or_cidr ""
fail_if  injection     is_ip_or_cidr '1.2.3.4;rm'

pass_if v6_full       is_ip_or_cidr 2001:0db8:0000:0000:0000:0000:0000:0001
pass_if v6_short      is_ip_or_cidr 2001:db8::1
pass_if v6_loopback   is_ip_or_cidr ::1
pass_if v6_any        is_ip_or_cidr ::
pass_if v6_cidr       is_ip_or_cidr 2001:db8::/32
pass_if v6_linklocal  is_ip_or_cidr fe80::1
pass_if v6_trail_dbl  is_ip_or_cidr 2001:db8::
pass_if v6_mapped     is_ip_or_cidr ::ffff:1.2.3.4
fail_if  v6_colon      is_ip_or_cidr :
fail_if  v6_colons     is_ip_or_cidr :::::
fail_if  v6_triple     is_ip_or_cidr 2001:::1
fail_if  v6_two_dbl    is_ip_or_cidr 2001::db8::1
fail_if  v6_lead_one   is_ip_or_cidr :2001:db8::1
fail_if  v6_trail_one  is_ip_or_cidr 2001:db8::1:
fail_if  v6_long_grp   is_ip_or_cidr 2001:db8::12345
fail_if  v6_nine       is_ip_or_cidr 1:2:3:4:5:6:7:8:9
fail_if  v6_seven      is_ip_or_cidr 1:2:3:4:5:6:7
fail_if  v6_dbl_full   is_ip_or_cidr 1:2:3:4::5:6:7:8
fail_if  v6_bad_v4     is_ip_or_cidr ::ffff:1.2.3.999
fail_if  v6_mask       is_ip_or_cidr 2001:db8::/129
fail_if  v6_hex        is_ip_or_cidr 2001:db8::g

pass_if loop_v4       is_loopback_entry 127.0.0.1/8
pass_if loop_v6       is_loopback_entry ::1
fail_if  loop_other    is_loopback_entry 10.0.0.1

# ---------------------------------------------------------------- 端口 / 时间 / 版本

pass_if port_one       valid_ports 22
pass_if port_many      valid_ports 22,2222
pass_if port_max       valid_ports 65535
fail_if  port_zero      valid_ports 0
fail_if  port_big       valid_ports 65536
fail_if  port_huge      valid_ports 700000
fail_if  port_lead_zero valid_ports 022
fail_if  port_lead_mix  valid_ports 22,0222
fail_if  port_trailing  valid_ports "22,"
fail_if  port_name      valid_ports ssh
fail_if  port_empty     valid_ports ""

pass_if time_m    valid_time 15m
pass_if time_w    valid_time 1w
pass_if time_sec  valid_time 3600
fail_if  time_unit valid_time 1x
fail_if  time_none valid_time ""
eq  seconds_w "$(to_seconds 1w)" 604800
eq  seconds_d "$(to_seconds 1d)" 86400

pass_if ver_new   ver_ge 1.0.2 0.11
pass_if ver_same  ver_ge 0.11.1 0.11
pass_if ver_short ver_ge 1.1 0.11
fail_if  ver_old   ver_ge 0.10.2 0.11
fail_if  ver_none  ver_ge 0.0 0.10

# ---------------------------------------------------------------- 封禁阶梯

reset_defaults
eq ladder_factor1 "$(show_ladder)" "1天 → 2天 → 4天 → 7天（封顶）"
CFG_FACTOR=2
eq ladder_factor2 "$(show_ladder)" "1天 → 4天 → 7天（封顶）"
CFG_INCREMENT=false
eq ladder_off "$(show_ladder)" "每次 1天（未启用递增）"

reset_defaults
pass_if consistent_default params_consistent
CFG_MAXTIME=1h
fail_if  consistent_small_max params_consistent
CFG_INCREMENT=false
pass_if consistent_no_increment params_consistent

# ---------------------------------------------------------------- 配置读写

reset_defaults
CFG_PORT="22,2222"
CFG_IGNOREIP="127.0.0.1/8 ::1 8.8.8.8"
CFG_MODE=aggressive
CFG_FACTOR=1.5
render_config >"$JAIL_LOCAL"
reset_defaults
load_config
eq rt_port      "$CFG_PORT" "22,2222"
eq rt_ignoreip  "$CFG_IGNOREIP" "127.0.0.1/8 ::1 8.8.8.8"
eq rt_mode      "$CFG_MODE" aggressive
eq rt_factor    "$CFG_FACTOR" 1.5
eq rt_increment "$CFG_INCREMENT" true
eq rt_backend   "$CFG_BACKEND" systemd
eq rt_banaction "$CFG_BANACTION" nftables-multiport
pass_if in_whitelist  in_ignoreip 8.8.8.8
fail_if  not_whitelist in_ignoreip 8.8.4.4
pass_if jail_ascii    ascii_only "$JAIL_LOCAL"

# 关闭递增时显式写 false（MSBOOST 的文件里可能是 true），不写 factor / maxtime
CFG_INCREMENT=false
render_config >"$JAIL_LOCAL"
eq  increment_false  "$(ini_get "$JAIL_LOCAL" sshd bantime.increment)" false
fail_if  factor_omitted grep -q 'bantime.factor' "$JAIL_LOCAL"
load_config
eq rt_increment_off "$CFG_INCREMENT" false

# SSH 的设置都在 [sshd]，[DEFAULT] 只留封禁动作
reset_defaults
render_config >"$JAIL_LOCAL"
eq layout_sshd_ignoreip    "$(ini_get "$JAIL_LOCAL" sshd ignoreip)" "127.0.0.1/8 ::1"
eq layout_sshd_bantime     "$(ini_get "$JAIL_LOCAL" sshd bantime)" 1d
eq layout_sshd_maxretry    "$(ini_get "$JAIL_LOCAL" sshd maxretry)" 5
eq layout_sshd_increment   "$(ini_get "$JAIL_LOCAL" sshd bantime.increment)" true
eq layout_sshd_banaction   "$(ini_get "$JAIL_LOCAL" sshd banaction)" nftables-multiport
eq layout_default_action   "$(ini_get "$JAIL_LOCAL" DEFAULT banaction)" nftables-multiport
eq layout_default_allports "$(ini_get "$JAIL_LOCAL" DEFAULT banaction_allports)" nftables-allports
eq layout_default_no_ip    "$(ini_get "$JAIL_LOCAL" DEFAULT ignoreip)" ""
eq layout_default_no_time  "$(ini_get "$JAIL_LOCAL" DEFAULT bantime)" ""

# v1.0 写的 jail.local（参数在 [DEFAULT]）照样能读
cat >"$JAIL_LOCAL" <<EOF
$MARKER
# Generated: 2026-11-10 12:00:00

[DEFAULT]
ignoreip = 127.0.0.1/8 ::1 8.8.8.8
banaction = iptables-multiport
banaction_allports = iptables-allports

bantime = 2d
findtime = 10m
maxretry = 3
bantime.increment = true
bantime.factor = 2
bantime.maxtime = 4w

[sshd]
enabled = true
mode = aggressive
backend = auto
port = 2222
EOF
load_config
eq v10_ignoreip  "$CFG_IGNOREIP" "127.0.0.1/8 ::1 8.8.8.8"
eq v10_banaction "$CFG_BANACTION" iptables-multiport
eq v10_allports  "$CFG_BANACTION_ALL" iptables-allports
eq v10_bantime   "$CFG_BANTIME" 2d
eq v10_findtime  "$CFG_FINDTIME" 10m
eq v10_maxretry  "$CFG_MAXRETRY" 3
eq v10_increment "$CFG_INCREMENT" true
eq v10_factor    "$CFG_FACTOR" 2
eq v10_maxtime   "$CFG_MAXTIME" 4w
eq v10_mode      "$CFG_MODE" aggressive
eq v10_backend   "$CFG_BACKEND" auto
eq v10_port      "$CFG_PORT" 2222
# 第一次按新布局写入时重启（动作的行搬进了 [sshd]）
cp "$JAIL_LOCAL" "$tmp/v10.local"
render_config >"$tmp/v11.local"
pass_if v10_to_v11_restart needs_restart "$tmp/v10.local" "$tmp/v11.local"

# 白名单清空后读回来仍是空，不回落到默认值
reset_defaults
CFG_IGNOREIP=""
render_config >"$JAIL_LOCAL"
load_config
eq rt_ignoreip_empty "$CFG_IGNOREIP" ""

# 带方括号的动作名
reset_defaults
CFG_BANACTION='nftables[type=multiport]'
render_config >"$JAIL_LOCAL"
load_config
eq rt_banaction_brackets "$CFG_BANACTION" 'nftables[type=multiport]'

# 非本脚本生成的 jail.local 不读取
printf '[sshd]\nenabled = true\nport = 999\n' >"$JAIL_LOCAL"
fail_if  unmanaged_not_loaded load_config
eq  unmanaged_port "$CFG_PORT" 22
fail_if  unmanaged_flag is_managed

# 只改 reload 能生效的键 -> 不需要重启；改端口 / 模式 -> 需要重启
reset_defaults
render_config >"$tmp/a.local"
CFG_IGNOREIP="127.0.0.1/8 ::1 8.8.8.8"; CFG_BANTIME=2d; CFG_MAXRETRY=3; CFG_FACTOR=2
render_config >"$tmp/b.local"
fail_if  reload_enough needs_restart "$tmp/a.local" "$tmp/b.local"
CFG_PORT="22,2222"
render_config >"$tmp/c.local"
pass_if restart_on_port needs_restart "$tmp/b.local" "$tmp/c.local"
CFG_PORT=22; CFG_MODE=aggressive
render_config >"$tmp/d.local"
pass_if restart_on_mode needs_restart "$tmp/b.local" "$tmp/d.local"
rm -f "$JAIL_LOCAL"

# fail2ban.local
write_f2b_local
eq  f2b_local_purgeage "$(ini_get "$F2B_LOCAL" Definition dbpurgeage)" 2592000
pass_if f2b_local_ascii ascii_only "$F2B_LOCAL"
# 别人写的 fail2ban.local 不覆盖
printf '[Definition]\nloglevel = DEBUG\n' >"$F2B_LOCAL"
write_f2b_local 2>/dev/null
eq  f2b_local_untouched "$(ini_get "$F2B_LOCAL" Definition loglevel)" DEBUG

# ---------------------------------------------------------------- MSBOOST

eq  source_none "$(config_source)" none
fail_if  msb_absent has_msboost
eq  msb_absent_ignoreip "$(msboost_ignoreip)" ""

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
port = 22,22022
ignoreip = 127.0.0.1/8 ::1 198.51.100.10 2001:db8::10 203.0.0.0/16
banaction = nftables-multiport
bantime = 1d
findtime = 15m
maxretry = 5
bantime.increment = true
bantime.factor = 1
bantime.maxtime = 1w
EOF
pass_if msb_detect has_msboost
eq  msb_source "$(config_source)" msboost
load_msboost_config
eq  msb_port      "$CFG_PORT" "22,22022"
eq  msb_ignoreip  "$CFG_IGNOREIP" "127.0.0.1/8 ::1 198.51.100.10 2001:db8::10 203.0.0.0/16"
eq  msb_backend   "$CFG_BACKEND" systemd
eq  msb_banaction "$CFG_BANACTION" nftables-multiport
eq  msb_bantime   "$CFG_BANTIME" 1d
eq  msb_maxretry  "$CFG_MAXRETRY" 5
eq  msb_increment "$CFG_INCREMENT" true
eq  msb_maxtime   "$CFG_MAXTIME" 1w
msb=$(msboost_ignoreip)
pass_if msb_entry       is_msboost_entry 198.51.100.10 "$msb"
pass_if msb_entry_net   is_msboost_entry 203.0.0.0/16 "$msb"
fail_if  msb_entry_loop  is_msboost_entry ::1 "$msb"
fail_if  msb_entry_other is_msboost_entry 8.8.8.8 "$msb"

# 接管以后以本脚本的 jail.local 为准，MSBOOST 的文件还在
render_config >"$JAIL_LOCAL"
eq  msb_source_script "$(config_source)" script
pass_if msb_still_there has_msboost
fail_if  new_layout_not_v10 is_v10_layout

# v1.0 的 jail.local 压在 MSBOOST 上（实际生效的是 MSBOOST 的白名单）：
# 读出来时并上 MSBOOST 的条目，改写成新格式后执行机还在白名单里
cat >"$JAIL_LOCAL" <<EOF
$MARKER
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1 192.0.2.7
banaction = nftables-multiport
banaction_allports = nftables-allports
bantime = 1d
findtime = 15m
maxretry = 3

[sshd]
enabled = true
mode = normal
backend = systemd
port = 22
EOF
pass_if v10_layout_detected is_v10_layout
load_config
eq  v10_msb_merged   "$CFG_IGNOREIP" "127.0.0.1/8 ::1 192.0.2.7 198.51.100.10 2001:db8::10 203.0.0.0/16"
eq  v10_msb_maxretry "$CFG_MAXRETRY" 3
render_config >"$JAIL_LOCAL"
fail_if  v10_layout_gone is_v10_layout
# 新格式里删掉的 MSBOOST 条目不会再被并回来
CFG_IGNOREIP="127.0.0.1/8 ::1 192.0.2.7"
render_config >"$JAIL_LOCAL"
load_config
eq  new_layout_no_merge "$CFG_IGNOREIP" "127.0.0.1/8 ::1 192.0.2.7"
# 空白名单也是新格式（ignoreip 键在，值为空）
CFG_IGNOREIP=""
render_config >"$JAIL_LOCAL"
pass_if ini_has_empty ini_has "$JAIL_LOCAL" sshd ignoreip
fail_if  empty_not_v10 is_v10_layout
fail_if  ini_has_missing ini_has "$JAIL_LOCAL" sshd nosuchkey

# 别人的 jail.local 也盖在 MSBOOST 上面
printf '[sshd]\nmaxretry = 3\n' >"$JAIL_LOCAL"
eq  msb_source_foreign "$(config_source)" foreign
rm -f "$JAIL_LOCAL"

# 恢复默认值时带上 MSBOOST 的白名单，已有的不重复
reset_defaults
CFG_IGNOREIP="127.0.0.1/8 ::1 8.8.8.8"
merge_ignoreip "$msb"
eq  msb_merge "$CFG_IGNOREIP" "127.0.0.1/8 ::1 8.8.8.8 198.51.100.10 2001:db8::10 203.0.0.0/16"
CFG_IGNOREIP=""
merge_ignoreip "$msb"
eq  msb_merge_empty "$CFG_IGNOREIP" "127.0.0.1/8 ::1 198.51.100.10 2001:db8::10 203.0.0.0/16"

# fail2ban 低于 0.11 时 MSBOOST 不写递增；格式不对的白名单条目不带过来
cat >"$MSB_JAIL" <<'EOF'
# Managed by MSBOOST (msboost-fail2ban-v1)
[sshd]
enabled = true
mode = normal
backend = auto
port = 22
ignoreip = 127.0.0.1/8 ::1 not-an-ip 203.0.113.5
banaction = iptables[type=multiport]
bantime = 1d
findtime = 15m
maxretry = 5
EOF
load_msboost_config
eq  msb_old_increment "$CFG_INCREMENT" false
eq  msb_old_backend   "$CFG_BACKEND" auto
eq  msb_old_banaction "$CFG_BANACTION" 'iptables[type=multiport]'
eq  msb_old_ignoreip  "$CFG_IGNOREIP" "127.0.0.1/8 ::1 203.0.113.5"

# 第一行不是 MSBOOST 的标记就不算
printf '[sshd]\nenabled = true\n' >"$MSB_JAIL"
fail_if  msb_unmarked has_msboost
eq  msb_unmarked_source "$(config_source)" none
rm -f "$MSB_JAIL"

fail_if  msb_node_no is_msboost_node
: >"$MSB_NODE_STATE"
pass_if msb_node_yes is_msboost_node
rm -f "$MSB_NODE_STATE"

# ---------------------------------------------------------------- 白名单覆盖（含 IPv4 网段）

CFG_IGNOREIP="127.0.0.1/8 ::1 203.0.0.0/16 198.51.100.10 2001:db8::10"
eq  cover_net   "$(ignoreip_cover 203.0.113.9)" 203.0.0.0/16
eq  cover_exact "$(ignoreip_cover 198.51.100.10)" 198.51.100.10
eq  cover_loop  "$(ignoreip_cover 127.0.0.53)" 127.0.0.1/8
eq  cover_v6    "$(ignoreip_cover 2001:db8::10)" 2001:db8::10
fail_if  cover_other    in_ignoreip 203.1.0.1
fail_if  cover_v6_other in_ignoreip 2001:db8::11
pass_if cidr_32       ip4_in_cidr 1.2.3.4 1.2.3.4/32
fail_if  cidr_32_no    ip4_in_cidr 1.2.3.5 1.2.3.4/32
pass_if cidr_0        ip4_in_cidr 9.9.9.9 0.0.0.0/0
pass_if cidr_24       ip4_in_cidr 10.1.2.255 10.1.2.0/24
fail_if  cidr_24_no    ip4_in_cidr 10.1.3.0 10.1.2.0/24
fail_if  cidr_no_mask  ip4_in_cidr 1.2.3.4 1.2.3.4
fail_if  cidr_bad_mask ip4_in_cidr 1.2.3.4 1.2.3.0/33
fail_if  cidr_v6       ip4_in_cidr 2001:db8::1 2001:db8::/32
CFG_IGNOREIP=""
fail_if  cover_empty   in_ignoreip 1.2.3.4

# ---------------------------------------------------------------- 登录 IP 识别

eq client_v4     "$(SSH_CONNECTION='203.0.113.9 51000 10.0.0.2 22' detect_client_ip)" "203.0.113.9"
eq client_mapped "$(SSH_CONNECTION='::ffff:203.0.113.9 51000 ::ffff:10.0.0.2 22' detect_client_ip)" "203.0.113.9"
eq client_zone   "$(SSH_CONNECTION='fe80::1%eth0 51000 fe80::2%eth0 22' detect_client_ip)" "fe80::1"
eq client_junk   "$(SSH_CONNECTION='not-an-ip 1 2 3' detect_client_ip)" ""

echo "pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
