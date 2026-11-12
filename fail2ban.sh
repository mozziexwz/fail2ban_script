#!/usr/bin/env bash
#
# fail2ban 一键部署 / 管理脚本（保护 SSH）
# https://github.com/mozziexwz/fail2ban_script
#
# 兼容 MSBOOST：MSBOOST 部署节点时配置的 fail2ban 可以直接查看、解封；
# 改白名单或参数时由本脚本接管，MSBOOST 的白名单原样保留。
#
# 用法:
#   bash fail2ban.sh                 交互菜单
#   bash fail2ban.sh install [-y]    一键部署（-y 全部使用默认值，不提问）
#   bash fail2ban.sh status          查看状态
#   bash fail2ban.sh unban <IP>|--all
#   bash fail2ban.sh ban <IP>
#   bash fail2ban.sh ports           仅显示检测到的 SSH 端口
#   bash fail2ban.sh uninstall [-y]

set -u

SCRIPT_VERSION="1.1.0"
F2B_DIR="${F2B_DIR:-/etc/fail2ban}"
JAIL_LOCAL="$F2B_DIR/jail.local"
F2B_LOCAL="$F2B_DIR/fail2ban.local"
F2B_LOG="${F2B_LOG:-/var/log/fail2ban.log}"
# 生成的配置文件只写 ASCII，避免 fail2ban 在 C locale 下读配置出编码问题
MARKER="# Managed by fail2ban.sh (fail2ban_script)"
JAIL="sshd"
# MSBOOST（网站 v2.12.0+、本地版 v1.2.0+）部署和升级节点时写的配置。本脚本只读，不改不删。
# MSBOOST 看到任何 *.local 就不再改动 fail2ban，所以本脚本写了 jail.local 之后它的文件就固定不变了。
MSB_JAIL="$F2B_DIR/jail.d/zz-msboost.conf"
MSB_MARKER="# Managed by MSBOOST"
MSB_NODE_STATE="${MSB_NODE_STATE:-/etc/msboost/install.env}"
ASSUME_YES=0
INPUT=""
PKG=""
OS_ID=""
OS_VER=""

# ---------------------------------------------------------------- 输出 / 输入

RED=""; GREEN=""; YELLOW=""; CYAN=""; BOLD=""; NC=""
if [ -t 1 ]; then
  RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'
  CYAN=$'\033[36m'; BOLD=$'\033[1m'; NC=$'\033[0m'
fi

info() { printf '%s\n' "${CYAN}[信息]${NC} $*"; }
ok()   { printf '%s\n' "${GREEN}[完成]${NC} $*"; }
warn() { printf '%s\n' "${YELLOW}[注意]${NC} $*" >&2; }
err()  { printf '%s\n' "${RED}[错误]${NC} $*" >&2; }

init_input() {
  if [ -t 0 ]; then
    INPUT=/dev/stdin
  elif { : </dev/tty; } 2>/dev/null; then
    INPUT=/dev/tty        # 例如 curl ... | bash
  else
    INPUT=""
  fi
}

trim() {
  local s=$1
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

# ask "提示" [默认值]  -> 结果放在 REPLY；读到 EOF 返回 1
ask() {
  local prompt=$1 def=${2:-}
  if [ "$ASSUME_YES" = 1 ] || [ -z "$INPUT" ]; then
    REPLY=$def
    return 0
  fi
  if [ -n "$def" ]; then
    printf '%s [%s]: ' "$prompt" "$def"
  else
    printf '%s: ' "$prompt"
  fi
  if ! IFS= read -r REPLY <"$INPUT"; then
    REPLY=$def
    echo
    return 1
  fi
  REPLY=$(trim "$REPLY")
  [ -z "$REPLY" ] && REPLY=$def
  return 0
}

# confirm "问题" [y|n]  -> 默认值在 -y 模式下直接生效
confirm() {
  local def=${2:-n} hint="y/N"
  [ "$def" = y ] && hint="Y/n"
  if [ "$ASSUME_YES" = 1 ] || [ -z "$INPUT" ]; then
    [ "$def" = y ]
    return
  fi
  printf '%s (%s): ' "$1" "$hint"
  local a=""
  IFS= read -r a <"$INPUT" || { echo; a=""; }
  a=$(trim "$a")
  [ -z "$a" ] && a=$def
  case "$a" in y|Y|yes|YES|Yes) return 0 ;; *) return 1 ;; esac
}

pause() {
  [ "$ASSUME_YES" = 1 ] || [ -z "$INPUT" ] && return 0
  printf '\n按回车返回菜单...'
  local _x
  IFS= read -r _x <"$INPUT" || true
}

# ---------------------------------------------------------------- 基础检查

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    err "需要 root 权限，请用 root 运行，或: sudo bash $0"
    exit 1
  fi
}

require_systemd() {
  if ! command -v systemctl >/dev/null 2>&1 || [ ! -d /run/systemd/system ]; then
    err "本脚本只支持使用 systemd 的系统。"
    return 1
  fi
}

need_f2b() {
  if ! command -v fail2ban-client >/dev/null 2>&1; then
    err "尚未安装 fail2ban，请先执行菜单 1（一键部署）。"
    return 1
  fi
}

need_running() {
  need_f2b || return 1
  if ! fail2ban-client ping >/dev/null 2>&1; then
    err "fail2ban 服务未运行，请先在「服务管理」里启动。"
    return 1
  fi
}

is_managed() { [ -f "$JAIL_LOCAL" ] && grep -qF "$MARKER" "$JAIL_LOCAL"; }

# MSBOOST 写的 jail.d/zz-msboost.conf，第一行是它的标记
has_msboost() {
  local first=""
  [ -f "$MSB_JAIL" ] && [ ! -L "$MSB_JAIL" ] || return 1
  IFS= read -r first <"$MSB_JAIL" || true
  [[ $first == "$MSB_MARKER"* ]]
}

# 装过 MSBOOST 节点的服务器
is_msboost_node() { [ -f "$MSB_NODE_STATE" ]; }

# sshd jail 现在按谁的配置运行：script / msboost / foreign / none
config_source() {
  if is_managed; then echo script
  elif [ -e "$JAIL_LOCAL" ]; then echo foreign
  elif has_msboost; then echo msboost
  else echo none
  fi
}

config_source_label() {
  case "$(config_source)" in
    script)
      if has_msboost; then printf '本脚本（%s，已接管 MSBOOST 的配置）' "$JAIL_LOCAL"
      else printf '本脚本（%s）' "$JAIL_LOCAL"; fi ;;
    msboost) printf 'MSBOOST（%s）' "$MSB_JAIL" ;;
    foreign) printf '%s（不是本脚本生成的）' "$JAIL_LOCAL" ;;
    *)       printf '发行版默认配置' ;;
  esac
}

# 修改白名单 / 参数 / 端口之前调用；MSBOOST 管理的服务器先询问是否接管
need_managed() {
  is_managed && return 0
  if [ "$(config_source)" = msboost ]; then
    msboost_takeover_notice
    confirm "现在由本脚本接管？" y && takeover_msboost && return 0
    return 1
  fi
  err "没有找到本脚本生成的 $JAIL_LOCAL，请先执行菜单 1（一键部署）。"
  return 1
}

detect_os() {
  if [ -r /etc/os-release ]; then
    OS_ID=$(. /etc/os-release 2>/dev/null; printf '%s' "${ID:-}")
    OS_VER=$(. /etc/os-release 2>/dev/null; printf '%s' "${VERSION_ID:-}")
  fi
  if command -v apt-get >/dev/null 2>&1; then PKG=apt
  elif command -v dnf >/dev/null 2>&1; then PKG=dnf
  elif command -v yum >/dev/null 2>&1; then PKG=yum
  else PKG=""
  fi
}

f2b_version() {
  fail2ban-client --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -n1
}

# ver_ge 1.0.2 0.11  -> 只比较 主.次 版本
ver_ge() {
  local a1 a2 b1 b2 _r
  IFS=. read -r a1 a2 _r <<<"$1"
  IFS=. read -r b1 b2 _r <<<"$2"
  a1=${a1:-0}; a2=${a2:-0}; b1=${b1:-0}; b2=${b2:-0}
  (( a1 > b1 || (a1 == b1 && a2 >= b2) ))
}

# ---------------------------------------------------------------- 校验

is_ipv4() {
  local ip=$1 o
  # 不接受前导零（010.0.0.1 在有些工具里会被当成八进制）
  local oct='(0|[1-9][0-9]{0,2})'
  [[ $ip =~ ^$oct\.$oct\.$oct\.$oct$ ]] || return 1
  for o in "${BASH_REMATCH[@]:1}"; do
    (( o <= 255 )) || return 1
  done
}

# 统计一段不含 "::" 的 IPv6 片段有几组，格式不对返回 1；空串算 0 组
_v6_groups() {
  local seg=$1 g n=0
  if [ -z "$seg" ]; then echo 0; return 0; fi
  [[ $seg == :* || $seg == *: || $seg == *::* ]] && return 1
  local IFS=:
  for g in $seg; do
    [[ $g =~ ^[0-9A-Fa-f]{1,4}$ ]] || return 1
    n=$((n + 1))
  done
  echo "$n"
}

is_ipv6() {
  local ip=$1 v4 h t nh nt
  [[ $ip == *:* && $ip =~ ^[0-9A-Fa-f:.]+$ ]] || return 1
  if [[ $ip == *.* ]]; then
    # 末尾内嵌 IPv4（如 ::ffff:1.2.3.4），占两组
    v4=${ip##*:}
    is_ipv4 "$v4" || return 1
    ip="${ip%"$v4"}0:0"
  fi
  if [[ $ip == *::* ]]; then
    h=${ip%%::*}
    t=${ip#*::}
    nh=$(_v6_groups "$h") || return 1
    nt=$(_v6_groups "$t") || return 1
    (( nh + nt <= 7 ))
  else
    nh=$(_v6_groups "$ip") || return 1
    (( nh == 8 ))
  fi
}

is_loopback_entry() {
  [[ $1 == 127.* || $1 == ::1 || $1 == ::1/128 ]]
}

# 接受 IPv4 / IPv6，可带 /掩码
is_ip_or_cidr() {
  local v=$1 ip mask
  ip=${v%%/*}
  if [[ $v == */* ]]; then
    mask=${v#*/}
    [[ $mask =~ ^(0|[1-9][0-9]{0,2})$ ]] || return 1
    if is_ipv4 "$ip"; then (( mask <= 32 )) || return 1
    elif is_ipv6 "$ip"; then (( mask <= 128 )) || return 1
    else return 1
    fi
    return 0
  fi
  is_ipv4 "$ip" || is_ipv6 "$ip"
}

valid_time() { [[ $1 =~ ^[0-9]+(s|m|h|d|w|mo|y)?$ ]]; }

valid_ports() {
  local p
  # 不接受前导零：022 写进防火墙规则可能被当成八进制
  [[ $1 =~ ^[1-9][0-9]{0,4}(,[1-9][0-9]{0,4})*$ ]] || return 1
  local IFS=,
  for p in $1; do
    (( p <= 65535 )) || return 1
  done
}

to_seconds() {
  local n u
  [[ $1 =~ ^([0-9]+)(s|m|h|d|w|mo|y)?$ ]] || return 1
  n=${BASH_REMATCH[1]}
  u=${BASH_REMATCH[2]:-s}
  case "$u" in
    m)  n=$((n * 60)) ;;
    h)  n=$((n * 3600)) ;;
    d)  n=$((n * 86400)) ;;
    w)  n=$((n * 604800)) ;;
    mo) n=$((n * 2592000)) ;;
    y)  n=$((n * 31536000)) ;;
  esac
  printf '%s' "$n"
}

fmt_duration() {
  local s=$1 out="" d h m
  d=$((s / 86400)); h=$(((s % 86400) / 3600)); m=$(((s % 3600) / 60))
  (( d > 0 )) && out+="${d}天"
  (( h > 0 )) && out+="${h}小时"
  (( m > 0 )) && out+="${m}分钟"
  [ -z "$out" ] && out="${s}秒"
  printf '%s' "$out"
}

# ---------------------------------------------------------------- 配置读写

reset_defaults() {
  CFG_IGNOREIP="127.0.0.1/8 ::1"
  CFG_BANACTION="nftables-multiport"
  CFG_BANACTION_ALL="nftables-allports"
  CFG_BANTIME="1d"
  CFG_FINDTIME="15m"
  CFG_MAXRETRY="5"
  CFG_INCREMENT="true"
  CFG_FACTOR="1"
  CFG_MAXTIME="1w"
  CFG_MODE="normal"
  CFG_BACKEND="systemd"
  CFG_PORT="22"
}

# ini_get 文件 段名 键名
ini_get() {
  awk -v sec="$2" -v key="$3" '
    /^[[:space:]]*\[/ {
      cur = $0
      sub(/^[[:space:]]*\[/, "", cur); sub(/\].*$/, "", cur)
      next
    }
    /^[[:space:]]*[#;]/ { next }
    cur == sec {
      i = index($0, "=")
      if (!i) next
      k = substr($0, 1, i - 1); v = substr($0, i + 1)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", k)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", v)
      if (k == key) { print v; exit }
    }' "$1" 2>/dev/null
}

# ini_has 文件 段名 键名   这个键是否写在该段里（值可以为空）
ini_has() {
  awk -v sec="$2" -v key="$3" '
    /^[[:space:]]*\[/ {
      cur = $0
      sub(/^[[:space:]]*\[/, "", cur); sub(/\].*$/, "", cur)
      next
    }
    /^[[:space:]]*[#;]/ { next }
    cur == sec {
      i = index($0, "=")
      if (!i) next
      k = substr($0, 1, i - 1)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", k)
      if (k == key) { found = 1; exit }
    }
    END { exit !found }' "$1" 2>/dev/null
}

# v1.0 写的 jail.local：白名单和封禁参数在 [DEFAULT]，在 MSBOOST 的服务器上会被它的 [sshd] 盖住
is_v10_layout() { is_managed && ! ini_has "$JAIL_LOCAL" "$JAIL" ignoreip; }

# _ld 变量 文件 键   先找 [sshd]，再找 [DEFAULT]（v1.0 把大部分参数写在 [DEFAULT] 里）
_ld() {
  local v
  v=$(ini_get "$2" "$JAIL" "$3")
  [ -n "$v" ] || v=$(ini_get "$2" DEFAULT "$3")
  [ -n "$v" ] && printf -v "$1" '%s' "$v"
  return 0
}

# read_config 文件 -> CFG_*
read_config() {
  local f=$1
  reset_defaults
  CFG_INCREMENT="false"
  CFG_IGNOREIP=""        # 白名单被清空时文件里是空值，不能回落到默认值
  _ld CFG_IGNOREIP      "$f" ignoreip
  _ld CFG_BANACTION     "$f" banaction
  _ld CFG_BANACTION_ALL "$f" banaction_allports
  _ld CFG_BANTIME       "$f" bantime
  _ld CFG_FINDTIME      "$f" findtime
  _ld CFG_MAXRETRY      "$f" maxretry
  _ld CFG_INCREMENT     "$f" bantime.increment
  _ld CFG_FACTOR        "$f" bantime.factor
  _ld CFG_MAXTIME       "$f" bantime.maxtime
  _ld CFG_MODE          "$f" mode
  _ld CFG_BACKEND       "$f" backend
  _ld CFG_PORT          "$f" port
  CFG_IGNOREIP=$(trim "${CFG_IGNOREIP//,/ }")
  return 0
}

load_config() {
  reset_defaults
  is_managed || return 1
  read_config "$JAIL_LOCAL"
  # v1.0 的文件压在 MSBOOST 上面时，实际生效的是 MSBOOST 的白名单。
  # 改写成新格式之前先把它并进来，执行机不会因为升级本脚本而掉出白名单。
  if is_v10_layout && has_msboost; then
    merge_ignoreip "$(msboost_ignoreip)"
  fi
  return 0
}

# 读 MSBOOST 的 jail.d/zz-msboost.conf（设置都在 [sshd] 里）
load_msboost_config() {
  reset_defaults
  has_msboost || return 1
  read_config "$MSB_JAIL"
  CFG_IGNOREIP=$(msboost_ignoreip)
  valid_ports "$CFG_PORT" || CFG_PORT=$(detect_ssh_ports)
  [ -n "$CFG_PORT" ] || CFG_PORT=22
  return 0
}

# MSBOOST 白名单里格式正确的条目：回环地址、网站执行机的 IP、部署节点时的来源地址
msboost_ignoreip() {
  local v x out="" arr=()
  has_msboost || return 0
  v=$(ini_get "$MSB_JAIL" "$JAIL" ignoreip)
  read -ra arr <<<"${v//,/ }"
  for x in ${arr[@]+"${arr[@]}"}; do
    is_ip_or_cidr "$x" && out+="${out:+ }$x"
  done
  printf '%s' "$out"
}

# in_list 条目 "空格分隔的列表"   精确匹配
in_list() {
  local x arr=()
  read -ra arr <<<"${2//,/ }"
  for x in ${arr[@]+"${arr[@]}"}; do
    [ "$x" = "$1" ] && return 0
  done
  return 1
}

# 把列表里还不在 CFG_IGNOREIP 中的条目追加进去
merge_ignoreip() {
  local x arr=()
  read -ra arr <<<"${1//,/ }"
  for x in ${arr[@]+"${arr[@]}"}; do
    in_list "$x" "$CFG_IGNOREIP" || CFG_IGNOREIP="${CFG_IGNOREIP:+$CFG_IGNOREIP }$x"
  done
}

# SSH 的设置全部写在 [sshd]：jail.d/*.conf 先于 jail.local 读取，但其中 [sshd] 段的值
# 比 jail.local 的 [DEFAULT] 优先。MSBOOST 的 zz-msboost.conf 就把设置写在 [sshd] 里，
# 所以只有写在 [sshd] 里才能盖过它。[DEFAULT] 只留封禁动作，供以后添加的其他 jail 使用。
render_config() {
  cat <<EOF
$MARKER
# Generated: $(date '+%F %T')
# Change settings through the script menu; manual edits are overwritten
# the next time the script rewrites this file.
# The SSH settings are all in [$JAIL]: only there do they also win over
# [$JAIL] values in jail.d/*.conf, such as MSBOOST's zz-msboost.conf.

[DEFAULT]
banaction = $CFG_BANACTION
banaction_allports = $CFG_BANACTION_ALL

[$JAIL]
enabled = true
mode = $CFG_MODE
backend = $CFG_BACKEND
port = $CFG_PORT
banaction = $CFG_BANACTION
ignoreip = $CFG_IGNOREIP
bantime = $CFG_BANTIME
findtime = $CFG_FINDTIME
maxretry = $CFG_MAXRETRY
EOF
  if [ "$CFG_INCREMENT" = true ]; then
    cat <<EOF
bantime.increment = true
bantime.factor = $CFG_FACTOR
bantime.maxtime = $CFG_MAXTIME
EOF
  else
    # 显式写 false：MSBOOST 的文件里可能是 true
    echo "bantime.increment = false"
  fi
}

# 封禁历史默认只保留 1 天左右，递增封禁需要更长的记忆。
# fail2ban 读取的是 [Definition] 段，写在这里对新旧版本都生效。
write_f2b_local() {
  if [ -f "$F2B_LOCAL" ] && ! grep -qF "$MARKER" "$F2B_LOCAL"; then
    if ! grep -qE '^[[:space:]]*dbpurgeage' "$F2B_LOCAL"; then
      warn "已存在非本脚本生成的 $F2B_LOCAL，未修改。"
      warn "建议手动在 [Definition] 段加入: dbpurgeage = 2592000"
    fi
    return 0
  fi
  cat >"$F2B_LOCAL" <<EOF
$MARKER
# Keep ban history for 30 days so bantime.increment recognises repeat offenders.
[Definition]
dbpurgeage = 2592000
EOF
  chmod 644 "$F2B_LOCAL"
}

wait_jail() {
  local i
  for i in $(seq 1 20); do
    fail2ban-client status "$JAIL" >/dev/null 2>&1 && return 0
    systemctl is-failed --quiet fail2ban 2>/dev/null && return 1
    sleep 1
  done
  return 1
}

show_failure_logs() {
  echo "----- journalctl -u fail2ban (最近 15 行) -----" >&2
  journalctl -u fail2ban -n 15 --no-pager 2>/dev/null | cut -c1-300 >&2
  if [ -s "$F2B_LOG" ]; then
    echo "----- $F2B_LOG 中的错误 -----" >&2
    tail -n 60 "$F2B_LOG" | grep -E ' (ERROR|CRITICAL) ' | tail -n 8 | cut -c1-200 |
      sed -E 's/(.{200})$/\1 .../' >&2
  fi
}

# reload 只对这些键可靠：ignoreip / bantime* / findtime / maxretry。
# 端口、封禁动作、过滤模式、后端的改动要重启才会重建防火墙规则和过滤器（实测 reload 不更新 nft 规则里的端口）。
needs_restart() {
  local skip='^[[:space:]]*(#|ignoreip|bantime|findtime|maxretry)'
  [ "$(grep -vE "$skip" "$1" 2>/dev/null)" != "$(grep -vE "$skip" "$2" 2>/dev/null)" ]
}

# 让当前 jail.local 生效：activate reload|restart
activate() {
  local how=$1
  if [ "$how" = reload ] && fail2ban-client ping >/dev/null 2>&1; then
    if ! fail2ban-client reload >/dev/null 2>&1; then
      warn "重新加载失败，改为重启服务。"
      how=restart
    fi
  else
    how=restart
  fi
  if [ "$how" = restart ]; then
    systemctl restart fail2ban || return 1
  fi
  wait_jail
}

# 写入 jail.local -> 校验 -> 生效；任何一步失败都还原为修改前的配置
# apply_config          能 reload 就 reload（不会撤掉再恢复现有封禁），否则重启
# apply_config restart  强制重启（部署时用，fail2ban.local 的改动需要重启才生效）
apply_config() {
  local how=${1:-reload}
  local tmp out ver had_prev=0
  tmp=$(mktemp) || { err "无法创建临时文件"; return 1; }
  render_config >"$tmp"

  mkdir -p "$F2B_DIR"
  if [ -f "$JAIL_LOCAL" ]; then
    cp -p "$JAIL_LOCAL" "$JAIL_LOCAL.prev"
    had_prev=1
    needs_restart "$JAIL_LOCAL.prev" "$tmp" && how=restart
  else
    how=restart
  fi
  cat "$tmp" >"$JAIL_LOCAL"
  chmod 644 "$JAIL_LOCAL"
  rm -f "$tmp"

  ver=$(f2b_version)
  if ver_ge "${ver:-0.0}" 0.10; then
    if ! out=$(fail2ban-client -t 2>&1); then
      err "配置校验失败（fail2ban-client -t）："
      printf '%s\n' "$out" | grep -E 'ERROR|CRITICAL' | cut -c1-300 | sed 's/^/    /' >&2
      if [ "$had_prev" = 1 ]; then
        cp -p "$JAIL_LOCAL.prev" "$JAIL_LOCAL"
        warn "已还原为修改前的配置，运行中的服务未受影响。"
      else
        rm -f "$JAIL_LOCAL"
        warn "已删除刚写入的配置。"
      fi
      return 1
    fi
  fi

  systemctl enable fail2ban >/dev/null 2>&1 || warn "设置开机自启失败。"
  # fail2ban-client -t 只查语法和文件是否存在，查不出非法取值，所以生效失败也要回滚
  if ! activate "$how"; then
    err "新配置没能生效（服务未启动或 $JAIL jail 没有起来）。"
    show_failure_logs
    if [ "$had_prev" = 1 ]; then
      cp -p "$JAIL_LOCAL.prev" "$JAIL_LOCAL"
      warn "已还原为修改前的配置，正在重启服务..."
      if systemctl restart fail2ban 2>/dev/null && wait_jail; then
        ok "服务已恢复到修改前的状态。"
      else
        err "还原后服务仍然没能启动（修改前的配置本身可能就有问题），请查看: journalctl -u fail2ban"
      fi
    fi
    return 1
  fi
  ok "配置已生效，$JAIL jail 运行中。"
}

# 封禁阶梯预览：首次 = bantime；第 n 次(n>=2) = bantime * 2^(n-1) * factor，上限 maxtime
show_ladder() {
  local b m i t out=""
  if [ "$CFG_BANTIME" = "-1" ]; then printf '永久封禁'; return; fi
  b=$(to_seconds "$CFG_BANTIME") || { printf '%s' "$CFG_BANTIME"; return; }
  if [ "$CFG_INCREMENT" != true ]; then
    printf '每次 %s（未启用递增）' "$(fmt_duration "$b")"
    return
  fi
  m=$(to_seconds "$CFG_MAXTIME") || { printf '%s 起，上限 %s' "$CFG_BANTIME" "$CFG_MAXTIME"; return; }
  if [ "$m" -lt "$b" ]; then
    printf '首次 %s，但上限只有 %s —— 上限应不小于首次封禁时长' "$(fmt_duration "$b")" "$(fmt_duration "$m")"
    return
  fi
  for i in 0 1 2 3 4 5; do
    if [ "$i" -eq 0 ]; then
      t=$b
    else
      t=$(awk -v b="$b" -v i="$i" -v f="$CFG_FACTOR" -v m="$m" \
        'BEGIN { t = b * (2 ^ i) * f; if (t > m) t = m; printf "%d", t }')
    fi
    out+="${out:+ → }$(fmt_duration "$t")"
    if [ "$i" -gt 0 ] && [ "$t" -ge "$m" ]; then
      out+="（封顶）"
      break
    fi
  done
  printf '%s' "$out"
}

print_config_summary() {
  printf '  SSH 端口:   %s\n' "$CFG_PORT"
  printf '  触发条件:   %s 内失败 %s 次\n' "$CFG_FINDTIME" "$CFG_MAXRETRY"
  printf '  封禁阶梯:   %s\n' "$(show_ladder)"
  printf '  过滤模式:   %s\n' "$CFG_MODE"
  printf '  日志后端:   %s\n' "$CFG_BACKEND"
  printf '  封禁动作:   %s\n' "$CFG_BANACTION"
  printf '  白名单:     %s\n' "$CFG_IGNOREIP"
}

# ---------------------------------------------------------------- SSH 端口 / 登录 IP

parse_ss_sshd_ports() {
  awk '$1 == "LISTEN" && /"sshd"/ { n = split($4, a, ":"); if (a[n] ~ /^[0-9]+$/) print a[n] }'
}

parse_socket_ports() {
  grep -oE ':[0-9]+ \(Stream\)' | grep -oE '[0-9]+'
}

parse_sshd_T_ports() {
  awk 'tolower($1) == "port" && $2 ~ /^[0-9]+$/ { print $2 }'
}

join_ports() {
  grep -E '^[0-9]+$' | sort -n -u | paste -sd, -
}

# 取并集：实际监听的 sshd + socket 激活的 ssh.socket + sshd -T 的生效配置
detect_ssh_ports() {
  local ports="" unit sshd_bin
  if command -v ss >/dev/null 2>&1; then
    ports+=$'\n'$(ss -tlnp 2>/dev/null | parse_ss_sshd_ports)
  fi
  if command -v systemctl >/dev/null 2>&1; then
    for unit in ssh.socket sshd.socket; do
      if systemctl is-active --quiet "$unit" 2>/dev/null; then
        ports+=$'\n'$(systemctl show "$unit" -p Listen 2>/dev/null | parse_socket_ports)
      fi
    done
  fi
  sshd_bin=$(command -v sshd 2>/dev/null || true)
  [ -z "$sshd_bin" ] && [ -x /usr/sbin/sshd ] && sshd_bin=/usr/sbin/sshd
  if [ -n "$sshd_bin" ]; then
    ports+=$'\n'$("$sshd_bin" -T 2>/dev/null | parse_sshd_T_ports)
  fi
  printf '%s\n' "$ports" | join_ports
}

detect_client_ip() {
  local ip=""
  if [ -n "${SSH_CONNECTION:-}" ]; then
    ip=${SSH_CONNECTION%% *}
  elif [ -n "${SSH_CLIENT:-}" ]; then
    ip=${SSH_CLIENT%% *}
  else
    ip=$(who -m 2>/dev/null | sed -n 's/.*(\([^)]*\)).*/\1/p' | head -n1)
  fi
  ip=${ip%%%*}            # 去掉 IPv6 的 %zone
  ip=${ip#::ffff:}        # IPv4-mapped IPv6
  if is_ipv4 "$ip" || is_ipv6 "$ip"; then
    printf '%s' "$ip"
  fi
}

ip4_to_int() {
  local IFS=. a b c d
  read -r a b c d <<<"$1"
  echo $(( (a << 24) | (b << 16) | (c << 8) | d ))
}

# ip4_in_cidr IP 网段   IPv4 网段是否包含这个 IP
ip4_in_cidr() {
  local net=${2%/*} bits=${2#*/} mask
  [[ $2 == */* ]] && is_ipv4 "$1" && is_ipv4 "$net" || return 1
  [[ $bits =~ ^(0|[1-9][0-9]?)$ ]] && (( bits <= 32 )) || return 1
  mask=$(( bits == 0 ? 0 : (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF ))
  (( ($(ip4_to_int "$1") & mask) == ($(ip4_to_int "$net") & mask) ))
}

# ignoreip_cover IP -> 打印白名单里覆盖它的条目：相同的地址，或包含它的 IPv4 网段
# （MSBOOST 本地版把电脑所在的 /16 放进白名单）
ignoreip_cover() {
  local x arr=()
  read -ra arr <<<"${CFG_IGNOREIP//,/ }"
  for x in ${arr[@]+"${arr[@]}"}; do
    if [ "$x" = "$1" ] || ip4_in_cidr "$1" "$x"; then
      printf '%s' "$x"
      return 0
    fi
  done
  return 1
}

in_ignoreip() { ignoreip_cover "$1" >/dev/null; }

# ---------------------------------------------------------------- 安装

pkg_installed() {
  case "$PKG" in
    apt) dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed' ;;
    dnf|yum) rpm -q "$1" >/dev/null 2>&1 ;;
    *) return 1 ;;
  esac
}

ensure_epel() {
  [ "$OS_ID" = fedora ] && return 0
  rpm -q epel-release >/dev/null 2>&1 && return 0
  info "启用 EPEL 仓库（fail2ban 在 EPEL 里）..."
  "$PKG" install -y epel-release && return 0
  if [ "$OS_ID" = ol ]; then
    "$PKG" install -y "oracle-epel-release-el${OS_VER%%.*}" && return 0
  fi
  warn "自动启用 EPEL 失败，如果下面安装 fail2ban 失败，请先手动启用 EPEL。"
  return 1
}

install_pkgs() {
  local want=() missing=() p
  case "$PKG" in
    apt)     want=(fail2ban python3-systemd nftables) ;;
    dnf|yum) want=(fail2ban fail2ban-systemd nftables) ;;
    *) err "不支持的系统：找不到 apt-get / dnf / yum。"; return 1 ;;
  esac
  for p in "${want[@]}"; do
    pkg_installed "$p" || missing+=("$p")
  done
  if [ "${#missing[@]}" -eq 0 ]; then
    ok "依赖已安装: ${want[*]}"
    return 0
  fi
  info "安装: ${missing[*]}"
  case "$PKG" in
    apt)
      apt-get update -qq || warn "apt-get update 有报错，继续尝试安装。"
      DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}"
      ;;
    dnf|yum)
      pkg_installed fail2ban || ensure_epel || true
      "$PKG" install -y "${missing[@]}"
      ;;
  esac
  if ! command -v fail2ban-client >/dev/null 2>&1; then
    err "fail2ban 安装失败，请查看上面的包管理器输出。"
    return 1
  fi
  # 注意：这里故意不启用 nftables.service，只需要 nft 命令本身。
  # 启用该服务会加载 /etc/nftables.conf（通常带 flush ruleset），可能冲掉 ufw / docker 的规则。
}

choose_banaction() {
  if command -v nft >/dev/null 2>&1 && nft list tables >/dev/null 2>&1; then
    if [ -f "$F2B_DIR/action.d/nftables-multiport.conf" ]; then
      CFG_BANACTION="nftables-multiport"
      CFG_BANACTION_ALL="nftables-allports"
      return 0
    elif [ -f "$F2B_DIR/action.d/nftables.conf" ]; then
      CFG_BANACTION="nftables[type=multiport]"
      CFG_BANACTION_ALL="nftables[type=allports]"
      return 0
    fi
  fi
  warn "nftables 在本机不可用（缺少 nft 或内核不支持），改用 iptables 动作。"
  CFG_BANACTION="iptables-multiport"
  CFG_BANACTION_ALL="iptables-allports"
  command -v iptables >/dev/null 2>&1 || warn "也没有找到 iptables，封禁可能无法生效，请检查防火墙组件。"
}

# fail2ban 实际使用的 python 解释器（取 fail2ban-server 的 shebang）
f2b_python() {
  local s py=""
  s=$(command -v fail2ban-server 2>/dev/null) && py=$(sed -n '1s/^#! *//p' "$s" 2>/dev/null)
  printf '%s' "${py:-python3}"
}

choose_backend() {
  local py
  py=$(f2b_python)
  # shellcheck disable=SC2086
  if [ -d /run/systemd/system ] && $py -c 'import systemd.journal' >/dev/null 2>&1; then
    CFG_BACKEND="systemd"
  else
    warn "python 的 systemd 模块不可用，backend 改用 auto（读取日志文件）。"
    CFG_BACKEND="auto"
  fi
}

# ---------------------------------------------------------------- MSBOOST

msboost_takeover_notice() {
  info "这台服务器的 fail2ban 是 MSBOOST 配置的（$MSB_JAIL）。由本脚本接管后："
  echo "  - MSBOOST 的白名单（网站执行机的 IP、部署节点时的来源地址）和参数原样带过来，写进 $JAIL_LOCAL；"
  echo "  - MSBOOST 的文件不改不删，只是其中的设置被 $JAIL_LOCAL 覆盖；"
  echo "  - 之后 MSBOOST「升级节点」会显示「已有 fail2ban 配置，未改动」，不再更新白名单。"
  echo "    网站新增或更换执行机后，要在菜单 5 把新执行机的 IP 加进白名单；"
  echo "  - 想交还给 MSBOOST：菜单 10 卸载，只删除本脚本的配置，fail2ban 改回按 MSBOOST 的配置运行。"
}

# 菜单 5/6/7 里接管：把 MSBOOST 的参数、白名单、端口原样转成本脚本的 jail.local
takeover_msboost() {
  need_f2b || return 1
  load_msboost_config || return 1
  choose_banaction
  choose_backend
  write_f2b_local
  apply_config restart || return 1
  ok "已由本脚本接管，MSBOOST 的文件保持原样。"
}

# ---------------------------------------------------------------- 一键部署

do_install() {
  require_root
  require_systemd || return 1
  detect_os
  echo "${BOLD}== 一键部署 fail2ban ==${NC}"

  local ver detected myip cover bak src keep=0

  # 已有配置的处理（先问清楚再装软件包，取消时不留改动）
  reset_defaults
  src=$(config_source)
  case "$src" in
    script)
      if confirm "检测到本脚本之前生成的配置，保留现有参数和白名单？（选 n 恢复默认值）" y; then
        load_config
        keep=1
      fi
      ;;
    foreign)
      bak="$JAIL_LOCAL.bak.$(date +%Y%m%d-%H%M%S)"
      warn "已存在 $JAIL_LOCAL（不是本脚本生成的），将备份后覆盖。"
      confirm "继续？" y || { info "已取消。"; return 1; }
      cp -p "$JAIL_LOCAL" "$bak" && ok "已备份到 $bak"
      ;;
    msboost)
      msboost_takeover_notice
      confirm "继续部署（由本脚本接管）？" y || { info "已取消。"; return 1; }
      load_msboost_config
      keep=1
      ;;
  esac
  # 恢复默认值时也带上 MSBOOST 的白名单，网站执行机不能因此被封
  if [ "$keep" != 1 ] && has_msboost; then
    merge_ignoreip "$(msboost_ignoreip)"
    info "已带上 MSBOOST 的白名单: $CFG_IGNOREIP"
  fi
  if [ "$src" != script ] && is_msboost_node && ! has_msboost; then
    warn "这是 MSBOOST 节点，但 MSBOOST 没有配置它的 fail2ban。由本脚本配置后，MSBOOST 以后也不会改动 fail2ban，"
    warn "网站执行机不会自动加入白名单；用网站管理这台服务器的话，可以在菜单 5 添加执行机的 IP。"
  fi

  install_pkgs || return 1
  ver=$(f2b_version)
  info "fail2ban 版本: ${ver:-未知}"

  choose_banaction
  choose_backend

  if ver_ge "${ver:-0.0}" 0.11; then
    [ "$keep" = 1 ] || CFG_INCREMENT="true"
  else
    warn "fail2ban ${ver:-?} 低于 0.11，不支持递增封禁（bantime.increment），已关闭该项。"
    CFG_INCREMENT="false"
  fi

  # SSH 端口
  detected=$(detect_ssh_ports)
  if [ -n "$detected" ]; then
    ok "检测到 SSH 端口: $detected"
  else
    warn "没能检测到 SSH 端口，默认使用 22，请确认。"
    detected="22"
  fi
  while true; do
    ask "要保护的 SSH 端口（多个用逗号分隔，回车确认）" "$detected" || true
    if valid_ports "$REPLY"; then CFG_PORT=$REPLY; break; fi
    err "端口格式不对，例如: 22 或 22,2222"
    [ "$ASSUME_YES" = 1 ] || [ -z "$INPUT" ] && { CFG_PORT=$detected; break; }
  done

  # 当前登录 IP
  myip=$(detect_client_ip)
  if [ -n "$myip" ]; then
    if cover=$(ignoreip_cover "$myip"); then
      [ "$cover" = "$myip" ] || info "你当前的登录 IP $myip 在白名单网段 $cover 里。"
    else
      info "你当前的登录 IP 是 $myip"
      if confirm "把它加入白名单（永不封禁）？固定 IP 建议加，动态 IP 不建议" n; then
        CFG_IGNOREIP="${CFG_IGNOREIP:+$CFG_IGNOREIP }$myip"
      fi
    fi
  fi

  write_f2b_local
  apply_config restart || return 1

  echo
  echo "${BOLD}部署完成，当前配置：${NC}"
  print_config_summary
  if has_msboost; then
    info "MSBOOST 的 $MSB_JAIL 保持原样，其中的设置已被 $JAIL_LOCAL 覆盖。"
  fi
  echo
  fail2ban-client status "$JAIL" 2>/dev/null | sed 's/^/  /'
  if [ -n "$myip" ] && ! in_ignoreip "$myip"; then
    echo
    warn "你的 IP $myip 不在白名单里：${CFG_FINDTIME} 内输错 ${CFG_MAXRETRY} 次密码同样会被封。"
  fi
}

# ---------------------------------------------------------------- 状态 / 封禁管理

svc_state() {
  local s
  s=$(systemctl is-active fail2ban 2>/dev/null)
  case "$s" in
    active)   printf '%s' "${GREEN}运行中${NC}" ;;
    failed)   printf '%s' "${RED}启动失败${NC}" ;;
    inactive) printf '%s' "${YELLOW}已停止${NC}" ;;
    *)        printf '%s' "${YELLOW}${s:-未知}${NC}" ;;
  esac
}

enabled_state() {
  local s
  s=$(systemctl is-enabled fail2ban 2>/dev/null)
  printf '%s' "${s:-未知}"
}

banned_count() {
  fail2ban-client status "$JAIL" 2>/dev/null |
    awk -F: '/Currently banned/ { gsub(/[[:space:]]/, "", $2); print $2 }'
}

banned_list() {
  fail2ban-client status "$JAIL" 2>/dev/null |
    sed -n 's/.*Banned IP list:[[:space:]]*//p' | tr -s ' \t' '\n' | grep -v '^$'
}

do_status() {
  need_f2b || return 1
  local out
  echo "${BOLD}== fail2ban 状态 ==${NC}"
  printf '  版本:       %s\n' "$(f2b_version)"
  printf '  服务:       %s\n' "$(svc_state)"
  printf '  开机自启:   %s\n' "$(enabled_state)"
  printf '  配置来源:   %s\n' "$(config_source_label)"
  case "$(config_source)" in
    script)
      load_config
      print_config_summary
      if is_v10_layout && has_msboost; then
        warn "jail.local 还是 v1.0 的格式，白名单和封禁参数被 MSBOOST 的 $MSB_JAIL 盖住了，实际按 MSBOOST 的生效。"
        warn "执行一次菜单 1（保留现有参数），或在菜单 5/6 保存一次，就会改成新格式并生效（上面的白名单已合并 MSBOOST 的条目）。"
      fi
      ;;
    msboost)
      load_msboost_config
      print_config_summary
      info "解封、封禁、日志可以直接用；改白名单、参数或端口时（菜单 5/6/7），本脚本会先询问是否接管。"
      ;;
    foreign) warn "当前 jail.local 不是本脚本生成的，下面只显示运行状态。" ;;
    *)       warn "没有本脚本或 MSBOOST 的配置，下面只显示运行状态。" ;;
  esac
  echo
  if ! fail2ban-client ping >/dev/null 2>&1; then
    warn "fail2ban 服务未运行。"
    return 1
  fi
  if ! fail2ban-client status "$JAIL"; then
    warn "$JAIL jail 未启用。"
    return 1
  fi
  echo
  echo "当前封禁（IP / 封禁时间 + 时长 = 到期时间）："
  if out=$(fail2ban-client get "$JAIL" banip --with-time 2>/dev/null) && [ -n "$out" ]; then
    printf '%s\n' "$out" | sed 's/^/  /'
  elif [ "$(banned_count)" = "0" ]; then
    echo "  （无）"
  else
    banned_list | sed 's/^/  /'
  fi
}

do_unban() {
  need_running || return 1
  local target=${1:-}
  if [ "$target" = "--all" ]; then
    fail2ban-client unban --all >/dev/null && ok "已解封全部 IP。"
    return
  fi
  if ! is_ip_or_cidr "$target"; then
    err "不是合法的 IP: $target"
    return 1
  fi
  if fail2ban-client unban "$target" >/dev/null 2>&1 ||
     fail2ban-client set "$JAIL" unbanip "$target" >/dev/null 2>&1; then
    ok "已解封 $target"
  else
    err "解封失败: $target"
    return 1
  fi
}

do_ban() {
  need_running || return 1
  local target=${1:-} myip
  if ! is_ip_or_cidr "$target"; then
    err "不是合法的 IP: $target"
    return 1
  fi
  myip=$(detect_client_ip)
  if [ -n "$myip" ] && [ "$target" = "$myip" ]; then
    warn "$target 是你当前的登录 IP，封禁后你会立刻断开！"
    confirm "确定要封禁自己？" n || return 1
  fi
  if fail2ban-client set "$JAIL" banip "$target" >/dev/null; then
    ok "已封禁 $target"
  else
    err "封禁失败: $target"
    return 1
  fi
}

menu_unban() {
  need_running || return 1
  local list
  list=$(banned_list)
  if [ -z "$list" ]; then
    info "当前没有被封禁的 IP。"
    return 0
  fi
  echo "当前封禁的 IP："
  printf '%s\n' "$list" | sed 's/^/  /'
  echo
  ask "输入要解封的 IP（输入 all 解封全部，直接回车取消）" "" || return 0
  case "$REPLY" in
    "") return 0 ;;
    all|ALL) confirm "确定解封全部 IP？" n && do_unban --all ;;
    *) do_unban "$REPLY" ;;
  esac
}

menu_ban() {
  need_running || return 1
  ask "输入要封禁的 IP（直接回车取消）" "" || return 0
  [ -z "$REPLY" ] && return 0
  do_ban "$REPLY"
}

# ---------------------------------------------------------------- 白名单

# 已在白名单里（本身或所在网段）时提示并返回 0
already_whitelisted() {
  local cover
  cover=$(ignoreip_cover "$1") || return 1
  if [ "$cover" = "$1" ]; then
    info "$1 已在白名单里。"
  else
    info "$1 已在白名单网段 $cover 里。"
  fi
}

# 白名单里由 MSBOOST 写入的条目（不含回环地址）
is_msboost_entry() {
  ! is_loopback_entry "$1" && in_list "$1" "$2"
}

menu_whitelist() {
  need_managed || return 1
  local items i n myip target msb tag
  while true; do
    load_config
    read -ra items <<<"$CFG_IGNOREIP"
    myip=$(detect_client_ip)
    msb=$(msboost_ignoreip)
    echo
    echo "${BOLD}== 白名单（ignoreip）==${NC}"
    i=1
    if [ "${#items[@]}" -gt 0 ]; then
      for n in "${items[@]}"; do
        tag=""
        is_msboost_entry "$n" "$msb" && tag="  （MSBOOST）"
        printf '  %2d) %s%s\n' "$i" "$n" "$tag"
        i=$((i + 1))
      done
    else
      echo "  （空）"
    fi
    if [ -n "$msb" ]; then
      echo "  标着 MSBOOST 的条目是 MSBOOST 写入的：网站执行机的 IP，或部署节点时的来源地址。"
    fi
    echo
    echo "  a) 添加 IP / 网段"
    echo "  d) 删除"
    [ -n "$myip" ] && ! in_ignoreip "$myip" && echo "  m) 添加当前登录 IP ($myip)"
    echo "  0) 返回"
    ask "请选择" "" || return 0
    case "$REPLY" in
      a|A)
        ask "输入 IP 或网段（如 1.2.3.4 或 1.2.3.0/24）" "" || continue
        target=$REPLY
        [ -z "$target" ] && continue
        if ! is_ip_or_cidr "$target"; then err "格式不对: $target"; continue; fi
        already_whitelisted "$target" && continue
        CFG_IGNOREIP="${CFG_IGNOREIP:+$CFG_IGNOREIP }$target"
        apply_config && fail2ban-client unban "$target" >/dev/null 2>&1
        ;;
      m|M)
        [ -z "$myip" ] && continue
        already_whitelisted "$myip" && continue
        CFG_IGNOREIP="${CFG_IGNOREIP:+$CFG_IGNOREIP }$myip"
        apply_config && fail2ban-client unban "$myip" >/dev/null 2>&1
        ;;
      d|D)
        ask "输入要删除的序号" "" || continue
        if ! [[ $REPLY =~ ^[0-9]+$ ]] || [ "$REPLY" -lt 1 ] || [ "$REPLY" -gt "${#items[@]}" ]; then
          err "序号无效。"
          continue
        fi
        target=${items[$((REPLY - 1))]}
        if is_loopback_entry "$target"; then
          warn "$target 是本机回环地址，一般应保留在白名单里。"
          confirm "确定删除？" n || continue
        elif is_msboost_entry "$target" "$msb"; then
          warn "$target 是 MSBOOST 写入的（网站执行机的 IP，或部署节点时的来源地址）。"
          warn "删掉后，从这里连接时输错几次密码就会被封，MSBOOST 的任务也就连不上这台服务器了。"
          confirm "确定删除？" n || continue
        fi
        unset "items[$((REPLY - 1))]"
        CFG_IGNOREIP="${items[*]:-}"
        apply_config
        ;;
      0|"") return 0 ;;
      *) warn "无效选项。" ;;
    esac
  done
}

# ---------------------------------------------------------------- 修改参数

# 启用递增时，封禁上限不能小于首次封禁时长
params_consistent() {
  local b m
  [ "$CFG_INCREMENT" = true ] || return 0
  [ "$CFG_BANTIME" = "-1" ] && return 0
  b=$(to_seconds "$CFG_BANTIME") || return 0
  m=$(to_seconds "$CFG_MAXTIME") || return 0
  if [ "$m" -lt "$b" ]; then
    err "bantime.maxtime（$CFG_MAXTIME）小于 bantime（$CFG_BANTIME），请先调整其中一个。"
    return 1
  fi
}

menu_params() {
  need_managed || return 1
  load_config
  local dirty=0 ver
  ver=$(f2b_version)
  while true; do
    echo
    echo "${BOLD}== 修改参数 ==${NC}"
    printf '  1) bantime          首次封禁时长       %s\n' "$CFG_BANTIME"
    printf '  2) findtime         统计时间窗口       %s\n' "$CFG_FINDTIME"
    printf '  3) maxretry         窗口内允许失败次数 %s\n' "$CFG_MAXRETRY"
    printf '  4) bantime.increment 递增封禁          %s\n' "$CFG_INCREMENT"
    printf '  5) bantime.factor   递增系数           %s\n' "$CFG_FACTOR"
    printf '  6) bantime.maxtime  封禁时长上限       %s\n' "$CFG_MAXTIME"
    printf '  7) mode             sshd 过滤模式      %s\n' "$CFG_MODE"
    echo
    printf '  封禁阶梯预览: %s\n' "$(show_ladder)"
    echo
    if [ "$dirty" = 1 ]; then
      echo "  s) 保存并应用    q) 放弃修改并返回"
    else
      echo "  0) 返回"
    fi
    ask "请选择" "" || return 0
    case "$REPLY" in
      1)
        ask "bantime（如 1h / 1d / 1w，-1 为永久）" "$CFG_BANTIME" || continue
        if [ "$REPLY" = "-1" ] || valid_time "$REPLY"; then CFG_BANTIME=$REPLY; dirty=1
        else err "格式不对。"; fi
        ;;
      2)
        ask "findtime（如 10m / 15m / 1h）" "$CFG_FINDTIME" || continue
        if valid_time "$REPLY"; then CFG_FINDTIME=$REPLY; dirty=1; else err "格式不对。"; fi
        ;;
      3)
        ask "maxretry（正整数）" "$CFG_MAXRETRY" || continue
        if [[ $REPLY =~ ^[1-9][0-9]*$ ]]; then CFG_MAXRETRY=$REPLY; dirty=1; else err "需要正整数。"; fi
        ;;
      4)
        if ! ver_ge "${ver:-0.0}" 0.11; then
          err "fail2ban ${ver:-?} 低于 0.11，不支持递增封禁。"
          continue
        fi
        if [ "$CFG_INCREMENT" = true ]; then CFG_INCREMENT=false; else CFG_INCREMENT=true; fi
        dirty=1
        ;;
      5)
        echo "  说明：默认公式本身每次翻倍，factor 是额外乘数。"
        echo "        factor=1 → 1 倍、2 倍、4 倍、8 倍...；factor=2 → 1 倍、4 倍、8 倍、16 倍..."
        ask "bantime.factor（正数）" "$CFG_FACTOR" || continue
        if [[ $REPLY =~ ^[0-9]+(\.[0-9]+)?$ ]] && awk -v f="$REPLY" 'BEGIN { exit !(f > 0) }'; then
          CFG_FACTOR=$REPLY; dirty=1
        else err "需要大于 0 的数字。"; fi
        ;;
      6)
        ask "bantime.maxtime（如 1w / 4w）" "$CFG_MAXTIME" || continue
        if valid_time "$REPLY"; then CFG_MAXTIME=$REPLY; dirty=1; else err "格式不对。"; fi
        ;;
      7)
        echo "  normal     只匹配明确的认证失败（默认）"
        echo "  ddos       额外匹配预认证阶段的异常断开 / 扫描"
        echo "  extra      额外匹配算法协商失败等少见情况"
        echo "  aggressive 以上全部（抓得最多，误伤风险略高）"
        ask "mode" "$CFG_MODE" || continue
        case "$REPLY" in
          normal|ddos|extra|aggressive) CFG_MODE=$REPLY; dirty=1 ;;
          *) err "只能是 normal / ddos / extra / aggressive。" ;;
        esac
        ;;
      s|S)
        [ "$dirty" = 1 ] || continue
        if ! params_consistent; then continue; fi
        apply_config && dirty=0
        return 0
        ;;
      q|Q) info "已放弃修改。"; return 0 ;;
      0|"")
        if [ "$dirty" = 1 ]; then
          if confirm "有未保存的修改，保存并应用？" y; then
            if ! params_consistent; then continue; fi
            apply_config
          fi
        fi
        return 0
        ;;
      *) warn "无效选项。" ;;
    esac
  done
}

# ---------------------------------------------------------------- SSH 端口重新识别

menu_port() {
  need_managed || return 1
  load_config
  local detected
  detected=$(detect_ssh_ports)
  echo "  配置中的端口: $CFG_PORT"
  echo "  检测到的端口: ${detected:-（未检测到）}"
  ask "要写入的端口（多个用逗号分隔）" "${detected:-$CFG_PORT}" || return 0
  if ! valid_ports "$REPLY"; then
    err "端口格式不对，例如: 22 或 22,2222"
    return 1
  fi
  if [ "$REPLY" = "$CFG_PORT" ]; then
    ok "端口没有变化，无需修改。"
    return 0
  fi
  CFG_PORT=$REPLY
  apply_config
}

# ---------------------------------------------------------------- 日志

log_recent_bans() {
  if [ -s "$F2B_LOG" ]; then
    grep -E '\] (Ban|Unban|Restore Ban|Increase Ban) ' "$F2B_LOG" | tail -n 30
  else
    journalctl -u fail2ban --no-pager -n 500 2>/dev/null |
      grep -E '\] (Ban|Unban|Restore Ban|Increase Ban) ' | tail -n 30
  fi
}

log_follow() {
  info "实时日志，按 Ctrl+C 返回菜单。"
  trap ':' INT
  if [ -f "$F2B_LOG" ]; then
    tail -n 20 -f "$F2B_LOG"
  else
    journalctl -u fail2ban -n 20 -f
  fi
  trap - INT
  echo
}

ssh_fail_top() {
  local src="" f
  if command -v journalctl >/dev/null 2>&1; then
    src=$(journalctl _COMM=sshd _COMM=sshd-session --since "24 hours ago" --no-pager -o cat 2>/dev/null)
  fi
  if [ -z "$src" ]; then
    for f in /var/log/auth.log /var/log/secure; do
      [ -r "$f" ] && src=$(tail -n 50000 "$f" | grep -E 'sshd(-session)?\[')
      [ -n "$src" ] && break
    done
  fi
  printf '%s\n' "$src" |
    grep -E 'Failed password|Invalid user|authentication failure|maximum authentication attempts|Connection closed by (authenticating|invalid) user' |
    grep -oE '(from |rhost=)[0-9a-fA-F:.]+' |
    sed -E 's/^(from |rhost=)//' |
    sort | uniq -c | sort -rn | head -n 10
}

menu_logs() {
  local out
  while true; do
    echo
    echo "${BOLD}== 日志 ==${NC}"
    echo "  1) 最近的封禁 / 解封记录"
    echo "  2) 实时跟踪 fail2ban 日志"
    echo "  3) 最近 24 小时 SSH 失败登录来源 Top 10"
    echo "  0) 返回"
    ask "请选择" "" || return 0
    case "$REPLY" in
      1)
        out=$(log_recent_bans)
        if [ -n "$out" ]; then printf '%s\n' "$out"; else info "还没有封禁记录。"; fi
        ;;
      2) log_follow ;;
      3)
        out=$(ssh_fail_top)
        if [ -n "$out" ]; then
          echo "  失败日志条数  来源 IP"
          printf '%s\n' "$out"
        else
          info "最近 24 小时没有 SSH 失败登录记录。"
        fi
        ;;
      0|"") return 0 ;;
      *) warn "无效选项。" ;;
    esac
  done
}

# ---------------------------------------------------------------- 服务管理 / 卸载

menu_service() {
  need_f2b || return 1
  while true; do
    echo
    echo "${BOLD}== 服务管理 ==${NC}  当前: $(svc_state)  开机自启: $(enabled_state)"
    echo "  1) 启动    2) 停止    3) 重启"
    echo "  4) 开启开机自启    5) 关闭开机自启"
    echo "  0) 返回"
    ask "请选择" "" || return 0
    case "$REPLY" in
      1) systemctl start fail2ban && ok "已启动。" ;;
      2) systemctl stop fail2ban && ok "已停止（停止期间所有封禁规则会被撤掉，启动后恢复）。" ;;
      3) systemctl restart fail2ban && ok "已重启。" ;;
      4) systemctl enable fail2ban >/dev/null 2>&1 && ok "已开启开机自启。" ;;
      5) systemctl disable fail2ban >/dev/null 2>&1 && ok "已关闭开机自启。" ;;
      0|"") return 0 ;;
      *) warn "无效选项。" ;;
    esac
  done
}

do_uninstall() {
  require_root
  detect_os
  local msb=0 mine=0 latest=""
  has_msboost && msb=1
  if is_managed || { [ -f "$F2B_LOCAL" ] && grep -qF "$MARKER" "$F2B_LOCAL"; }; then mine=1; fi
  echo "${BOLD}== 卸载 ==${NC}"
  if [ "$msb" = 1 ]; then
    if [ "$mine" != 1 ]; then
      info "这台服务器的 fail2ban 由 MSBOOST 管理，没有本脚本生成的配置，不需要卸载。"
      echo "  要彻底去掉 fail2ban，请自行卸载软件包；MSBOOST 下次升级节点时会重新安装。"
      return 0
    fi
    echo "  将移除本脚本生成的配置。这台服务器还有 MSBOOST 的 fail2ban 配置（$MSB_JAIL），"
    echo "  移除后 fail2ban 不停，改回按 MSBOOST 的配置保护 SSH，软件包保留。"
  else
    echo "  将停止 fail2ban、关闭开机自启，并移除本脚本生成的配置。"
  fi
  if [ "$ASSUME_YES" != 1 ]; then
    confirm "确定继续？" n || { info "已取消。"; return 0; }
  fi

  if [ "$msb" != 1 ] && command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now fail2ban >/dev/null 2>&1 && ok "已停止 fail2ban 并关闭开机自启。"
  fi

  if is_managed; then
    rm -f "$JAIL_LOCAL" "$JAIL_LOCAL.prev"
    ok "已删除 $JAIL_LOCAL"
    latest=$(ls -1t "$JAIL_LOCAL".bak.* 2>/dev/null | head -n1)
    if [ -n "$latest" ]; then
      cp -p "$latest" "$JAIL_LOCAL" && ok "已恢复部署前的配置: $latest"
    fi
  elif [ -f "$JAIL_LOCAL" ]; then
    warn "$JAIL_LOCAL 不是本脚本生成的，保持不动。"
  fi
  if [ -f "$F2B_LOCAL" ] && grep -qF "$MARKER" "$F2B_LOCAL"; then
    rm -f "$F2B_LOCAL"
    ok "已删除 $F2B_LOCAL"
  fi

  # 交还给 MSBOOST：服务不停，重启后按 MSBOOST 的配置运行
  if [ "$msb" = 1 ]; then
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
      if systemctl restart fail2ban 2>/dev/null && wait_jail; then
        ok "fail2ban 已改回按 MSBOOST 的配置运行。"
      else
        err "fail2ban 没能按 MSBOOST 的配置启动，请查看: journalctl -u fail2ban"
        show_failure_logs
      fi
    else
      info "fail2ban 当前没有运行，下次启动时按 MSBOOST 的配置。"
    fi
    if [ -e "$JAIL_LOCAL" ]; then
      info "$JAIL_LOCAL 是部署前就有的配置，MSBOOST 仍会把这台服务器当作已有配置，不会更新白名单。"
    else
      info "在 MSBOOST 网站或本地版上「升级节点」一次，MSBOOST 会按当前执行机刷新白名单。"
    fi
    ok "卸载流程结束。"
    return 0
  fi

  if command -v fail2ban-client >/dev/null 2>&1 && [ "$ASSUME_YES" != 1 ]; then
    if confirm "同时卸载 fail2ban 软件包？（nftables 等依赖保留）" n; then
      case "$PKG" in
        apt) DEBIAN_FRONTEND=noninteractive apt-get purge -y fail2ban ;;
        dnf|yum) "$PKG" remove -y 'fail2ban*' ;;
        *) warn "未知的包管理器，请手动卸载。" ;;
      esac
    fi
  fi
  if is_msboost_node && [ ! -e "$JAIL_LOCAL" ]; then
    info "这是 MSBOOST 节点：在 MSBOOST 网站或本地版上「升级节点」一次，MSBOOST 会重新配置 fail2ban。"
  fi
  ok "卸载流程结束。"
}

# ---------------------------------------------------------------- 主菜单

menu_header() {
  local state="${YELLOW}未安装${NC}" extra="" src
  if command -v fail2ban-client >/dev/null 2>&1; then
    state=$(svc_state)
    if fail2ban-client ping >/dev/null 2>&1; then
      extra="  当前封禁: $(banned_count || true) 个"
    fi
  fi
  case "$(config_source)" in
    script)
      src="本脚本"
      has_msboost && src="本脚本（已接管 MSBOOST）"
      ;;
    msboost) src="MSBOOST" ;;
    foreign) src="其他（jail.local 不是本脚本生成的）" ;;
    *)       src="未配置" ;;
  esac
  echo
  echo "${BOLD}=========== fail2ban 管理脚本 v${SCRIPT_VERSION} ===========${NC}"
  echo "  状态: ${state}${extra}"
  echo "  配置: ${src}"
  echo "-----------------------------------------------"
  echo "   1) 一键部署（安装 + 配置 + 启动）"
  echo "   2) 查看状态 / 封禁列表"
  echo "   3) 解封 IP"
  echo "   4) 手动封禁 IP"
  echo "   5) 白名单管理"
  echo "   6) 修改参数"
  echo "   7) 重新识别 SSH 端口"
  echo "   8) 日志"
  echo "   9) 服务管理"
  echo "  10) 卸载"
  echo "   0) 退出"
  echo "-----------------------------------------------"
}

menu() {
  if [ -z "$INPUT" ]; then
    err "没有可用的交互终端。请直接使用子命令，例如: bash $0 install -y"
    exit 1
  fi
  while true; do
    menu_header
    ask "请选择 [0-10]" "" || exit 0
    case "$REPLY" in
      1)  do_install;     pause ;;
      2)  do_status;      pause ;;
      3)  menu_unban;     pause ;;
      4)  menu_ban;       pause ;;
      5)  menu_whitelist ;;
      6)  menu_params ;;
      7)  menu_port;      pause ;;
      8)  menu_logs ;;
      9)  menu_service ;;
      10) do_uninstall;   pause ;;
      0|q|Q) exit 0 ;;
      "") ;;
      *)  warn "无效选项: $REPLY" ;;
    esac
  done
}

usage() {
  cat <<EOF
fail2ban 一键部署 / 管理脚本 v${SCRIPT_VERSION}

用法:
  bash $0                    进入交互菜单
  bash $0 install [-y]       一键部署（-y: 不提问，全部使用默认值）
  bash $0 status             查看状态和封禁列表
  bash $0 unban <IP>|--all   解封
  bash $0 ban <IP>           手动封禁
  bash $0 ports              显示检测到的 SSH 端口
  bash $0 uninstall [-y]     卸载
EOF
}

main() {
  local args=() a
  for a in "$@"; do
    case "$a" in
      -y|--yes) ASSUME_YES=1 ;;
      -h|--help) usage; exit 0 ;;
      -V|--version) echo "$SCRIPT_VERSION"; exit 0 ;;
      *) args+=("$a") ;;
    esac
  done
  init_input
  reset_defaults

  local cmd=${args[0]:-}
  case "$cmd" in
    "")        require_root; menu ;;
    install)   do_install ;;
    status)    require_root; do_status ;;
    unban)     require_root; do_unban "${args[1]:-}" ;;
    ban)       require_root; do_ban "${args[1]:-}" ;;
    ports)     detect_ssh_ports ;;
    uninstall) do_uninstall ;;
    *) err "未知命令: $cmd"; usage; exit 1 ;;
  esac
}

# 被 source 时不执行（方便测试）；直接运行或 curl | bash 时执行
if [ -z "${BASH_SOURCE[0]:-}" ] || [ "${BASH_SOURCE[0]}" = "$0" ]; then
  main "$@"
fi
