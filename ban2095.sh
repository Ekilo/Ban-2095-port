#!/usr/bin/env bash
set -Eeuo pipefail

PORT="2095"
SSH_PORT="${SSH_PORT:-22}"
ENABLE_IPV6="${ENABLE_IPV6:-1}"

ALLOW_V4=(
  "127.0.0.0/8"
  "10.0.0.0/8"
  "172.16.0.0/12"
  "192.168.0.0/16"
)

ALLOW_V6=(
  "::1/128"
  "fc00::/7"
  "fe80::/10"
)

CHAIN_V4="PORT_${PORT}_FILTER"
CHAIN_V6="PORT_${PORT}_FILTER_V6"
BACKUP_DIR="/root/fw-backup-${PORT}-$(date +%F_%H%M%S)"

log() {
  echo "[INFO] $*"
}

warn() {
  echo "[WARN] $*" >&2
}

die() {
  echo "[ERROR] $*" >&2
  exit 1
}

need_root() {
  [[ "${EUID}" -eq 0 ]] || die "请使用 root 或 sudo 执行此脚本"
}

need_apt() {
  command -v apt-get >/dev/null 2>&1 || die "未检测到 apt-get，本脚本仅适用于 Debian/Ubuntu 系"
  command -v dpkg >/dev/null 2>&1 || die "未检测到 dpkg，当前系统不适合使用此脚本"
}

is_container_like() {
  if grep -qaE 'docker|lxc|containerd|kubepods' /proc/1/cgroup 2>/dev/null; then
    return 0
  fi
  [[ -f /.dockerenv ]] && return 0
  return 1
}

install_packages() {
  export DEBIAN_FRONTEND=noninteractive

  local need_update=0

  if ! command -v iptables >/dev/null 2>&1; then
    need_update=1
  fi

  if ! dpkg -s iptables-persistent >/dev/null 2>&1; then
    need_update=1
  fi

  if ! dpkg -s netfilter-persistent >/dev/null 2>&1; then
    need_update=1
  fi

  if [[ "$need_update" -eq 1 ]]; then
    log "开始更新软件源"
    apt-get update -y
  else
    log "所需软件包已存在，跳过 apt-get update"
  fi

  if ! command -v iptables >/dev/null 2>&1; then
    log "安装 iptables"
    apt-get install -y iptables
  else
    log "iptables 已安装，跳过"
  fi

  if ! dpkg -s iptables-persistent >/dev/null 2>&1 || ! dpkg -s netfilter-persistent >/dev/null 2>&1; then
    log "安装 iptables-persistent / netfilter-persistent"
    apt-get install -y iptables-persistent netfilter-persistent
  else
    log "iptables-persistent 和 netfilter-persistent 已安装，跳过"
  fi

  command -v iptables >/dev/null 2>&1 || die "iptables 安装失败"
  command -v iptables-save >/dev/null 2>&1 || die "iptables-save 不可用"
  command -v iptables-restore >/dev/null 2>&1 || die "iptables-restore 不可用"
  command -v netfilter-persistent >/dev/null 2>&1 || die "netfilter-persistent 安装失败"

  if [[ "$ENABLE_IPV6" == "1" ]]; then
    command -v ip6tables >/dev/null 2>&1 || die "ip6tables 不可用，请检查安装"
    command -v ip6tables-save >/dev/null 2>&1 || die "ip6tables-save 不可用"
    command -v ip6tables-restore >/dev/null 2>&1 || die "ip6tables-restore 不可用"
  fi
}

check_kernel_capability() {
  if ! iptables -L >/dev/null 2>&1; then
    die "当前环境无法操作 iptables。可能是容器环境未授予 NET_ADMIN 权限，或内核模块不可用"
  fi

  if [[ "$ENABLE_IPV6" == "1" ]]; then
    if ! ip6tables -L >/dev/null 2>&1; then
      warn "当前环境无法操作 ip6tables，自动关闭 IPv6 防火墙配置"
      ENABLE_IPV6="0"
    fi
  fi
}

backup_current_rules() {
  mkdir -p "$BACKUP_DIR"
  iptables-save > "${BACKUP_DIR}/rules.v4.before"

  if command -v ip6tables-save >/dev/null 2>&1; then
    ip6tables-save > "${BACKUP_DIR}/rules.v6.before" 2>/dev/null || true
  fi

  cat > "${BACKUP_DIR}/restore.sh" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"

if [[ -f "${DIR}/rules.v4.before" ]]; then
  iptables-restore < "${DIR}/rules.v4.before"
fi

if command -v ip6tables-restore >/dev/null 2>&1 && [[ -f "${DIR}/rules.v6.before" ]]; then
  ip6tables-restore < "${DIR}/rules.v6.before" || true
fi

mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4

if command -v ip6tables-save >/dev/null 2>&1; then
  ip6tables-save > /etc/iptables/rules.v6 || true
fi

systemctl restart netfilter-persistent || true
echo "[OK] 已回滚到执行前的防火墙规则"
EOF

  chmod 700 "${BACKUP_DIR}/restore.sh"
  log "已备份当前规则到 ${BACKUP_DIR}"
}

ipt_has_rule() {
  iptables -C "$@" >/dev/null 2>&1
}

ip6t_has_rule() {
  ip6tables -C "$@" >/dev/null 2>&1
}

ensure_chain_v4() {
  if ! iptables -nL "$CHAIN_V4" >/dev/null 2>&1; then
    iptables -N "$CHAIN_V4"
  fi
}

ensure_chain_v6() {
  if ! ip6tables -nL "$CHAIN_V6" >/dev/null 2>&1; then
    ip6tables -N "$CHAIN_V6"
  fi
}

insert_jump_v4() {
  if ! ipt_has_rule INPUT -p tcp --dport "$PORT" -j "$CHAIN_V4"; then
    iptables -I INPUT 1 -p tcp --dport "$PORT" -j "$CHAIN_V4"
  fi
}

insert_jump_v6() {
  if ! ip6t_has_rule INPUT -p tcp --dport "$PORT" -j "$CHAIN_V6"; then
    ip6tables -I INPUT 1 -p tcp --dport "$PORT" -j "$CHAIN_V6"
  fi
}

protect_base_rules() {
  if ! ipt_has_rule INPUT -i lo -j ACCEPT; then
    iptables -I INPUT 1 -i lo -j ACCEPT
  fi

  if ! ipt_has_rule INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; then
    iptables -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  fi

  if ! ipt_has_rule INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT; then
    iptables -I INPUT 1 -p tcp --dport "$SSH_PORT" -j ACCEPT
  fi

  if [[ "$ENABLE_IPV6" == "1" ]]; then
    if ! ip6t_has_rule INPUT -i lo -j ACCEPT; then
      ip6tables -I INPUT 1 -i lo -j ACCEPT
    fi

    if ! ip6t_has_rule INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; then
      ip6tables -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    fi

    if ! ip6t_has_rule INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT; then
      ip6tables -I INPUT 1 -p tcp --dport "$SSH_PORT" -j ACCEPT
    fi
  fi
}

apply_v4_rules() {
  ensure_chain_v4
  iptables -F "$CHAIN_V4"

  for net in "${ALLOW_V4[@]}"; do
    iptables -A "$CHAIN_V4" -p tcp -s "$net" --dport "$PORT" -j ACCEPT
  done

  iptables -A "$CHAIN_V4" -p tcp --dport "$PORT" -j DROP
  insert_jump_v4
}

apply_v6_rules() {
  [[ "$ENABLE_IPV6" == "1" ]] || return 0

  ensure_chain_v6
  ip6tables -F "$CHAIN_V6"

  for net in "${ALLOW_V6[@]}"; do
    ip6tables -A "$CHAIN_V6" -p tcp -s "$net" --dport "$PORT" -j ACCEPT
  done

  ip6tables -A "$CHAIN_V6" -p tcp --dport "$PORT" -j DROP
  insert_jump_v6
}

save_persistent_rules() {
  mkdir -p /etc/iptables
  iptables-save > /etc/iptables/rules.v4

  if [[ "$ENABLE_IPV6" == "1" ]]; then
    ip6tables-save > /etc/iptables/rules.v6
  else
    : > /etc/iptables/rules.v6
  fi

  systemctl enable netfilter-persistent >/dev/null 2>&1 || true
  systemctl restart netfilter-persistent
}

show_rules() {
  echo
  echo "========== IPv4 =========="
  iptables -S INPUT | grep -- "--dport ${PORT}" || true
  iptables -S "$CHAIN_V4" || true

  if [[ "$ENABLE_IPV6" == "1" ]]; then
    echo
    echo "========== IPv6 =========="
    ip6tables -S INPUT | grep -- "--dport ${PORT}" || true
    ip6tables -S "$CHAIN_V6" || true
  fi

  echo
  echo "========== 持久化 =========="
  systemctl is-enabled netfilter-persistent || true
  systemctl --no-pager --full status netfilter-persistent | sed -n '1,12p' || true
}

show_usage_tip() {
  echo
  echo "[OK] 已完成配置"
  echo "[OK] 规则备份目录: ${BACKUP_DIR}"
  echo "[OK] 回滚脚本: ${BACKUP_DIR}/restore.sh"
  echo
  echo "验证命令："
  echo "  ss -lntp | grep :${PORT}"
  echo "  iptables -S INPUT | grep ${PORT}"
  echo "  iptables -S ${CHAIN_V4}"
  if [[ "$ENABLE_IPV6" == "1" ]]; then
    echo "  ip6tables -S INPUT | grep ${PORT}"
    echo "  ip6tables -S ${CHAIN_V6}"
  fi
  echo
  echo "内网访问 ${PORT} 应成功，外网访问 ${PORT} 应失败。"
  echo
  echo "如需回滚："
  echo "  ${BACKUP_DIR}/restore.sh"
}

main() {
  need_root
  need_apt

  if is_container_like; then
    warn "检测到可能是容器环境，若没有 NET_ADMIN 权限，iptables 可能无法生效"
  fi

  install_packages
  check_kernel_capability
  backup_current_rules

  log "添加基础保护规则"
  protect_base_rules

  log "配置 IPv4: 仅允许内网访问端口 ${PORT}"
  apply_v4_rules

  if [[ "$ENABLE_IPV6" == "1" ]]; then
    log "配置 IPv6: 仅允许内网访问端口 ${PORT}"
    apply_v6_rules
  else
    warn "已跳过 IPv6 规则配置"
  fi

  log "保存规则并启用开机持久化"
  save_persistent_rules

  show_rules
  show_usage_tip
}

main "$@"
