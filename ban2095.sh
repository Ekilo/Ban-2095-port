#!/usr/bin/env bash
set -Eeuo pipefail

# =========================
# 配置区（按需修改）
# =========================
PORT="2095"

# SSH 端口保护，避免误锁自己
SSH_PORT="${SSH_PORT:-22}"

# 是否处理 IPv6：1=处理，0=跳过
ENABLE_IPV6="${ENABLE_IPV6:-1}"

# 允许访问 2095 的 IPv4 内网网段
ALLOW_V4=(
  "127.0.0.0/8"
  "10.0.0.0/8"
  "172.16.0.0/12"
  "192.168.0.0/16"
)

# 允许访问 2095 的 IPv6 内网/本地网段
# ::1 回环
# fc00::/7 ULA（私有 IPv6）
# fe80::/10 链路本地
ALLOW_V6=(
  "::1/128"
  "fc00::/7"
  "fe80::/10"
)

# 自定义链名称
CHAIN_V4="PORT_${PORT}_FILTER"
CHAIN_V6="PORT_${PORT}_FILTER_V6"

# 备份目录
BACKUP_DIR="/root/fw-backup-${PORT}-$(date +%F_%H%M%S)"

# =========================
# 基础函数
# =========================
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

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "缺少命令: $1"
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

append_unique_v4() {
  local table_args=("$@")
  if ! ipt_has_rule "${table_args[@]}"; then
    iptables -A "${table_args[@]}"
  fi
}

append_unique_v6() {
  local table_args=("$@")
  if ! ip6t_has_rule "${table_args[@]}"; then
    ip6tables -A "${table_args[@]}"
  fi
}

insert_unique_input_jump_v4() {
  if ! ipt_has_rule INPUT -p tcp --dport "$PORT" -j "$CHAIN_V4"; then
    iptables -I INPUT 1 -p tcp --dport "$PORT" -j "$CHAIN_V4"
  fi
}

insert_unique_input_jump_v6() {
  if ! ip6t_has_rule INPUT -p tcp --dport "$PORT" -j "$CHAIN_V6"; then
    ip6tables -I INPUT 1 -p tcp --dport "$PORT" -j "$CHAIN_V6"
  fi
}

save_rules() {
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

backup_current_rules() {
  mkdir -p "$BACKUP_DIR"
  iptables-save > "${BACKUP_DIR}/rules.v4.before"
  ip6tables-save > "${BACKUP_DIR}/rules.v6.before" || true

  cat > "${BACKUP_DIR}/restore.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
iptables-restore < "${DIR}/rules.v4.before"
if command -v ip6tables-restore >/dev/null 2>&1 && [ -s "${DIR}/rules.v6.before" ]; then
  ip6tables-restore < "${DIR}/rules.v6.before"
fi
iptables-save > /etc/iptables/rules.v4
if command -v ip6tables-save >/dev/null 2>&1; then
  ip6tables-save > /etc/iptables/rules.v6 || true
fi
systemctl restart netfilter-persistent || true
echo "[OK] 已回滚到执行前规则"
EOF
  chmod 700 "${BACKUP_DIR}/restore.sh"
}

install_packages() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y iptables iptables-persistent netfilter-persistent
}

protect_basic_access() {
  # 放行回环
  if ! ipt_has_rule INPUT -i lo -j ACCEPT; then
    iptables -I INPUT 1 -i lo -j ACCEPT
  fi

  # 放行已建立连接，避免影响现有会话
  if ! ipt_has_rule INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; then
    iptables -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  fi

  # 保护 SSH
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

apply_port_rules_v4() {
  ensure_chain_v4

  # 清空自定义链后重建，保证内容一致
  iptables -F "$CHAIN_V4"

  # 允许内网访问指定端口
  for net in "${ALLOW_V4[@]}"; do
    iptables -A "$CHAIN_V4" -p tcp -s "$net" --dport "$PORT" -j ACCEPT
  done

  # 拒绝其他 IPv4 来源访问该端口
  iptables -A "$CHAIN_V4" -p tcp --dport "$PORT" -j DROP

  # 将该端口流量引入自定义链
  insert_unique_input_jump_v4
}

apply_port_rules_v6() {
  [[ "$ENABLE_IPV6" == "1" ]] || return 0

  ensure_chain_v6
  ip6tables -F "$CHAIN_V6"

  for net in "${ALLOW_V6[@]}"; do
    ip6tables -A "$CHAIN_V6" -p tcp -s "$net" --dport "$PORT" -j ACCEPT
  done

  # 拒绝其他 IPv6 来源访问该端口
  ip6tables -A "$CHAIN_V6" -p tcp --dport "$PORT" -j DROP

  insert_unique_input_jump_v6
}

show_result() {
  echo
  echo "========== IPv4 规则 =========="
  iptables -S INPUT | grep -- "--dport ${PORT}" || true
  iptables -S "$CHAIN_V4" || true

  if [[ "$ENABLE_IPV6" == "1" ]]; then
    echo
    echo "========== IPv6 规则 =========="
    ip6tables -S INPUT | grep -- "--dport ${PORT}" || true
    ip6tables -S "$CHAIN_V6" || true
  fi

  echo
  echo "========== 持久化状态 =========="
  systemctl is-enabled netfilter-persistent || true
  systemctl --no-pager --full status netfilter-persistent | sed -n '1,12p' || true

  echo
  echo "[OK] 配置完成"
  echo "[OK] 备份目录: ${BACKUP_DIR}"
  echo "[OK] 回滚脚本: ${BACKUP_DIR}/restore.sh"
  echo
  echo "建议验证："
  echo "1. 内网主机访问 ${PORT} 应成功"
  echo "2. 外网主机访问 ${PORT} 应失败"
  echo "3. 本机执行: ss -lntp | grep :${PORT}"
}

main() {
  [[ "${EUID}" -eq 0 ]] || die "请用 root 执行"
  need_cmd apt-get
  need_cmd systemctl

  log "备份当前防火墙规则"
  backup_current_rules

  log "安装 iptables / iptables-persistent / netfilter-persistent"
  install_packages

  need_cmd iptables
  need_cmd iptables-save
  need_cmd iptables-restore
  need_cmd netfilter-persistent

  if [[ "$ENABLE_IPV6" == "1" ]]; then
    need_cmd ip6tables
    need_cmd ip6tables-save
    need_cmd ip6tables-restore
  fi

  log "保护基础连接（lo / 已建立连接 / SSH）"
  protect_basic_access

  log "应用 IPv4 规则"
  apply_port_rules_v4

  if [[ "$ENABLE_IPV6" == "1" ]]; then
    log "应用 IPv6 规则"
    apply_port_rules_v6
  fi

  log "保存并启用持久化"
  save_rules

  show_result
}

main "$@"
