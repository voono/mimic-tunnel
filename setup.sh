#!/usr/bin/env bash
#
# mimic-tunnel.sh - install and manage a Mimic-based WireGuard-over-fake-TCP
# relay tunnel across two servers.
#
#   Server 1 = the box that actually runs WireGuard
#   Server 2 = the internal/domestic relay the game client connects to
#
# Run this SAME script on both servers; it will ask which role each one plays.
#
# Usage:
#   sudo ./mimic-tunnel.sh install            interactive install / reconfigure
#   sudo ./mimic-tunnel.sh uninstall [--purge]
#   sudo ./mimic-tunnel.sh start|stop|restart
#   sudo ./mimic-tunnel.sh status
#   sudo ./mimic-tunnel.sh stats
#
# After "install", this script copies itself to /usr/local/sbin/mimic-tunnel,
# so afterwards you can just run:  mimic-tunnel status
#
# Only tested on Debian 12/13 (bookworm/trixie) or Ubuntu 24.04 (noble),
# since that's what the official Mimic package supports.

set -euo pipefail

# ============================================================
# Constants
# ============================================================
INSTALL_PATH="/usr/local/sbin/mimic-tunnel"
STATE_DIR="/etc/mimic-tunnel"
STATE_FILE="${STATE_DIR}/config"
RULES_UNIT="/etc/systemd/system/mimic-tunnel-rules.service"
COMMENT_TAG="mimic-tunnel"

# ============================================================
# Small helpers
# ============================================================
c_red()    { printf '\033[31m%s\033[0m\n' "$*"; }
c_green()  { printf '\033[32m%s\033[0m\n' "$*"; }
c_yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
die() { c_red "Error: $*"; exit 1; }
need_root() { [[ $EUID -eq 0 ]] || die "This command must be run as root (sudo)."; }

# ask VAR "prompt text" [default]
# Always prompts interactively. If VAR is already set (e.g. from a previous
# install, or exported by the caller) that value is offered as the default.
ask() {
  local __var="$1" __prompt="$2" __default="${3:-}"
  local __current="${!__var:-}"
  local __def="${__current:-$__default}"
  local __input=""
  if [[ -n "$__def" ]]; then
    read -rp "$__prompt [$__def]: " __input
    __input="${__input:-$__def}"
  else
    while [[ -z "$__input" ]]; do
      read -rp "$__prompt: " __input
    done
  fi
  printf -v "$__var" '%s' "$__input"
}

is_valid_ipv4() {
  local ip="$1" o
  [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  for o in "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}" "${BASH_REMATCH[4]}"; do
    (( 10#$o <= 255 )) || return 1
  done
}

is_valid_port() {
  [[ "$1" =~ ^[0-9]{1,5}$ ]] || return 1
  (( 10#$1 >= 1 && 10#$1 <= 65535 ))
}

detect_iface() {
  ip route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+' | head -1 || true
}

# Tries several IP-echo services in turn (silently) so a single blocked/403'd
# provider doesn't break detection.
detect_public_ip() {
  local ip url
  for url in https://api.ipify.org https://ifconfig.me/ip https://icanhazip.com https://ipv4.icanhazip.com; do
    ip="$(curl -4 -fsS --max-time 5 "$url" 2>/dev/null | tr -d '[:space:]')" || true
    if is_valid_ipv4 "$ip"; then
      echo "$ip"
      return 0
    fi
  done
  return 1
}

load_state() {
  [[ -f "$STATE_FILE" ]] || die "Not installed yet (no $STATE_FILE). Run: $0 install"
  # shellcheck disable=SC1090
  . "$STATE_FILE"
}

# ============================================================
# iptables rule management (idempotent, tagged with a comment so it can be
# listed/removed cleanly regardless of exact IPs/ports used)
# ============================================================
_rule() {
  # _rule <table> <chain> <rule-spec> <add|remove>
  local table="$1" chain="$2" spec="$3" action="$4"
  local tbl_flag=()
  if [[ "$table" != "filter" ]]; then
    tbl_flag=(-t "$table")
  fi
  if [[ "$action" == "add" ]]; then
    # shellcheck disable=SC2086
    if ! iptables "${tbl_flag[@]}" -C "$chain" $spec 2>/dev/null; then
      # shellcheck disable=SC2086
      iptables "${tbl_flag[@]}" -A "$chain" $spec
    fi
  else
    # shellcheck disable=SC2086
    iptables "${tbl_flag[@]}" -D "$chain" $spec 2>/dev/null || true
  fi
}

apply_rules() {
  local action="$1"   # add | remove
  load_state
  if [[ "$ROLE" == "server1" ]]; then
    _rule nat    PREROUTING "-p udp -s $PEER_IP --dport $DISGUISE_PORT -m comment --comment $COMMENT_TAG -j REDIRECT --to-port $WG_PORT" "$action"
    _rule filter INPUT      "-p tcp -s $PEER_IP --dport $DISGUISE_PORT -m comment --comment $COMMENT_TAG -j ACCEPT" "$action"
    _rule filter INPUT      "-p udp -s $PEER_IP --dport $DISGUISE_PORT -m comment --comment $COMMENT_TAG -j ACCEPT" "$action"
  else
    _rule nat PREROUTING  "-p udp --dport $CLIENT_PORT -m comment --comment $COMMENT_TAG -j DNAT --to-destination ${PEER_IP}:${DISGUISE_PORT}" "$action"
    _rule nat POSTROUTING "-p udp -d $PEER_IP --dport $DISGUISE_PORT -m comment --comment $COMMENT_TAG -j MASQUERADE" "$action"
    _rule filter INPUT    "-p udp --dport $CLIENT_PORT -m comment --comment $COMMENT_TAG -j ACCEPT" "$action"
  fi
}

cmd_apply_rules() {
  need_root
  local action="${1:-}"
  [[ "$action" == "add" || "$action" == "remove" ]] || die "Usage: $0 apply-rules add|remove"
  apply_rules "$action"
}

# ============================================================
# Install helpers
# ============================================================
check_distro_and_kernel() {
  [[ -f /etc/os-release ]] || die "Could not find /etc/os-release."
  # shellcheck disable=SC1091
  . /etc/os-release
  CODENAME="${VERSION_CODENAME:-}"
  case "$CODENAME" in
    bookworm|trixie|noble) ;;
    *) die "Distro '$CODENAME' is not supported by the official Mimic package (only bookworm/trixie/noble). Build from source instead: https://github.com/hack3ric/mimic/blob/master/docs/building.md" ;;
  esac
  ARCH="$(dpkg --print-architecture)"

  KVER="$(uname -r)"
  local kmajor kminor
  kmajor="$(echo "$KVER" | cut -d. -f1)"
  kminor="$(echo "$KVER" | cut -d. -f2)"
  if (( kmajor < 6 || (kmajor == 6 && kminor < 1) )); then
    die "Kernel $KVER is older than 6.1; Mimic requires dynptrs (kernel >=6.1)."
  fi
}

install_prerequisites() {
  c_yellow "-> Installing prerequisites..."
  apt-get update -qq
  apt-get install -y -qq curl wget "linux-headers-${KVER}" iptables >/dev/null || \
    c_yellow "Warning: installing linux-headers-${KVER} failed; if the DKMS module fails to build, install matching kernel headers manually."
}

install_mimic_package() {
  if command -v mimic >/dev/null 2>&1; then
    c_green "-> Mimic is already installed, skipping download."
    return
  fi
  c_yellow "-> Fetching latest Mimic release for ${CODENAME}/${ARCH}..."
  local tmpdir api_json all_urls mimic_url dkms_url
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' RETURN

  api_json="$(curl -fsL https://api.github.com/repos/hack3ric/mimic/releases/latest 2>/dev/null)" || \
    die "Could not reach GitHub's API to fetch the latest Mimic release (it may be rate-limited - try again shortly)."
  all_urls="$(echo "$api_json" | grep -oE 'https://github\.com/hack3ric/mimic/releases/download/[^"]+\.deb' || true)"

  mimic_url="$(echo "$all_urls" | grep "${CODENAME}_mimic_" | grep -v dkms | grep "_${ARCH}\.deb" | head -1 || true)"
  dkms_url="$(echo "$all_urls"  | grep "${CODENAME}_mimic-dkms_"        | grep "_${ARCH}\.deb" | head -1 || true)"

  [[ -n "$mimic_url" && -n "$dkms_url" ]] || \
    die "Could not find a matching package for ${CODENAME}/${ARCH} in the latest release (GitHub's API may be rate-limited - try again in a bit). Check manually: https://github.com/hack3ric/mimic/releases"

  wget -q -P "$tmpdir" "$mimic_url" "$dkms_url"
  apt-get install -y -qq "$tmpdir"/*.deb
}

write_mimic_filter_config() {
  mkdir -p /etc/mimic
  if [[ "$ROLE" == "server1" ]]; then
    cat > "/etc/mimic/${IFACE}.conf" <<EOF
# managed by mimic-tunnel - do not edit by hand, re-run 'mimic-tunnel install' instead
filter = local=${PUBLIC_IP}:${DISGUISE_PORT}
EOF
  else
    cat > "/etc/mimic/${IFACE}.conf" <<EOF
# managed by mimic-tunnel - do not edit by hand, re-run 'mimic-tunnel install' instead
filter = remote=${PEER_IP}:${DISGUISE_PORT}
EOF
  fi
}

install_self() {
  local src
  src="$(readlink -f "${BASH_SOURCE[0]}")"
  if [[ "$src" != "$INSTALL_PATH" ]]; then
    install -m 0755 "$src" "$INSTALL_PATH"
    c_green "Installed this script to $INSTALL_PATH - from now on just run: mimic-tunnel <command>"
  fi
}

install_rules_service() {
  cat > "$RULES_UNIT" <<EOF
[Unit]
Description=mimic-tunnel iptables rules
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${INSTALL_PATH} apply-rules add
ExecStop=${INSTALL_PATH} apply-rules remove

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
}

# ============================================================
# Commands
# ============================================================
cmd_install() {
  need_root

  if [[ -f "$STATE_FILE" ]]; then
    c_yellow "Existing configuration found - current values are offered as defaults."
    # shellcheck disable=SC1090
    . "$STATE_FILE"
  fi

  echo "Which server is this?"
  echo "  1) Server 1 - runs WireGuard"
  echo "  2) Server 2 - internal relay (game client connects here over plain UDP)"
  local role_default="" choice
  case "${ROLE:-}" in
    server1) role_default=1 ;;
    server2) role_default=2 ;;
  esac
  if [[ -n "$role_default" ]]; then
    read -rp "Select [1/2] [$role_default]: " choice
    choice="${choice:-$role_default}"
  else
    read -rp "Select [1/2]: " choice
  fi
  case "$choice" in
    1) ROLE=server1 ;;
    2) ROLE=server2 ;;
    *) die "Invalid selection." ;;
  esac

  local detected_iface
  detected_iface="$(detect_iface)"
  ask IFACE "Network interface" "$detected_iface"

  ask DISGUISE_PORT "Port that should look like TCP on the wire" "${DISGUISE_PORT:-443}"
  while ! is_valid_port "$DISGUISE_PORT"; do
    c_yellow "That doesn't look like a valid port (1-65535)."
    unset DISGUISE_PORT; ask DISGUISE_PORT "Port that should look like TCP on the wire" "443"
  done

  if [[ "$ROLE" == "server1" ]]; then
    ask PEER_IP "Server 2 (relay) IP"
    while ! is_valid_ipv4 "$PEER_IP"; do
      c_yellow "That doesn't look like a valid IPv4 address."
      unset PEER_IP; ask PEER_IP "Server 2 (relay) IP"
    done

    ask WG_PORT "Real WireGuard port on this server" "${WG_PORT:-1080}"
    while ! is_valid_port "$WG_PORT"; do
      c_yellow "That doesn't look like a valid port (1-65535)."
      unset WG_PORT; ask WG_PORT "Real WireGuard port on this server" "1080"
    done

    local detected_public_ip
    detected_public_ip="$(detect_public_ip || true)"
    if [[ -z "$detected_public_ip" ]]; then
      c_yellow "Could not auto-detect this server's public IP (all lookup services failed or are blocked here) - enter it manually."
    fi
    ask PUBLIC_IP "This server's public IP" "${PUBLIC_IP:-$detected_public_ip}"
    while ! is_valid_ipv4 "$PUBLIC_IP"; do
      c_yellow "That doesn't look like a valid IPv4 address."
      unset PUBLIC_IP; ask PUBLIC_IP "This server's public IP"
    done
  else
    ask PEER_IP "Server 1 (WireGuard) public IP"
    while ! is_valid_ipv4 "$PEER_IP"; do
      c_yellow "That doesn't look like a valid IPv4 address."
      unset PEER_IP; ask PEER_IP "Server 1 (WireGuard) public IP"
    done

    ask CLIENT_PORT "Port the game client will connect to (UDP)" "${CLIENT_PORT:-1080}"
    while ! is_valid_port "$CLIENT_PORT"; do
      c_yellow "That doesn't look like a valid port (1-65535)."
      unset CLIENT_PORT; ask CLIENT_PORT "Port the game client will connect to (UDP)" "1080"
    done
  fi

  echo
  c_green "== Configuration summary =="
  echo "Role:          $ROLE"
  echo "Interface:     $IFACE"
  echo "Disguise port: $DISGUISE_PORT"
  if [[ "$ROLE" == "server1" ]]; then
    echo "Public IP:     $PUBLIC_IP"
    echo "WG port:       $WG_PORT"
    echo "Server 2 IP:   $PEER_IP"
  else
    echo "Server 1 IP:   $PEER_IP"
    echo "Client port:   $CLIENT_PORT"
  fi
  echo
  read -rp "Proceed with installation? [Y/n]: " confirm
  if [[ "${confirm,,}" == "n" ]]; then
    die "Aborted."
  fi

  check_distro_and_kernel
  install_prerequisites
  install_mimic_package
  modprobe mimic
  echo mimic > /etc/modules-load.d/mimic.conf

  mkdir -p "$STATE_DIR"
  {
    echo "ROLE=$ROLE"
    echo "IFACE=$IFACE"
    echo "DISGUISE_PORT=$DISGUISE_PORT"
    echo "PEER_IP=$PEER_IP"
    if [[ "$ROLE" == "server1" ]]; then
      echo "WG_PORT=$WG_PORT"
      echo "PUBLIC_IP=$PUBLIC_IP"
    else
      echo "CLIENT_PORT=$CLIENT_PORT"
    fi
  } > "$STATE_FILE"

  write_mimic_filter_config
  install_self
  install_rules_service
  apply_rules add
  systemctl enable --now mimic-tunnel-rules.service

  if [[ "$ROLE" == "server2" ]]; then
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    if grep -q '^net.ipv4.ip_forward' /etc/sysctl.conf 2>/dev/null; then
      sed -i 's/^net.ipv4.ip_forward.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf
    else
      echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi
  fi

  systemctl enable --now "mimic@${IFACE}"

  echo
  c_green "== Install complete =="
  echo "Manage it later with: mimic-tunnel status | stats | start | stop | restart | uninstall"
  if [[ "$ROLE" == "server1" ]]; then
    echo
    c_yellow "One manual step remains: lower WireGuard's MTU by 12 bytes."
    echo "In wg0.conf ([Interface] section), add or edit:"
    echo "    MTU = 1408"
    echo "Then: systemctl restart wg-quick@wg0"
  else
    echo
    echo "Point the client's WireGuard config at:"
    echo "    Endpoint = <this server's IP>:${CLIENT_PORT}"
  fi
}

cmd_uninstall() {
  need_root
  load_state

  local purge=0
  if [[ "${1:-}" == "--purge" ]]; then
    purge=1
  fi

  read -rp "This will remove the mimic-tunnel configuration on this server. Continue? [y/N]: " confirm
  [[ "${confirm,,}" == "y" ]] || die "Aborted."

  systemctl disable --now "mimic@${IFACE}" 2>/dev/null || true
  systemctl disable --now mimic-tunnel-rules.service 2>/dev/null || true
  rm -f "$RULES_UNIT"
  systemctl daemon-reload

  rm -f "/etc/mimic/${IFACE}.conf"
  rm -f "$STATE_FILE"
  rmdir "$STATE_DIR" 2>/dev/null || true

  if (( purge )); then
    c_yellow "-> Purging the mimic package and kernel module..."
    apt-get remove -y -qq mimic mimic-dkms >/dev/null 2>&1 || true
    rm -f /etc/modules-load.d/mimic.conf
    modprobe -r mimic 2>/dev/null || true
  fi

  c_green "== Uninstalled =="
  if (( ! purge )); then
    echo "Note: the mimic package itself was left installed. Use 'uninstall --purge' to remove it too."
  fi
}

cmd_start()   { need_root; load_state; systemctl start "mimic@${IFACE}"; c_green "Started."; }
cmd_stop()    { need_root; load_state; systemctl stop "mimic@${IFACE}"; c_yellow "Stopped (obfuscation is off; iptables rules are still in place)."; }
cmd_restart() { need_root; load_state; systemctl restart "mimic@${IFACE}"; c_green "Restarted."; }

cmd_status() {
  need_root
  load_state
  c_green "== mimic-tunnel status =="
  echo "Role:          $ROLE"
  echo "Interface:     $IFACE"
  echo "Disguise port: $DISGUISE_PORT"
  if [[ "$ROLE" == "server1" ]]; then
    echo "Public IP:     $PUBLIC_IP"
    echo "WG port:       $WG_PORT"
    echo "Peer (Server2):$PEER_IP"
  else
    echo "Peer (Server1):$PEER_IP"
    echo "Client port:   $CLIENT_PORT"
  fi
  echo
  echo "--- systemd: mimic@${IFACE} ---"
  systemctl --no-pager --full status "mimic@${IFACE}" || true
  echo
  echo "--- systemd: mimic-tunnel-rules ---"
  systemctl --no-pager --full status mimic-tunnel-rules.service || true
  echo
  echo "--- active Mimic connections ---"
  mimic show -c || true
  if [[ "$ROLE" == "server1" ]] && command -v wg >/dev/null 2>&1; then
    echo
    echo "--- WireGuard ---"
    wg show || true
  fi
}

cmd_stats() {
  need_root
  load_state
  c_green "== traffic counters for mimic-tunnel's iptables rules =="
  echo "--- nat table ---"
  iptables -t nat -L -n -v --line-numbers | grep -E "Chain|$COMMENT_TAG" || true
  echo
  echo "--- filter/INPUT ---"
  iptables -L INPUT -n -v --line-numbers | grep -E "Chain|$COMMENT_TAG" || true
  echo
  echo "--- active Mimic connections ---"
  mimic show -c || true
}

usage() {
  cat <<EOF
mimic-tunnel - install and manage a Mimic-based WireGuard-over-fake-TCP relay

Usage: $(basename "$0") <command>

Commands:
  install              Interactively install/reconfigure this server's side of the tunnel
  uninstall [--purge]  Remove the tunnel config (add --purge to also remove the mimic package)
  start                Start the obfuscation service
  stop                 Stop the obfuscation service (iptables rules stay in place)
  restart              Restart the obfuscation service
  status               Show service status, active connections, and current config
  stats                Show packet/byte counters for the tunnel's iptables rules
EOF
}

main() {
  local cmd="${1:-}"
  shift || true
  case "$cmd" in
    install)      cmd_install "$@" ;;
    uninstall)    cmd_uninstall "$@" ;;
    start)        cmd_start ;;
    stop)         cmd_stop ;;
    restart)      cmd_restart ;;
    status)       cmd_status ;;
    stats)        cmd_stats ;;
    apply-rules)  cmd_apply_rules "$@" ;;
    -h|--help|help|"") usage ;;
    *) c_red "Unknown command: $cmd"; usage; exit 1 ;;
  esac
}

main "$@"