#!/usr/bin/env bash
#
# mimic-tunnel.sh - install and manage one or more Mimic-based WireGuard-over-
# fake-TCP relay tunnels across two servers.
#
#   Server 1 = the box that actually runs WireGuard
#   Server 2 = the internal/domestic relay the game client connects to
#
# Run this SAME script on both servers; it will ask which role each one plays.
# A server pair can carry multiple independent tunnels (e.g. several
# WireGuard instances), each with its own disguise/client/WireGuard port,
# sharing the same network interface.
#
# Usage:
#   sudo ./mimic-tunnel.sh install                     one-time per-server setup (role/interface)
#   sudo ./mimic-tunnel.sh tunnel add [name]            add a new tunnel
#   sudo ./mimic-tunnel.sh tunnel edit <name>           reconfigure an existing tunnel
#   sudo ./mimic-tunnel.sh tunnel remove <name>         remove one tunnel
#   sudo ./mimic-tunnel.sh tunnel list                  list configured tunnels
#   sudo ./mimic-tunnel.sh uninstall [--purge]          remove everything on this server
#   sudo ./mimic-tunnel.sh start|stop|restart           control the Mimic service
#   sudo ./mimic-tunnel.sh status [name]
#   sudo ./mimic-tunnel.sh stats [name]
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
GLOBAL_FILE="${STATE_DIR}/config"
TUNNELS_DIR="${STATE_DIR}/tunnels"
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

is_valid_name() {
  [[ "$1" =~ ^[A-Za-z0-9_-]+$ ]]
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

# ============================================================
# Config: one global file (role/interface/public IP) plus one file per
# tunnel (peer IP/ports). Tunnels share the server's single interface, so
# they end up as multiple `filter =` lines in the same Mimic config file.
# ============================================================
load_global() {
  [[ -f "$GLOBAL_FILE" ]] || die "Not installed yet (no $GLOBAL_FILE). Run: mimic-tunnel install"
  # shellcheck disable=SC1090
  . "$GLOBAL_FILE"
}

write_global() {
  mkdir -p "$STATE_DIR"
  {
    echo "ROLE=$ROLE"
    echo "IFACE=$IFACE"
    [[ "$ROLE" == "server1" ]] && echo "PUBLIC_IP=$PUBLIC_IP"
  } > "$GLOBAL_FILE"
}

list_tunnel_names() {
  [[ -d "$TUNNELS_DIR" ]] || return 0
  local f
  for f in "$TUNNELS_DIR"/*.conf; do
    [[ -e "$f" ]] || continue
    basename "$f" .conf
  done | sort
}

tunnel_exists() { [[ -f "$TUNNELS_DIR/$1.conf" ]]; }

load_tunnel() {
  local f="$TUNNELS_DIR/$1.conf"
  [[ -f "$f" ]] || die "No such tunnel: $1 (see: mimic-tunnel tunnel list)"
  # shellcheck disable=SC1090
  . "$f"
}

write_tunnel() {
  local name="$1"
  mkdir -p "$TUNNELS_DIR"
  {
    echo "PEER_IP=$PEER_IP"
    echo "DISGUISE_PORT=$DISGUISE_PORT"
    if [[ "$ROLE" == "server1" ]]; then
      echo "WG_PORT=$WG_PORT"
    else
      echo "CLIENT_PORT=$CLIENT_PORT"
    fi
  } > "$TUNNELS_DIR/${name}.conf"
}

# value_used_by_other_tunnel FIELD VALUE EXCLUDE_NAME
# Prints the conflicting tunnel's name and returns 0 if some other tunnel
# already uses VALUE for FIELD (DISGUISE_PORT on server1, CLIENT_PORT on
# server2 - the ports Mimic/iptables use to tell tunnels apart).
value_used_by_other_tunnel() {
  local field="$1" value="$2" exclude="$3" n v
  for n in $(list_tunnel_names); do
    [[ "$n" == "$exclude" ]] && continue
    v="$(grep -E "^${field}=" "$TUNNELS_DIR/${n}.conf" 2>/dev/null | cut -d= -f2-)"
    if [[ "$v" == "$value" ]]; then
      echo "$n"
      return 0
    fi
  done
  return 1
}

# ============================================================
# iptables rule management (idempotent, tagged with a per-tunnel comment so
# rules can be listed/removed individually regardless of exact IPs/ports)
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

# tunnel_rules NAME ADD|REMOVE PEER_IP DISGUISE_PORT PORT
# PORT is WG_PORT on server1 or CLIENT_PORT on server2. Values are taken as
# explicit arguments (not read from globals) so callers can safely remove
# rules for OLD values while new ones are already sitting in the shell's
# PEER_IP/DISGUISE_PORT/... variables (e.g. during `tunnel edit`).
# Expects ROLE (global) to be loaded.
tunnel_rules() {
  local name="$1" action="$2" peer_ip="$3" disguise_port="$4" port="$5"
  local tag="${COMMENT_TAG}:${name}"
  if [[ "$ROLE" == "server1" ]]; then
    _rule nat    PREROUTING "-p udp -s $peer_ip --dport $disguise_port -m comment --comment $tag -j REDIRECT --to-port $port" "$action"
    _rule filter INPUT      "-p tcp -s $peer_ip --dport $disguise_port -m comment --comment $tag -j ACCEPT" "$action"
    _rule filter INPUT      "-p udp -s $peer_ip --dport $disguise_port -m comment --comment $tag -j ACCEPT" "$action"
  else
    _rule nat PREROUTING  "-p udp --dport $port -m comment --comment $tag -j DNAT --to-destination ${peer_ip}:${disguise_port}" "$action"
    _rule nat POSTROUTING "-p udp -d $peer_ip --dport $disguise_port -m comment --comment $tag -j MASQUERADE" "$action"
    _rule filter INPUT    "-p udp --dport $port -m comment --comment $tag -j ACCEPT" "$action"
  fi
}

# tunnel_port_var: name of the port variable that (together with PEER_IP and
# DISGUISE_PORT) uniquely identifies a tunnel's rules for the current ROLE.
tunnel_port_var() { [[ "$ROLE" == "server1" ]] && echo WG_PORT || echo CLIENT_PORT; }

apply_tunnel_from_disk() {
  local name="$1" action="$2" portvar port
  load_tunnel "$name"
  portvar="$(tunnel_port_var)"
  port="${!portvar}"
  tunnel_rules "$name" "$action" "$PEER_IP" "$DISGUISE_PORT" "$port"
}

cmd_apply_rules() {
  need_root
  local action="${1:-}"
  [[ "$action" == "add" || "$action" == "remove" ]] || die "Usage: $0 apply-rules add|remove [tunnel-name]"
  local name="${2:-}"
  load_global
  if [[ -n "$name" ]]; then
    apply_tunnel_from_disk "$name" "$action"
  else
    local n
    for n in $(list_tunnel_names); do
      apply_tunnel_from_disk "$n" "$action"
    done
  fi
}

# Rebuilds /etc/mimic/<iface>.conf from every configured tunnel. Mimic
# supports multiple `filter =` lines per interface (OR'ed), so all tunnels
# on this server share one Mimic instance.
regen_mimic_filter_config() {
  mkdir -p /etc/mimic
  local n
  {
    echo "# managed by mimic-tunnel - do not edit by hand, use 'mimic-tunnel tunnel add/edit/remove' instead"
    for n in $(list_tunnel_names); do
      load_tunnel "$n"
      if [[ "$ROLE" == "server1" ]]; then
        echo "filter = local=${PUBLIC_IP}:${DISGUISE_PORT}"
      else
        echo "filter = remote=${PEER_IP}:${DISGUISE_PORT}"
      fi
    done
  } > "/etc/mimic/${IFACE}.conf"
}

# ============================================================
# One-time migration from the old single-tunnel config layout, so updating
# the script in place doesn't break an existing install.
# ============================================================
migrate_legacy_config() {
  [[ $EUID -eq 0 ]] || return 0
  [[ -f "$GLOBAL_FILE" ]] || return 0
  grep -q '^DISGUISE_PORT=' "$GLOBAL_FILE" || return 0

  c_yellow "-> Migrating existing config to the multi-tunnel layout (as tunnel 'default')..."
  local ROLE IFACE PEER_IP DISGUISE_PORT WG_PORT CLIENT_PORT PUBLIC_IP
  # shellcheck disable=SC1090
  . "$GLOBAL_FILE"

  local old_tag="$COMMENT_TAG"
  if [[ "$ROLE" == "server1" ]]; then
    _rule nat    PREROUTING "-p udp -s $PEER_IP --dport $DISGUISE_PORT -m comment --comment $old_tag -j REDIRECT --to-port $WG_PORT" remove
    _rule filter INPUT      "-p tcp -s $PEER_IP --dport $DISGUISE_PORT -m comment --comment $old_tag -j ACCEPT" remove
    _rule filter INPUT      "-p udp -s $PEER_IP --dport $DISGUISE_PORT -m comment --comment $old_tag -j ACCEPT" remove
  else
    _rule nat PREROUTING  "-p udp --dport $CLIENT_PORT -m comment --comment $old_tag -j DNAT --to-destination ${PEER_IP}:${DISGUISE_PORT}" remove
    _rule nat POSTROUTING "-p udp -d $PEER_IP --dport $DISGUISE_PORT -m comment --comment $old_tag -j MASQUERADE" remove
    _rule filter INPUT    "-p udp --dport $CLIENT_PORT -m comment --comment $old_tag -j ACCEPT" remove
  fi

  write_tunnel "default"
  write_global
  local portvar port
  portvar="$(tunnel_port_var)"
  port="${!portvar}"
  tunnel_rules "default" add "$PEER_IP" "$DISGUISE_PORT" "$port"
  regen_mimic_filter_config
  systemctl restart "mimic@${IFACE}" 2>/dev/null || true
  c_green "-> Migration complete. Manage this tunnel as 'default', or rename it by adding a new one and removing this."
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
# Commands: global per-server setup
# ============================================================
cmd_install() {
  need_root

  if [[ -f "$GLOBAL_FILE" ]]; then
    c_yellow "Existing configuration found - current values are offered as defaults."
    load_global
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

  if [[ "$ROLE" == "server1" ]]; then
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
  fi

  echo
  c_green "== Configuration summary =="
  echo "Role:          $ROLE"
  echo "Interface:     $IFACE"
  [[ "$ROLE" == "server1" ]] && echo "Public IP:     $PUBLIC_IP"
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

  write_global
  mkdir -p "$TUNNELS_DIR"
  regen_mimic_filter_config
  install_self
  install_rules_service
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
  c_green "== Base install complete =="
  echo "Manage it later with: mimic-tunnel status | stats | start | stop | restart | uninstall"

  if [[ -z "$(list_tunnel_names)" ]]; then
    echo
    read -rp "No tunnels configured yet. Add one now? [Y/n]: " add_now
    if [[ "${add_now,,}" != "n" ]]; then
      cmd_tunnel_add ""
      return
    fi
    echo "Add one later with: mimic-tunnel tunnel add"
  else
    c_yellow "-> Restarting Mimic to apply current settings to existing tunnels..."
    systemctl restart "mimic@${IFACE}"
  fi
}

cmd_uninstall() {
  need_root
  load_global

  local purge=0
  if [[ "${1:-}" == "--purge" ]]; then
    purge=1
  fi

  read -rp "This will remove ALL mimic-tunnel configuration ($(list_tunnel_names | wc -l | tr -d ' ') tunnel(s)) on this server. Continue? [y/N]: " confirm
  [[ "${confirm,,}" == "y" ]] || die "Aborted."

  systemctl disable --now "mimic@${IFACE}" 2>/dev/null || true
  systemctl disable --now mimic-tunnel-rules.service 2>/dev/null || true
  rm -f "$RULES_UNIT"
  systemctl daemon-reload

  rm -f "/etc/mimic/${IFACE}.conf"
  rmdir /etc/mimic 2>/dev/null || true
  rm -rf "$TUNNELS_DIR"
  rm -f "$GLOBAL_FILE"
  rmdir "$STATE_DIR" 2>/dev/null || true
  rm -f "$INSTALL_PATH"

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
  if [[ "$ROLE" == "server2" ]]; then
    echo "Note: net.ipv4.ip_forward=1 (set in /etc/sysctl.conf by install) was left as-is in case"
    echo "anything else on this server relies on it. Revert manually if you don't need it:"
    echo "    sudo sed -i 's/^net.ipv4.ip_forward=1/net.ipv4.ip_forward=0/' /etc/sysctl.conf && sudo sysctl -p"
  fi
}

# ============================================================
# Commands: per-tunnel management
# ============================================================
tunnel_summary_and_next_steps() {
  local name="$1"
  echo
  c_green "== Tunnel '$name' summary =="
  if [[ "$ROLE" == "server1" ]]; then
    echo "Peer (Server2): $PEER_IP"
    echo "Disguise port:  $DISGUISE_PORT"
    echo "WG port:        $WG_PORT"
    echo
    c_yellow "One manual step remains: lower this tunnel's WireGuard MTU by 12 bytes."
    echo "In its wg config ([Interface] section), add or edit:"
    echo "    MTU = 1408"
    echo "Then restart that WireGuard interface."
  else
    echo "Peer (Server1): $PEER_IP"
    echo "Disguise port:  $DISGUISE_PORT"
    echo "Client port:    $CLIENT_PORT"
    echo
    echo "Point this tunnel's client WireGuard config at:"
    echo "    Endpoint = <this server's IP>:${CLIENT_PORT}"
  fi
}

cmd_tunnel_add() {
  need_root
  [[ -f "$GLOBAL_FILE" ]] || die "Run 'mimic-tunnel install' first (sets up role/interface for this server)."
  load_global

  local name="${1:-}"
  if [[ -z "$name" ]]; then
    local suggested
    suggested="tunnel$(( $(list_tunnel_names | wc -l | tr -d ' ') + 1 ))"
    ask name "Tunnel name" "$suggested"
  fi
  while ! is_valid_name "$name"; do
    c_yellow "Use only letters, numbers, '-' and '_'."
    unset name; ask name "Tunnel name"
  done

  local editing=0 conflict portvar
  local old_peer_ip="" old_disguise_port="" old_port=""
  if tunnel_exists "$name"; then
    editing=1
    c_yellow "Tunnel '$name' already exists - reconfiguring it (previous values as defaults)."
    load_tunnel "$name"
    old_peer_ip="$PEER_IP"
    old_disguise_port="$DISGUISE_PORT"
    portvar="$(tunnel_port_var)"
    old_port="${!portvar}"
  fi

  if [[ "$ROLE" == "server1" ]]; then
    ask PEER_IP "Server 2 (relay) IP"
    while ! is_valid_ipv4 "$PEER_IP"; do
      c_yellow "That doesn't look like a valid IPv4 address."
      unset PEER_IP; ask PEER_IP "Server 2 (relay) IP"
    done

    ask WG_PORT "Real WireGuard port for this tunnel" "${WG_PORT:-1080}"
    while ! is_valid_port "$WG_PORT"; do
      c_yellow "That doesn't look like a valid port (1-65535)."
      unset WG_PORT; ask WG_PORT "Real WireGuard port for this tunnel" "1080"
    done
  else
    ask PEER_IP "Server 1 (WireGuard) public IP"
    while ! is_valid_ipv4 "$PEER_IP"; do
      c_yellow "That doesn't look like a valid IPv4 address."
      unset PEER_IP; ask PEER_IP "Server 1 (WireGuard) public IP"
    done

    ask CLIENT_PORT "Port the game client will connect to (UDP)" "${CLIENT_PORT:-1080}"
    while true; do
      if ! is_valid_port "$CLIENT_PORT"; then
        c_yellow "That doesn't look like a valid port (1-65535)."
      elif conflict="$(value_used_by_other_tunnel CLIENT_PORT "$CLIENT_PORT" "$name")"; then
        c_yellow "Client port $CLIENT_PORT is already used by tunnel '$conflict'."
      else
        break
      fi
      unset CLIENT_PORT; ask CLIENT_PORT "Port the game client will connect to (UDP)" "1080"
    done
  fi

  ask DISGUISE_PORT "Port that should look like TCP on the wire for this tunnel" "${DISGUISE_PORT:-443}"
  while true; do
    if ! is_valid_port "$DISGUISE_PORT"; then
      c_yellow "That doesn't look like a valid port (1-65535)."
    elif [[ "$ROLE" == "server1" ]] && conflict="$(value_used_by_other_tunnel DISGUISE_PORT "$DISGUISE_PORT" "$name")"; then
      c_yellow "Disguise port $DISGUISE_PORT is already used by tunnel '$conflict' on this server."
    else
      break
    fi
    unset DISGUISE_PORT; ask DISGUISE_PORT "Port that should look like TCP on the wire for this tunnel" "443"
  done

  echo
  c_green "== Configuration summary: tunnel '$name' =="
  if [[ "$ROLE" == "server1" ]]; then
    echo "Server 2 IP:   $PEER_IP"
    echo "WG port:       $WG_PORT"
  else
    echo "Server 1 IP:   $PEER_IP"
    echo "Client port:   $CLIENT_PORT"
  fi
  echo "Disguise port: $DISGUISE_PORT"
  echo
  read -rp "Proceed? [Y/n]: " confirm
  if [[ "${confirm,,}" == "n" ]]; then
    die "Aborted."
  fi

  local new_port
  portvar="$(tunnel_port_var)"
  new_port="${!portvar}"

  if (( editing )); then
    tunnel_rules "$name" remove "$old_peer_ip" "$old_disguise_port" "$old_port"
  fi
  write_tunnel "$name"
  regen_mimic_filter_config
  tunnel_rules "$name" add "$PEER_IP" "$DISGUISE_PORT" "$new_port"
  systemctl enable --now "mimic@${IFACE}"
  systemctl restart "mimic@${IFACE}"

  tunnel_summary_and_next_steps "$name"
}

cmd_tunnel_edit() {
  local name="${1:-}"
  [[ -n "$name" ]] || die "Usage: $0 tunnel edit <name>"
  need_root
  load_global
  tunnel_exists "$name" || die "No such tunnel: $name (see: mimic-tunnel tunnel list)"
  cmd_tunnel_add "$name"
}

cmd_tunnel_remove() {
  local name="${1:-}"
  [[ -n "$name" ]] || die "Usage: $0 tunnel remove <name>"
  need_root
  load_global
  tunnel_exists "$name" || die "No such tunnel: $name (see: mimic-tunnel tunnel list)"

  read -rp "Remove tunnel '$name'? [y/N]: " confirm
  [[ "${confirm,,}" == "y" ]] || die "Aborted."

  load_tunnel "$name"
  local portvar port
  portvar="$(tunnel_port_var)"
  port="${!portvar}"
  tunnel_rules "$name" remove "$PEER_IP" "$DISGUISE_PORT" "$port"
  rm -f "${TUNNELS_DIR}/${name}.conf"
  regen_mimic_filter_config
  systemctl restart "mimic@${IFACE}" 2>/dev/null || true

  c_green "Removed tunnel '$name'."
}

cmd_tunnel_list() {
  need_root
  load_global
  c_green "== mimic-tunnel: $ROLE on ${IFACE} =="
  local names n
  names="$(list_tunnel_names)"
  if [[ -z "$names" ]]; then
    echo "No tunnels configured. Add one with: mimic-tunnel tunnel add"
    return
  fi
  for n in $names; do
    load_tunnel "$n"
    echo
    echo "[$n]"
    if [[ "$ROLE" == "server1" ]]; then
      echo "  Peer (Server2): $PEER_IP"
      echo "  Disguise port:  $DISGUISE_PORT"
      echo "  WG port:        $WG_PORT"
    else
      echo "  Peer (Server1): $PEER_IP"
      echo "  Disguise port:  $DISGUISE_PORT"
      echo "  Client port:    $CLIENT_PORT"
    fi
  done
}

cmd_tunnel() {
  local sub="${1:-}"
  shift || true
  case "$sub" in
    add)    cmd_tunnel_add "${1:-}" ;;
    edit)   cmd_tunnel_edit "${1:-}" ;;
    remove) cmd_tunnel_remove "${1:-}" ;;
    list)   cmd_tunnel_list ;;
    *) die "Usage: $0 tunnel add|edit|remove|list [name]" ;;
  esac
}

# ============================================================
# Commands: service control / status (apply to the whole server, since all
# of a server's tunnels share one Mimic instance on one interface)
# ============================================================
cmd_start()   { need_root; load_global; systemctl start "mimic@${IFACE}"; c_green "Started."; }
cmd_stop()    { need_root; load_global; systemctl stop "mimic@${IFACE}"; c_yellow "Stopped (obfuscation is off; iptables rules are still in place)."; }
cmd_restart() { need_root; load_global; systemctl restart "mimic@${IFACE}"; c_green "Restarted."; }

cmd_status() {
  need_root
  load_global
  local name="${1:-}"
  c_green "== mimic-tunnel status =="
  echo "Role:          $ROLE"
  echo "Interface:     $IFACE"
  [[ "$ROLE" == "server1" ]] && echo "Public IP:     $PUBLIC_IP"
  echo
  if [[ -n "$name" ]]; then
    load_tunnel "$name"
    echo "-- tunnel '$name' --"
    if [[ "$ROLE" == "server1" ]]; then
      echo "Peer (Server2):$PEER_IP   Disguise port:$DISGUISE_PORT   WG port:$WG_PORT"
    else
      echo "Peer (Server1):$PEER_IP   Disguise port:$DISGUISE_PORT   Client port:$CLIENT_PORT"
    fi
  else
    cmd_tunnel_list
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
  load_global
  local name="${1:-}"
  local tag="$COMMENT_TAG"
  [[ -n "$name" ]] && tag="${COMMENT_TAG}:${name}"
  c_green "== traffic counters for mimic-tunnel's iptables rules${name:+ (tunnel '$name')} =="
  echo "--- nat table ---"
  iptables -t nat -L -n -v --line-numbers | grep -E "Chain|$tag" || true
  echo
  echo "--- filter/INPUT ---"
  iptables -L INPUT -n -v --line-numbers | grep -E "Chain|$tag" || true
  echo
  echo "--- active Mimic connections ---"
  mimic show -c || true
}

usage() {
  cat <<EOF
mimic-tunnel - install and manage one or more Mimic-based WireGuard-over-
fake-TCP relay tunnels

Usage: $(basename "$0") <command>

Commands:
  install                    One-time (or reconfigurable) per-server setup: role, interface
  tunnel add [name]          Add a new tunnel (prompts for a name if omitted)
  tunnel edit <name>         Reconfigure an existing tunnel
  tunnel remove <name>       Remove one tunnel (other tunnels keep working)
  tunnel list                List configured tunnels
  uninstall [--purge]        Remove everything on this server (add --purge to also remove the mimic package)
  start                      Start the obfuscation service
  stop                       Stop the obfuscation service (iptables rules stay in place)
  restart                    Restart the obfuscation service
  status [name]              Show service status, active connections, and current config
  stats [name]               Show packet/byte counters for the tunnel's iptables rules
EOF
}

main() {
  migrate_legacy_config

  local cmd="${1:-}"
  shift || true
  case "$cmd" in
    install)      cmd_install "$@" ;;
    tunnel)       cmd_tunnel "$@" ;;
    uninstall)    cmd_uninstall "$@" ;;
    start)        cmd_start ;;
    stop)         cmd_stop ;;
    restart)      cmd_restart ;;
    status)       cmd_status "$@" ;;
    stats)        cmd_stats "$@" ;;
    apply-rules)  cmd_apply_rules "$@" ;;
    -h|--help|help|"") usage ;;
    *) c_red "Unknown command: $cmd"; usage; exit 1 ;;
  esac
}

main "$@"
