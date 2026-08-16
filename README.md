# mimic-tunnel

Relay a WireGuard UDP connection through an internal/domestic server that only
allows outbound UDP to local destinations, disguising the middle hop as TCP so
it survives UDP QoS/blocking. Built around [Mimic](https://github.com/hack3ric/mimic),
an eBPF UDP→fake-TCP obfuscator.

```
[Game client] --UDP--> [Server 2: relay] --fake-TCP (Mimic)--> [Server 1] --> WireGuard
```

- **Server 1** — the box that actually runs WireGuard.
- **Server 2** — an internal/domestic server the client *can* reach over plain
  UDP. It DNATs that traffic onward to Server 1, and Mimic disguises it as TCP
  on the wire in between.

One script, `mimic-tunnel.sh`, runs on **both** servers — it asks which role
each one plays and configures itself accordingly.

## Requirements

- Debian 12 (bookworm), Debian 13 (trixie), or Ubuntu 24.04 (noble) — amd64.
  These are the only distros the official Mimic `.deb` packages target. Other
  distros need Mimic [built from source](https://github.com/hack3ric/mimic/blob/master/docs/building.md).
- Kernel ≥ 6.1 (needed for eBPF dynptrs).
- Root access on both servers.
- WireGuard already set up on Server 1.

## Install

Copy `mimic-tunnel.sh` to **each** server and run it as root:

```bash
sudo ./mimic-tunnel.sh install
```

You'll be prompted for:

| Prompt | Asked on | Notes |
|---|---|---|
| Role (1 or 2) | both | which server this is |
| Network interface | both | auto-detected, override if needed |
| Disguise port | both | the port that looks like TCP on the wire (default `443`) |
| Server 2 IP | Server 1 only | so the redirect rule only trusts your relay |
| Real WireGuard port | Server 1 only | default `1080` |
| This server's public IP | Server 1 only | auto-detected via several fallback services; type it manually if detection fails |
| Server 1's public IP | Server 2 only | where the real WireGuard instance is |
| Client port | Server 2 only | the UDP port the game client connects to (default `1080`) |

The installer then:
1. Installs the Mimic `.deb` + DKMS kernel module for your distro/kernel.
2. Adds the `iptables` NAT rules for your role (idempotent — safe to re-run).
3. Writes `/etc/mimic/<iface>.conf` with the right Mimic filter.
4. Installs itself to `/usr/local/sbin/mimic-tunnel` and enables the systemd
   services so everything survives a reboot.

At the end it prints one manual step for Server 1: lower WireGuard's MTU by
12 bytes (Mimic's per-packet overhead) — the installer tells you the exact
line to add to `wg0.conf`.

### Client config

Point the client's WireGuard config at **Server 2**, not Server 1:

```
[Peer]
Endpoint = <Server 2 IP>:<client port>
```

Nothing else about the WireGuard config changes — Mimic is fully transparent
to WireGuard's own crypto.

## Managing the tunnel

After install, run these from anywhere (no `./` or `.sh` needed):

```bash
mimic-tunnel status      # role/config summary, systemd status, active Mimic
                          # connections, and `wg show` on Server 1
mimic-tunnel stats        # packet/byte counters on the tunnel's iptables rules
mimic-tunnel start        # turn obfuscation on
mimic-tunnel stop         # turn obfuscation off (iptables rules stay in place)
mimic-tunnel restart
mimic-tunnel uninstall [--purge]   # --purge also removes the mimic package
```

Re-running `mimic-tunnel install` reconfigures in place, offering your
previous answers as defaults.

## Files it creates

| Path | Purpose |
|---|---|
| `/usr/local/sbin/mimic-tunnel` | the script itself, after first install |
| `/etc/mimic-tunnel/config` | saved role/IPs/ports, read by every command |
| `/etc/mimic/<iface>.conf` | Mimic's own filter config |
| `/etc/systemd/system/mimic-tunnel-rules.service` | adds the iptables rules on boot, removes them on stop/disable |
| `/etc/modules-load.d/mimic.conf` | loads the `mimic` kernel module at boot |

## Persistence

Instead of relying on `iptables-persistent`, the iptables rules are owned by
their own oneshot systemd service (`mimic-tunnel-rules.service`). It adds the
rules on start (boot) and **removes them on stop**, which is also what makes
`mimic-tunnel uninstall` leave a clean system with no orphaned rules. All
rules carry an iptables comment (`mimic-tunnel`) so `stats`/uninstall can find
them regardless of the exact IPs/ports you configured.

## Troubleshooting

- **`mimic-tunnel status`** first — check both systemd services are `active`
  and that `mimic show -c` lists a connection.
- **No connection at all**: confirm the disguise port is open in any
  upstream/cloud firewall (not just this host's `iptables`) for *both* TCP and
  UDP — Mimic's wire format is TCP-shaped but the local network stack still
  sees the pre/post-mangled packet as UDP at various points.
- **Public IP auto-detection fails**: some networks block or rate-limit
  `ifconfig.me`/`ipify`/etc. The script tries four different providers before
  giving up, and if all of them fail it just asks you to type the IP in —
  this is expected on some networks, not an error.
- **High jitter/packet loss**: verify the MTU step was done
  (`wg show` MTU vs. the interface MTU — WireGuard should be 12 bytes lower).
- **Traffic counters**: `mimic-tunnel stats` shows packet/byte counts per rule
  — 0 packets on the `PREROUTING`/`DNAT` rule on Server 2 means the client
  isn't reaching it; 0 packets on Server 1's `REDIRECT` rule means Server 2
  isn't getting traffic out.

## Uninstall

```bash
sudo mimic-tunnel uninstall            # remove config, rules, services
sudo mimic-tunnel uninstall --purge    # also remove the mimic package + kernel module
```

## References

- [Mimic](https://github.com/hack3ric/mimic) — the eBPF UDP→TCP obfuscator this relies on.
- [Mimic getting-started guide](https://github.com/hack3ric/mimic/blob/master/docs/getting-started.md)
- [Mimic building from source](https://github.com/hack3ric/mimic/blob/master/docs/building.md) (for distros outside bookworm/trixie/noble)
