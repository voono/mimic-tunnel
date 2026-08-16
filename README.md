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
each one plays and configures itself accordingly. A single server pair can
carry **multiple independent tunnels** (e.g. several WireGuard instances),
each with its own disguise/client/WireGuard port, sharing one network
interface.

## Requirements

- Debian 12 (bookworm), Debian 13 (trixie), or Ubuntu 24.04 (noble) — amd64.
  These are the only distros the official Mimic `.deb` packages target. Other
  distros need Mimic [built from source](https://github.com/hack3ric/mimic/blob/master/docs/building.md).
- Kernel ≥ 6.1 (needed for eBPF dynptrs).
- Root access on both servers.
- WireGuard already set up on Server 1.

## Quick setup

Run on **each** server, as root:

```bash
curl -fsSL https://raw.githubusercontent.com/voono/mimic-tunnel/main/mimic-tunnel.sh | sudo bash -s -- install
```

This downloads the script, runs the interactive installer (asks which role
this server plays), and installs itself to `/usr/local/sbin/mimic-tunnel` so
you can manage it afterwards with just `mimic-tunnel <command>` — no need to
re-download.

Prefer to inspect the script first, or keep a local clone to update via
`git pull`?

```bash
git clone https://github.com/voono/mimic-tunnel.git
cd mimic-tunnel
sudo ./mimic-tunnel.sh install
```

### Updating

Re-run the same one-liner (or `git pull` + `sudo ./mimic-tunnel.sh install`
if you cloned). It's safe to re-run at any time:

- Existing config is offered back to you as the default at each prompt.
- Existing tunnels are left running and are automatically migrated to any
  new config format the update introduces.
- The systemd services and iptables rules are reapplied idempotently.

Once installed, you can also just run `mimic-tunnel install` on the server
itself to reconfigure or update in place — no need to fetch the script again
unless a new version was released.

## Setting up your first tunnel

`install` sets up the server's role/interface and then walks you straight
into adding your first tunnel. You'll be prompted for:

| Prompt | Asked on | Notes |
|---|---|---|
| Role (1 or 2) | both, once per server | which server this is |
| Network interface | both, once per server | auto-detected, override if needed |
| This server's public IP | Server 1 only, once per server | auto-detected via several fallback services; type it manually if detection fails |
| Tunnel name | both, per tunnel | identifies this tunnel (e.g. `wg0`, `game1`) |
| Server 2 IP | Server 1 only, per tunnel | so the redirect rule only trusts your relay |
| Real WireGuard port | Server 1 only, per tunnel | default `1080` |
| Server 1's public IP | Server 2 only, per tunnel | where the real WireGuard instance is |
| Client port | Server 2 only, per tunnel | the UDP port the game client connects to (default `1080`) |
| Disguise port | both, per tunnel | the port that looks like TCP on the wire (default `443`); must be unique per tunnel on Server 1 |

The installer then:
1. Installs the Mimic `.deb` + DKMS kernel module for your distro/kernel.
2. Adds the `iptables` NAT rules for your role and this tunnel (idempotent —
   safe to re-run).
3. Writes/updates `/etc/mimic/<iface>.conf` with a `filter =` line per tunnel.
4. Installs itself to `/usr/local/sbin/mimic-tunnel` and enables the systemd
   services so everything survives a reboot.

At the end it prints one manual step for Server 1: lower that tunnel's
WireGuard MTU by 12 bytes (Mimic's per-packet overhead) — the installer
tells you the exact line to add to its `wg0.conf`.

### Client config

Point the client's WireGuard config at **Server 2**, not Server 1:

```
[Peer]
Endpoint = <Server 2 IP>:<client port>
```

Nothing else about the WireGuard config changes — Mimic is fully transparent
to WireGuard's own crypto.

## Adding more tunnels

Run this on **both** servers for each additional tunnel you want (e.g. a
second WireGuard instance, another game server):

```bash
sudo mimic-tunnel tunnel add [name]     # prompts for a name if omitted
```

Every tunnel gets its own disguise/client/WireGuard port but shares the
server's interface and Mimic instance, so adding one just appends a new
`filter =` line and reloads Mimic — the other tunnels keep running
uninterrupted.

```bash
mimic-tunnel tunnel list                # see all tunnels and their settings
sudo mimic-tunnel tunnel edit <name>    # reconfigure one, previous values as defaults
sudo mimic-tunnel tunnel remove <name>  # remove just this one
```

## Managing the tunnels

After install, run these from anywhere (no `./` or `.sh` needed):

```bash
mimic-tunnel status [name]   # role/config summary, systemd status, active Mimic
                              # connections, and `wg show` on Server 1;
                              # add a tunnel name to focus on just that one
mimic-tunnel stats [name]    # packet/byte counters on the iptables rules,
                              # all tunnels or just one
mimic-tunnel start           # turn obfuscation on (affects all tunnels)
mimic-tunnel stop            # turn obfuscation off (iptables rules stay in place)
mimic-tunnel restart
mimic-tunnel uninstall [--purge]   # remove everything, incl. all tunnels
                                    # (--purge also removes the mimic package)
```

Re-running `mimic-tunnel install` reconfigures the server's role/interface in
place, offering your previous answers as defaults, then reapplies all
existing tunnels.

## Files it creates

| Path | Purpose |
|---|---|
| `/usr/local/sbin/mimic-tunnel` | the script itself, after first install |
| `/etc/mimic-tunnel/config` | saved role/interface/public IP, shared by all tunnels |
| `/etc/mimic-tunnel/tunnels/<name>.conf` | saved peer IP/ports for one tunnel |
| `/etc/mimic/<iface>.conf` | Mimic's own filter config — one `filter =` line per tunnel |
| `/etc/systemd/system/mimic-tunnel-rules.service` | adds every tunnel's iptables rules on boot, removes them on stop/disable |
| `/etc/modules-load.d/mimic.conf` | loads the `mimic` kernel module at boot |

## Persistence

Instead of relying on `iptables-persistent`, the iptables rules are owned by
their own oneshot systemd service (`mimic-tunnel-rules.service`). It adds
every tunnel's rules on start (boot) and **removes them on stop**, which is
also what makes `mimic-tunnel uninstall` leave a clean system with no
orphaned rules. Each tunnel's rules carry their own iptables comment
(`mimic-tunnel:<name>`) so `stats`/`tunnel remove`/uninstall can find and
manage them individually, regardless of the exact IPs/ports configured.

## Troubleshooting

- **`mimic-tunnel status`** first — check both systemd services are `active`
  and that `mimic show -c` lists a connection. Add a tunnel name
  (`mimic-tunnel status <name>`) to check just one.
- **No connection at all**: confirm the disguise port is open in any
  upstream/cloud firewall (not just this host's `iptables`) for *both* TCP and
  UDP — Mimic's wire format is TCP-shaped but the local network stack still
  sees the pre/post-mangled packet as UDP at various points.
- **Public IP auto-detection fails**: some networks block or rate-limit
  `ifconfig.me`/`ipify`/etc. The script tries four different providers before
  giving up, and if all of them fail it just asks you to type the IP in —
  this is expected on some networks, not an error.
- **High jitter/packet loss**: verify the MTU step was done for the affected
  tunnel (`wg show` MTU vs. the interface MTU — WireGuard should be 12 bytes
  lower).
- **Traffic counters**: `mimic-tunnel stats [name]` shows packet/byte counts
  per rule — 0 packets on the `PREROUTING`/`DNAT` rule on Server 2 means the
  client isn't reaching it; 0 packets on Server 1's `REDIRECT` rule means
  Server 2 isn't getting traffic out.
- **One tunnel broken, others fine**: they're independent — check
  `mimic-tunnel tunnel list` for the affected tunnel's config and
  `mimic-tunnel stats <name>` for its counters specifically.

## Uninstall

```bash
sudo mimic-tunnel tunnel remove <name>  # remove just one tunnel, others keep running
sudo mimic-tunnel uninstall             # remove everything: all tunnels, config, rules, services
sudo mimic-tunnel uninstall --purge     # also remove the mimic package + kernel module
```

## References

- [Mimic](https://github.com/hack3ric/mimic) — the eBPF UDP→TCP obfuscator this relies on.
- [Mimic getting-started guide](https://github.com/hack3ric/mimic/blob/master/docs/getting-started.md)
- [Mimic building from source](https://github.com/hack3ric/mimic/blob/master/docs/building.md) (for distros outside bookworm/trixie/noble)
