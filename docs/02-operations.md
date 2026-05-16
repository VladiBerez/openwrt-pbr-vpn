# 02. Operations

Day-to-day work, automation, and troubleshooting.

---

## 1. The `ovpn-pbr` tool

After `pip install -e .` (or `pip install openwrt-pbr-vpn`):

```text
ovpn-pbr update [--no-upload]      # resolve domains, push to router, restart PBR
ovpn-pbr upload                    # push current local vpn-routes.sh (no resolve)
ovpn-pbr routes show               # dump nft set from router
ovpn-pbr routes add <CIDR>...      # ad-hoc additions
ovpn-pbr routes rm  <CIDR>...      # removals

ovpn-pbr wg set --config peer.conf       # apply a WireGuard peer to vpnclient
ovpn-pbr wg show                          # current peer state
ovpn-pbr wg probe --dir ./configs/        # find a peer that survives DPI

ovpn-pbr ovpn set --config x.ovpn         # install + patch + restart
ovpn-pbr ovpn probe --dir ./configs/      # find a profile that survives DPI

ovpn-pbr diagnose                  # tun state, PBR, set size, ping tests
ovpn-pbr emergency-off             # drop kill-switch, stop VPN (restore WAN)
ovpn-pbr killswitch-on             # re-enable strict_enforcement

ovpn-pbr keys install              # generate ed25519 + push to router (passwordless from now on)
ovpn-pbr keys store                # save router password in OS keyring
ovpn-pbr keys test                 # verify current creds work
```

---

## 2. How `update` works

1. **DoH resolve.** Each domain in `domains.txt` is queried in parallel (16 threads) against Google DoH and Cloudflare DoH. This mirrors what `rockblack.pro/ip-address` does in a browser.
2. **Parse existing.** A regex pulls all CIDR / single IPs out of every `nft add element inet fw4 $S "{ ... }"` in your local `vpn-routes.sh`, turns them into `ipaddress.IPv4Network`.
3. **Filter.** Each resolved IP is checked with `addr in network` — if it falls inside any existing CIDR (even a /16), it's skipped. This is what keeps the file from growing forever.
4. **Aggregate.** If 3+ new IPs land in the same /24, they collapse into a single `1.2.3.0/24` line (configurable via `auto_aggregate_24`).
5. **Append.** New entries land at the end of the file under `# --- auto-added YYYY-MM-DD HH:MM (N entries) ---`, in batches of 15 per `nft add element` call. Idempotent — re-running won't duplicate.
6. **Upload.** Uses SSH `exec_command("cat > /etc/pbr.d/vpn-routes.sh")` — **not** SFTP, because dropbear (default OpenWrt SSH server) doesn't ship the SFTP subsystem.
7. **`sed -i 's/\r//'`** runs on the router as belt-and-braces CRLF protection.
8. **`service pbr restart`** picks up the new set.

---

## 3. WireGuard instead of OpenVPN

When OpenVPN gets blocked (see [03-anti-dpi.md](03-anti-dpi.md)), WireGuard is the next thing to try.

```bash
ovpn-pbr wg set --config peer.conf
```

This:

1. Wipes the old `network.vpnclient` interface (whether it was OpenVPN's `proto=none / device=tun0` or another WG peer).
2. Recreates `vpnclient` as `proto=wireguard` with the parsed `[Interface]` block.
3. Adds the `[Peer]` as `network.@wireguard_vpnclient[-1]` with `route_allowed_ips='0'` (critical — see below).
4. `uci commit network && /etc/init.d/network reload`.

### Why `route_allowed_ips='0'`

With `AllowedIPs=0.0.0.0/0` on a peer, OpenWrt by default installs a default route through the WG interface into the **main** routing table — your entire LAN's internet would fall into the tunnel. We don't want that for split-tunnel: PBR manages its own routing table (`pbr_vpnclient`) where the VPN default route lives. Setting `route_allowed_ips='0'` keeps `vpnclient` UP but leaves the main table alone.

### Probing endpoints

If you have multiple `.conf` files (e.g. one per country from your provider), `wg probe` cycles through them, applies each, generates traffic via `ping -I vpnclient`, and checks whether the peer's `received` counter actually grows. This catches the **"tunnel up, RX=0"** DPI case where handshake passes but data is silently dropped.

```bash
ovpn-pbr wg probe --dir ./hideme/wireguard/
```

Pass criteria: `received` > 5 KB within 10 seconds of probe traffic.

---

## 4. Firewall pitfalls

After installing `luci-app-pbr`, check zones:

```sh
uci show firewall | grep -E 'zone|network'
```

You want `vpnclient` in the **WAN zone**:

```
firewall.@zone[1].name='wan'
firewall.@zone[1].network='wan' 'wan6' 'vpnclient'
firewall.@zone[1].masq='1'
```

If you see a separate zone `vpn` with `forward='REJECT'`, LAN traffic to the VPN set will be dropped. Fix:

```sh
uci -q del_list firewall.@zone[2].network='vpnclient'
uci -q delete firewall.@zone[2]
uci add_list firewall.@zone[1].network='vpnclient'

# Also remove any leftover forwarding rule pointing at the deleted zone:
for i in 0 1 2 3; do
  d=$(uci -q get firewall.@forwarding[$i].dest 2>/dev/null)
  [ "$d" = vpn ] && uci -q delete firewall.@forwarding[$i]
done

uci commit firewall
fw4 reload
service pbr restart
```

---

## 5. Credentials

Three options, picked automatically by the config loader:

1. **SSH key (recommended).** `ovpn-pbr keys install` generates ed25519 in `~/.ssh/id_openwrt` and adds the public key to `/etc/dropbear/authorized_keys` on the router. Then `ROUTER_SSH_KEY=~/.ssh/id_openwrt` in `.env` — no password anywhere.
2. **OS keyring.** `ovpn-pbr keys store` prompts for the password and saves it in Windows Credential Manager / macOS Keychain / Linux Secret Service. No plaintext on disk.
3. **`.env` plaintext.** Set `ROUTER_PASSWORD` in `.env` (which is git-ignored). Simplest, least secure.

`router.conf` (the original INI format) is still supported but deprecated.

---

## 6. Common diagnostics

```bash
ovpn-pbr diagnose
```

prints:

- `ip link show tun0 / vpnclient`
- `wg show vpnclient`
- `service pbr status` excerpt
- `ip route show table pbr_vpnclient`
- nft set element count
- WAN ping (8.8.8.8)
- firewall zones
- last OpenVPN log lines

Useful manual commands on the router:

```sh
uci show pbr
logread | grep -iE 'pbr|openvpn|wireguard' | tail -30
service pbr support       # full report, redacts sensitive bits
ip route show table pbr_vpnclient
ip rule list | grep pbr
wg show
```

### `ping -I vpnclient` from the router is misleading

A ping from the **router itself** doesn't go through PBR — PBR's `pbr_forward` chain only matches **forwarded** traffic from LAN. So `ping -I vpnclient 1.1.1.1` may fail even when LAN clients work fine.

Real test: from a LAN device (PC/phone), `ping 157.240.205.174`. With a working VPN you'll see ~50-150ms latency through the exit country.

---

## 7. Adding new services

Want to add a new blocked service?

```bash
echo "newservice.example.com" >> domains.txt
ovpn-pbr update
```

If a service rotates IPs across a huge Cloudflare or similar CDN, consider adding the broader CIDR by hand in `vpn-routes.sh`:

```sh
nft add element inet fw4 $S "{ 104.16.0.0/13 }" 2>/dev/null
```

`nft auto-merge` will absorb any overlapping smaller entries. Trade-off: bigger range means more traffic into VPN — including some sites you may not actually need there.

---

## 8. Emergency procedures

### Restore working internet when VPN is broken

```bash
ovpn-pbr emergency-off
```

This sets `strict_enforcement=0`, stops OpenVPN, and brings `vpnclient` down. Result: all traffic goes through WAN. Blocked services become unreachable directly (normal), everything else works.

### Roll back a network/firewall change

Every UCI-modifying command on the router takes a backup:

```sh
ls -la /etc/config/network.bak.*
cp /etc/config/network.bak.<timestamp> /etc/config/network
/etc/init.d/network restart
```

Same pattern for `firewall`, `pbr`, `openvpn`.

---

## 9. Updating the repo

```bash
git pull
pip install -e .                # picks up new deps if any
ovpn-pbr update                 # routes file gets re-synced
```

Tests:

```bash
pip install -e ".[dev]"
pytest -v
```
