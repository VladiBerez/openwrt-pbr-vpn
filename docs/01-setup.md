# 01. Initial OpenWrt + PBR + VPN setup

One-time router-side configuration. After this, day-to-day work happens through `ovpn-pbr` from your workstation (see [02-operations.md](02-operations.md)) or the [Web UI](../../openwrt-pbr-vpn-ui/README.md).

**Verified on:** OpenWrt 25.12.2, PBR 1.2.2-r12, WireGuard (primary as of May 2026) / OpenVPN 2.6.

> **Note (May 2026):** Russian ТСПУ DPI began aggressively dropping OpenVPN and WireGuard data channels starting 15 May 2026. WireGuard with fresh endpoints from your provider is currently the most reliable option. See [03-anti-dpi.md](03-anti-dpi.md) if probing fails for all endpoints.

---

## 1. Architecture

```
[Phone / PC on Wi-Fi 192.168.1.x]
        │
        ▼
   [OpenWrt router]
        │
        ├─► Regular traffic (8.8.8.8, banks, work tools…) ──► WAN
        │
        └─► Traffic to IPs in the VPN set ──► vpnclient ──► WireGuard exit
```

| Component | Role |
|-----------|------|
| **WireGuard** (or OpenVPN) | Brings up `vpnclient` interface |
| **PBR** (`pbr` + `luci-app-pbr`) | Marks matching packets via nftables, sends them via the VPN routing table |
| **`/etc/pbr.d/vpn-routes.sh`** | Custom user file — populates nft-set `pbr_vpnclient_4_dst_ip_user` |
| **`ovpn-pbr`** (workstation CLI) | Resolves domains, pushes route updates, switches WG endpoints |
| **Web UI** (optional, localhost:3000) | Browser dashboard for status, endpoint switching, and route editing |

PBR does **not** block anything. It only **redirects** matches into the VPN; everything else takes the normal WAN path.

PBR docs: <https://docs.openwrt.melmac.ca/pbr/1.2.2/#custom-user-files>

---

## 2. Required packages

```sh
apk update
apk add pbr luci-app-pbr
apk add wireguard-tools kmod-wireguard          # WireGuard (recommended)
apk add openvpn-openssl luci-app-openvpn        # OpenVPN (fallback)
# Useful helpers:
apk add resolveip ip-full
```

Then in LuCI: **Services → Policy Based Routing** — enable the service.

---

## 3. VPN client

### 3.0. WireGuard (recommended)

`ovpn-pbr wg set --config peer.conf` handles the full setup: it parses the `.conf` file and writes the correct UCI configuration.

```bash
# Apply a WireGuard peer from your provider (place .conf files in vpn-pool/)
ovpn-pbr wg set --config vpn-pool/finland.conf

# Or use the Web UI → Endpoints page → Switch button
```

This creates the `vpnclient` interface as `proto=wireguard` with `route_allowed_ips='0'` (critical for split-tunnel — see [02-operations.md §3](02-operations.md#3-wireguard-recommended)). If you want to test all peers automatically:

```bash
ovpn-pbr wg probe --dir vpn-pool/
# Or use Endpoints → Probe all in the Web UI
```

For the underlying UCI structure, see [02-operations.md §3](02-operations.md#3-wireguard-recommended).

---

### 3.1. OpenVPN (fallback) — `.ovpn` requirements

For split-tunnel the profile **must** include:

```ini
route-nopull
pull-filter ignore "redirect-gateway"
pull-filter ignore "dhcp-option DNS"
tun-mtu 1400
mssfix 1360
verb 5
```

- **`route-nopull`** — don't accept routes pushed by the server, otherwise everything ends up in the tunnel.
- `redirect-gateway def1` and `dhcp-option DNS` must be **commented out** (the `pull-filter ignore` lines additionally drop them if the server pushes them).
- MTU values are tuned for a PPPoE WAN (~1492 MTU). Adjust for your link.

`ovpn-pbr ovpn set --config Netherlands.ovpn` patches all of this automatically — you can skip the manual edit.

### 3.2. Network and firewall (`/etc/config/network`)

A logical interface that names the OpenVPN tun device:

```
config interface 'vpnclient'
    option proto 'none'
    option device 'tun0'
```

For WireGuard the same `vpnclient` name is used but with `proto 'wireguard'` — see [02-operations.md §3](02-operations.md#3-wireguard-instead-of-openvpn).

### 3.3. Firewall (`/etc/config/firewall`)

`vpnclient` lives in the **WAN zone** (same masquerading, same forwarding rules):

```
config zone
    option name 'wan'
    list network 'wan'
    list network 'vpnclient'
    option masq '1'
```

**Common pitfall:** the LuCI PBR wizard sometimes creates a separate zone called `vpn` with `forward='REJECT'`. That breaks LAN→VPN forwarding. Move `vpnclient` to the WAN zone (see [02-operations.md §4](02-operations.md#4-firewall-pitfalls)).

### 3.4. PBR (`/etc/config/pbr`)

```
config pbr 'config'
    option enabled '1'
    option strict_enforcement '1'
    option resolver_set 'none'
    list supported_interface 'vpnclient'
    option uplink_interface 'wan'
```

- **`strict_enforcement '1'`** — if the VPN drops, traffic matched for VPN is **dropped** rather than leaking via WAN. Acts as a kill-switch for the set.
- **`resolver_set 'none'`** — domain-based policies aren't resolved via dnsmasq-nftset. We feed the set directly from `vpn-routes.sh`.

### 3.5. Hotplug (optional)

Reload the firewall when the VPN comes up:

```sh
cat > /etc/hotplug.d/iface/30-vpn-fw << 'EOF'
#!/bin/sh
[ "$ACTION" = "ifup" ] && [ "$INTERFACE" = "vpnclient" ] && fw4 reload
EOF
chmod +x /etc/hotplug.d/iface/30-vpn-fw
```

### 3.6. Autostart

```sh
service openvpn enable
service pbr enable
```

---

## 4. Custom user files (`/etc/pbr.d/`)

Since PBR 1.1.8+, every `*.sh` in `/etc/pbr.d/` runs at PBR start. The script's job is to populate the nft-set:

```
pbr_vpnclient_4_dst_ip_user
```

This tool ships a starter set in `config/seed-routes.sh` (Telegram, Meta, Cloudflare, Google, etc.). Copy it on first install:

```sh
scp config/seed-routes.sh root@192.168.1.1:/etc/pbr.d/vpn-routes.sh
ssh root@192.168.1.1 "sed -i 's/\\r//' /etc/pbr.d/vpn-routes.sh && chmod +x /etc/pbr.d/vpn-routes.sh && service pbr restart"
```

After that, day-to-day updates: `ovpn-pbr update`.

---

## 5. First validation

```sh
# Number of elements in the VPN set
nft list set inet fw4 pbr_vpnclient_4_dst_ip_user | grep -c '\.'

# Is a specific IP in the VPN set?
nft get element inet fw4 pbr_vpnclient_4_dst_ip_user "{ 157.240.253.174 }" \
    && echo "VPN" || echo "DIRECT"

# PBR overview
service pbr status

# From the router (note: pings from the router itself bypass PBR — see ops doc)
# Real test is from a LAN client.
```

| Target | Expected from LAN |
|--------|-------------------|
| Instagram IP (`157.240.x`) | ~50–150ms (via VPN) |
| `8.8.8.8` | 30–40ms (direct WAN) |

If everything works, move on to [02-operations.md](02-operations.md) for day-to-day automation.

Optionally start the Web UI for a browser-based dashboard:

```bash
cd openwrt-pbr-vpn-ui
npm run build && npm start   # http://localhost:3000
```
