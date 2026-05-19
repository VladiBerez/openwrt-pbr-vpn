# openwrt-pbr-vpn

[![test](https://github.com/VladiBerez/openwrt-pbr-vpn/actions/workflows/test.yml/badge.svg)](https://github.com/VladiBerez/openwrt-pbr-vpn/actions/workflows/test.yml)
[![PyPI](https://img.shields.io/pypi/v/openwrt-pbr-vpn)](https://pypi.org/project/openwrt-pbr-vpn/)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Automated split-tunnel VPN management for **OpenWrt + PBR** routers. Resolves blocked-service domains through DoH, keeps an `nft` set up to date, pushes everything to the router over SSH, and includes a full-featured **web UI** for day-to-day operations.

Supports OpenVPN and WireGuard with DPI-bypass probing — detects and works around ТСПУ-style data-channel blocks by testing actual packet flow rather than counters.

## What problem this solves

You run **OpenWrt + PBR (`luci-app-pbr`) + a VPN** with a split-tunnel: most traffic exits through your ISP, but a curated list of IPs (Meta, Telegram, YouTube, AI services, etc.) is routed through the VPN. Maintaining that list by hand is painful — CDNs rotate, new services get blocked overnight. This tool keeps it fresh and keeps your VPN alive under deep-packet inspection.

## Quick start

```bash
pip install openwrt-pbr-vpn

# SSH credentials (pick one):
ovpn-pbr keys install          # generate ed25519 key, push to router (recommended)
ovpn-pbr keys store            # save password in OS keyring
# or: set ROUTER_HOST / ROUTER_PASSWORD in .env

# Seed domain list and push
cp config/domains.example.txt domains.txt
ovpn-pbr update                # resolve → dedupe → push → restart PBR
ovpn-pbr diagnose              # verify tun/wg, PBR, nft set size
```

## Commands

### Routes

```text
ovpn-pbr update [--no-upload]           resolve domains, dedupe, push nft set, restart PBR
ovpn-pbr upload                         push current local routes file without re-resolving
ovpn-pbr routes show                    dump current nft set from router
ovpn-pbr routes add <CIDR|IP> ...       append entries and push
ovpn-pbr routes rm  <CIDR|IP> ...       remove entries and push
```

### WireGuard

```text
ovpn-pbr wg set   --config peer.conf    configure WG interface from .conf, bring it up
ovpn-pbr wg show                        wg show + handshake/transfer state
ovpn-pbr wg probe --dir ./pool/         test each .conf for DPI survival (ROUTERS-tagged first)
ovpn-pbr wg probe --dir ./pool/ --stream  same, but emit NDJSON per endpoint as it finishes
ovpn-pbr wg warp  [--wgcf-url URL]      register Cloudflare WARP via wgcf, apply as WG peer
```

### OpenVPN

```text
ovpn-pbr ovpn set   --config x.ovpn    install .ovpn (patched for split-tunnel), restart
ovpn-pbr ovpn probe --dir ./pool/      test each .ovpn, return first that survives DPI
```

### Diagnostics

```text
ovpn-pbr diagnose                       tun/wg state, PBR, nft set size, DNS
ovpn-pbr doctor                         self-check with PASS/WARN/FAIL + fix hints
ovpn-pbr logs [--follow] [--lines N] [--filter PATTERN]  stream router logread output
ovpn-pbr emergency-off                  disable kill-switch, stop VPN (restore raw WAN)
ovpn-pbr killswitch-on                  re-enable strict_enforcement
```

### Daemon

```text
ovpn-pbr daemon --pool ./pool/ [OPTIONS]
  --interval N          check every N seconds (default 60)
  --handshake-stale N   seconds before handshake is considered stale (default 300)
  --dead-ttl N          skip dead peer for N seconds (default 3600)
  --bad-threshold N     consecutive bad ticks before switching (default 3)
  --on-switch SCRIPT    called with old_peer new_peer on switch
  --on-fail SCRIPT      called with failed_peer on mark-dead
```

Long-running watchdog that monitors the active WireGuard peer and auto-switches to the next working candidate from the pool.

### Advanced / anti-DPI

```text
ovpn-pbr amnezia check              check kmod-amneziawg availability for your router arch
ovpn-pbr xray install               install Xray-core + configure VLESS+Reality
  --server IP --uuid UUID
  [--sni HOST] [--public-key KEY] [--short-id ID] [--fingerprint BROWSER]
```

### Keys

```text
ovpn-pbr keys install [--path PATH] [--force]   generate ed25519, install on router
ovpn-pbr keys store                              save password in OS keyring
ovpn-pbr keys test                               verify current credentials
```

### JSON output

Every command accepts `--json` for scripting:

```bash
ovpn-pbr --json diagnose | jq '.wireguard.rx_bytes'
ovpn-pbr --json doctor   | jq '.overall'
ovpn-pbr --json update   | jq '.new_ips | length'
```

## Web UI

The companion Next.js UI (`openwrt-pbr-vpn-ui`) provides a browser interface for all operations:

- **Dashboard** — VPN status cards, live traffic chart (rx/tx history via SQLite), emergency stop
- **Endpoints** — endpoint grid with probe badges; "Probe all" with real-time per-endpoint streaming
- **Routes** — nft set table, bulk-add panel, type badges (CIDR / HOST / IPv6)
- **Logs** — live `logread` stream with syslog parsing, pause/resume, highlight filter
- **Settings** — SSH + VPN config form backed by `router.conf`
- **Doctor** — self-check report with PASS/WARN/FAIL rows and fix hints

```bash
cd openwrt-pbr-vpn-ui
npm install
npm run dev        # http://localhost:3000
```

## DPI bypass

The probe commands test actual data-channel flow (`ping -I <iface> 8.8.8.8`) rather than kernel RX counters (which are always 0 for TUN devices). They detect the ТСПУ pattern — handshake succeeds, TX grows, RX stays ~0 — and skip affected endpoints automatically.

ROUTERS-tagged configs (from HideMyName or similar) are tried first. See [docs/03-anti-dpi.md](docs/03-anti-dpi.md) for the full picture.

## Documentation

- [docs/01-setup.md](docs/01-setup.md) — initial OpenWrt + PBR + VPN setup
- [docs/02-operations.md](docs/02-operations.md) — daily usage, automation, troubleshooting
- [docs/03-anti-dpi.md](docs/03-anti-dpi.md) — ТСПУ bypass: WireGuard ROUTERS, Xray, AmneziaWG, WARP

## Architecture

```text
your-PC                           OpenWrt router
────────────────                  ──────────────────────────────
ovpn-pbr update                   /etc/pbr.d/vpn-routes.sh  ← nft set elements
   │                              /etc/config/network        ← VPN interface (wg/ovpn)
   │  DoH (Google + Cloudflare)   /etc/config/pbr            ← PBR rules
   ├─► resolve domains.txt        /etc/wireguard/vpn-pool/   ← WG peer configs
   │                              /etc/openvpn/              ← OVPN profiles
   │  SSH (paramiko, no SFTP)     /etc/xray/config.json      ← Xray VLESS+Reality
   └─► push + restart PBR
```

Credentials stay on your machine. All router communication is SSH exec over your LAN.

## Requirements

- Python 3.10+
- OpenWrt with `luci-app-pbr`, `wireguard-tools` or `openvpn`
- Router SSH access (dropbear is fine — no SFTP needed)

## License

MIT. See [LICENSE](LICENSE).
