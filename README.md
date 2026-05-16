# openwrt-pbr-vpn

Automated split-tunnel VPN management for **OpenWrt + PBR** routers. Resolves blocked-service domains through DoH (the way `rockblack.pro/ip-address` does in the browser, but headless), keeps an `nft` set up to date, and pushes everything to the router over SSH. Supports both OpenVPN and WireGuard, with probe/diagnose tooling for the DPI cat-and-mouse game.

## What problem this solves

You run **OpenWrt + PBR (`luci-app-pbr`) + a VPN (OpenVPN/WireGuard)** with a split-tunnel: most traffic goes straight through your ISP, but a curated list of IPs (Meta, Telegram, YouTube, AI services, etc.) gets routed through the VPN. Maintaining that list by hand is painful — IPs rotate, CDNs change, new services get blocked. This tool keeps it fresh.

## Quick start

```bash
git clone https://github.com/your-org/openwrt-pbr-vpn.git
cd openwrt-pbr-vpn
pip install -e .

# Set up creds (pick one):
ovpn-pbr keys install              # SSH key (recommended)
# OR
ovpn-pbr keys store                # OS keyring (Windows Credential Manager / macOS Keychain / Linux Secret Service)
# OR
cp .env.example .env && $EDITOR .env  # plain env file (less secure)

# Seed your domains and routes
cp config/domains.example.txt domains.txt
cp config/seed-routes.sh vpn-routes.sh

# First run
ovpn-pbr update                    # resolve domains, push to router, restart PBR
ovpn-pbr diagnose                  # verify VPN, set size, ping tests
```

## Commands

```text
ovpn-pbr update [--no-upload]       # resolve domains, dedupe vs existing CIDR, push, restart PBR
ovpn-pbr routes show                # list current nft set on router
ovpn-pbr routes add <CIDR|IP> ...   # manual additions
ovpn-pbr routes rm  <CIDR|IP> ...   # manual removals

ovpn-pbr wg set --config peer.conf  # configure WireGuard as the VPN interface
ovpn-pbr wg probe --dir ./configs/  # test multiple WG configs for DPI survival
ovpn-pbr wg show                    # current peer state, handshakes, transfer counters

ovpn-pbr ovpn set  --config x.ovpn  # configure OpenVPN as the VPN interface
ovpn-pbr ovpn probe --dir ./configs/

ovpn-pbr diagnose                   # tun/wg state, PBR, set size, route table
ovpn-pbr emergency-off              # disable kill-switch and stop VPN (restore raw WAN)
ovpn-pbr keys install               # generate + push SSH key to router
ovpn-pbr keys store                 # save router password in OS keyring
```

## Documentation

- [docs/01-setup.md](docs/01-setup.md) — initial OpenWrt + PBR + VPN setup (one-time)
- [docs/02-operations.md](docs/02-operations.md) — using this tool, automation, troubleshooting
- [docs/03-anti-dpi.md](docs/03-anti-dpi.md) — what to do when ТСПУ blocks your VPN (Xray, Amnezia, WARP)

## Architecture

```text
your-PC                       OpenWrt router
─────────                     ──────────────
ovpn-pbr update               /etc/pbr.d/vpn-routes.sh ← nft set elements
   │                          /etc/config/network       ← VPN interface
   │   DoH (Google + CF)      /etc/config/firewall      ← masq, zones
   ├─► resolve domains.txt    /etc/config/pbr           ← PBR config
   │                          /etc/openvpn/*.ovpn       ← OpenVPN profiles
   │   SSH exec               /etc/wireguard/           ← WG profiles
   └─► push + restart PBR
```

Credentials never leave your machine. Everything talks SSH to the router on your LAN.

## Why no SFTP

OpenWrt's default SSH daemon is `dropbear`, which does not include the SFTP subsystem. This tool writes files through plain `cat > path` over an exec channel — works on stock OpenWrt without installing extra packages.

## Status

Alpha. Used in production on one router. Tests cover the core logic (DoH, nft parsing, route deduplication). VPN switching and probe modules tested manually.

## License

MIT. See [LICENSE](LICENSE).
