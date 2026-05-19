# openwrt-pbr-vpn: CLI + Web UI for split-tunnel VPN on OpenWrt, with automatic DPI/ТСПУ detection

Hey r/openwrt. Built a tool for managing policy-based routing on OpenWrt routers where only blocked services go through VPN — everything else stays on the regular ISP path. Posting because the DPI detection piece might be of interest to people dealing with deep packet inspection blocks.

**Repo:** https://github.com/VladiBerez/openwrt-pbr-vpn  
**License:** MIT | **Requires:** Python 3.10+, OpenWrt with nftables

---

## The problem it solves

Full-tunnel VPN on a home router tanks latency for everything. Split-tunnel by domain is the better answer, but keeping the routing set current is tedious — blocked services change IPs, CDNs rotate, DoH helps but you need something to poll it automatically and push the nft set updates to the router over SSH.

On top of that, in some regions (Russia specifically) ISPs operate ТСПУ hardware that does stateful DPI. It lets the WireGuard handshake through, then silently drops the data channel. Your tunnel appears "up" — pings don't tell you anything — but traffic doesn't flow.

---

## DPI/ТСПУ detection

The probe doesn't rely on ICMP. It opens the WireGuard tunnel, then measures **TX vs RX byte counters** over a short interval. If TX climbs while RX stays near zero, the data channel is blocked at the ISP level. The handshake succeeded, but you're sending into a void.

Terminal output when a blocked endpoint is detected and skipped:

```
[probe] wg0  endpoint 185.x.x.x:51820
  tx_bytes: 48320 (+48320)  rx_bytes: 0 (+0)
[probe] ТСПУ pattern detected — rx stalled, tx growing
[probe] skipping endpoint 185.x.x.x:51820
[probe] trying next endpoint: 194.x.x.x:51820  [ROUTERS tag]
  tx_bytes: 1240 (+1240)  rx_bytes: 9870 (+9870)
[probe] endpoint OK — activating
```

ROUTERS-tagged endpoints in HideMyName are prioritized because they apply server-side patches specifically to survive ТСПУ.

---

## Escalation path when WireGuard is fully blocked

If WireGuard doesn't survive at all, the tool can step through:

1. WireGuard (default)
2. Cloudflare WARP via wgcf
3. Xray VLESS+Reality
4. AmneziaWG

Each step is tried automatically in daemon mode when the current peer degrades below threshold.

---

## Architecture notes

- **No agent on the router.** Everything runs on the host machine; the tool SSHes into the router using stock dropbear. No SFTP required.
- **Daemon mode** runs a watchdog loop: probes active endpoint, switches peers on degradation, keeps the nft routing set updated.
- **DoH resolution** keeps the IP set for blocked domains fresh without depending on the router's DNS.
- **Web UI** (Next.js) gives a dashboard with a live traffic chart, an endpoint probe panel with real-time streaming output, a log viewer, and settings. Useful if you don't want to stay in the terminal.

---

## Quick start

```bash
git clone https://github.com/VladiBerez/openwrt-pbr-vpn
cd openwrt-pbr-vpn
pip install -r requirements.txt
cp config.example.yml config.yml   # fill in router SSH + VPN credentials
python pbr.py probe                # run endpoint probes manually
python pbr.py daemon               # start watchdog
```

---

It's early but functional. Happy to answer questions about the ТСПУ detection logic or the nftables set management. PRs welcome.
