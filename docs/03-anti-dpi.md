# 03. When the VPN itself gets blocked (anti-DPI playbook)

The Russian DPI infrastructure ("ТСПУ") evolved from blocking specific sites by IP to active protocol detection. As of mid-May 2026, plain OpenVPN and WireGuard handshakes pass through, but the **data channel** is selectively dropped right after — you'll see `tun0` up, `wg show` reports a successful handshake, then nothing flows.

This document covers diagnosis and known workarounds.

---

## 1. Symptom matrix

| Behaviour | Likely cause |
|---|---|
| `service openvpn restart` → `TLS handshake failed` after 60s | DPI blocks TLS handshake of OpenVPN. Try another server / port / `tls-crypt-v2`. |
| OpenVPN: `Initialization Sequence Completed`, but `ping -I tun0` returns 100% loss | DPI blocks **data channel** after handshake passes. Worst case — try WireGuard or Xray. |
| WireGuard: `wg show` shows recent handshake, `received: 3 KiB / sent: 1 MiB` (asymmetric) | Same — handshake leaked through but reply data is being dropped. |
| Endpoint pings normally (ICMP) but VPN data doesn't flow | Confirms it's protocol-layer DPI, not IP-layer blocking of the endpoint. |
| Some specific endpoint works, others don't (same provider) | DPI maintains per-endpoint heuristics — try new endpoints. |

---

## 2. Diagnosis sequence

```bash
ovpn-pbr diagnose
```

Look at the **`wg show vpnclient`** block specifically:

- `latest handshake: 30 seconds ago` (or similar, recent) — control channel OK
- `transfer: <RX> received, <TX> sent` — **this is the key signal**

If `RX` is tiny (a few KB, never grows) while `TX` keeps growing — DPI is killing your reply traffic. The tunnel is "up" only in the WireGuard sense; it carries nothing.

Direct test:

```sh
# On the router:
ping -c 5 <vpn_endpoint_ip>    # should work (ICMP)
wg show vpnclient transfer     # rx counter
# Generate traffic from a LAN client to anything blocked, wait 10 seconds,
# check wg show transfer again. If rx didn't grow → blocked.
```

---

## 3. Probe automation

When your provider gives you a folder of country configs, brute-force test them:

```bash
ovpn-pbr wg probe --dir ./hideme/wireguard/
ovpn-pbr ovpn probe --dir ./hideme/openvpn/
```

This applies each config, generates a few seconds of test traffic, and only accepts an endpoint if the RX counter actually grows past a threshold. Stops at the first survivor.

---

## 4. What doesn't help (don't waste time)

- ❌ Switching country (Croatia → Germany → Estonia → USA) — usually all blocked alike when DPI is active.
- ❌ Switching OpenVPN obfuscation between `Without obfuscation` / `tls-crypt` / `tls-crypt-v2` — all detectable.
- ❌ UDP → TCP — same protocol fingerprint, same fate.
- ❌ MTU tuning (1280, 1400, 1420) — DPI doesn't care about packet size.
- ❌ Restarting the router / VPN service.

---

## 5. What actually helps

In order of effort vs. payoff:

### A. Wait it out

VPN providers (HideMyName, Mullvad, etc.) usually roll new endpoints within 24–48 hours. Subscribe to their status channel and re-download `.conf` files when they announce fixes.

The router config doesn't need to change — just swap the peer:

```bash
ovpn-pbr wg set --config new-peer.conf
```

### B. Cloudflare WARP via `wgcf`

```sh
# On the router:
apk add wgcf
wgcf register
wgcf generate
```

This produces a standard WireGuard `.conf` pointing at Cloudflare's `engage.cloudflareclient.com` endpoint. Cloudflare's IPs sometimes survive ТСПУ heuristics better than commercial VPN providers because their fingerprint is different. ~50% success rate. Free.

### C. Xray VLESS + Reality (most robust)

Reality is the current state-of-the-art for evading ТСПУ. The trick: client and server both speak real TLS to a "decoy" domain (`www.microsoft.com`, `www.amd.com`, etc.) — for DPI it looks indistinguishable from a regular HTTPS connection. The Reality protocol injects the actual proxy session inside that TLS stream using the user's UUID.

Requirements:

- A VPS outside Russia ($3–5/month is plenty)
- `xray-core` on the router (`apk add xray-core`)
- A Reality server (3X-UI is the easy GUI)

Quick server setup (on the VPS, Debian/Ubuntu):

```sh
bash <(curl -Ls https://raw.githubusercontent.com/MHSanaei/3x-ui/master/install.sh)
# Through the web panel, create a VLESS+Reality user. Save the generated client URI.
```

The router needs `xray-core` running as a SOCKS5/HTTP front-end with a VLESS outbound; configure PBR to route via the resulting proxy. Out of scope for this playbook — see [3X-UI docs](https://github.com/MHSanaei/3x-ui).

### D. AmneziaVPN

A Russian project specifically built for ТСПУ evasion. They offer:

- **AmneziaWG** — WireGuard with `Junk` packets prepended to handshake (Wireshark sees random UDP, not WG). Requires `amneziawg-tools` and `kmod-amneziawg` on the router — **not** in stock OpenWrt 25.x feeds yet.
- **OpenVPN over Cloak** — OpenVPN wrapped in fake-TLS that looks like HTTPS to a real website.

Self-hosted on a $3 VPS. Setup via their desktop app (which generates server-side config and client URIs).

### E. Stunnel-wrapped OpenVPN

Wrap OpenVPN-TCP inside a TLS tunnel that points to your VPS on port 443. From DPI's perspective it's HTTPS. `apk add stunnel` on the router; needs a `stunnel.conf` and a `.crt`/`.key` matching the server side.

Lower ceiling than Xray Reality but easier to set up and entirely free.

---

## 6. Decision tree

```text
VPN stopped working
├── ICMP to endpoint works?
│   ├── No  → endpoint blocked, change endpoint / provider
│   └── Yes
│       ├── WireGuard handshake completes?
│       │   ├── No  → DPI eats handshake; try Xray/Amnezia
│       │   └── Yes
│       │       ├── `wg show` RX growing with traffic?
│       │       │   ├── Yes → tunnel works, fix DNS/firewall/PBR
│       │       │   └── No  → DPI eats data channel; try a different endpoint, then Xray/Amnezia
```

Most "VPN suddenly broke" reports in May–June 2026 ended at the "DPI eats data channel, switch to Xray" branch.

---

## 7. Permanent move to Xray (sketch)

When you commit to Xray as the primary tunnel:

1. Replace `vpnclient` interface in `/etc/config/network` with a dummy that just keeps the name (PBR still references it for the nft-set).
2. Add a SOCKS5/redirect-mode Xray inbound listening locally (e.g. `127.0.0.1:1080` or TPROXY).
3. Change PBR to route packets to a local mark that `iptables`/`nftables` redirects into Xray instead of `tun0`.
4. Xray outbound = VLESS+Reality → your VPS → internet.

This is more involved than swapping a `.conf`, but it's the most resilient option against the current generation of DPI. There's a [companion guide planned] in this repo — feel free to PR.

---

## 8. Tools and links

- HideMyName status: <https://t.me/hidemyname_ru>
- Amnezia: <https://amnezia.org>
- Cloudflare WARP via wgcf: <https://github.com/ViRb3/wgcf>
- 3X-UI (Xray panel): <https://github.com/MHSanaei/3x-ui>
- Reality protocol spec: <https://github.com/XTLS/REALITY>
- ТСПУ technical analysis: <https://ntc.party/>
