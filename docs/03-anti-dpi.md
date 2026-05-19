# 03. When the VPN itself gets blocked (anti-DPI playbook)

The Russian DPI infrastructure ("ТСПУ") evolved from blocking specific sites by IP to active protocol detection. Starting 15 May 2026, plain OpenVPN and WireGuard handshakes pass through, but the **data channel** is selectively dropped right after — you'll see `tun0` up, `wg show` reports a successful handshake, then nothing flows.

HideMyName rotated endpoints within ~48 hours of the initial block (17 May 2026). However ТСПУ continues to update its heuristics, so new blocks can appear at any time. **Download fresh `.conf` files from your provider when probing fails**, then re-run `wg probe` or use the Web UI.

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
ovpn-pbr wg probe --dir ./vpn-pool/
ovpn-pbr ovpn probe --dir ./vpn-pool/
```

Or use the Web UI: **Endpoints → Probe all**. The UI calls `/api/probe` which runs `wg probe --dir $VPN_POOL_DIR` with a 5-minute timeout and shows the winner inline.

The probe applies each config, generates a few seconds of test traffic, and only accepts an endpoint if the RX counter actually grows past a threshold. Stops at the first survivor.

---

## 4. What doesn't help (don't waste time)

- ❌ Switching country on **regular** endpoints (S1/S2/H12 etc.) — usually all blocked alike when DPI is active.
- ❌ Switching OpenVPN obfuscation (`Without obfuscation` / `tls-crypt` / `tls-crypt-v2`) on **regular** endpoints — the data channel is still detectable. `tls-crypt-v2` obfuscates the control channel only; `P_DATA_V2` packets remain fingerprinted.
- ❌ UDP → TCP — same protocol fingerprint, same fate.
- ❌ MTU tuning (1280, 1400, 1420) — DPI doesn't care about packet size.
- ❌ Restarting the router / VPN service.
- ❌ Using `ip -s link show tun0 RX` as a data-flow test — **this counter is always 0 for TUN devices** even when data flows fine. Use `ping -I tun0` or OpenVPN `status` file (`TUN/TAP write bytes`) instead.

---

## 5. What actually helps

In order of effort vs. payoff:

### A. Wait it out + look for ROUTERS-tagged endpoints

VPN providers (HideMyName, Mullvad, etc.) usually roll new endpoints within 24–48 hours. Subscribe to their status channel and re-download `.conf` files when they announce fixes.

**HideMyName-specific:** when standard servers are blocked, look for **`ROUTERS`-tagged servers** in the download page (e.g. `Belgium, Brussels ROUTERS6`, `Croatia, Zagreb ROUTERS3`, `Moldova, Chisinau ROUTERS2`). These are dedicated router-facing endpoints with different routing paths. Confirmed working on 19 May 2026 when all S1/S2/H12 endpoints were dead:

| Server | Port | tls-crypt-v2 | Ping |
|---|---|---|---|
| Belgium, Brussels ROUTERS6 | 58989 | ✓ | 79ms 0% loss |
| Croatia, Zagreb ROUTERS3 | 56752 | ✓ | 91ms |
| Moldova, Chisinau ROUTERS2 | 60101 | ✓ | 116ms |

Download the `tls-crypt-v2 (OpenVPN 2.5+)` pack from your HideMyName account. OpenWrt ships OpenVPN **2.6.x** which supports it.

Swap the config:

```bash
ovpn-pbr ovpn probe --dir ./vpn-pool/   # finds the first working config
ovpn-pbr ovpn set --config <winner>.ovpn
```

### B. Cloudflare WARP via `wgcf`

The easiest path is the `warp` subcommand, which handles everything from the workstation:

```bash
ovpn-pbr wg warp
```

This downloads `wgcf` onto the router, registers a free WARP account, generates a WireGuard config, and applies it as `vpnclient` — all in one step. No manual SSH session needed. For non-MIPS routers, pass the correct binary URL:

```bash
# arm64 (Raspberry Pi, some newer routers):
ovpn-pbr wg warp --wgcf-url https://github.com/ViRb3/wgcf/releases/latest/download/wgcf_linux_arm64
```

If you prefer to do it manually on the router:

```sh
apk add wgcf
wgcf register
wgcf generate
# Then copy the resulting wgcf-profile.conf to the workstation and:
ovpn-pbr wg set --config wgcf-profile.conf
```

Why WARP sometimes works when regular VPNs don't: WARP sends WireGuard traffic to Cloudflare infrastructure on **UDP port 2408**. This port and Cloudflare's IP ranges are often treated differently by ТСПУ heuristics (Cloudflare powers half the internet; blanket-blocking it has collateral damage). The WireGuard fingerprint is also subtly different from a typical VPN peer. ~50% success rate. Free tier is sufficient for most routing use cases.

### C. Xray VLESS + Reality (most robust)

Reality is the current state-of-the-art for evading ТСПУ. The trick: client and server both speak real TLS to a "decoy" domain (`www.microsoft.com`, `www.amd.com`, etc.) — for DPI it looks indistinguishable from a regular HTTPS connection. The Reality protocol injects the actual proxy session inside that TLS stream using the user's UUID.

Requirements:

- A VPS outside Russia ($3–5/month is plenty)
- A Reality server (3X-UI is the easy GUI)
- The `ovpn-pbr xray install` command handles the router side

#### Automated install

```bash
ovpn-pbr xray install --server YOUR_VPS_IP --uuid YOUR_UUID
```

This:

1. Downloads the `xray-core` binary onto the router.
2. Writes a VLESS+Reality client config with a **SOCKS5 inbound on `127.0.0.1:1080`**.
3. Registers a `procd` init service so Xray starts on boot and restarts on crash.

Additional flags you may need to match your server's Reality settings:

| Flag | Default | Description |
|------|---------|-------------|
| `--sni DOMAIN` | `www.microsoft.com` | The "decoy" domain Reality impersonates |
| `--public-key KEY` | _(required if non-default)_ | Reality server public key |
| `--short-id ID` | _(required if non-default)_ | Reality short ID |
| `--fingerprint FP` | `chrome` | TLS client fingerprint (`chrome`, `firefox`, `safari`, `ios`, `random`) |

Example with all flags:

```bash
ovpn-pbr xray install \
  --server 185.100.200.50 \
  --uuid xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx \
  --public-key AbCdEfGh123456... \
  --short-id 0123abcd \
  --sni www.microsoft.com \
  --fingerprint chrome
```

#### Why Reality works

Reality mimics the TLS handshake of a real website (default: `www.microsoft.com`). From the DPI perspective, the packet stream is indistinguishable from a normal HTTPS session to Microsoft. The actual VLESS payload is tunnelled inside that TLS session using the user's UUID as an authentication token. No server certificate to detect, no unusual port patterns — the traffic fingerprint matches a browser visiting a popular site.

#### Server setup (VPS)

```sh
bash <(curl -Ls https://raw.githubusercontent.com/MHSanaei/3x-ui/master/install.sh)
# Through the web panel, create a VLESS+Reality inbound. Copy the UUID, public key, and short ID.
# Then run ovpn-pbr xray install with those values.
```

See [3X-UI docs](https://github.com/MHSanaei/3x-ui) and [Reality protocol spec](https://github.com/XTLS/REALITY) for server-side configuration details.

### D. AmneziaVPN

A Russian project specifically built for ТСПУ evasion. They offer:

- **AmneziaWG** — WireGuard with `Junk` packets prepended to handshake (Wireshark sees random UDP, not WG). Requires `amneziawg-tools` and `kmod-amneziawg` on the router.
- **OpenVPN over Cloak** — OpenVPN wrapped in fake-TLS that looks like HTTPS to a real website.

#### Checking kernel module availability before installing

The most common failure point is `kmod-amneziawg` not being available for your router's architecture/kernel combination. Check before attempting an install:

```bash
ovpn-pbr amnezia check
```

This queries the relevant APK repositories for your router's exact arch and kernel version and reports:

- Whether `amneziawg-tools` is available
- Whether `kmod-amneziawg` is available (the critical piece)
- The exact package version that would be installed

If `kmod-amneziawg` is not found, the command says so clearly rather than letting `apk add` fail silently mid-install. In that case you'll need to compile the module from source (see [Slava-Shchipunov/awg-openwrt](https://github.com/Slava-Shchipunov/awg-openwrt)).

**Router availability (as of May 2026):** `amneziawg-tools` pre-built `.apk` packages exist for most architectures. However **`kmod-amneziawg` is not available** for `mediatek/mt7622` (and several other targets) — must be compiled from source against the exact kernel version. Without the kernel module, the tools do nothing. Standard WireGuard without AmneziaWG obfuscation: handshake sometimes passes, but ТСПУ kills the data channel within seconds.

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
