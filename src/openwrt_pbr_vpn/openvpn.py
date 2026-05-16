"""OpenVPN profile management on OpenWrt.

The router runs the standard `openvpn` service. Each profile lives at
`/etc/openvpn/<Name>.ovpn` and is wired up via `/etc/config/openvpn`.

For split-tunnel with PBR we patch each profile so it doesn't pull a
default route or DNS from the server — see `patch_for_split_tunnel`.
"""
from __future__ import annotations

import time
from pathlib import Path

from .config import Config
from .output import get_logger
from .router import Router

log = get_logger("openvpn")

SPLIT_TUNNEL_BLOCK = """
# === split-tunnel additions (managed by openwrt-pbr-vpn) ===
route-nopull
pull-filter ignore "redirect-gateway"
pull-filter ignore "dhcp-option DNS"
tun-mtu 1400
mssfix 1360
verb 5

"""


def patch_for_split_tunnel(conf_text: str) -> str:
    """Comment out `redirect-gateway` / `dhcp-option DNS` and prepend split-tunnel options.

    The block is inserted before the first `<ca>` tag so it lands in the
    main config section, not inside cert PEM blocks.
    """
    text = conf_text
    text = _comment(text, "redirect-gateway def1", "split-tunnel: PBR decides routes")
    text = _comment(text, "dhcp-option DNS 1.1.1.1", "split-tunnel: keep WAN DNS")
    text = _comment(text, "dhcp-option DNS 8.8.8.8", "split-tunnel: keep WAN DNS")
    if "<ca>" in text:
        text = text.replace("<ca>", SPLIT_TUNNEL_BLOCK + "<ca>", 1)
    else:
        text = text.rstrip() + "\n" + SPLIT_TUNNEL_BLOCK
    return text


def _comment(text: str, needle: str, why: str) -> str:
    if needle in text:
        text = text.replace(needle, f"#{needle}  # {why}")
    return text


def install(r: Router, cfg: Config, name: str, conf_text: str, *, patch: bool = True) -> str:
    """Upload an .ovpn profile (optionally patched) and register it in UCI.

    Disables all other OpenVPN profiles so only one is active at a time.
    Returns the remote path of the uploaded profile.
    """
    if patch:
        conf_text = patch_for_split_tunnel(conf_text)

    remote_path = f"/etc/openvpn/{name}.ovpn"
    r.upload_bytes(conf_text.encode("utf-8"), remote_path, mode=0o600)

    # List current configs and disable them all
    existing = r.run("uci show openvpn | grep '=openvpn$' | cut -d. -f2 | cut -d= -f1").stdout.split()
    for old in existing:
        r.uci_set(f"openvpn.{old}.enabled", "0")

    # Register/replace this one
    r.run(f"uci -q delete openvpn.{name}")
    r.run(f"uci set openvpn.{name}=openvpn", check=True)
    r.uci_set(f"openvpn.{name}.config", remote_path)
    r.uci_set(f"openvpn.{name}.enabled", "1")
    r.uci_commit("openvpn")
    return remote_path


def restart(r: Router) -> None:
    r.run("killall openvpn 2>/dev/null || true")
    time.sleep(2)
    r.run("service openvpn restart", check=True)


def wait_for_tun(r: Router, *, timeout: int = 90, interval: int = 5) -> bool:
    """Wait until tun0 device appears UP. Returns success."""
    elapsed = 0
    while elapsed < timeout:
        out = r.run("ip link show tun0 2>&1 | head -1").stdout
        if "UP" in out and "does not exist" not in out:
            return True
        time.sleep(interval)
        elapsed += interval
    return False


def last_log(r: Router, lines: int = 20) -> str:
    return r.run(f"logread | grep -i openvpn | tail -{lines}").stdout


def probe(
    r: Router,
    cfg: Config,
    profiles: list[tuple[str, Path]],
    *,
    handshake_timeout: int = 60,
) -> tuple[str, Path] | None:
    """Try each (name, path) in order, return the first one whose tun0 stays UP
    AND can ping out (via `ip route add 1.1.1.1 dev tun0`).
    """
    for name, path in profiles:
        log.info(f"\n--- probing OpenVPN {name} ({path.name}) ---")
        text = patch_for_split_tunnel(path.read_text(encoding="utf-8"))
        install(r, cfg, name, text, patch=False)
        restart(r)
        if not wait_for_tun(r, timeout=handshake_timeout):
            log.info(f"  {name}: tun0 never came up")
            continue
        r.run("ip route add 1.1.1.1/32 dev tun0 2>/dev/null || true")
        try:
            res = r.run("ping -c 3 -W 3 1.1.1.1 | tail -1")
            if "0 received" in res.stdout or "0 packets received" in res.stdout:
                log.info(f"  {name}: tun0 up but data channel dead")
                continue
            log.info(f"  *** {name} WORKS ***")
            return name, path
        finally:
            r.run("ip route del 1.1.1.1/32 dev tun0 2>/dev/null || true")
    return None
