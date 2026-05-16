"""Health checks and emergency procedures."""
from __future__ import annotations

import re
from typing import Any

from .config import Config
from .output import fmt_age, fmt_bytes, get_logger
from .router import Router

log = get_logger("diagnose")


def collect_state(cfg: Config) -> dict[str, Any]:
    """Gather a structured snapshot of router/VPN/PBR state.

    Returns a dict suitable for JSON output. Each section is independent:
    if a check fails (e.g. WireGuard isn't running), the corresponding
    key is None / empty rather than the whole call exploding.
    """
    state: dict[str, Any] = {
        "host": cfg.host,
        "vpn_interface": cfg.vpn_interface,
        "nft_set": cfg.nft_set,
    }
    with Router(cfg) as r:
        # WireGuard
        wg_raw = r.run(f"wg show {cfg.vpn_interface} 2>&1").stdout
        state["wireguard"] = _parse_wg_show(wg_raw) if "interface:" in wg_raw else None

        # tun0 (OpenVPN style)
        tun = r.run("ip link show tun0 2>&1 | head -1").stdout
        state["tun0_up"] = "UP" in tun and "does not exist" not in tun

        # vpnclient L3
        iface = r.run(f"ip link show {cfg.vpn_interface} 2>&1 | head -1").stdout
        state["vpn_interface_up"] = "UP" in iface and "does not exist" not in iface

        # PBR
        state["pbr_running"] = r.run("pidof pbr >/dev/null 2>&1").rc == 0 or (
            r.run("service pbr status 2>&1 | head -3").stdout.find("pbr ") != -1
        )
        state["pbr_strict_enforcement"] = r.uci_get("pbr.config.strict_enforcement") == "1"

        # nft set size
        cnt = r.run(f"nft list set inet fw4 {cfg.nft_set} 2>/dev/null | grep -c '\\.'").stdout.strip()
        state["nft_set_dots"] = int(cnt) if cnt.isdigit() else 0

        # WAN ping
        wan = r.run("ping -c 2 -W 2 8.8.8.8 2>&1 | tail -2").stdout
        state["wan_ping"] = "0 packets received" not in wan and "0 received" not in wan

        # OpenVPN profile (if any enabled)
        ovpn = r.run("uci show openvpn 2>&1 | grep 'enabled=.1.' | head -1").stdout.strip()
        state["openvpn_enabled_profile"] = ovpn.split(".")[1] if ovpn and "openvpn." in ovpn else None
    return state


_WG_INT_RE = re.compile(r"^interface:\s+(\S+)", re.MULTILINE)
_WG_PEER_RE = re.compile(r"^peer:\s+(\S+)", re.MULTILINE)
_WG_ENDPOINT_RE = re.compile(r"^\s+endpoint:\s+(\S+)", re.MULTILINE)
_WG_HANDSHAKE_RE = re.compile(r"^\s+latest handshake:\s+(.+?)$", re.MULTILINE)
_WG_TRANSFER_RE = re.compile(
    r"^\s+transfer:\s+([\d.]+)\s+(\w+)\s+received,\s+([\d.]+)\s+(\w+)\s+sent",
    re.MULTILINE,
)


def _parse_wg_show(text: str) -> dict[str, Any]:
    """Parse output of `wg show <iface>` into a dict."""
    m_int = _WG_INT_RE.search(text)
    m_peer = _WG_PEER_RE.search(text)
    m_endpoint = _WG_ENDPOINT_RE.search(text)
    m_hs = _WG_HANDSHAKE_RE.search(text)
    m_tx = _WG_TRANSFER_RE.search(text)

    rx_bytes = tx_bytes = 0
    if m_tx:
        rx_bytes = _human_to_bytes(float(m_tx.group(1)), m_tx.group(2))
        tx_bytes = _human_to_bytes(float(m_tx.group(3)), m_tx.group(4))

    return {
        "interface": m_int.group(1) if m_int else None,
        "peer": m_peer.group(1) if m_peer else None,
        "endpoint": m_endpoint.group(1) if m_endpoint else None,
        "latest_handshake": m_hs.group(1).strip() if m_hs else None,
        "rx_bytes": rx_bytes,
        "tx_bytes": tx_bytes,
    }


def _human_to_bytes(n: float, unit: str) -> int:
    units = {"B": 1, "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3, "TiB": 1024**4}
    return int(n * units.get(unit, 1))


def format_human(state: dict[str, Any]) -> str:
    """Pretty-print state dict for terminal."""
    lines = [f"=== {state['host']} ==="]
    lines.append(f"VPN interface ({state['vpn_interface']}): "
                 f"{'UP' if state['vpn_interface_up'] else 'DOWN'}")
    lines.append(f"tun0: {'UP' if state['tun0_up'] else 'DOWN'}")

    wg = state.get("wireguard")
    if wg:
        lines.append("WireGuard:")
        lines.append(f"  endpoint: {wg['endpoint']}")
        lines.append(f"  handshake: {wg['latest_handshake']}")
        lines.append(
            f"  rx={fmt_bytes(wg['rx_bytes'])} tx={fmt_bytes(wg['tx_bytes'])}"
        )
    else:
        lines.append("WireGuard: not active")

    lines.append(f"PBR: {'running' if state['pbr_running'] else 'NOT running'}, "
                 f"strict={'ON' if state['pbr_strict_enforcement'] else 'off'}")
    lines.append(f"nft set lines (dotted): {state['nft_set_dots']}")
    lines.append(f"WAN: {'OK' if state['wan_ping'] else 'NO REPLY'}")
    if state.get("openvpn_enabled_profile"):
        lines.append(f"OpenVPN profile enabled: {state['openvpn_enabled_profile']}")
    return "\n".join(lines)


def diagnose(cfg: Config) -> dict[str, Any]:
    """High-level diagnose: returns state dict."""
    return collect_state(cfg)


def emergency_off(cfg: Config) -> dict[str, Any]:
    """Disable kill-switch, stop the VPN — restore raw WAN connectivity for everyone."""
    log.info("Disabling PBR strict_enforcement and stopping VPN…")
    result: dict[str, Any] = {"actions": []}
    with Router(cfg) as r:
        r.uci_set("pbr.config.strict_enforcement", "0")
        r.uci_commit("pbr")
        r.run("service pbr restart")
        result["actions"].append("pbr_strict_disabled")
        r.run("service openvpn stop 2>/dev/null || true")
        result["actions"].append("openvpn_stopped")
        r.run(f"ifdown {cfg.vpn_interface} 2>/dev/null || true")
        result["actions"].append("vpn_interface_down")
        wan = r.run("ping -c 2 -W 2 1.1.1.1 | tail -2")
        result["wan_ping_ok"] = "0 packets received" not in wan.stdout
    log.info("✓ Kill-switch off. All traffic now via WAN (blocked services unreachable).")
    return result


def enable_killswitch(cfg: Config) -> dict[str, Any]:
    with Router(cfg) as r:
        r.uci_set("pbr.config.strict_enforcement", "1")
        r.uci_commit("pbr")
        r.run("service pbr restart")
    log.info("✓ strict_enforcement=1 — VPN-set IPs will be dropped if VPN is down.")
    return {"strict_enforcement": "1"}
