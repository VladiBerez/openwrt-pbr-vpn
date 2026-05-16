"""Health checks and emergency procedures."""
from __future__ import annotations

from .config import Config
from .router import Router


def diagnose(cfg: Config) -> None:
    """Run a battery of checks and print results."""
    with Router(cfg) as r:
        sections = [
            ("Interface (tun0)", "ip link show tun0 2>&1 | head -2"),
            (f"Interface ({cfg.vpn_interface})", f"ip link show {cfg.vpn_interface} 2>&1 | head -2"),
            ("WireGuard state", f"wg show {cfg.vpn_interface} 2>&1"),
            ("PBR status", "service pbr status 2>&1 | head -20"),
            ("PBR table", f"ip route show table pbr_{cfg.vpn_interface} 2>&1 | head -3"),
            ("nft set size", f"nft list set inet fw4 {cfg.nft_set} 2>&1 | grep -c '\\.'"),
            ("WAN ping (8.8.8.8)", "ping -c 2 -W 2 8.8.8.8 2>&1 | tail -2"),
            ("Firewall zones", "uci show firewall | grep -E 'name|network|masq' | head -20"),
            ("Last OpenVPN log", "logread | grep -i openvpn | tail -5"),
        ]
        for title, cmd in sections:
            print(f"\n=== {title} ===")
            res = r.run(cmd)
            for line in res.stdout.splitlines():
                print(f"  {line}")


def emergency_off(cfg: Config) -> None:
    """Disable kill-switch, stop the VPN — restore raw WAN connectivity for everyone."""
    print("Disabling PBR strict_enforcement and stopping VPN…")
    with Router(cfg) as r:
        r.uci_set("pbr.config.strict_enforcement", "0")
        r.uci_commit("pbr")
        r.run("service pbr restart")
        r.run("service openvpn stop 2>/dev/null || true")
        r.run(f"ifdown {cfg.vpn_interface} 2>/dev/null || true")
        print("✓ Kill-switch off. All traffic now via WAN (blocked services unreachable).")
        # Quick WAN sanity check
        wan = r.run("ping -c 2 -W 2 1.1.1.1 | tail -2")
        for line in wan.stdout.splitlines():
            print(f"  {line}")


def enable_killswitch(cfg: Config) -> None:
    with Router(cfg) as r:
        r.uci_set("pbr.config.strict_enforcement", "1")
        r.uci_commit("pbr")
        r.run("service pbr restart")
        print("✓ strict_enforcement=1 — VPN-set IPs will be dropped if VPN is down.")
