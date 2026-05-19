"""Self-check command that flags configuration problems with a fix hint.

Inspired by `brew doctor` / `cargo doctor` — runs a fixed battery of checks
and reports each as PASS/WARN/FAIL with an actionable suggestion.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

from .config import Config
from .output import get_logger
from .router import Router

log = get_logger("doctor")

Severity = Literal["pass", "warn", "fail"]


@dataclass
class Check:
    name: str
    status: Severity
    detail: str
    fix: str | None = None


@dataclass
class DoctorReport:
    host: str
    checks: list[Check] = field(default_factory=list)

    @property
    def overall(self) -> Severity:
        if any(c.status == "fail" for c in self.checks):
            return "fail"
        if any(c.status == "warn" for c in self.checks):
            return "warn"
        return "pass"

    @property
    def summary(self) -> dict[str, int]:
        return {
            "pass": sum(1 for c in self.checks if c.status == "pass"),
            "warn": sum(1 for c in self.checks if c.status == "warn"),
            "fail": sum(1 for c in self.checks if c.status == "fail"),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "overall": self.overall,
            "summary": self.summary,
            "checks": [asdict(c) for c in self.checks],
        }


def _check_ssh(r: Router) -> Check:
    res = r.run("uname -a", timeout=10)
    if res.ok and res.stdout.strip():
        return Check("ssh_auth", "pass", f"SSH OK: {res.stdout.strip()}")
    return Check(
        "ssh_auth",
        "fail",
        "SSH connected but `uname` failed",
        "Check that the user has shell access; some routers disable it for non-root users.",
    )


def _check_pbr_package(r: Router) -> Check:
    res = r.run(
        "which service && service pbr status >/dev/null 2>&1 || apk list --installed 2>/dev/null | grep -q '^pbr-'"
    )
    if res.ok:
        return Check("pbr_installed", "pass", "pbr package present")
    return Check(
        "pbr_installed",
        "fail",
        "pbr package not found",
        "Run on the router: apk add pbr luci-app-pbr",
    )


def _check_pbr_running(r: Router) -> Check:
    res = r.run("service pbr status 2>&1 | head -3")
    if "pbr " in res.stdout:
        return Check("pbr_running", "pass", "PBR service is running")
    return Check(
        "pbr_running",
        "fail",
        "PBR not running",
        "Run on the router: service pbr enable && service pbr restart",
    )


def _check_vpn_interface(r: Router, cfg: Config) -> Check:
    res = r.run(f"ip link show {cfg.vpn_interface} 2>&1 | head -1")
    if "does not exist" in res.stdout:
        return Check(
            "vpn_interface",
            "fail",
            f"Interface '{cfg.vpn_interface}' not configured",
            "Configure WireGuard with `ovpn-pbr wg set --config peer.conf` or OpenVPN with `ovpn-pbr ovpn set`.",
        )
    if "UP" in res.stdout:
        return Check("vpn_interface", "pass", f"{cfg.vpn_interface} is UP")
    return Check(
        "vpn_interface",
        "warn",
        f"{cfg.vpn_interface} exists but is DOWN",
        "Run on the router: ifup " + cfg.vpn_interface,
    )


def _check_firewall_zone(r: Router, cfg: Config) -> Check:
    """`vpnclient` must live in the WAN zone (masquerade=1, lan->wan forward).

    If it sits in a separate 'vpn' zone with forward=REJECT (default of the
    luci-app-pbr wizard), LAN traffic to VPN-set IPs gets dropped.
    """
    out = r.run("uci show firewall").stdout
    vpn_zone_name = None
    for line in out.splitlines():
        if cfg.vpn_interface in line and ".network=" in line:
            # firewall.@zone[2].network='vpnclient'
            idx = line.split("[")[1].split("]")[0]
            name = r.uci_get(f"firewall.@zone[{idx}].name") or ""
            vpn_zone_name = name
            break
    if vpn_zone_name == "wan":
        return Check("firewall_zone", "pass", "vpnclient in WAN zone")
    if vpn_zone_name is None:
        return Check(
            "firewall_zone",
            "fail",
            f"{cfg.vpn_interface} not in any firewall zone",
            "Add to WAN zone: uci add_list firewall.@zone[1].network='vpnclient' && uci commit firewall && fw4 reload",
        )
    return Check(
        "firewall_zone",
        "warn",
        f"{cfg.vpn_interface} in zone '{vpn_zone_name}' (not 'wan')",
        "Move to WAN zone — see docs/02-operations.md §4 for full procedure.",
    )


def _check_nft_set(r: Router, cfg: Config) -> Check:
    res = r.run(f"nft list set inet fw4 {cfg.nft_set} 2>&1")
    if "No such file" in res.stdout or "does not exist" in res.stdout or not res.ok:
        return Check(
            "nft_set",
            "fail",
            f"nft set {cfg.nft_set} doesn't exist",
            "PBR creates it when the VPN interface is up. Bring up the VPN first.",
        )
    count_res = r.run(f"nft list set inet fw4 {cfg.nft_set} | grep -c '\\.'")
    n = int(count_res.stdout.strip() or 0)
    if n == 0:
        return Check("nft_set", "warn", "nft set exists but is empty", "Run: ovpn-pbr update")
    if n < 5:
        return Check(
            "nft_set",
            "warn",
            f"nft set has only {n} entries — likely empty seed",
            "Run: ovpn-pbr update",
        )
    return Check("nft_set", "pass", f"nft set has {n} dotted lines")


def _check_wan_reach(r: Router) -> Check:
    res = r.run("ping -c 2 -W 2 1.1.1.1 | tail -2")
    if "0 packets received" in res.stdout or "0 received" in res.stdout:
        return Check(
            "wan_reachable",
            "fail",
            "Cannot reach 1.1.1.1 over WAN",
            "Check WAN: ifstatus wan; logread | tail -50",
        )
    return Check("wan_reachable", "pass", "WAN can reach 1.1.1.1")


def _check_strict_enforcement(r: Router) -> Check:
    val = r.uci_get("pbr.config.strict_enforcement")
    if val == "1":
        return Check("strict_enforcement", "pass", "kill-switch ON (strict_enforcement=1)")
    return Check(
        "strict_enforcement",
        "warn",
        f"kill-switch OFF (strict_enforcement={val!r}). Traffic for VPN-set IPs leaks via WAN if VPN drops.",
        "Run: ovpn-pbr killswitch-on",
    )


def _check_routes_table(r: Router, cfg: Config) -> Check:
    res = r.run(f"ip route show table pbr_{cfg.vpn_interface} 2>&1 | head -3")
    if "default" in res.stdout:
        return Check("pbr_route_table", "pass", f"pbr_{cfg.vpn_interface} has default route")
    return Check(
        "pbr_route_table",
        "warn",
        f"pbr_{cfg.vpn_interface} has no default route",
        "PBR rebuilds this when VPN comes up. Try: service pbr restart",
    )


# Threshold constants for ТСПУ detection
_TSPU_TX_RX_RATIO = 100  # TX must be >100x RX
_TSPU_TX_MIN_BYTES = 50 * 1024  # TX must exceed 50 KB


def _parse_wg_transfer(wg_raw: str) -> tuple[int, int]:
    """Return (rx_bytes, tx_bytes) from `wg show` output; both 0 if not found."""
    m = re.search(
        r"transfer:\s+([\d.]+)\s+(\w+)\s+received,\s+([\d.]+)\s+(\w+)\s+sent",
        wg_raw,
    )
    if not m:
        return 0, 0
    units = {"B": 1, "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3, "TiB": 1024**4}
    rx = int(float(m.group(1)) * units.get(m.group(2), 1))
    tx = int(float(m.group(3)) * units.get(m.group(4), 1))
    return rx, tx


def _check_tspu_data_channel(r: Router, cfg: Config) -> Check:
    """Detect the Russian ТСПУ (DPI) pattern: handshake OK but RX ~0 while TX grows."""
    wg_raw = r.run(f"wg show {cfg.vpn_interface} 2>&1").stdout

    if "interface:" not in wg_raw:
        # WireGuard not active — skip this check
        return Check(
            "tspu_data_channel",
            "pass",
            "WireGuard not active — ТСПУ check skipped",
        )

    has_handshake = "latest handshake:" in wg_raw
    if not has_handshake:
        return Check(
            "tspu_data_channel",
            "pass",
            "No WireGuard handshake yet — ТСПУ check not applicable",
        )

    rx_bytes, tx_bytes = _parse_wg_transfer(wg_raw)
    tx_kb = tx_bytes // 1024
    rx_kb = rx_bytes // 1024

    suspicious = (tx_bytes > _TSPU_TX_MIN_BYTES and rx_bytes == 0) or (
        rx_bytes > 0
        and tx_bytes > _TSPU_TX_RX_RATIO * rx_bytes
        and tx_bytes > _TSPU_TX_MIN_BYTES
    )

    if suspicious:
        return Check(
            "tspu_data_channel",
            "warn",
            (
                f"VPN data channel may be blocked by ТСПУ (DPI): "
                f"TX={tx_kb}KB, RX={rx_kb}KB — asymmetric traffic pattern. "
                "Handshake passes but reply traffic is dropped."
            ),
            (
                "Run 'ovpn-pbr wg probe --dir ./vpn-pool/' to find a working endpoint, "
                "or try ROUTERS-tagged servers from your provider."
            ),
        )

    return Check(
        "tspu_data_channel",
        "pass",
        f"Data channel traffic looks normal: TX={tx_kb}KB, RX={rx_kb}KB",
    )


CHECKS: list[Callable[..., Check]] = [
    _check_ssh,
    _check_pbr_package,
    _check_pbr_running,
    _check_vpn_interface,
    _check_firewall_zone,
    _check_nft_set,
    _check_wan_reach,
    _check_strict_enforcement,
    _check_routes_table,
    _check_tspu_data_channel,
]


def run(cfg: Config) -> DoctorReport:
    """Execute all checks against `cfg.host` and return a report."""
    report = DoctorReport(host=cfg.host)
    with Router(cfg) as r:
        for check_fn in CHECKS:
            try:
                # Pass cfg if the function takes it
                code = check_fn.__code__
                if "cfg" in code.co_varnames[: code.co_argcount]:
                    c = check_fn(r, cfg)
                else:
                    c = check_fn(r)
            except Exception as e:
                c = Check(
                    check_fn.__name__.lstrip("_"),
                    "fail",
                    f"check exploded: {e}",
                    "Inspect logs / re-run with -v",
                )
            report.checks.append(c)
    return report


def format_human(report: DoctorReport) -> str:
    """Pretty-print a DoctorReport for terminal output."""
    icons = {"pass": "✓", "warn": "!", "fail": "✗"}
    lines = [
        f"doctor: {report.host}  [{report.overall.upper()}]",
        f"  pass={report.summary['pass']}  warn={report.summary['warn']}  fail={report.summary['fail']}",
        "",
    ]
    for c in report.checks:
        lines.append(f"  [{icons[c.status]}] {c.name}: {c.detail}")
        if c.status != "pass" and c.fix:
            lines.append(f"      → {c.fix}")
    return "\n".join(lines)
