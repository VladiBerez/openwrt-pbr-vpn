"""Parse and emit nft-set fragments used by `/etc/pbr.d/vpn-routes.sh`."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from pathlib import Path

# Captures the content inside `{ … }` of `nft add element inet fw4 $S "{ … }"`.
NFT_ELEMENT_RE = re.compile(r"\{([^}]*)\}")
IP_OR_CIDR_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?\b")


def parse_networks(routes_file: Path) -> list[ipaddress.IPv4Network]:
    """Extract all IPv4 networks (and single IPs as /32) from a vpn-routes.sh."""
    text = routes_file.read_text(encoding="utf-8", errors="ignore")
    nets: list[ipaddress.IPv4Network] = []
    for m in NFT_ELEMENT_RE.finditer(text):
        for token in IP_OR_CIDR_RE.findall(m.group(1)):
            try:
                nets.append(ipaddress.ip_network(token, strict=False))
            except ValueError:
                continue
    return nets


def is_covered(ip: str, networks: list[ipaddress.IPv4Network]) -> bool:
    """True if `ip` is already covered by any of the given networks.

    Invalid / non-IPv4 inputs return True (i.e. "skip it") so callers can
    filter without try/except.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if not isinstance(addr, ipaddress.IPv4Address):
        return True
    return any(addr in n for n in networks)


def aggregate_into_24(
    ips: list[str],
    existing: list[ipaddress.IPv4Network],
    min_count: int = 3,
) -> tuple[list[str], list[str]]:
    """Collapse 3+ new IPs in the same /24 into a single CIDR.

    Returns (new_cidrs, remaining_singles).
    """
    by_24: dict[str, list[str]] = {}
    for ip in ips:
        octets = ip.split(".")
        if len(octets) != 4:
            continue
        net24 = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
        by_24.setdefault(net24, []).append(ip)

    new_cidrs: list[str] = []
    new_singles: list[str] = []
    for net24, members in by_24.items():
        net_obj = ipaddress.ip_network(net24)
        # Skip /24s already covered by a wider network in `existing`.
        if any(net_obj.subnet_of(n) for n in existing if n.prefixlen <= 24):
            continue
        if len(members) >= min_count:
            new_cidrs.append(net24)
        else:
            new_singles.extend(members)
    return new_cidrs, new_singles


def render_append_block(
    items: list[str],
    nft_set_var: str = "$S",
    batch_size: int = 15,
    timestamp: datetime | None = None,
) -> str:
    """Render new entries as a block of `nft add element` lines."""
    stamp = (timestamp or datetime.now()).strftime("%Y-%m-%d %H:%M")
    lines = [f"# --- auto-added {stamp} ({len(items)} entries) ---"]
    for i in range(0, len(items), batch_size):
        chunk = items[i : i + batch_size]
        lines.append(
            f'nft add element inet fw4 {nft_set_var} "{{ ' + ", ".join(chunk) + ' }" 2>/dev/null'
        )
    return "\n".join(lines) + "\n"


def append_to_file(routes_file: Path, block: str) -> None:
    """Append a rendered block to vpn-routes.sh with LF line endings."""
    text = routes_file.read_text(encoding="utf-8")
    if not text.endswith("\n"):
        text += "\n"
    routes_file.write_text(text + block, encoding="utf-8", newline="\n")
