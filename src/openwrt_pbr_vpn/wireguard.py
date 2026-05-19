"""WireGuard configuration on OpenWrt via UCI + probing endpoints for DPI survival."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from pathlib import Path

from .config import Config
from .output import get_logger
from .router import Router

log = get_logger("wireguard")


def _parse_rtt(stdout: str) -> float | None:
    """Extract the average RTT from BusyBox ping output.

    Looks for a line like:
        round-trip min/avg/max = 78.234/79.012/80.456 ms
    Returns the avg value rounded to 1 decimal place, or None if not found.
    """
    m = re.search(r"min/avg/max\s*=\s*[\d.]+/([\d.]+)/[\d.]+", stdout)
    if m:
        try:
            return round(float(m.group(1)), 1)
        except ValueError:
            pass
    return None


def _probe_sort_key(path: Path) -> tuple[int, str]:
    """Sort key that puts ROUTERS-tagged files first, then alphabetical."""
    name = path.stem.upper()
    priority = 0 if "ROUTERS" in name else 1
    return (priority, path.name)


@dataclass
class WgPeer:
    address: str  # e.g. "10.103.248.74/32"
    private_key: str
    public_key: str  # peer's public key
    endpoint_host: str
    endpoint_port: int
    persistent_keepalive: int = 25
    mtu: int = 1280
    dns: str | None = None  # only informational; we don't push it into UCI

    @classmethod
    def from_conf(cls, conf_text: str) -> WgPeer:
        """Parse a WireGuard .conf as exported by most clients."""

        def grab(section: str, key: str) -> str | None:
            m = re.search(
                rf"\[{section}\][^[]*?^\s*{key}\s*=\s*(.+?)\s*$",
                conf_text,
                re.MULTILINE | re.IGNORECASE,
            )
            return m.group(1).strip() if m else None

        address = grab("Interface", "Address")
        priv = grab("Interface", "PrivateKey")
        dns = grab("Interface", "DNS")
        mtu_raw = grab("Interface", "MTU")

        pub = grab("Peer", "PublicKey")
        endpoint = grab("Peer", "Endpoint")
        ka_raw = grab("Peer", "PersistentKeepalive")

        if not all([address, priv, pub, endpoint]):
            raise ValueError(
                "WireGuard .conf is missing required fields (Address/PrivateKey/PublicKey/Endpoint)"
            )

        # endpoint can be "host:port" or "[v6]:port"
        if endpoint.startswith("["):
            host, _, port = endpoint[1:].partition("]:")
        else:
            host, _, port = endpoint.rpartition(":")
        return cls(
            address=address,
            private_key=priv,
            public_key=pub,
            endpoint_host=host,
            endpoint_port=int(port),
            persistent_keepalive=int(ka_raw or 25),
            mtu=int(mtu_raw or 1280),
            dns=dns,
        )

    @classmethod
    def from_file(cls, path: Path) -> WgPeer:
        return cls.from_conf(Path(path).read_text(encoding="utf-8"))


def apply(r: Router, cfg: Config, peer: WgPeer, *, route_allowed_ips: bool = False) -> None:
    """Configure `cfg.vpn_interface` on the router as WireGuard with the given peer.

    Set route_allowed_ips=False for split-tunnel (PBR will manage routes).
    """
    iface = cfg.vpn_interface

    # Wipe previous WG peers attached to this interface
    r.run(f"while uci -q delete network.@wireguard_{iface}[0]; do :; done")
    r.uci_delete(f"network.{iface}")

    r.run(f"uci set network.{iface}=interface", check=True)
    r.uci_set(f"network.{iface}.proto", "wireguard")
    r.uci_set(f"network.{iface}.private_key", peer.private_key)
    r.uci_add_list(f"network.{iface}.addresses", peer.address)
    r.uci_set(f"network.{iface}.mtu", str(peer.mtu))

    r.run(f"uci add network wireguard_{iface}", check=True)
    r.uci_set(f"network.@wireguard_{iface}[-1].public_key", peer.public_key)
    r.uci_add_list(f"network.@wireguard_{iface}[-1].allowed_ips", "0.0.0.0/0")
    r.uci_set(f"network.@wireguard_{iface}[-1].endpoint_host", peer.endpoint_host)
    r.uci_set(f"network.@wireguard_{iface}[-1].endpoint_port", str(peer.endpoint_port))
    r.uci_set(
        f"network.@wireguard_{iface}[-1].persistent_keepalive",
        str(peer.persistent_keepalive),
    )
    r.uci_set(
        f"network.@wireguard_{iface}[-1].route_allowed_ips",
        "1" if route_allowed_ips else "0",
    )

    r.uci_commit("network")
    r.run("/etc/init.d/network reload", check=True)


def show(r: Router, cfg: Config) -> str:
    return r.run(f"wg show {cfg.vpn_interface}").stdout


def transfer_counters(r: Router, cfg: Config) -> tuple[int, int]:
    """Return (rx_bytes, tx_bytes) for the peer of `cfg.vpn_interface`."""
    out = r.run(f"wg show {cfg.vpn_interface} transfer").stdout.strip()
    # Format: <peer_pubkey>\t<rx_bytes>\t<tx_bytes>
    parts = out.split()
    if len(parts) >= 3:
        try:
            return int(parts[-2]), int(parts[-1])
        except ValueError:
            pass
    return 0, 0


def probe(
    r: Router,
    cfg: Config,
    peers: list[tuple[str, WgPeer]],
    *,
    handshake_timeout: int = 30,
    on_result=None,  # callable(dict) or None
) -> tuple[str, WgPeer] | None:
    """Cycle through (name, WgPeer) candidates, return the first that passes.

    Pass criteria: ping -c 3 -W 6 -I <vpn_interface> 8.8.8.8 exits 0 and
    reports at least one packet received.  We do NOT rely on wg RX counters
    because under ТСПУ/DPI the device can forward traffic while the kernel
    RX counter stays near zero.
    """
    iface = cfg.vpn_interface
    for name, peer in peers:
        log.info(f"\n--- probing {name} ({peer.endpoint_host}:{peer.endpoint_port}) ---")
        apply(r, cfg, peer)
        time.sleep(4)

        r.run(f"ip route add 8.8.8.8/32 dev {iface} 2>/dev/null || true")
        try:
            res = r.run(f"ping -c 3 -W 6 -I {iface} 8.8.8.8")
            data_ok = res.rc == 0 and (
                " received" in res.stdout
                and "0 received" not in res.stdout
                and "0 packets received" not in res.stdout
            )
            if on_result is not None:
                on_result({"name": name, "status": "ok" if data_ok else "dead", "rtt": _parse_rtt(res.stdout)})
            if data_ok:
                log.info(f"  *** {name} WORKS — data channel alive ***")
                return name, peer
            log.info(f"  {name} dead (no reply traffic)")
        finally:
            r.run(f"ip route del 8.8.8.8/32 dev {iface} 2>/dev/null || true")
    return None
