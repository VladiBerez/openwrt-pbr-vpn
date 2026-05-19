"""Cloudflare WARP registration via wgcf and WireGuard application."""

from __future__ import annotations

_DEFAULT_WGCF_URL = (
    "https://github.com/ViRb3/wgcf/releases/latest/download/wgcf_linux_mips"
)

from .config import Config
from .output import get_logger
from .router import Router
from .wireguard import WgPeer
from . import wireguard

log = get_logger("warp")


def register(
    r: Router,
    cfg: Config,
    wgcf_url: str = _DEFAULT_WGCF_URL,
) -> WgPeer:
    """Download wgcf, register a WARP account, generate a WireGuard profile, and
    return the parsed WgPeer.

    Steps performed on the router:
    1. Download the wgcf binary to /tmp/wgcf.
    2. Make it executable and run ``wgcf register --accept-tos``.
    3. Run ``wgcf generate`` to produce /tmp/wgcf-profile.conf.
    4. Read and parse that file into a WgPeer.
    """
    wgcf_path = "/tmp/wgcf"

    log.info("Downloading wgcf binary…")
    r.run(
        f"wget -O {wgcf_path} {wgcf_url}",
        timeout=120,
        check=True,
    )

    log.info("Registering WARP account…")
    r.run(
        f"chmod +x {wgcf_path} && cd /tmp && {wgcf_path} register --accept-tos",
        timeout=60,
        check=True,
    )

    log.info("Generating WireGuard profile…")
    r.run(
        f"cd /tmp && {wgcf_path} generate",
        timeout=60,
        check=True,
    )

    log.info("Reading generated profile…")
    conf_text = r.run("cat /tmp/wgcf-profile.conf", check=True).stdout

    peer = WgPeer.from_conf(conf_text)
    log.info(
        f"WARP peer parsed: endpoint={peer.endpoint_host}:{peer.endpoint_port}"
        f"  address={peer.address}"
    )
    return peer


def install(
    r: Router,
    cfg: Config,
    wgcf_url: str = _DEFAULT_WGCF_URL,
) -> WgPeer:
    """Register a WARP account and apply it as the router's VPN interface.

    Calls :func:`register` then :func:`wireguard.apply`.  Returns the WgPeer
    so the caller can report the endpoint/address.
    """
    peer = register(r, cfg, wgcf_url=wgcf_url)
    log.info(f"Applying WireGuard config to interface {cfg.vpn_interface}…")
    wireguard.apply(r, cfg, peer)
    return peer
