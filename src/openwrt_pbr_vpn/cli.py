"""Command-line interface for openwrt-pbr-vpn."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from . import amnezia, daemon, diagnose, doctor, keys, openvpn, routes, warp, wireguard, xray
from .config import Config, load_config
from .output import emit_result, setup_logging
from .router import Router


def _load(args) -> Config:
    overrides: dict = {}
    if getattr(args, "host", None):
        overrides["host"] = args.host
    if getattr(args, "user", None):
        overrides["user"] = args.user
    return load_config(**overrides)


# ----- subcommand handlers (each returns a dict + optional human-text) -----


def cmd_update(args) -> tuple[dict, str]:
    cfg = _load(args)
    summary = routes.update(cfg, upload=not args.no_upload)
    human = (
        f"domains={summary['domains']} "
        f"resolved={summary['total_resolved']} "
        f"new={len(summary['new_ips'])} "
        f"uploaded={summary['uploaded']}"
    )
    return summary, human


def cmd_upload(args) -> tuple[dict, str]:
    cfg = _load(args)
    routes.upload_only(cfg)
    return {"uploaded": True}, "✓ uploaded"


def cmd_routes_show(args) -> tuple[dict, str]:
    cfg = _load(args)
    raw = routes.routes_show(cfg)
    return {"raw": raw}, raw


def cmd_routes_add(args) -> tuple[dict, str]:
    cfg = _load(args)
    routes.routes_add(cfg, args.entries)
    return {"added": args.entries}, f"✓ added {len(args.entries)} entries"


def cmd_routes_rm(args) -> tuple[dict, str]:
    cfg = _load(args)
    n = routes.routes_remove(cfg, args.entries)
    return {"removed": n, "requested": args.entries}, f"✓ removed {n}/{len(args.entries)}"


def cmd_wg_set(args) -> tuple[dict, str]:
    cfg = _load(args)
    peer = wireguard.WgPeer.from_file(Path(args.config))
    with Router(cfg) as r:
        wireguard.apply(r, cfg, peer)
        raw = wireguard.show(r, cfg)
    result = {
        "endpoint": f"{peer.endpoint_host}:{peer.endpoint_port}",
        "address": peer.address,
        "wg_show": raw,
    }
    return result, f"✓ applied WireGuard peer {peer.endpoint_host}:{peer.endpoint_port}"


def cmd_wg_show(args) -> tuple[dict, str]:
    cfg = _load(args)
    state = diagnose.collect_state(cfg)
    wg = state.get("wireguard")
    if not wg:
        return {"wireguard": None}, "WireGuard not active"
    human = (
        f"endpoint={wg['endpoint']}\n"
        f"handshake={wg['latest_handshake']}\n"
        f"rx={wg['rx_bytes']} tx={wg['tx_bytes']}"
    )
    return {"wireguard": wg}, human


def cmd_wg_probe(args) -> tuple[dict, str]:
    cfg = _load(args)
    files = sorted(Path(args.dir).glob("*.conf"), key=wireguard._probe_sort_key)
    if not files:
        raise FileNotFoundError(f"No .conf files in {args.dir}")
    peers = [(p.stem, wireguard.WgPeer.from_file(p)) for p in files]
    with Router(cfg) as r:
        winner = wireguard.probe(r, cfg, peers)
    if winner:
        return (
            {"winner": winner[0], "candidates": [p[0] for p in peers]},
            f"WINNER: {winner[0]}",
        )
    return (
        {"winner": None, "candidates": [p[0] for p in peers]},
        "No candidate survived the data-channel test",
    )


_DEFAULT_WGCF_URL = (
    "https://github.com/ViRb3/wgcf/releases/latest/download/wgcf_linux_mips"
)


def cmd_wg_warp(args) -> tuple[dict, str]:
    cfg = _load(args)
    with Router(cfg) as r:
        peer = warp.install(r, cfg, wgcf_url=args.wgcf_url)
    return (
        {"endpoint": f"{peer.endpoint_host}:{peer.endpoint_port}", "address": peer.address},
        f"✓ WARP applied to {cfg.vpn_interface}",
    )


def cmd_ovpn_set(args) -> tuple[dict, str]:
    cfg = _load(args)
    path = Path(args.config)
    with Router(cfg) as r:
        openvpn.install(r, cfg, path.stem, path.read_text(encoding="utf-8"))
        openvpn.restart(r)
        ok = openvpn.wait_for_tun(r)
    return (
        {"profile": path.stem, "tun_up": ok},
        "tun0 UP" if ok else "tun0 did NOT come up — check logs",
    )


def cmd_ovpn_probe(args) -> tuple[dict, str]:
    cfg = _load(args)
    files = sorted(Path(args.dir).glob("*.ovpn"), key=openvpn._probe_sort_key)
    if not files:
        raise FileNotFoundError(f"No .ovpn files in {args.dir}")
    profiles = [(p.stem.replace(" ", "_").replace(",", ""), p) for p in files]
    with Router(cfg) as r:
        winner = openvpn.probe(r, cfg, profiles)
    if winner:
        return (
            {"winner": winner[0], "candidates": [p[0] for p in profiles]},
            f"WINNER: {winner[0]}",
        )
    return (
        {"winner": None, "candidates": [p[0] for p in profiles]},
        "No profile survived — DPI likely blocks OpenVPN",
    )


def cmd_diagnose(args) -> tuple[dict, str]:
    cfg = _load(args)
    state = diagnose.diagnose(cfg)
    return state, diagnose.format_human(state)


def cmd_emergency_off(args) -> tuple[dict, str]:
    cfg = _load(args)
    result = diagnose.emergency_off(cfg)
    return result, "✓ kill-switch off, VPN stopped"


def cmd_killswitch_on(args) -> tuple[dict, str]:
    cfg = _load(args)
    result = diagnose.enable_killswitch(cfg)
    return result, "✓ strict_enforcement=1"


def cmd_amnezia_check(args) -> tuple[dict, str]:
    cfg = _load(args)
    result = amnezia.check(cfg)
    return result, amnezia.format_human(result)


def cmd_daemon(args) -> tuple[dict, str]:
    cfg = _load(args)
    dcfg = daemon.DaemonConfig(
        pool_dir=Path(args.pool),
        check_interval=args.interval,
        handshake_stale_seconds=args.handshake_stale,
        dead_ttl=args.dead_ttl,
        cooldown_seconds=args.cooldown,
        consecutive_bad_to_switch=args.bad_threshold,
        on_switch_cmd=args.on_switch,
        on_fail_cmd=args.on_fail,
        max_iterations=args.max_iterations,
    )
    d = daemon.Daemon(cfg, dcfg)
    d.install_signal_handlers()
    state = d.run()
    return daemon.to_dict(state), f"daemon stopped; last peer={state.current_peer}"


def cmd_doctor(args) -> tuple[dict, str]:
    cfg = _load(args)
    report = doctor.run(cfg)
    return report.to_dict(), doctor.format_human(report)


def cmd_keys_install(args) -> tuple[dict, str]:
    cfg = _load(args)
    path = Path(args.path) if args.path else keys.DEFAULT_KEY_PATH
    keys.generate_key(path, force=args.force)
    keys.install_key(cfg, path)
    return {"key_path": str(path), "host": cfg.host}, f"✓ key installed on {cfg.host}"


def cmd_keys_store(args) -> tuple[dict, str]:
    cfg = _load(args)
    keys.keyring_store(cfg)
    return {"host": cfg.host}, f"✓ password saved for {cfg.host}"


def cmd_keys_test(args) -> tuple[dict, str]:
    cfg = _load(args)
    try:
        keys.keyring_test(cfg)
        return {"host": cfg.host, "ok": True}, "✓ authenticated"
    except Exception as e:
        return {"host": cfg.host, "ok": False, "error": str(e)}, f"✗ {e}"


def cmd_xray_install(args) -> tuple[dict, str]:
    cfg = _load(args)
    with Router(cfg) as r:
        result = xray.install(
            r,
            cfg,
            args.server,
            args.uuid,
            sni=args.sni,
            public_key=args.public_key,
            short_id=args.short_id,
            fingerprint=args.fingerprint,
        )
    return result, f"✓ Xray installed on {cfg.host}"


# ----- parser wiring -----


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ovpn-pbr",
        description="Split-tunnel VPN management for OpenWrt + PBR.",
    )
    p.add_argument("--host", help="Override router host (else from .env)")
    p.add_argument("--user", help="Override SSH user")
    p.add_argument("--json", action="store_true", help="Output result as JSON (for scripting / UI)")
    verbosity = p.add_mutually_exclusive_group()
    verbosity.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    verbosity.add_argument("-q", "--quiet", action="store_true", help="Suppress info logs")

    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("update", help="Resolve domains, dedupe, push to router")
    s.add_argument("--no-upload", action="store_true", help="Update local file only")
    s.set_defaults(func=cmd_update)

    s = sub.add_parser("upload", help="Push current local routes file without resolving")
    s.set_defaults(func=cmd_upload)

    s_routes = sub.add_parser("routes", help="Inspect/edit nft set")
    sr = s_routes.add_subparsers(dest="sub", required=True)
    sr.add_parser("show", help="Dump nft set from router").set_defaults(func=cmd_routes_show)
    a = sr.add_parser("add", help="Append entries and push")
    a.add_argument("entries", nargs="+", help="IPs or CIDRs")
    a.set_defaults(func=cmd_routes_add)
    rm = sr.add_parser("rm", help="Remove entries and push")
    rm.add_argument("entries", nargs="+")
    rm.set_defaults(func=cmd_routes_rm)

    s_wg = sub.add_parser("wg", help="WireGuard control")
    sw = s_wg.add_subparsers(dest="sub", required=True)
    a = sw.add_parser("set", help="Apply a WireGuard .conf as the VPN interface")
    a.add_argument("--config", required=True, help="Path to .conf")
    a.set_defaults(func=cmd_wg_set)
    sw.add_parser("show", help="wg show").set_defaults(func=cmd_wg_show)
    a = sw.add_parser("probe", help="Try each .conf in dir, return first that survives DPI")
    a.add_argument("--dir", required=True)
    a.set_defaults(func=cmd_wg_probe)
    a = sw.add_parser("warp", help="Register Cloudflare WARP via wgcf and apply as VPN interface")
    a.add_argument(
        "--wgcf-url",
        default=_DEFAULT_WGCF_URL,
        help="URL to download the wgcf binary (default: Linux MIPS build from GitHub)",
    )
    a.set_defaults(func=cmd_wg_warp)

    s_ovpn = sub.add_parser("ovpn", help="OpenVPN control")
    so = s_ovpn.add_subparsers(dest="sub", required=True)
    a = so.add_parser("set", help="Install .ovpn (patched for split-tunnel) and restart")
    a.add_argument("--config", required=True)
    a.set_defaults(func=cmd_ovpn_set)
    a = so.add_parser("probe", help="Try each .ovpn in dir")
    a.add_argument("--dir", required=True)
    a.set_defaults(func=cmd_ovpn_probe)

    sub.add_parser("diagnose", help="Print health/state").set_defaults(func=cmd_diagnose)
    sub.add_parser(
        "doctor", help="Self-check: run a battery of audits with fix hints"
    ).set_defaults(func=cmd_doctor)

    s_daemon = sub.add_parser(
        "daemon",
        help="Long-running watchdog: monitor and auto-switch VPN peers from a pool",
    )
    s_daemon.add_argument("--pool", required=True, help="Directory with WireGuard .conf files")
    s_daemon.add_argument(
        "--interval",
        type=int,
        default=60,
        help="Seconds between health checks (default 60)",
    )
    s_daemon.add_argument(
        "--handshake-stale",
        type=float,
        default=300.0,
        help="Handshake age (s) past which we consider it stale (default 300)",
    )
    s_daemon.add_argument(
        "--dead-ttl",
        type=float,
        default=3600.0,
        help="Skip a peer flagged dead for this many seconds (default 3600)",
    )
    s_daemon.add_argument(
        "--cooldown",
        type=float,
        default=300.0,
        help="Sleep this long when every peer is dead (default 300)",
    )
    s_daemon.add_argument(
        "--bad-threshold",
        type=int,
        default=3,
        help="Consecutive bad ticks before switching peers (default 3)",
    )
    s_daemon.add_argument(
        "--on-switch",
        help="Script called on endpoint switch: receives old_endpoint new_endpoint as $1 $2",
    )
    s_daemon.add_argument(
        "--on-fail",
        help="Script called when a peer is marked dead: receives failed_peer_name as $1",
    )
    s_daemon.add_argument(
        "--max-iterations",
        type=int,
        help="Stop after N ticks (mainly for tests; daemon runs forever otherwise)",
    )
    s_daemon.set_defaults(func=cmd_daemon)

    sub.add_parser("emergency-off", help="Disable kill-switch and stop VPN (raw WAN)").set_defaults(
        func=cmd_emergency_off
    )
    sub.add_parser("killswitch-on", help="Enable strict_enforcement again").set_defaults(
        func=cmd_killswitch_on
    )

    s_keys = sub.add_parser("keys", help="SSH key / keyring management")
    sk = s_keys.add_subparsers(dest="sub", required=True)
    a = sk.add_parser("install", help="Generate ed25519 key and install on router")
    a.add_argument("--path", help="Key path (default ~/.ssh/id_openwrt)")
    a.add_argument("--force", action="store_true")
    a.set_defaults(func=cmd_keys_install)
    sk.add_parser("store", help="Save router password in OS keyring").set_defaults(
        func=cmd_keys_store
    )
    sk.add_parser("test", help="Verify current credentials work").set_defaults(func=cmd_keys_test)

    s_amnezia = sub.add_parser("amnezia", help="AmneziaWG availability checks")
    sa = s_amnezia.add_subparsers(dest="sub", required=True)
    sa.add_parser(
        "check",
        help="Check whether kmod-amneziawg is available for this router's arch/kernel",
    ).set_defaults(func=cmd_amnezia_check)

    s_xray = sub.add_parser("xray", help="Xray-core VLESS+Reality control")
    sx = s_xray.add_subparsers(dest="sub", required=True)
    a = sx.add_parser(
        "install",
        help="Install Xray-core binary and configure a VLESS+Reality outbound",
    )
    a.add_argument("--server", required=True, help="VLESS server IP or hostname")
    a.add_argument("--uuid", required=True, help="VLESS user UUID")
    a.add_argument(
        "--sni",
        default="www.microsoft.com",
        help="TLS SNI / Reality server name (default: www.microsoft.com)",
    )
    a.add_argument(
        "--public-key",
        default="",
        dest="public_key",
        help="Reality public key (base64)",
    )
    a.add_argument(
        "--short-id",
        default="",
        dest="short_id",
        help="Reality short ID (hex)",
    )
    a.add_argument(
        "--fingerprint",
        default="chrome",
        help="uTLS fingerprint (default: chrome)",
    )
    a.set_defaults(func=cmd_xray_install)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(verbose=args.verbose, quiet=args.quiet or args.json)
    try:
        outcome: Any = args.func(args)
    except KeyboardInterrupt:
        sys.stderr.write("\nInterrupted.\n")
        return 130
    except Exception as e:
        sys.stderr.write(f"ERROR: {e}\n")
        return 1

    # Handlers return (result_dict, human_str). Older ones may return None.
    if isinstance(outcome, tuple) and len(outcome) == 2:
        result, human = outcome
    else:
        result, human = outcome, None
    emit_result(result, as_json=args.json, human=human)
    return 0


if __name__ == "__main__":
    sys.exit(main())
