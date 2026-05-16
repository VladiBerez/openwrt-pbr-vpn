"""Command-line interface for openwrt-pbr-vpn."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import diagnose, keys, openvpn, routes, wireguard
from .config import Config, load_config
from .router import Router


def _load(args) -> Config:
    overrides: dict = {}
    if getattr(args, "host", None):
        overrides["host"] = args.host
    if getattr(args, "user", None):
        overrides["user"] = args.user
    return load_config(**overrides)


# ----- subcommand handlers -----

def cmd_update(args) -> int:
    cfg = _load(args)
    routes.update(cfg, upload=not args.no_upload)
    return 0


def cmd_upload(args) -> int:
    cfg = _load(args)
    routes.upload_only(cfg)
    return 0


def cmd_routes_show(args) -> int:
    cfg = _load(args)
    print(routes.routes_show(cfg))
    return 0


def cmd_routes_add(args) -> int:
    cfg = _load(args)
    routes.routes_add(cfg, args.entries)
    return 0


def cmd_routes_rm(args) -> int:
    cfg = _load(args)
    routes.routes_remove(cfg, args.entries)
    return 0


def cmd_wg_set(args) -> int:
    cfg = _load(args)
    peer = wireguard.WgPeer.from_file(Path(args.config))
    with Router(cfg) as r:
        wireguard.apply(r, cfg, peer)
        print(wireguard.show(r, cfg))
    return 0


def cmd_wg_show(args) -> int:
    cfg = _load(args)
    with Router(cfg) as r:
        print(wireguard.show(r, cfg))
    return 0


def cmd_wg_probe(args) -> int:
    cfg = _load(args)
    files = sorted(Path(args.dir).glob("*.conf"))
    if not files:
        print(f"No .conf files in {args.dir}", file=sys.stderr)
        return 2
    peers = [(p.stem, wireguard.WgPeer.from_file(p)) for p in files]
    with Router(cfg) as r:
        winner = wireguard.probe(r, cfg, peers)
    if winner:
        print(f"\nWINNER: {winner[0]}")
        return 0
    print("\nNone of the candidates passed the data-channel test.", file=sys.stderr)
    return 1


def cmd_ovpn_set(args) -> int:
    cfg = _load(args)
    path = Path(args.config)
    with Router(cfg) as r:
        openvpn.install(r, cfg, path.stem, path.read_text(encoding="utf-8"))
        openvpn.restart(r)
        ok = openvpn.wait_for_tun(r)
        print("tun0 UP" if ok else "tun0 did NOT come up — check logs")
        print(openvpn.last_log(r))
    return 0 if ok else 1


def cmd_ovpn_probe(args) -> int:
    cfg = _load(args)
    files = sorted(Path(args.dir).glob("*.ovpn"))
    if not files:
        print(f"No .ovpn files in {args.dir}", file=sys.stderr)
        return 2
    profiles = [(p.stem.replace(" ", "_").replace(",", ""), p) for p in files]
    with Router(cfg) as r:
        winner = openvpn.probe(r, cfg, profiles)
    if winner:
        print(f"\nWINNER: {winner[0]}")
        return 0
    print("\nNo profile survived. ТСПУ likely blocks OpenVPN.", file=sys.stderr)
    return 1


def cmd_diagnose(args) -> int:
    cfg = _load(args)
    diagnose.diagnose(cfg)
    return 0


def cmd_emergency_off(args) -> int:
    cfg = _load(args)
    diagnose.emergency_off(cfg)
    return 0


def cmd_killswitch_on(args) -> int:
    cfg = _load(args)
    diagnose.enable_killswitch(cfg)
    return 0


def cmd_keys_install(args) -> int:
    cfg = _load(args)
    path = Path(args.path) if args.path else keys.DEFAULT_KEY_PATH
    keys.generate_key(path, force=args.force)
    keys.install_key(cfg, path)
    return 0


def cmd_keys_store(args) -> int:
    cfg = _load(args)
    keys.keyring_store(cfg)
    return 0


def cmd_keys_test(args) -> int:
    cfg = _load(args)
    try:
        keys.keyring_test(cfg)
        return 0
    except Exception:
        return 1


# ----- parser wiring -----

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ovpn-pbr",
        description="Split-tunnel VPN management for OpenWrt + PBR.",
    )
    p.add_argument("--host", help="Override router host (else from .env)")
    p.add_argument("--user", help="Override SSH user")

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

    s_ovpn = sub.add_parser("ovpn", help="OpenVPN control")
    so = s_ovpn.add_subparsers(dest="sub", required=True)
    a = so.add_parser("set", help="Install .ovpn (patched for split-tunnel) and restart")
    a.add_argument("--config", required=True)
    a.set_defaults(func=cmd_ovpn_set)
    a = so.add_parser("probe", help="Try each .ovpn in dir")
    a.add_argument("--dir", required=True)
    a.set_defaults(func=cmd_ovpn_probe)

    sub.add_parser("diagnose", help="Print health/state").set_defaults(func=cmd_diagnose)
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
    sk.add_parser("store", help="Save router password in OS keyring").set_defaults(func=cmd_keys_store)
    sk.add_parser("test", help="Verify current credentials work").set_defaults(func=cmd_keys_test)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
