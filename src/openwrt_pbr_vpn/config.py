"""Configuration loader.

Reads from (in order of precedence):
1. Explicit CLI flags (handled by cli.py, passed in via overrides=)
2. Environment variables (loaded from .env if present)
3. Optional INI file at ./router.conf or ./config/router.conf (for compatibility)

The password may live in:
- Env var ROUTER_PASSWORD
- OS keyring (preferred) — service="openwrt-pbr-vpn", username=ROUTER_HOST
- Never read from disk in plaintext unless ROUTER_PASSWORD env is set.
"""
from __future__ import annotations

import configparser
import os
from dataclasses import dataclass, field
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:  # dotenv is a runtime dep, but be graceful
    def load_dotenv(*_a, **_kw):
        return False

try:
    import keyring
except ImportError:
    keyring = None  # type: ignore[assignment]

KEYRING_SERVICE = "openwrt-pbr-vpn"


@dataclass
class Config:
    host: str
    port: int = 22
    user: str = "root"
    password: str | None = None  # None → use ssh_key
    ssh_key: Path | None = None

    vpn_interface: str = "vpnclient"
    remote_routes: str = "/etc/pbr.d/vpn-routes.sh"

    local_routes: Path = field(default_factory=lambda: Path("vpn-routes.sh"))
    domains: Path = field(default_factory=lambda: Path("domains.txt"))
    backups_dir: Path = field(default_factory=lambda: Path("backups"))

    batch_size: int = 15
    auto_aggregate_24: bool = True
    restart_pbr: bool = True

    @property
    def nft_set(self) -> str:
        """nft set name PBR creates for this interface (IPv4 user-defined)."""
        return f"pbr_{self.vpn_interface}_4_dst_ip_user"


def _ini_get(parser: configparser.ConfigParser, section: str, key: str, default: str | None = None) -> str | None:
    try:
        return parser.get(section, key)
    except (configparser.NoSectionError, configparser.NoOptionError):
        return default


def _resolve_password(host: str, env_password: str | None) -> str | None:
    """Try env first, then keyring."""
    if env_password:
        return env_password
    if keyring is not None:
        try:
            return keyring.get_password(KEYRING_SERVICE, host)
        except Exception:
            return None
    return None


def store_password(host: str, password: str) -> None:
    """Save password in OS keyring."""
    if keyring is None:
        raise RuntimeError("`keyring` package not installed. Run: pip install keyring")
    keyring.set_password(KEYRING_SERVICE, host, password)


def delete_password(host: str) -> None:
    if keyring is None:
        return
    try:
        keyring.delete_password(KEYRING_SERVICE, host)
    except Exception:
        pass


def load_config(
    env_file: Path | None = None,
    ini_file: Path | None = None,
    **overrides,
) -> Config:
    """Load config from .env + optional INI + overrides.

    Precedence: overrides > env > INI > defaults.
    """
    # Load .env from common locations
    if env_file is not None and env_file.exists():
        load_dotenv(env_file)
    else:
        for cand in (Path(".env"), Path("config/.env")):
            if cand.exists():
                load_dotenv(cand)
                break

    # Optional INI for backward-compat
    ini = configparser.ConfigParser()
    if ini_file is not None and ini_file.exists():
        ini.read(ini_file, encoding="utf-8")
    else:
        for cand in (Path("router.conf"), Path("config/router.conf")):
            if cand.exists():
                ini.read(cand, encoding="utf-8")
                break

    host = (
        overrides.get("host")
        or os.environ.get("ROUTER_HOST")
        or _ini_get(ini, "router", "host")
    )
    if not host:
        raise RuntimeError(
            "Router host not configured. Set ROUTER_HOST in .env, or pass --host."
        )

    port = int(
        overrides.get("port")
        or os.environ.get("ROUTER_PORT")
        or _ini_get(ini, "router", "port", "22")
    )

    user = (
        overrides.get("user")
        or os.environ.get("ROUTER_USER")
        or _ini_get(ini, "router", "user", "root")
    )

    ssh_key_raw = (
        overrides.get("ssh_key")
        or os.environ.get("ROUTER_SSH_KEY")
        or _ini_get(ini, "router", "ssh_key")
    )
    ssh_key = Path(os.path.expanduser(ssh_key_raw)) if ssh_key_raw else None

    env_password = (
        overrides.get("password")
        or os.environ.get("ROUTER_PASSWORD")
        or _ini_get(ini, "router", "password")
    )
    password = _resolve_password(host, env_password)

    if not password and not (ssh_key and ssh_key.exists()):
        raise RuntimeError(
            f"No SSH credentials found for {user}@{host}.\n"
            "  Either:\n"
            "    1) Set ROUTER_SSH_KEY in .env and run `ovpn-pbr keys install`, or\n"
            "    2) Run `ovpn-pbr keys store` to save password in OS keyring, or\n"
            "    3) Set ROUTER_PASSWORD in .env (least secure)."
        )

    return Config(
        host=host,
        port=port,
        user=user,
        password=password,
        ssh_key=ssh_key,
        vpn_interface=os.environ.get("VPN_INTERFACE")
            or _ini_get(ini, "vpn", "interface", "vpnclient")
            or "vpnclient",
        remote_routes=os.environ.get("REMOTE_ROUTES_PATH")
            or _ini_get(ini, "paths", "remote_routes", "/etc/pbr.d/vpn-routes.sh")
            or "/etc/pbr.d/vpn-routes.sh",
        local_routes=Path(
            os.environ.get("LOCAL_ROUTES_PATH")
            or _ini_get(ini, "paths", "local_routes", "vpn-routes.sh")
            or "vpn-routes.sh"
        ),
        domains=Path(
            os.environ.get("DOMAINS_PATH")
            or _ini_get(ini, "paths", "domains", "domains.txt")
            or "domains.txt"
        ),
        backups_dir=Path(
            os.environ.get("BACKUPS_DIR")
            or _ini_get(ini, "paths", "backups_dir", "backups")
            or "backups"
        ),
        batch_size=int(_ini_get(ini, "behavior", "batch_size", "15") or 15),
        auto_aggregate_24=(_ini_get(ini, "behavior", "auto_aggregate_24", "true") or "true").lower()
            in ("1", "true", "yes"),
        restart_pbr=(_ini_get(ini, "behavior", "restart_pbr", "true") or "true").lower()
            in ("1", "true", "yes"),
    )
