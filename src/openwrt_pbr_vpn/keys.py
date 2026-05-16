"""SSH key management and OS-keyring password storage."""

from __future__ import annotations

import getpass
from pathlib import Path

import paramiko

from .config import Config, delete_password, store_password
from .output import get_logger

log = get_logger("keys")


DEFAULT_KEY_PATH = Path.home() / ".ssh" / "id_openwrt"


def generate_key(path: Path = DEFAULT_KEY_PATH, *, force: bool = False) -> Path:
    """Generate an ed25519 SSH key for use with OpenWrt. Returns the path."""
    if path.exists() and not force:
        log.info("Key already exists at %s. Use --force to regenerate.", path)
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    key = paramiko.Ed25519Key.generate()
    key.write_private_key_file(str(path))
    pub = f"ssh-ed25519 {key.get_base64()} openwrt-pbr-vpn"
    path.with_suffix(".pub").write_text(pub + "\n", encoding="utf-8")
    log.info("✓ Generated %s (+ .pub)", path)
    return path


def install_key(cfg: Config, key_path: Path = DEFAULT_KEY_PATH) -> None:
    """Push our public key into the router's authorized_keys (dropbear)."""
    pub_path = key_path.with_suffix(".pub")
    if not pub_path.exists():
        generate_key(key_path)
    pub = pub_path.read_text(encoding="utf-8").strip()

    # First connection uses password (interactive)
    pw = cfg.password or getpass.getpass(f"Password for {cfg.user}@{cfg.host}: ")

    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(
        hostname=cfg.host,
        port=cfg.port,
        username=cfg.user,
        password=pw,
        look_for_keys=False,
        allow_agent=False,
        timeout=15,
    )
    try:
        # dropbear stores keys in /etc/dropbear/authorized_keys
        cmd = (
            "mkdir -p /etc/dropbear && "
            "touch /etc/dropbear/authorized_keys && "
            "chmod 0700 /etc/dropbear && "
            "chmod 0600 /etc/dropbear/authorized_keys && "
            f"grep -qxF '{pub}' /etc/dropbear/authorized_keys || "
            f"echo '{pub}' >> /etc/dropbear/authorized_keys"
        )
        _, stdout, stderr = c.exec_command(cmd, timeout=30)
        rc = stdout.channel.recv_exit_status()
        if rc != 0:
            err = stderr.read().decode(errors="ignore")
            raise RuntimeError(f"Failed to install key (rc={rc}): {err}")
        log.info("✓ Installed public key on %s", cfg.host)
        log.info(
            "  Set ROUTER_SSH_KEY=%s in your .env and you can clear ROUTER_PASSWORD.", key_path
        )
    finally:
        c.close()


def keyring_store(cfg: Config) -> None:
    pw = getpass.getpass(f"Password for {cfg.user}@{cfg.host}: ")
    store_password(cfg.host, pw)
    log.info("✓ Saved password for %s in OS keyring.", cfg.host)


def keyring_clear(cfg: Config) -> None:
    delete_password(cfg.host)
    log.info("✓ Cleared keyring entry for %s (if any).", cfg.host)


def keyring_test(cfg: Config) -> None:
    """Try authenticating with currently-configured credentials."""
    try:
        from .router import Router

        with Router(cfg) as r:
            out = r.run("uname -a").stdout.strip()
        log.info("✓ Authenticated to %s: %s", cfg.host, out)
    except Exception as e:
        log.error("✗ Auth failed: %s", e)
        raise
