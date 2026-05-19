"""Xray-core VLESS+Reality setup on OpenWrt.

Handles binary installation, config generation, and procd service wiring
for a DPI-resistant VLESS+Reality outbound.
"""

from __future__ import annotations

import json

from .config import Config
from .output import get_logger
from .router import Router

log = get_logger("xray")

_ARCH_MAP = {
    "mips": "mips",
    "aarch64": "arm64",
}

_ARCH_ZIP = {
    "mips": "Xray-linux-mips.zip",
    "arm64": "Xray-linux-arm64-v8a.zip",
}

BINARY_PATH = "/usr/local/bin/xray"
CONFIG_PATH = "/etc/xray/config.json"
SERVICE_PATH = "/etc/init.d/xray"


def _detect_arch(r: Router) -> str:
    uname = r.run("uname -m").stdout.strip()
    for key, arch in _ARCH_MAP.items():
        if key in uname:
            return arch
    log.warning("Unknown arch %r, defaulting to mips", uname)
    return "mips"


def install_binary(r: Router, arch: str = "mips") -> str:
    """Download and install the Xray binary from GitHub releases.

    Returns the path to the installed binary.
    """
    zip_name = _ARCH_ZIP.get(arch, _ARCH_ZIP["mips"])
    url = f"https://github.com/XTLS/Xray-core/releases/latest/download/{zip_name}"

    log.info("Downloading Xray (%s) from %s", arch, url)
    r.run(f"wget -O /tmp/xray.zip {url}", timeout=120, check=True)

    log.info("Unpacking Xray binary to /usr/local/bin/")
    r.run(
        "cd /tmp && unzip -o xray.zip xray -d /usr/local/bin && chmod +x /usr/local/bin/xray",
        check=True,
    )

    return BINARY_PATH


def write_config(
    r: Router,
    server_ip: str,
    uuid: str,
    *,
    sni: str = "www.microsoft.com",
    fingerprint: str = "chrome",
    public_key: str = "",
    short_id: str = "",
) -> None:
    """Write a classic Xray JSON config for VLESS+Reality to /etc/xray/config.json."""

    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "socks",
                "protocol": "socks",
                "listen": "127.0.0.1",
                "port": 1080,
                "settings": {"auth": "noauth"},
            }
        ],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": server_ip,
                            "port": 443,
                            "users": [
                                {
                                    "id": uuid,
                                    "flow": "xtls-rprx-vision",
                                    "encryption": "none",
                                }
                            ],
                        }
                    ]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "serverName": sni,
                        "fingerprint": fingerprint,
                        "publicKey": public_key,
                        "shortId": short_id,
                    },
                },
            }
        ],
    }

    r.run("mkdir -p /etc/xray", check=True)
    content = json.dumps(config, indent=2)
    log.info("Writing Xray config to %s", CONFIG_PATH)
    r.upload_bytes(content.encode("utf-8"), CONFIG_PATH, mode=0o600)


_SERVICE_SCRIPT = """\
#!/bin/sh /etc/rc.common

USE_PROCD=1
START=95
STOP=10

XRAY_BIN=/usr/local/bin/xray
XRAY_CONFIG=/etc/xray/config.json

start_service() {
    procd_open_instance
    procd_set_param command "$XRAY_BIN" run -c "$XRAY_CONFIG"
    procd_set_param respawn
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
"""


def install_service(r: Router) -> None:
    """Install a procd init script for Xray, enable and start it."""
    log.info("Installing Xray procd service at %s", SERVICE_PATH)
    r.upload_bytes(_SERVICE_SCRIPT.encode("utf-8"), SERVICE_PATH, mode=0o755)

    r.run(f"chmod +x {SERVICE_PATH} && {SERVICE_PATH} enable", check=True)
    log.info("Starting Xray service")
    r.run(f"{SERVICE_PATH} start", check=True)


def install(
    r: Router,
    cfg: Config,
    server_ip: str,
    uuid: str,
    **kwargs,
) -> dict:
    """Orchestrate full Xray installation: binary + config + service.

    Returns a summary dict with connection details.
    """
    sni = kwargs.get("sni", "www.microsoft.com")

    log.info("Detecting router architecture")
    arch = _detect_arch(r)

    install_binary(r, arch)
    write_config(r, server_ip, uuid, **kwargs)
    install_service(r)

    return {
        "binary": BINARY_PATH,
        "server": server_ip,
        "port": 443,
        "sni": sni,
    }
