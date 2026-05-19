"""AmneziaWG availability check for OpenWrt routers.

Detects whether kmod-amneziawg and amneziawg-tools are available in the
router's package repos and reports how to install them (or why they cannot
be installed on the detected architecture/kernel).
"""

from __future__ import annotations

from typing import Any

from .config import Config
from .output import get_logger
from .router import Router

log = get_logger("amnezia")

_AWG_REPO_URL = "https://github.com/Slava-Shchipunov/awg-openwrt"

# Architectures known to lack kmod-amneziawg in official / community repos.
# This list is a hint only — the live `apk search` result is authoritative.
_KNOWN_MISSING_ARCHES = {
    "mediatek/mt7622",
    "mt7622",
}


def _pkg_available(r: Router, pkg: str) -> bool:
    """Return True if *pkg* appears in `apk search` output (OpenWrt 25.x)."""
    res = r.run(f"apk search {pkg} 2>/dev/null | grep -q '^{pkg}'")
    if res.rc == 0:
        return True
    # Fallback: opkg (older firmware)
    res2 = r.run(f"opkg list 2>/dev/null | grep -q '^{pkg} '")
    return res2.rc == 0


def _pkg_installed(r: Router, pkg: str) -> bool:
    """Return True if *pkg* is already installed."""
    res = r.run(
        f"apk list --installed 2>/dev/null | grep -q '^{pkg}'"
        f" || opkg list-installed 2>/dev/null | grep -q '^{pkg} '"
    )
    return res.rc == 0


def check(cfg: Config) -> dict[str, Any]:
    """SSH to the router and check AmneziaWG availability.

    Returns a structured dict:
    {
        "available": bool,         # kmod available (kmod + tools both in repo)
        "arch": str,
        "kernel": str,
        "kmod_in_repo": bool,
        "tools_in_repo": bool,
        "kmod_installed": bool,
        "tools_installed": bool,
        "install_cmd": str | None,
        "note": str,
    }
    """
    with Router(cfg) as r:
        kernel = r.run("uname -r 2>/dev/null").stdout.strip() or "unknown"
        arch_raw = r.run(
            "cat /etc/openwrt_release 2>/dev/null | grep OPENWRT_ARCH"
        ).stdout.strip()
        # e.g. OPENWRT_ARCH="aarch64_cortex-a53"
        arch = arch_raw.split("=")[-1].strip().strip('"').strip("'") if arch_raw else "unknown"

        kmod_in_repo = _pkg_available(r, "kmod-amneziawg")
        tools_in_repo = _pkg_available(r, "amneziawg-tools")
        kmod_installed = _pkg_installed(r, "kmod-amneziawg")
        tools_installed = _pkg_installed(r, "amneziawg-tools")

    available = kmod_in_repo and tools_in_repo

    if available:
        install_cmd = "apk add kmod-amneziawg amneziawg-tools"
        if kmod_installed and tools_installed:
            note = "kmod-amneziawg and amneziawg-tools are already installed."
        elif kmod_installed:
            note = "kmod-amneziawg is installed; install amneziawg-tools to complete setup."
            install_cmd = "apk add amneziawg-tools"
        elif tools_installed:
            note = "amneziawg-tools is installed; install kmod-amneziawg to complete setup."
            install_cmd = "apk add kmod-amneziawg"
        else:
            note = f"Available — install with: {install_cmd}"
    else:
        install_cmd = None
        parts: list[str] = []
        if not kmod_in_repo:
            parts.append(
                f"kmod-amneziawg not available for {arch!r} in current repos. "
                f"Must compile from source against kernel {kernel}. "
                f"See: {_AWG_REPO_URL}"
            )
        if not tools_in_repo:
            parts.append(
                "amneziawg-tools not available in current repos "
                "(usually present when kmod is available)."
            )
        note = " ".join(parts) if parts else "AmneziaWG packages not found in repos."

    return {
        "available": available,
        "arch": arch,
        "kernel": kernel,
        "kmod_in_repo": kmod_in_repo,
        "tools_in_repo": tools_in_repo,
        "kmod_installed": kmod_installed,
        "tools_installed": tools_installed,
        "install_cmd": install_cmd,
        "note": note,
    }


def format_human(result: dict[str, Any]) -> str:
    """Pretty-print amnezia check result."""
    lines = [
        f"AmneziaWG check  arch={result['arch']}  kernel={result['kernel']}",
        f"  kmod-amneziawg  in_repo={'YES' if result['kmod_in_repo'] else 'NO '}  "
        f"installed={'YES' if result['kmod_installed'] else 'NO'}",
        f"  amneziawg-tools in_repo={'YES' if result['tools_in_repo'] else 'NO '}  "
        f"installed={'YES' if result['tools_installed'] else 'NO'}",
        "",
        f"  {'[OK]' if result['available'] else '[WARN]'} {result['note']}",
    ]
    if result["install_cmd"]:
        lines.append(f"  Install: {result['install_cmd']}")
    return "\n".join(lines)
