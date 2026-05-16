"""openwrt-pbr-vpn — automated split-tunnel VPN management for OpenWrt + PBR."""

__version__ = "0.1.0"

# Make UTF-8 the default for stdout/stderr — Windows cp1251 consoles otherwise
# choke on arrows/checkmarks emitted by the CLI.
import contextlib as _contextlib
import sys as _sys

for _stream in (_sys.stdout, _sys.stderr):
    with _contextlib.suppress(Exception):
        _stream.reconfigure(encoding="utf-8")
