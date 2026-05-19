"""Tests for OpenVPN profile patching and probe data-channel detection."""

from __future__ import annotations

from pathlib import Path
from unittest import mock

import pytest

from openwrt_pbr_vpn.config import Config
from openwrt_pbr_vpn.openvpn import patch_for_split_tunnel, probe
from openwrt_pbr_vpn.router import CommandResult


def test_comments_out_redirect_gateway_and_dns() -> None:
    src = """client
remote example.com 1194
dhcp-option DNS 1.1.1.1
redirect-gateway def1
<ca>
...PEM...
</ca>
"""
    out = patch_for_split_tunnel(src)
    assert "#redirect-gateway def1" in out
    assert "#dhcp-option DNS 1.1.1.1" in out
    # Original options should NOT appear uncommented anywhere
    for line in out.splitlines():
        s = line.lstrip()
        if s.startswith("#"):
            continue
        assert s != "redirect-gateway def1"
        assert s != "dhcp-option DNS 1.1.1.1"


def test_inserts_split_tunnel_block_before_ca() -> None:
    src = """client
remote example.com 1194
<ca>
PEM
</ca>
"""
    out = patch_for_split_tunnel(src)
    # The split-tunnel block must come BEFORE the <ca> tag
    pos_block = out.find("route-nopull")
    pos_ca = out.find("<ca>")
    assert 0 <= pos_block < pos_ca


def test_appends_block_when_no_ca_section() -> None:
    src = "client\nremote example.com 1194\n"
    out = patch_for_split_tunnel(src)
    assert "route-nopull" in out
    assert 'pull-filter ignore "redirect-gateway"' in out


# ---------------------------------------------------------------------------
# probe() — data-channel detection via ping
# ---------------------------------------------------------------------------

_PING_SUCCESS = "PING 8.8.8.8: 3 packets transmitted, 3 received, 0% packet loss\n"
_PING_ZERO_RX = "PING 8.8.8.8: 3 packets transmitted, 0 received, 100% packet loss\n"

MINIMAL_OVPN = "client\nremote example.com 1194\n<ca>\nPEM\n</ca>\n"


def _ok(stdout: str = "", rc: int = 0) -> CommandResult:
    return CommandResult(cmd="", rc=rc, stdout=stdout, stderr="")


def _make_router_for_probe(ping_stdout: str, ping_rc: int = 0) -> mock.MagicMock:
    """Return a mock Router whose run() handles the probe call sequence.

    Direct r.run() calls in order:
      1. uci show openvpn | ...             (install → list existing configs)
      2. uci -q delete openvpn.<name>       (install)
      3. uci set openvpn.<name>=openvpn     (install, check=True)
      4. killall openvpn …                  (restart)
      5. service openvpn restart            (restart, check=True)
      6. ip link show tun0 …                (wait_for_tun → returns UP)
      7. ip route add 8.8.8.8/32 dev tun0  (probe)
      8. ping -c 3 -W 6 -I tun0 8.8.8.8   (data-channel test)
      9. ip route del 8.8.8.8/32 dev tun0  (probe finally)

    r.uci_set / r.uci_commit / r.uci_delete / r.upload_bytes are separate
    mock attributes and do NOT go through r.run().
    """
    r = mock.MagicMock()
    r.run.side_effect = [
        _ok(""),                        # uci show openvpn list (no existing)
        _ok(""),                        # uci -q delete openvpn.<name>
        _ok(""),                        # uci set openvpn.<name>=openvpn
        _ok(""),                        # killall openvpn
        _ok(""),                        # service openvpn restart
        _ok("2: tun0: <POINTOPOINT,UP,LOWER_UP>"),  # ip link show tun0
        _ok(""),                        # ip route add 8.8.8.8/32
        _ok(ping_stdout, ping_rc),      # ping -c 3 -W 6 -I tun0 8.8.8.8
        _ok(""),                        # ip route del 8.8.8.8/32
    ]
    return r


@pytest.fixture()
def cfg() -> Config:
    return Config(host="10.0.0.1", user="root", password="x")


@pytest.fixture()
def ovpn_profile(tmp_path: Path) -> tuple[str, Path]:
    p = tmp_path / "test.ovpn"
    p.write_text(MINIMAL_OVPN, encoding="utf-8")
    return "test", p


def test_probe_returns_profile_when_ping_succeeds(cfg, ovpn_profile) -> None:
    name, path = ovpn_profile
    r = _make_router_for_probe(_PING_SUCCESS, ping_rc=0)

    with mock.patch("openwrt_pbr_vpn.openvpn.time") as t:
        t.sleep = mock.MagicMock()
        result = probe(r, cfg, [(name, path)])

    assert result is not None
    assert result[0] == name


def test_probe_skips_profile_when_ping_zero_received(cfg, ovpn_profile) -> None:
    name, path = ovpn_profile
    r = _make_router_for_probe(_PING_ZERO_RX, ping_rc=1)

    with mock.patch("openwrt_pbr_vpn.openvpn.time") as t:
        t.sleep = mock.MagicMock()
        result = probe(r, cfg, [(name, path)])

    assert result is None


def test_probe_skips_profile_when_ping_exits_nonzero(cfg, ovpn_profile) -> None:
    name, path = ovpn_profile
    # ping exits non-zero even if output looks vaguely ok
    r = _make_router_for_probe("3 received", ping_rc=1)

    with mock.patch("openwrt_pbr_vpn.openvpn.time") as t:
        t.sleep = mock.MagicMock()
        result = probe(r, cfg, [(name, path)])

    assert result is None


def test_probe_returns_first_working_profile(cfg, tmp_path: Path) -> None:
    """First profile has dead data channel; second works — probe returns second."""
    dead = tmp_path / "dead.ovpn"
    dead.write_text(MINIMAL_OVPN, encoding="utf-8")
    good = tmp_path / "good.ovpn"
    good.write_text(MINIMAL_OVPN, encoding="utf-8")

    r = mock.MagicMock()
    r.run.side_effect = [
        # --- dead profile ---
        _ok(""),                        # uci show list (no existing)
        _ok(""),                        # uci -q delete
        _ok(""),                        # uci set
        _ok(""),                        # killall
        _ok(""),                        # service restart
        _ok("2: tun0: <POINTOPOINT,UP,LOWER_UP>"),  # ip link show tun0
        _ok(""),                        # ip route add
        _ok(_PING_ZERO_RX, 1),          # ping — dead
        _ok(""),                        # ip route del
        # --- good profile ---
        _ok(""),                        # uci show list (no existing)
        _ok(""),                        # uci -q delete
        _ok(""),                        # uci set
        _ok(""),                        # killall
        _ok(""),                        # service restart
        _ok("2: tun0: <POINTOPOINT,UP,LOWER_UP>"),  # ip link show tun0
        _ok(""),                        # ip route add
        _ok(_PING_SUCCESS, 0),          # ping — good
        _ok(""),                        # ip route del
    ]

    with mock.patch("openwrt_pbr_vpn.openvpn.time") as t:
        t.sleep = mock.MagicMock()
        result = probe(r, cfg, [("dead", dead), ("good", good)])

    assert result is not None
    assert result[0] == "good"
