"""Tests for WireGuard .conf parsing and probe data-channel detection."""

from __future__ import annotations
from unittest import mock

import pytest

from openwrt_pbr_vpn.config import Config
from openwrt_pbr_vpn.router import CommandResult
from openwrt_pbr_vpn.wireguard import WgPeer, probe

SAMPLE = """
[Interface]
Address = 10.103.248.74/32
PrivateKey = UOguEZZNeV35WT6bGhMixK8QlYFYTFPmCqYLcJnMrUM=
DNS = 1.1.1.1
MTU = 1280

[Peer]
PublicKey = O4xIqS5shAzoLze+USO8+bdxLuZ5U71WW9QAweX3EEU=
AllowedIPs = 0.0.0.0/0
Endpoint = 94.75.213.109:35402
PersistentKeepalive = 28
"""


def test_parses_basic_conf() -> None:
    p = WgPeer.from_conf(SAMPLE)
    assert p.address == "10.103.248.74/32"
    assert p.private_key == "UOguEZZNeV35WT6bGhMixK8QlYFYTFPmCqYLcJnMrUM="
    assert p.public_key == "O4xIqS5shAzoLze+USO8+bdxLuZ5U71WW9QAweX3EEU="
    assert p.endpoint_host == "94.75.213.109"
    assert p.endpoint_port == 35402
    assert p.persistent_keepalive == 28
    assert p.mtu == 1280
    assert p.dns == "1.1.1.1"


def test_rejects_missing_required_fields() -> None:
    with pytest.raises(ValueError):
        WgPeer.from_conf("[Interface]\nAddress = 10.0.0.1/32\n")


def test_default_keepalive_when_missing() -> None:
    p = WgPeer.from_conf("""
[Interface]
Address = 10.0.0.1/32
PrivateKey = aaaa
[Peer]
PublicKey = bbbb
Endpoint = 1.2.3.4:51820
""")
    assert p.persistent_keepalive == 25
    assert p.mtu == 1280


def test_parses_real_hidemyname_export() -> None:
    """The exact format HideMyName/AmneziaVPN/Mullvad export — verbatim from a
    real download. Catches surprises like Windows CRLF, BOM, extra blank lines,
    trailing whitespace on values, and DNS line ordering."""
    raw = (
        "﻿"
        "[Interface]\r\n"
        "Address = 10.103.248.74/32\r\n"
        "PrivateKey = UOguEZZNeV35WT6bGhMixK8QlYFYTFPmCqYLcJnMrUM=\r\n"
        "DNS = 1.1.1.1   \r\n"
        "MTU = 1280\r\n"
        "\r\n"
        "[Peer]\r\n"
        "PublicKey = O4xIqS5shAzoLze+USO8+bdxLuZ5U71WW9QAweX3EEU=\r\n"
        "AllowedIPs = 0.0.0.0/0\r\n"
        "Endpoint = 94.75.213.109:35402\r\n"
        "PersistentKeepalive = 28\r\n"
    )
    p = WgPeer.from_conf(raw)
    assert p.address == "10.103.248.74/32"
    assert p.endpoint_host == "94.75.213.109"
    assert p.endpoint_port == 35402
    assert p.persistent_keepalive == 28
    assert p.mtu == 1280
    assert p.dns == "1.1.1.1"


def test_parses_amneziawg_style_with_extra_jc_keys() -> None:
    """AmneziaWG configs add Jc/Jmin/Jmax/S1/S2/H1-H4 keys. We ignore them but
    must not crash on a real export."""
    raw = """
[Interface]
PrivateKey = aaaa
Address = 10.0.0.1/32
DNS = 1.1.1.1
Jc = 4
Jmin = 50
Jmax = 1000
S1 = 50
S2 = 100
H1 = 1
H2 = 2
H3 = 3
H4 = 4

[Peer]
PublicKey = bbbb
AllowedIPs = 0.0.0.0/0
Endpoint = aw.example.com:51820
PersistentKeepalive = 25
"""
    p = WgPeer.from_conf(raw)
    assert p.address == "10.0.0.1/32"
    assert p.endpoint_host == "aw.example.com"
    assert p.endpoint_port == 51820


def test_ipv6_endpoint_parsing() -> None:
    p = WgPeer.from_conf("""
[Interface]
Address = 10.0.0.1/32
PrivateKey = aaaa
[Peer]
PublicKey = bbbb
Endpoint = [2001:db8::1]:51820
""")
    assert p.endpoint_host == "2001:db8::1"
    assert p.endpoint_port == 51820


# ---------------------------------------------------------------------------
# probe() — data-channel detection via ping
# ---------------------------------------------------------------------------

_PING_SUCCESS = "PING 8.8.8.8: 3 packets transmitted, 3 received, 0% packet loss\n"
_PING_ZERO_RX = "PING 8.8.8.8: 3 packets transmitted, 0 received, 100% packet loss\n"

_SAMPLE_PEER = WgPeer(
    address="10.0.0.1/32",
    private_key="aaaa",
    public_key="bbbb",
    endpoint_host="1.2.3.4",
    endpoint_port=51820,
)


def _ok(stdout: str = "", rc: int = 0) -> CommandResult:
    return CommandResult(cmd="", rc=rc, stdout=stdout, stderr="")


def _apply_run_calls(ok: bool = True, ping_stdout: str = _PING_SUCCESS, ping_rc: int = 0):
    """Return the r.run() side-effect list for one probe iteration.

    apply() makes 4 direct r.run() calls:
      1. while uci -q delete network.@wireguard_<iface>[0]; do :; done
      2. uci set network.<iface>=interface  (check=True)
      3. uci add network wireguard_<iface>  (check=True)
      4. /etc/init.d/network reload         (check=True)

    probe() then adds:
      5. ip route add 8.8.8.8/32 dev <iface>
      6. ping -c 3 -W 6 -I <iface> 8.8.8.8
      7. ip route del 8.8.8.8/32 dev <iface>  (finally)
    """
    return [
        _ok(""),                        # wg peer wipe loop
        _ok(""),                        # uci set interface
        _ok(""),                        # uci add wireguard peer
        _ok(""),                        # /etc/init.d/network reload
        _ok(""),                        # ip route add
        _ok(ping_stdout, ping_rc),      # ping
        _ok(""),                        # ip route del
    ]


@pytest.fixture()
def wg_cfg() -> Config:
    return Config(host="10.0.0.1", user="root", password="x", vpn_interface="vpnclient")


def test_wg_probe_returns_peer_when_ping_succeeds(wg_cfg) -> None:
    r = mock.MagicMock()
    r.run.side_effect = _apply_run_calls(ping_stdout=_PING_SUCCESS, ping_rc=0)

    with mock.patch("openwrt_pbr_vpn.wireguard.time") as t:
        t.sleep = mock.MagicMock()
        result = probe(r, wg_cfg, [("Belgium", _SAMPLE_PEER)])

    assert result is not None
    assert result[0] == "Belgium"


def test_wg_probe_skips_peer_when_ping_zero_received(wg_cfg) -> None:
    r = mock.MagicMock()
    r.run.side_effect = _apply_run_calls(ping_stdout=_PING_ZERO_RX, ping_rc=1)

    with mock.patch("openwrt_pbr_vpn.wireguard.time") as t:
        t.sleep = mock.MagicMock()
        result = probe(r, wg_cfg, [("Belgium", _SAMPLE_PEER)])

    assert result is None


def test_wg_probe_skips_peer_when_ping_exits_nonzero(wg_cfg) -> None:
    r = mock.MagicMock()
    # ping exits 1 even though stdout looks like something received
    r.run.side_effect = _apply_run_calls(ping_stdout="3 received", ping_rc=1)

    with mock.patch("openwrt_pbr_vpn.wireguard.time") as t:
        t.sleep = mock.MagicMock()
        result = probe(r, wg_cfg, [("Belgium", _SAMPLE_PEER)])

    assert result is None


def test_wg_probe_returns_first_working_peer(wg_cfg) -> None:
    """First peer fails ping; second succeeds — probe must return the second."""
    dead_peer = WgPeer(
        address="10.0.0.2/32",
        private_key="cccc",
        public_key="dddd",
        endpoint_host="5.5.5.5",
        endpoint_port=51820,
    )
    r = mock.MagicMock()
    r.run.side_effect = (
        _apply_run_calls(ping_stdout=_PING_ZERO_RX, ping_rc=1)
        + _apply_run_calls(ping_stdout=_PING_SUCCESS, ping_rc=0)
    )

    with mock.patch("openwrt_pbr_vpn.wireguard.time") as t:
        t.sleep = mock.MagicMock()
        result = probe(r, wg_cfg, [("dead", dead_peer), ("good", _SAMPLE_PEER)])

    assert result is not None
    assert result[0] == "good"
