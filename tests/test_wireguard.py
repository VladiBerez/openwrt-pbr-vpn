"""Tests for WireGuard .conf parsing."""

from __future__ import annotations

import pytest

from openwrt_pbr_vpn.wireguard import WgPeer

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
