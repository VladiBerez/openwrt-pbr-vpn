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
