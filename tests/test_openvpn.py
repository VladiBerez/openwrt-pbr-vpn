"""Tests for OpenVPN profile patching."""
from __future__ import annotations

from openwrt_pbr_vpn.openvpn import patch_for_split_tunnel


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
