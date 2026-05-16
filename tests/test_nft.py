"""Tests for nft set parsing, coverage, aggregation, append rendering."""
from __future__ import annotations

import ipaddress
import shutil
import tempfile
from datetime import datetime
from pathlib import Path

import pytest

from openwrt_pbr_vpn import nft

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture()
def routes_file(tmp_path: Path) -> Path:
    dst = tmp_path / "vpn-routes.sh"
    shutil.copy(FIXTURES / "sample_vpn_routes.sh", dst)
    return dst


# ----- parse_networks -----

def test_extracts_all_cidrs_and_ips(routes_file: Path) -> None:
    nets = nft.parse_networks(routes_file)
    as_str = sorted(str(n) for n in nets)
    assert as_str == sorted([
        "157.240.0.0/16",
        "91.108.4.0/22",
        "1.2.3.4/32",
        "172.217.0.0/16",
        "142.250.0.0/15",
    ])


def test_ignores_ip_outside_nft_braces(routes_file: Path) -> None:
    nets = nft.parse_networks(routes_file)
    assert not any(ipaddress.ip_address("9.9.9.9") in n for n in nets)


# ----- is_covered -----

@pytest.fixture()
def sample_nets() -> list[ipaddress.IPv4Network]:
    return [
        ipaddress.ip_network("157.240.0.0/16"),
        ipaddress.ip_network("1.2.3.4/32"),
    ]


def test_exact_match(sample_nets) -> None:
    assert nft.is_covered("1.2.3.4", sample_nets)


def test_inside_subnet(sample_nets) -> None:
    assert nft.is_covered("157.240.205.174", sample_nets)


def test_outside(sample_nets) -> None:
    assert not nft.is_covered("8.8.8.8", sample_nets)


def test_invalid_ip_returns_true_to_filter_out(sample_nets) -> None:
    assert nft.is_covered("not-an-ip", sample_nets)


# ----- aggregate_into_24 -----

def test_aggregates_when_3_or_more_in_same_24() -> None:
    ips = ["5.5.5.1", "5.5.5.2", "5.5.5.3", "6.6.6.1"]
    cidrs, singles = nft.aggregate_into_24(ips, existing=[])
    assert "5.5.5.0/24" in cidrs
    assert singles == ["6.6.6.1"]


def test_aggregate_below_threshold_keeps_singles() -> None:
    ips = ["5.5.5.1", "5.5.5.2"]
    cidrs, singles = nft.aggregate_into_24(ips, existing=[])
    assert cidrs == []
    assert sorted(singles) == ["5.5.5.1", "5.5.5.2"]


def test_aggregate_skips_already_covered() -> None:
    ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    existing = [ipaddress.ip_network("10.0.0.0/8")]
    cidrs, singles = nft.aggregate_into_24(ips, existing=existing)
    assert cidrs == []
    assert singles == []


# ----- render_append_block + append_to_file -----

def test_render_produces_correct_batches() -> None:
    items = [f"10.0.0.{i}" for i in range(20)]
    block = nft.render_append_block(items, batch_size=15, timestamp=datetime(2026, 1, 1, 12, 0))
    assert "# --- auto-added 2026-01-01 12:00 (20 entries) ---" in block
    assert block.count("nft add element") == 2  # 15 + 5
    for ip in items:
        assert ip in block


def test_append_preserves_existing_and_uses_lf(routes_file: Path) -> None:
    block = nft.render_append_block(["10.0.0.1"], batch_size=15)
    nft.append_to_file(routes_file, block)
    raw = routes_file.read_bytes()
    assert b"\r\n" not in raw
    assert b"157.240.0.0/16" in raw  # original untouched
    assert b"10.0.0.1" in raw
