"""Tests for DoH resolver. Network calls are mocked."""
from __future__ import annotations

import io
import json
from unittest import mock

import pytest

from openwrt_pbr_vpn import doh


def _mock_response(ips: list[str]):
    body = json.dumps({"Answer": [{"type": 1, "data": ip} for ip in ips]}).encode()
    m = mock.MagicMock()
    m.__enter__ = mock.MagicMock(return_value=m)
    m.__exit__ = mock.MagicMock(return_value=False)
    m.read = mock.MagicMock(return_value=body)
    return m


def test_resolve_a_merges_resolvers() -> None:
    responses = [
        _mock_response(["1.1.1.1"]),
        _mock_response(["2.2.2.2", "1.1.1.1"]),
    ]
    with mock.patch("urllib.request.urlopen", side_effect=responses):
        ips = doh.resolve_a("example.com")
    assert ips == {"1.1.1.1", "2.2.2.2"}


def test_resolve_a_tolerates_one_failure() -> None:
    ok = _mock_response(["3.3.3.3"])
    with mock.patch("urllib.request.urlopen", side_effect=[Exception("boom"), ok]):
        ips = doh.resolve_a("example.com")
    assert ips == {"3.3.3.3"}


def test_load_domains_skips_comments_and_blanks(tmp_path) -> None:
    p = tmp_path / "domains.txt"
    p.write_text(
        "# comment\n"
        "\n"
        "example.com\n"
        "  foo.bar  \n"
        "# another\n",
        encoding="utf-8",
    )
    assert doh.load_domains(p) == ["example.com", "foo.bar"]
