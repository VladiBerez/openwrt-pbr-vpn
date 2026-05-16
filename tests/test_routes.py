"""Tests for the update flow. Router and DoH are mocked."""

from __future__ import annotations

import shutil
from pathlib import Path
from unittest import mock

import pytest

from openwrt_pbr_vpn import doh, routes
from openwrt_pbr_vpn.config import Config

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture()
def cfg(tmp_path: Path) -> Config:
    routes_file = tmp_path / "vpn-routes.sh"
    shutil.copy(FIXTURES / "sample_vpn_routes.sh", routes_file)

    domains_file = tmp_path / "domains.txt"
    domains_file.write_text("example.com\nnewservice.io\n", encoding="utf-8")

    return Config(
        host="10.0.0.1",
        user="root",
        password="x",
        local_routes=routes_file,
        domains=domains_file,
        backups_dir=tmp_path / "backups",
        batch_size=15,
    )


def test_update_skips_already_covered_ips(cfg: Config) -> None:
    """157.240.205.174 falls inside the existing 157.240.0.0/16 — must not be re-added."""
    resolved = {
        "example.com": {"157.240.205.174"},  # already covered
        "newservice.io": {"203.0.113.42"},  # new
    }
    with (
        mock.patch.object(doh, "resolve_many", return_value=resolved),
        mock.patch.object(routes, "_upload_only") as upload,
    ):
        summary = routes.update(cfg, upload=False)

    text = cfg.local_routes.read_text(encoding="utf-8")
    assert summary["new_ips"] == ["203.0.113.42"]
    assert "203.0.113.42" in text
    # the already-covered IP must NOT appear in any auto-added block
    auto_section = text.split("# --- auto-added", 1)[-1]
    assert "157.240.205.174" not in auto_section
    upload.assert_not_called()


def test_update_uploads_when_requested(cfg: Config) -> None:
    resolved = {"newservice.io": {"203.0.113.42"}}
    with (
        mock.patch.object(doh, "resolve_many", return_value=resolved),
        mock.patch.object(routes, "_upload_only") as upload,
    ):
        summary = routes.update(cfg, upload=True)
    assert summary["uploaded"] is True
    upload.assert_called_once_with(cfg)


def test_update_idempotent_on_second_run(cfg: Config) -> None:
    """Running twice with the same resolve result adds entries once."""
    resolved = {"x.com": {"203.0.113.99"}}

    with (
        mock.patch.object(doh, "resolve_many", return_value=resolved),
        mock.patch.object(routes, "_upload_only"),
    ):
        routes.update(cfg, upload=False)
        size_after_first = cfg.local_routes.stat().st_size
        routes.update(cfg, upload=False)
        size_after_second = cfg.local_routes.stat().st_size

    assert size_after_first == size_after_second
    assert cfg.local_routes.read_text().count("203.0.113.99") == 1


def test_update_no_new_ips_does_not_modify_file(cfg: Config) -> None:
    resolved = {"x.com": {"157.240.10.10"}}  # covered by 157.240.0.0/16
    before = cfg.local_routes.read_text(encoding="utf-8")
    with (
        mock.patch.object(doh, "resolve_many", return_value=resolved),
        mock.patch.object(routes, "_upload_only"),
    ):
        summary = routes.update(cfg, upload=False)
    after = cfg.local_routes.read_text(encoding="utf-8")
    assert summary["new_ips"] == []
    assert before == after


def test_update_raises_on_missing_local_file(tmp_path: Path) -> None:
    cfg = Config(
        host="10.0.0.1",
        user="root",
        password="x",
        local_routes=tmp_path / "missing.sh",
        domains=tmp_path / "domains.txt",
    )
    with pytest.raises(FileNotFoundError):
        routes.update(cfg, upload=False)


def test_routes_remove_strips_entries(cfg: Config) -> None:
    """routes_remove deletes the named entry from the file."""
    with mock.patch.object(routes, "_upload_only"):
        n = routes.routes_remove(cfg, ["1.2.3.4"])
    assert n == 1
    assert "1.2.3.4" not in cfg.local_routes.read_text(encoding="utf-8")


def test_routes_add_appends_block(cfg: Config) -> None:
    with mock.patch.object(routes, "_upload_only"):
        routes.routes_add(cfg, ["8.8.8.8", "1.0.0.0/24"])
    text = cfg.local_routes.read_text(encoding="utf-8")
    assert "8.8.8.8" in text
    assert "1.0.0.0/24" in text
