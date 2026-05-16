"""Tests for argparse wiring. Handlers are mocked."""
from __future__ import annotations

from unittest import mock

import pytest

from openwrt_pbr_vpn import cli


def test_help_lists_all_subcommands() -> None:
    parser = cli.build_parser()
    # argparse rejects bare `--help` via SystemExit; parse a known subcommand instead.
    args = parser.parse_args(["update", "--no-upload"])
    assert args.cmd == "update"
    assert args.no_upload is True


def test_requires_subcommand() -> None:
    parser = cli.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([])


def test_wg_set_requires_config() -> None:
    parser = cli.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["wg", "set"])


def test_routes_add_takes_entries() -> None:
    parser = cli.build_parser()
    args = parser.parse_args(["routes", "add", "1.2.3.4", "5.6.7.0/24"])
    assert args.entries == ["1.2.3.4", "5.6.7.0/24"]


@mock.patch("openwrt_pbr_vpn.cli.cmd_update", return_value=0)
def test_main_dispatches_to_handler(handler, monkeypatch) -> None:
    # We don't want load_config to inspect environment — handler is mocked.
    rc = cli.main(["update", "--no-upload"])
    assert rc == 0
    handler.assert_called_once()


@mock.patch("openwrt_pbr_vpn.cli.cmd_update", side_effect=RuntimeError("nope"))
def test_main_catches_exceptions_and_returns_1(handler, capsys) -> None:
    rc = cli.main(["update"])
    assert rc == 1
    captured = capsys.readouterr()
    assert "ERROR" in captured.err


@mock.patch("openwrt_pbr_vpn.cli.cmd_update", side_effect=KeyboardInterrupt())
def test_main_handles_ctrl_c(handler) -> None:
    rc = cli.main(["update"])
    assert rc == 130
