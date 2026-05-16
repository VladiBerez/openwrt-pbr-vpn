"""Tests for argparse wiring + --json output mode."""

from __future__ import annotations

import json
from unittest import mock

import pytest

from openwrt_pbr_vpn import cli

# ----- argument parsing -----


def test_update_parses_no_upload() -> None:
    parser = cli.build_parser()
    args = parser.parse_args(["update", "--no-upload"])
    assert args.cmd == "update"
    assert args.no_upload is True
    assert args.json is False
    assert args.verbose is False


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


def test_global_flags_parse() -> None:
    parser = cli.build_parser()
    args = parser.parse_args(["--json", "-v", "diagnose"])
    assert args.json is True
    assert args.verbose is True


def test_verbose_and_quiet_are_mutually_exclusive() -> None:
    parser = cli.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["-v", "-q", "diagnose"])


# ----- main() dispatch and exit codes -----


@mock.patch("openwrt_pbr_vpn.cli.cmd_update", return_value=({"new_ips": ["1.1.1.1"]}, "1 new"))
def test_main_dispatches_and_prints_human(handler, capsys) -> None:
    rc = cli.main(["update", "--no-upload"])
    assert rc == 0
    captured = capsys.readouterr()
    assert captured.out.strip() == "1 new"
    handler.assert_called_once()


@mock.patch("openwrt_pbr_vpn.cli.cmd_update", return_value=({"new_ips": ["1.1.1.1"]}, "1 new"))
def test_main_json_mode_emits_valid_json(handler, capsys) -> None:
    rc = cli.main(["--json", "update", "--no-upload"])
    assert rc == 0
    captured = capsys.readouterr()
    parsed = json.loads(captured.out)
    assert parsed == {"new_ips": ["1.1.1.1"]}


@mock.patch(
    "openwrt_pbr_vpn.cli.cmd_diagnose",
    return_value=({"host": "10.0.0.1", "tun0_up": True}, "tun0 UP"),
)
def test_diagnose_json_contains_state_keys(handler, capsys) -> None:
    cli.main(["--json", "diagnose"])
    parsed = json.loads(capsys.readouterr().out)
    assert parsed["host"] == "10.0.0.1"
    assert parsed["tun0_up"] is True


@mock.patch("openwrt_pbr_vpn.cli.cmd_update", side_effect=RuntimeError("boom"))
def test_main_catches_exceptions(handler, capsys) -> None:
    rc = cli.main(["update"])
    assert rc == 1
    assert "ERROR: boom" in capsys.readouterr().err


@mock.patch("openwrt_pbr_vpn.cli.cmd_update", side_effect=KeyboardInterrupt())
def test_main_handles_ctrl_c(handler) -> None:
    rc = cli.main(["update"])
    assert rc == 130


@mock.patch("openwrt_pbr_vpn.cli.cmd_update", return_value=({"foo": "bar"}, None))
def test_human_mode_falls_back_to_json_when_no_human_text(handler, capsys) -> None:
    cli.main(["update"])
    parsed = json.loads(capsys.readouterr().out)
    assert parsed == {"foo": "bar"}


@mock.patch("openwrt_pbr_vpn.cli.cmd_update")
def test_json_flag_silences_info_logs(handler, capsys) -> None:
    """--json sets quiet=True so progress logs don't pollute stderr."""
    import logging

    handler.return_value = ({"x": 1}, "x")
    cli.main(["--json", "update"])
    # In quiet mode the root level is WARNING
    assert logging.getLogger().level == logging.WARNING
