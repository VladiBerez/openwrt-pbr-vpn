"""Tests for output module — logging setup, JSON emission, formatters."""
from __future__ import annotations

import io
import json
import logging
import sys
from unittest import mock

import pytest

from openwrt_pbr_vpn import output


def test_setup_logging_default_is_info():
    output.setup_logging()
    assert logging.getLogger().level == logging.INFO


def test_setup_logging_verbose_sets_debug():
    output.setup_logging(verbose=True)
    assert logging.getLogger().level == logging.DEBUG


def test_setup_logging_quiet_sets_warning():
    output.setup_logging(quiet=True)
    assert logging.getLogger().level == logging.WARNING


def test_logger_keeps_stdout_clean(capsys, caplog):
    """Stdout must stay empty so callers can pipe machine-readable JSON cleanly."""
    output.setup_logging()
    with caplog.at_level(logging.INFO, logger="ovpn_pbr"):
        logging.getLogger("ovpn_pbr").info("hello")
    assert "hello" in caplog.text
    assert capsys.readouterr().out == ""


def test_stream_handler_targets_stderr():
    """The handler installed by setup_logging must point at stderr."""
    output.setup_logging()
    root = logging.getLogger()
    stream_handlers = [h for h in root.handlers if isinstance(h, logging.StreamHandler)]
    assert any(h.stream is sys.stderr for h in stream_handlers)


def test_emit_result_json_mode(capsys):
    output.emit_result({"foo": "bar", "n": 42}, as_json=True)
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload == {"foo": "bar", "n": 42}


def test_emit_result_human_mode_uses_human_text(capsys):
    output.emit_result({"foo": "bar"}, as_json=False, human="VPN: OK")
    captured = capsys.readouterr()
    assert captured.out.strip() == "VPN: OK"


def test_emit_result_human_mode_falls_back_to_json(capsys):
    output.emit_result({"foo": "bar"}, as_json=False)
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload == {"foo": "bar"}


def test_emit_result_handles_none_result(capsys):
    output.emit_result(None, as_json=False)
    captured = capsys.readouterr()
    # No output at all
    assert captured.out == ""


def test_fmt_bytes():
    assert output.fmt_bytes(0) == "0 B"
    assert output.fmt_bytes(500) == "500 B"
    assert output.fmt_bytes(1024) == "1.00 KiB"
    assert output.fmt_bytes(1024 * 1024) == "1.00 MiB"
    assert output.fmt_bytes(int(2.5 * 1024**3)) == "2.50 GiB"


def test_fmt_age_seconds():
    assert output.fmt_age(0) == "just now"
    assert output.fmt_age(4) == "just now"
    assert output.fmt_age(30) == "30s ago"


def test_fmt_age_minutes():
    assert output.fmt_age(125) == "2m 5s ago"


def test_fmt_age_hours():
    assert output.fmt_age(3725) == "1h 2m ago"


def test_fmt_age_days():
    assert output.fmt_age(90000) == "1d 1h ago"
