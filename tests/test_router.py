"""Tests for the paramiko wrapper. The SSH session itself is mocked."""

from __future__ import annotations

from unittest import mock

import pytest

from openwrt_pbr_vpn.config import Config
from openwrt_pbr_vpn.router import CommandResult, Router


@pytest.fixture()
def cfg() -> Config:
    return Config(host="10.0.0.1", user="root", password="x")


def _make_channel(rc: int = 0, stdout: bytes = b"", stderr: bytes = b""):
    chan = mock.MagicMock()
    chan.recv_exit_status.return_value = rc
    stdout_f = mock.MagicMock()
    stdout_f.channel = chan
    stdout_f.read.return_value = stdout
    stderr_f = mock.MagicMock()
    stderr_f.channel = chan
    stderr_f.read.return_value = stderr
    stdin_f = mock.MagicMock()
    stdin_f.channel = chan
    return stdin_f, stdout_f, stderr_f


def _patch_paramiko(monkeypatch, exec_side_effect):
    client = mock.MagicMock()
    client.exec_command.side_effect = exec_side_effect

    fake_ssh = mock.MagicMock()
    fake_ssh.SSHClient.return_value = client
    fake_ssh.AutoAddPolicy = mock.MagicMock()

    monkeypatch.setattr("openwrt_pbr_vpn.router.paramiko", fake_ssh)
    return client


def test_run_returns_stdout_and_rc(monkeypatch, cfg):
    chans = _make_channel(rc=0, stdout=b"hello\n")
    _patch_paramiko(monkeypatch, lambda *a, **kw: chans)
    r = Router(cfg)
    r.connect()
    result = r.run("echo hello")
    assert isinstance(result, CommandResult)
    assert result.ok
    assert result.stdout == "hello\n"
    assert result.rc == 0


def test_run_with_check_raises_on_nonzero(monkeypatch, cfg):
    chans = _make_channel(rc=2, stderr=b"boom")
    _patch_paramiko(monkeypatch, lambda *a, **kw: chans)
    r = Router(cfg)
    r.connect()
    with pytest.raises(RuntimeError, match="rc=2"):
        r.run("false", check=True)


def test_upload_bytes_normalizes_crlf(monkeypatch, cfg):
    captured: dict = {}

    def exec_command(cmd, timeout=None):
        chans = _make_channel(rc=0)
        # capture writes to stdin
        chans[0].write.side_effect = lambda data: captured.setdefault("data", data)
        return chans

    _patch_paramiko(monkeypatch, exec_command)
    r = Router(cfg)
    r.connect()
    r.upload_bytes(b"line1\r\nline2\r\n", "/tmp/x")
    assert captured["data"] == b"line1\nline2\n"


def test_uci_set_quotes_values(monkeypatch, cfg):
    seen: list[str] = []

    def exec_command(cmd, timeout=None):
        seen.append(cmd)
        return _make_channel(rc=0)

    _patch_paramiko(monkeypatch, exec_command)
    r = Router(cfg)
    r.connect()
    r.uci_set("network.foo.bar", "value with 'quotes'")
    assert any("'value with '\\''quotes'\\'''" in c for c in seen)


def test_context_manager_closes_client(monkeypatch, cfg):
    _patch_paramiko(monkeypatch, lambda *a, **kw: _make_channel())
    with Router(cfg) as r:
        assert r._client is not None
    # after exit
    assert r._client is None
