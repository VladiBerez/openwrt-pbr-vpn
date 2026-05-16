"""Tests for config loading (env + INI + overrides)."""

from __future__ import annotations

from unittest import mock

import pytest

from openwrt_pbr_vpn import config


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Wipe relevant env vars so tests are deterministic."""
    for k in (
        "ROUTER_HOST",
        "ROUTER_PORT",
        "ROUTER_USER",
        "ROUTER_PASSWORD",
        "ROUTER_SSH_KEY",
        "VPN_INTERFACE",
        "REMOTE_ROUTES_PATH",
        "LOCAL_ROUTES_PATH",
        "DOMAINS_PATH",
        "BACKUPS_DIR",
    ):
        monkeypatch.delenv(k, raising=False)


def test_loads_from_env(monkeypatch, tmp_path):
    monkeypatch.setenv("ROUTER_HOST", "10.0.0.1")
    monkeypatch.setenv("ROUTER_USER", "admin")
    monkeypatch.setenv("ROUTER_PASSWORD", "secret")
    monkeypatch.chdir(tmp_path)
    cfg = config.load_config()
    assert cfg.host == "10.0.0.1"
    assert cfg.user == "admin"
    assert cfg.password == "secret"


def test_overrides_win_over_env(monkeypatch, tmp_path):
    monkeypatch.setenv("ROUTER_HOST", "10.0.0.1")
    monkeypatch.setenv("ROUTER_PASSWORD", "x")
    monkeypatch.chdir(tmp_path)
    cfg = config.load_config(host="192.168.1.1")
    assert cfg.host == "192.168.1.1"


def test_nft_set_name_derived_from_interface(monkeypatch, tmp_path):
    monkeypatch.setenv("ROUTER_HOST", "10.0.0.1")
    monkeypatch.setenv("ROUTER_PASSWORD", "x")
    monkeypatch.setenv("VPN_INTERFACE", "myvpn")
    monkeypatch.chdir(tmp_path)
    cfg = config.load_config()
    assert cfg.nft_set == "pbr_myvpn_4_dst_ip_user"


def test_raises_when_no_host(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(RuntimeError, match="host"):
        config.load_config()


def test_raises_when_no_credentials(monkeypatch, tmp_path):
    monkeypatch.setenv("ROUTER_HOST", "10.0.0.1")
    monkeypatch.chdir(tmp_path)
    # Ensure keyring returns nothing
    with (
        mock.patch.object(config, "_resolve_password", return_value=None),
        pytest.raises(RuntimeError, match="credentials"),
    ):
        config.load_config()


def test_password_falls_back_to_keyring(monkeypatch, tmp_path):
    monkeypatch.setenv("ROUTER_HOST", "10.0.0.1")
    monkeypatch.chdir(tmp_path)
    with mock.patch.object(config, "_resolve_password", return_value="from-keyring"):
        cfg = config.load_config()
    assert cfg.password == "from-keyring"


def test_loads_from_ini_file(monkeypatch, tmp_path):
    ini = tmp_path / "router.conf"
    ini.write_text(
        "[router]\nhost=1.2.3.4\nuser=root\npassword=p\n[vpn]\ninterface=tun9\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    cfg = config.load_config()
    assert cfg.host == "1.2.3.4"
    assert cfg.vpn_interface == "tun9"
    assert cfg.password == "p"
