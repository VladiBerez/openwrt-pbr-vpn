"""Tests for the doctor command — checks evaluate router state into a report."""
from __future__ import annotations

from unittest import mock

import pytest

from openwrt_pbr_vpn import doctor
from openwrt_pbr_vpn.config import Config
from openwrt_pbr_vpn.doctor import Check, DoctorReport
from openwrt_pbr_vpn.router import CommandResult


@pytest.fixture()
def cfg() -> Config:
    return Config(host="10.0.0.1", user="root", password="x", vpn_interface="vpnclient")


# ----- DoctorReport aggregation -----

def test_overall_is_pass_when_all_pass():
    rep = DoctorReport(host="x", checks=[Check("a", "pass", "ok")])
    assert rep.overall == "pass"


def test_overall_warn_when_any_warn():
    rep = DoctorReport(host="x", checks=[
        Check("a", "pass", ""), Check("b", "warn", ""),
    ])
    assert rep.overall == "warn"


def test_overall_fail_dominates():
    rep = DoctorReport(host="x", checks=[
        Check("a", "pass", ""), Check("b", "warn", ""), Check("c", "fail", ""),
    ])
    assert rep.overall == "fail"


def test_summary_counts():
    rep = DoctorReport(host="x", checks=[
        Check("a", "pass", ""), Check("b", "pass", ""),
        Check("c", "warn", ""), Check("d", "fail", ""),
    ])
    assert rep.summary == {"pass": 2, "warn": 1, "fail": 1}


def test_to_dict_includes_overall_and_checks():
    rep = DoctorReport(host="r1", checks=[Check("a", "pass", "ok")])
    d = rep.to_dict()
    assert d["host"] == "r1"
    assert d["overall"] == "pass"
    assert d["checks"][0]["name"] == "a"


# ----- Individual check fns -----

def _mk_router(responses: dict[str, CommandResult]):
    r = mock.MagicMock()

    def run(cmd: str, **_kw):
        for needle, result in responses.items():
            if needle in cmd:
                return result
        return CommandResult(cmd=cmd, rc=0, stdout="", stderr="")

    r.run.side_effect = run
    r.uci_get.return_value = None
    return r


def test_ssh_check_passes_on_uname():
    r = _mk_router({"uname": CommandResult("uname", 0, "Linux router 5.15", "")})
    c = doctor._check_ssh(r)
    assert c.status == "pass"


def test_ssh_check_fails_when_no_output():
    r = _mk_router({"uname": CommandResult("uname", 1, "", "denied")})
    c = doctor._check_ssh(r)
    assert c.status == "fail"
    assert c.fix is not None


def test_pbr_running_check_passes_on_status():
    r = _mk_router({"service pbr status": CommandResult("x", 0, "pbr 1.2.2-r12 ...", "")})
    c = doctor._check_pbr_running(r)
    assert c.status == "pass"


def test_pbr_running_check_fails_when_absent():
    r = _mk_router({"service pbr status": CommandResult("x", 0, "(nothing)", "")})
    c = doctor._check_pbr_running(r)
    assert c.status == "fail"


def test_vpn_interface_warn_when_down(cfg):
    r = _mk_router({"ip link show vpnclient": CommandResult(
        "x", 0, "22: vpnclient: <POINTOPOINT,NOARP> mtu 1280 state DOWN", "")})
    c = doctor._check_vpn_interface(r, cfg)
    assert c.status == "warn"


def test_vpn_interface_fail_when_missing(cfg):
    r = _mk_router({"ip link show vpnclient": CommandResult(
        "x", 1, "Device \"vpnclient\" does not exist.", "")})
    c = doctor._check_vpn_interface(r, cfg)
    assert c.status == "fail"


def test_vpn_interface_pass_when_up(cfg):
    r = _mk_router({"ip link show vpnclient": CommandResult(
        "x", 0, "22: vpnclient: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1280", "")})
    c = doctor._check_vpn_interface(r, cfg)
    assert c.status == "pass"


def test_firewall_zone_pass_when_in_wan(cfg):
    r = mock.MagicMock()
    r.run.return_value = CommandResult(
        "x", 0,
        "firewall.@zone[1]=zone\n"
        "firewall.@zone[1].network='wan' 'wan6' 'vpnclient'\n",
        "",
    )
    r.uci_get.return_value = "wan"
    c = doctor._check_firewall_zone(r, cfg)
    assert c.status == "pass"


def test_firewall_zone_warn_when_in_separate_vpn_zone(cfg):
    r = mock.MagicMock()
    r.run.return_value = CommandResult(
        "x", 0,
        "firewall.@zone[2].network='vpnclient'\n",
        "",
    )
    r.uci_get.return_value = "vpn"
    c = doctor._check_firewall_zone(r, cfg)
    assert c.status == "warn"
    assert "vpn" in c.detail


def test_firewall_zone_fail_when_not_in_any_zone(cfg):
    r = mock.MagicMock()
    r.run.return_value = CommandResult("x", 0, "(unrelated)\n", "")
    r.uci_get.return_value = None
    c = doctor._check_firewall_zone(r, cfg)
    assert c.status == "fail"


def test_nft_set_fail_when_set_missing(cfg):
    def run(cmd, **_):
        if "list set" in cmd:
            return CommandResult("x", 1, "Error: No such file or directory", "")
        return CommandResult("x", 0, "", "")
    r = mock.MagicMock()
    r.run.side_effect = run
    c = doctor._check_nft_set(r, cfg)
    assert c.status == "fail"


def test_nft_set_warn_when_empty(cfg):
    def run(cmd, **_):
        if "grep -c" in cmd:
            return CommandResult("x", 0, "0\n", "")
        return CommandResult("x", 0, "table inet fw4 { ... }", "")
    r = mock.MagicMock()
    r.run.side_effect = run
    c = doctor._check_nft_set(r, cfg)
    assert c.status == "warn"


def test_nft_set_pass_when_populated(cfg):
    def run(cmd, **_):
        if "grep -c" in cmd:
            return CommandResult("x", 0, "178\n", "")
        return CommandResult("x", 0, "table inet fw4 { set ... { ... } }", "")
    r = mock.MagicMock()
    r.run.side_effect = run
    c = doctor._check_nft_set(r, cfg)
    assert c.status == "pass"
    assert "178" in c.detail


def test_strict_enforcement_warn_when_off():
    r = mock.MagicMock()
    r.uci_get.return_value = "0"
    c = doctor._check_strict_enforcement(r)
    assert c.status == "warn"


def test_strict_enforcement_pass_when_on():
    r = mock.MagicMock()
    r.uci_get.return_value = "1"
    c = doctor._check_strict_enforcement(r)
    assert c.status == "pass"


# ----- format_human -----

def test_format_human_renders_with_icons():
    rep = DoctorReport(host="r1", checks=[
        Check("a", "pass", "ok"),
        Check("b", "warn", "watch out", fix="do x"),
        Check("c", "fail", "broken", fix="do y"),
    ])
    text = doctor.format_human(rep)
    assert "[✓]" in text
    assert "[!]" in text
    assert "[✗]" in text
    assert "→ do x" in text
    assert "→ do y" in text


# ----- exception inside a check is captured, not propagated -----

def test_check_exception_becomes_fail(cfg):
    def boom(r, **_):
        raise RuntimeError("kaboom")

    with mock.patch.object(doctor, "CHECKS", [boom]):
        with mock.patch("openwrt_pbr_vpn.doctor.Router") as MockRouter:
            MockRouter.return_value.__enter__.return_value = mock.MagicMock()
            report = doctor.run(cfg)

    assert len(report.checks) == 1
    assert report.checks[0].status == "fail"
    assert "kaboom" in report.checks[0].detail
