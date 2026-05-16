"""Contract tests — the JSON shape the CLI emits must match what the UI expects.

These run the CLI as a subprocess and assert the structure of every command's
--json output. Network/SSH operations are short-circuited by feeding an
unreachable host so the run can't hang; we still get a parseable JSON-shaped
error response from the wrapped commands.

The UI's `src/shared/api/types.ts` is the consumer of these shapes; if you
change one without updating the other, this test catches it.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


def _run(*args: str, env_extra: dict[str, str] | None = None) -> tuple[int, str, str]:
    import os

    # Start from the parent process env (so PATH, Python, etc. work) but let
    # caller-supplied vars OVERRIDE anything inherited — that's the point.
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    if env_extra:
        env.update(env_extra)
    # We run the module directly so the test works even when the console_scripts
    # shim isn't on PATH.
    proc = subprocess.run(
        [sys.executable, "-m", "openwrt_pbr_vpn", "--json", *args],
        cwd=REPO,
        capture_output=True,
        text=True,
        timeout=20,
        env=env,
    )
    return proc.returncode, proc.stdout, proc.stderr


def test_cli_help_does_not_die() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "openwrt_pbr_vpn", "--help"],
        cwd=REPO,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert proc.returncode == 0
    assert b"--json" in proc.stdout.encode() or "--json" in proc.stdout


def test_unreachable_host_returns_clean_error() -> None:
    """With ROUTER_HOST=127.0.0.1 and no SSH server, the CLI must exit non-zero
    with a single-line error on stderr (no half-written JSON on stdout).

    The UI's CliError reads exitCode + stderr; this verifies that contract.
    """
    rc, out, err = _run(
        "diagnose",
        env_extra={
            "ROUTER_HOST": "127.0.0.1",
            "ROUTER_USER": "root",
            "ROUTER_PASSWORD": "x",
            "ROUTER_PORT": "1",  # nothing listens here
        },
    )
    assert rc != 0
    assert "ERROR" in err or err.strip()
    # Stdout must NOT contain a half-written JSON object: either it's empty,
    # or it's a clean JSON document. Otherwise UI's JSON.parse explodes.
    if out.strip():
        # Should be parseable as JSON if anything was printed
        try:
            json.loads(out)
        except json.JSONDecodeError as e:
            pytest.fail(f"Garbage on stdout that's not valid JSON: {e}\n{out!r}")


def test_doctor_report_shape_matches_ts_type() -> None:
    """We can't reach the router from CI, but we can build a DoctorReport
    object and serialise it through the same path the CLI uses. Verify the
    JSON keys match what `src/shared/api/types.ts` declares.

    UI contract (DoctorReport):
      host: string
      overall: "pass" | "warn" | "fail"
      summary: { pass: number, warn: number, fail: number }
      checks: { name, status, detail, fix }[]
    """
    from openwrt_pbr_vpn.doctor import Check, DoctorReport

    rep = DoctorReport(
        host="r1",
        checks=[
            Check("a", "pass", "ok"),
            Check("b", "warn", "watch out", fix="do x"),
        ],
    )
    serialized = json.dumps(rep.to_dict())
    parsed = json.loads(serialized)

    # Top-level keys
    assert set(parsed.keys()) == {"host", "overall", "summary", "checks"}
    # summary shape
    assert set(parsed["summary"].keys()) == {"pass", "warn", "fail"}
    # checks shape — every item must have all four fields the TS type declares
    for c in parsed["checks"]:
        assert set(c.keys()) == {"name", "status", "detail", "fix"}
        assert c["status"] in ("pass", "warn", "fail")


def test_diagnose_state_shape_matches_ts_type() -> None:
    """DiagnoseResult on the TS side has specific keys. Make sure
    collect_state() builds the same set."""
    from openwrt_pbr_vpn.diagnose import _parse_wg_show

    # _parse_wg_show is pure — produces the WireguardInfo dict the UI expects.
    out = """interface: vpnclient
  listening port: 33239

peer: ABCD
  endpoint: 1.2.3.4:51820
  latest handshake: 30 seconds ago
  transfer: 1.5 MiB received, 2.3 MiB sent
"""
    wg = _parse_wg_show(out)
    assert set(wg.keys()) == {
        "interface",
        "peer",
        "endpoint",
        "latest_handshake",
        "rx_bytes",
        "tx_bytes",
    }
    assert wg["interface"] == "vpnclient"
    assert wg["peer"] == "ABCD"
    assert wg["endpoint"] == "1.2.3.4:51820"
    assert wg["rx_bytes"] > 1_000_000  # ~1.5 MiB
    assert wg["tx_bytes"] > 2_000_000


def test_update_summary_shape_matches_ts_type() -> None:
    """UpdateResult: { domains, total_resolved, new_ips, uploaded }."""
    # tiny fixture
    import tempfile
    from unittest import mock

    from openwrt_pbr_vpn import doh, routes
    from openwrt_pbr_vpn.config import Config

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        routes_file = tmp_path / "vpn-routes.sh"
        routes_file.write_text(
            '#!/bin/sh\nS="pbr_vpnclient_4_dst_ip_user"\n'
            'nft add element inet fw4 $S "{ 1.2.3.0/24 }" 2>/dev/null\n',
            encoding="utf-8",
        )
        domains_file = tmp_path / "domains.txt"
        domains_file.write_text("example.com\n", encoding="utf-8")

        cfg = Config(
            host="x",
            user="x",
            password="x",
            local_routes=routes_file,
            domains=domains_file,
        )
        with (
            mock.patch.object(doh, "resolve_many", return_value={"example.com": {"5.5.5.5"}}),
            mock.patch.object(routes, "_upload_only"),
        ):
            summary = routes.update(cfg, upload=False)

    assert set(summary.keys()) == {"domains", "total_resolved", "new_ips", "uploaded"}
    assert isinstance(summary["new_ips"], list)
    assert all(isinstance(ip, str) for ip in summary["new_ips"])
