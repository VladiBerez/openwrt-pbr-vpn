"""Tests for daemon: classify_health, pick_next, persistence, main loop."""

from __future__ import annotations

import json
import time
from pathlib import Path
from unittest import mock

import pytest

from openwrt_pbr_vpn import daemon
from openwrt_pbr_vpn.config import Config
from openwrt_pbr_vpn.daemon import (
    Daemon,
    DaemonConfig,
    DaemonState,
    Health,
    PeerEntry,
    classify_health,
    load_pool,
    load_state,
    persist_state,
    pick_next,
    to_dict,
)
from openwrt_pbr_vpn.wireguard import WgPeer

# ----- fixtures -----

SAMPLE_CONF = """\
[Interface]
Address = 10.0.0.1/32
PrivateKey = aaaa

[Peer]
PublicKey = bbbb
AllowedIPs = 0.0.0.0/0
Endpoint = {host}:51820
PersistentKeepalive = 25
"""


@pytest.fixture()
def pool(tmp_path: Path) -> Path:
    """Create three valid .conf files in a temp pool dir."""
    for i, host in enumerate(["1.1.1.1", "2.2.2.2", "3.3.3.3"]):
        (tmp_path / f"peer{i}.conf").write_text(SAMPLE_CONF.format(host=host), encoding="utf-8")
    return tmp_path


@pytest.fixture()
def cfg() -> Config:
    return Config(host="10.0.0.1", user="root", password="x", vpn_interface="vpnclient")


# ----- load_pool -----


def test_load_pool_reads_all_conf_files(pool: Path) -> None:
    entries = load_pool(pool)
    assert [e.name for e in entries] == ["peer0", "peer1", "peer2"]
    assert isinstance(entries[0].peer, WgPeer)


def test_load_pool_skips_broken_files(pool: Path) -> None:
    (pool / "broken.conf").write_text("not a valid wg config", encoding="utf-8")
    entries = load_pool(pool)
    # Only the 3 valid ones come back
    assert len(entries) == 3


def test_load_pool_empty_dir(tmp_path: Path) -> None:
    assert load_pool(tmp_path) == []


# ----- pick_next -----


def _mk_pool(*names: str) -> list[PeerEntry]:
    return [PeerEntry(name=n, path=Path(f"{n}.conf"), peer=mock.MagicMock()) for n in names]


def test_pick_next_returns_first_when_nothing_dead() -> None:
    pool = _mk_pool("a", "b", "c")
    assert pick_next(pool, dead={}, now=100).name == "a"


def test_pick_next_skips_dead_within_ttl() -> None:
    pool = _mk_pool("a", "b", "c")
    dead = {"a": 100.0}
    assert pick_next(pool, dead, now=200, dead_ttl=1000).name == "b"


def test_pick_next_uses_dead_again_after_ttl() -> None:
    pool = _mk_pool("a", "b")
    dead = {"a": 100.0}
    assert pick_next(pool, dead, now=5000, dead_ttl=1000).name == "a"


def test_pick_next_skips_explicit_peer() -> None:
    pool = _mk_pool("a", "b", "c")
    assert pick_next(pool, dead={}, skip="a", now=100).name == "b"


def test_pick_next_returns_none_when_all_dead() -> None:
    pool = _mk_pool("a", "b")
    dead = {"a": 100.0, "b": 100.0}
    assert pick_next(pool, dead, now=200, dead_ttl=1000) is None


# ----- classify_health -----


def test_health_no_interface() -> None:
    assert (
        classify_health(
            has_interface=False,
            rx_now=0,
            rx_prev=0,
            tx_now=0,
            tx_prev=0,
            handshake_age_seconds=10,
            handshake_stale_seconds=300,
        )
        == Health.NO_INTERFACE
    )


def test_health_healthy_when_rx_grew() -> None:
    assert (
        classify_health(
            has_interface=True,
            rx_now=1000,
            rx_prev=500,
            tx_now=2000,
            tx_prev=1500,
            handshake_age_seconds=10,
            handshake_stale_seconds=300,
        )
        == Health.HEALTHY
    )


def test_health_no_handshake_when_handshake_too_old() -> None:
    assert (
        classify_health(
            has_interface=True,
            rx_now=500,
            rx_prev=500,
            tx_now=600,
            tx_prev=600,
            handshake_age_seconds=400,
            handshake_stale_seconds=300,
        )
        == Health.NO_HANDSHAKE
    )


def test_health_no_data_when_only_tx_grows() -> None:
    """Classic DPI signature: we send into the tunnel, nothing comes back."""
    assert (
        classify_health(
            has_interface=True,
            rx_now=500,
            rx_prev=500,
            tx_now=2000,
            tx_prev=500,
            handshake_age_seconds=10,
            handshake_stale_seconds=300,
        )
        == Health.NO_DATA
    )


def test_health_unknown_when_no_traffic_yet() -> None:
    assert (
        classify_health(
            has_interface=True,
            rx_now=0,
            rx_prev=0,
            tx_now=0,
            tx_prev=0,
            handshake_age_seconds=None,
            handshake_stale_seconds=300,
        )
        == Health.UNKNOWN
    )


# ----- persistence -----


def test_persist_and_load_roundtrip(tmp_path: Path) -> None:
    s = DaemonState(
        current_peer="alpha",
        last_rx=1234,
        last_tx=5678,
        last_health=Health.HEALTHY,
        dead={"old": 100.0, "older": 200.0},
    )
    p = tmp_path / "state.json"
    persist_state(s, p)
    loaded = load_state(p)
    assert loaded.current_peer == "alpha"
    assert loaded.last_rx == 1234
    assert loaded.last_health == Health.HEALTHY
    assert loaded.dead == {"old": 100.0, "older": 200.0}


def test_load_state_missing_file_returns_empty(tmp_path: Path) -> None:
    s = load_state(tmp_path / "nope.json")
    assert s.current_peer is None
    assert s.dead == {}


def test_load_state_corrupted_returns_empty(tmp_path: Path) -> None:
    p = tmp_path / "corrupt.json"
    p.write_text("{this is not json", encoding="utf-8")
    assert load_state(p).current_peer is None


def test_to_dict_serializable() -> None:
    s = DaemonState(current_peer="x", last_health=Health.NO_DATA, dead={"a": 1.5})
    d = to_dict(s)
    # Must round-trip through json
    serialized = json.dumps(d)
    assert "x" in serialized
    assert "no_data" in serialized


# ----- handshake age parser -----


def test_parse_handshake_age_returns_none_for_zero() -> None:
    assert daemon._parse_handshake_age("PUBKEY\t0") is None


def test_parse_handshake_age_returns_none_for_garbage() -> None:
    assert daemon._parse_handshake_age("garbage") is None


def test_parse_handshake_age_computes_age() -> None:
    now = time.time()
    text = f"PUBKEY\t{int(now - 60)}"
    age = daemon._parse_handshake_age(text)
    assert age is not None
    assert 55 < age < 65


# ----- main loop integration -----


def _mk_daemon(cfg: Config, pool: Path, *, max_iter: int = 1) -> tuple[Daemon, mock.MagicMock]:
    """Construct a daemon with a mocked Router and zero sleep."""
    fake_router = mock.MagicMock()
    fake_router.__enter__.return_value = fake_router
    fake_router.__exit__.return_value = False

    dcfg = DaemonConfig(
        pool_dir=pool,
        check_interval=0,
        handshake_stale_seconds=300,
        dead_ttl=3600,
        cooldown_seconds=0,
        consecutive_bad_to_switch=1,  # switch immediately on bad
        max_iterations=max_iter,
    )
    sleeps: list[float] = []
    d = Daemon(cfg, dcfg, sleep=sleeps.append, clock=lambda: 1000.0)
    d._sleeps = sleeps  # type: ignore[attr-defined]
    return d, fake_router


def test_daemon_raises_on_empty_pool(tmp_path: Path, cfg: Config) -> None:
    d = Daemon(cfg, DaemonConfig(pool_dir=tmp_path))
    with pytest.raises(RuntimeError, match=r"no \.conf files"):
        d.run()


def test_daemon_switches_to_first_peer(pool: Path, cfg: Config) -> None:
    d, fake_router = _mk_daemon(cfg, pool, max_iter=1)
    with (
        mock.patch.object(daemon, "Router", return_value=fake_router),
        mock.patch.object(daemon, "_apply_peer") as apply_peer,
        mock.patch.object(daemon, "sample_counters", return_value=(100, 100, 10.0, True)),
    ):
        state = d.run()
    apply_peer.assert_called()
    assert state.current_peer == "peer0"


def test_daemon_switches_on_no_data_health(pool: Path, cfg: Config) -> None:
    """rx flat + tx growing → mark dead → pick next peer."""
    d, fake_router = _mk_daemon(cfg, pool, max_iter=2)
    samples = iter(
        [
            (0, 0, 10.0, True),  # initial after first switch — unknown
            (0, 5000, 10.0, True),  # 2nd tick: tx grew, rx flat → NO_DATA
            (0, 0, 10.0, True),  # 3rd tick after switch
        ]
    )
    with (
        mock.patch.object(daemon, "Router", return_value=fake_router),
        mock.patch.object(daemon, "_apply_peer") as apply_peer,
        mock.patch.object(daemon, "sample_counters", side_effect=lambda *_a: next(samples)),
    ):
        state = d.run()

    # First peer was applied, then a second one after marking the first dead.
    assert apply_peer.call_count >= 2
    # peer0 is in dead cache
    assert "peer0" in state.dead


def test_daemon_resets_dead_cache_when_all_dead(pool: Path, cfg: Config) -> None:
    """If every peer is in `dead`, daemon clears the cache and sleeps cooldown."""
    d, fake_router = _mk_daemon(cfg, pool, max_iter=1)
    d.state.dead = {"peer0": 999.0, "peer1": 999.0, "peer2": 999.0}
    d.state.current_peer = None
    sleeps: list[float] = []
    d._sleep = sleeps.append
    with (
        mock.patch.object(daemon, "Router", return_value=fake_router),
        mock.patch.object(daemon, "_apply_peer"),
    ):
        d.run()
    assert d.state.dead == {}
    # cooldown sleep happened
    assert sleeps  # at least one


def test_full_recovery_scenario(pool: Path, cfg: Config) -> None:
    """End-to-end story: 'when the provider fixes one of three endpoints,
    the daemon eventually lands on it and stays there.'

    Timeline (consecutive_bad_to_switch=1 to keep the test short):
      tick 0 (peer0): tx grew while rx flat   → NO_DATA → mark peer0 dead, switch
      tick 1 (peer1): tx grew while rx flat   → NO_DATA → mark peer1 dead, switch
      tick 2 (peer2): rx grew                 → HEALTHY → stays
      tick 3 (peer2): rx grew again           → HEALTHY → stays
    """
    d, fake_router = _mk_daemon(cfg, pool, max_iter=4)

    samples = iter(
        [
            # tick 0: tx grew, rx flat → NO_DATA → switch peer0→peer1
            (0, 5000, 30.0, True),
            # tick 1: again tx grew, rx flat → NO_DATA → switch peer1→peer2
            (0, 200, 30.0, True),
            # tick 2: peer2 returns real data — HEALTHY (rx grew)
            (1500, 800, 5.0, True),
            # tick 3: still HEALTHY
            (3000, 1200, 5.0, True),
        ]
    )

    applied: list[str] = []

    def fake_apply(_r, _cfg, peer):
        applied.append(peer.endpoint_host)

    with (
        mock.patch.object(daemon, "Router", return_value=fake_router),
        mock.patch.object(daemon, "_apply_peer", side_effect=fake_apply),
        mock.patch.object(daemon, "sample_counters", side_effect=lambda *_a: next(samples)),
    ):
        state = d.run()

    # peer0 + peer1 must be in the dead cache; peer2 must NOT be.
    assert "peer0" in state.dead
    assert "peer1" in state.dead
    assert "peer2" not in state.dead
    # Daemon ended up actively on peer2.
    assert state.current_peer == "peer2"
    # Endpoints applied (peer0=1.1.1.1, peer1=2.2.2.2, peer2=3.3.3.3 per fixture).
    assert applied == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]


def test_recovery_when_first_endpoint_is_already_good(pool: Path, cfg: Config) -> None:
    """If the very first endpoint we try is healthy, we never switch."""
    d, fake_router = _mk_daemon(cfg, pool, max_iter=3)

    # Every tick shows rx growing — always HEALTHY.
    samples = iter(
        [
            (5000, 1000, 10.0, True),  # tick 0: rx grew → HEALTHY
            (10000, 2000, 8.0, True),  # tick 1: HEALTHY
            (15000, 3000, 6.0, True),  # tick 2: HEALTHY
        ]
    )

    with (
        mock.patch.object(daemon, "Router", return_value=fake_router),
        mock.patch.object(daemon, "_apply_peer") as apply_peer,
        mock.patch.object(daemon, "sample_counters", side_effect=lambda *_a: next(samples)),
    ):
        state = d.run()

    # Only the initial apply, no switches.
    assert apply_peer.call_count == 1
    assert state.current_peer == "peer0"
    assert state.dead == {}


def test_daemon_stop_breaks_loop(pool: Path, cfg: Config) -> None:
    d, fake_router = _mk_daemon(cfg, pool, max_iter=100)
    iter_count = {"n": 0}

    def stopping_sample(*_a):
        iter_count["n"] += 1
        if iter_count["n"] >= 3:
            d.request_stop()
        return (100 * iter_count["n"], 50, 10.0, True)

    with (
        mock.patch.object(daemon, "Router", return_value=fake_router),
        mock.patch.object(daemon, "_apply_peer"),
        mock.patch.object(daemon, "sample_counters", side_effect=stopping_sample),
    ):
        d.run()
    # Loop exited well before max_iter=100
    assert iter_count["n"] <= 5
