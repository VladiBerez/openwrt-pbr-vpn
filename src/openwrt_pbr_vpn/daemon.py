"""Long-running watchdog that auto-switches dead VPN endpoints.

Design:
- Walks `pool_dir` for `*.conf` (WireGuard) files.
- Every `check_interval` seconds, reads `wg show <iface> transfer` and
  decides if the current peer is healthy. Health rules:
    * RX bytes have grown since the previous tick → HEALTHY
    * RX flat AND TX growing AND last handshake older than `rx_stale_seconds`
      → DEAD (provider blocked / endpoint flaky / DPI on data channel)
- A DEAD peer is added to `dead_endpoints.json` with a timestamp. The next
  pick skips peers in there until `dead_cache_ttl` expires (default 1h).
- If every peer in the pool is currently dead, the daemon sleeps a longer
  `cooldown_seconds` and then retries from scratch (clears the cache).
- Hooks: `on_switch_cmd` / `on_fail_cmd` are shell commands receiving the
  peer name as $1 — for sending Telegram alerts, etc.
- SIGINT/SIGTERM → graceful stop.
"""

from __future__ import annotations

import contextlib
import json
import shlex
import signal
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from . import wireguard
from .config import Config
from .output import get_logger
from .router import Router
from .wireguard import WgPeer

log = get_logger("daemon")


class Health(str, Enum):
    HEALTHY = "healthy"  # rx growing
    NO_INTERFACE = "no_interface"  # iface down or missing
    NO_HANDSHAKE = "no_handshake"  # handshake age stale, never refreshes
    NO_DATA = "no_data"  # handshake fine, but data channel dead (rx flat)
    UNKNOWN = "unknown"  # first sample, can't compare yet


@dataclass
class PeerEntry:
    name: str
    path: Path
    peer: WgPeer


@dataclass
class DaemonState:
    """In-memory state across loop iterations."""

    current_peer: str | None = None
    last_rx: int = 0
    last_tx: int = 0
    last_change_ts: float = 0.0
    last_health: Health = Health.UNKNOWN
    dead: dict[str, float] = field(default_factory=dict)  # name -> failed_at


def load_pool(pool_dir: Path) -> list[PeerEntry]:
    """Load `*.conf` files from pool_dir into PeerEntry list (sorted by name)."""
    files = sorted(pool_dir.glob("*.conf"))
    entries: list[PeerEntry] = []
    for f in files:
        try:
            peer = WgPeer.from_file(f)
            entries.append(PeerEntry(name=f.stem, path=f, peer=peer))
        except Exception as e:
            log.warning("Skipping %s: %s", f.name, e)
    return entries


def pick_next(
    pool: list[PeerEntry],
    dead: dict[str, float],
    *,
    skip: str | None = None,
    now: float | None = None,
    dead_ttl: float = 3600.0,
) -> PeerEntry | None:
    """Pick the next viable peer.

    - Skips `skip` (the peer we just gave up on).
    - Skips peers whose dead-timestamp is younger than `dead_ttl`.
    - Returns None if every peer is currently dead.
    """
    now = now if now is not None else time.time()
    for entry in pool:
        if entry.name == skip:
            continue
        ts = dead.get(entry.name)
        if ts is not None and (now - ts) < dead_ttl:
            continue
        return entry
    return None


def classify_health(
    *,
    has_interface: bool,
    rx_now: int,
    rx_prev: int,
    tx_now: int,
    tx_prev: int,
    handshake_age_seconds: float | None,
    handshake_stale_seconds: float,
) -> Health:
    """Pure decision function — easy to unit-test."""
    if not has_interface:
        return Health.NO_INTERFACE
    if rx_now > rx_prev:
        return Health.HEALTHY
    if handshake_age_seconds is not None and handshake_age_seconds > handshake_stale_seconds:
        return Health.NO_HANDSHAKE
    if tx_now > tx_prev and rx_now == rx_prev:
        # Sending into the tunnel, getting nothing back — classic DPI data-channel kill.
        return Health.NO_DATA
    return Health.UNKNOWN


def _parse_handshake_age(text: str) -> float | None:
    """Convert `wg show … latest-handshakes` output (seconds since epoch) to age."""
    parts = text.strip().split()
    if len(parts) < 2:
        return None
    try:
        ts = int(parts[-1])
    except ValueError:
        return None
    if ts == 0:
        return None
    return max(0.0, time.time() - ts)


def _run_hook(cmd: str | None, *args: str) -> None:
    """Run a hook script non-blocking with the given positional arguments.

    Errors from hook scripts are logged but never crash the daemon.
    """
    if not cmd:
        return
    try:
        subprocess.run(
            [*shlex.split(cmd), *args],
            timeout=10,
            check=False,
        )
    except Exception as e:
        log.warning("Hook failed (%s): %s", cmd, e)


def sample_counters(r: Router, iface: str) -> tuple[int, int, float | None, bool]:
    """Single sample: (rx, tx, handshake_age_seconds_or_None, iface_up)."""
    link = r.run(f"ip link show {iface} 2>&1 | head -1").stdout
    iface_up = "UP" in link and "does not exist" not in link
    rx, tx = wireguard.transfer_counters(r, _StubCfg(iface))
    hs_out = r.run(f"wg show {iface} latest-handshakes 2>&1").stdout
    age = _parse_handshake_age(hs_out)
    return rx, tx, age, iface_up


@dataclass
class _StubCfg:
    """Minimal stand-in for Config when only vpn_interface is needed."""

    vpn_interface: str


def _apply_peer(r: Router, cfg: Config, peer: WgPeer) -> None:
    wireguard.apply(r, cfg, peer)


@dataclass
class DaemonConfig:
    pool_dir: Path
    check_interval: int = 60
    handshake_stale_seconds: float = 300.0
    dead_ttl: float = 3600.0
    cooldown_seconds: float = 300.0
    consecutive_bad_to_switch: int = 3
    on_switch_cmd: str | None = None
    on_fail_cmd: str | None = None
    max_iterations: int | None = None  # for tests / one-off runs


class Daemon:
    """Main daemon: keeps the VPN interface alive by cycling through the pool."""

    def __init__(
        self,
        cfg: Config,
        dcfg: DaemonConfig,
        *,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.time,
    ):
        self.cfg = cfg
        self.dcfg = dcfg
        self.state = DaemonState()
        self._stop = False
        self._sleep = sleep
        self._clock = clock
        self._bad_streak = 0

    def request_stop(self, *_args) -> None:
        self._stop = True
        log.info("daemon: stop requested")

    def install_signal_handlers(self) -> None:
        signal.signal(signal.SIGINT, self.request_stop)
        # SIGTERM is not available on Windows; install is best-effort.
        with contextlib.suppress(AttributeError, ValueError):
            signal.signal(signal.SIGTERM, self.request_stop)

    # ----- main loop -----

    def run(self) -> DaemonState:
        pool = load_pool(self.dcfg.pool_dir)
        if not pool:
            raise RuntimeError(f"Pool directory {self.dcfg.pool_dir} has no .conf files")

        log.info("daemon: starting with pool of %d peers", len(pool))

        with Router(self.cfg) as r:
            self._ensure_active_peer(r, pool)
            iteration = 0
            while not self._stop:
                if self.dcfg.max_iterations is not None and iteration >= self.dcfg.max_iterations:
                    break
                self._tick(r, pool)
                iteration += 1
                if self._stop:
                    break
                self._sleep(self.dcfg.check_interval)
        log.info("daemon: exiting")
        return self.state

    # ----- internals -----

    def _ensure_active_peer(self, r: Router, pool: list[PeerEntry]) -> None:
        """If no peer applied yet, pick & apply one."""
        if self.state.current_peer is not None:
            return
        entry = pick_next(pool, self.state.dead, now=self._clock(), dead_ttl=self.dcfg.dead_ttl)
        if entry is None:
            log.warning("daemon: every peer is dead, cooling down %ds", self.dcfg.cooldown_seconds)
            self.state.dead.clear()
            self._sleep(self.dcfg.cooldown_seconds)
            return
        self._switch_to(r, entry)

    def _switch_to(self, r: Router, entry: PeerEntry) -> None:
        log.info(
            "daemon: switching to %s (%s:%d)",
            entry.name,
            entry.peer.endpoint_host,
            entry.peer.endpoint_port,
        )
        old_peer = self.state.current_peer or ""
        _apply_peer(r, self.cfg, entry.peer)
        self.state.current_peer = entry.name
        self.state.last_rx = 0
        self.state.last_tx = 0
        self.state.last_change_ts = self._clock()
        self.state.last_health = Health.UNKNOWN
        self._bad_streak = 0
        _run_hook(self.dcfg.on_switch_cmd, old_peer, entry.name)

    def _tick(self, r: Router, pool: list[PeerEntry]) -> None:
        if self.state.current_peer is None:
            self._ensure_active_peer(r, pool)
            return

        rx, tx, hs_age, iface_up = sample_counters(r, self.cfg.vpn_interface)
        health = classify_health(
            has_interface=iface_up,
            rx_now=rx,
            rx_prev=self.state.last_rx,
            tx_now=tx,
            tx_prev=self.state.last_tx,
            handshake_age_seconds=hs_age,
            handshake_stale_seconds=self.dcfg.handshake_stale_seconds,
        )
        log.info(
            "daemon: peer=%s rx=%d (+%d) tx=%d (+%d) hs=%s -> %s",
            self.state.current_peer,
            rx,
            rx - self.state.last_rx,
            tx,
            tx - self.state.last_tx,
            f"{int(hs_age)}s" if hs_age is not None else "n/a",
            health.value,
        )

        self.state.last_rx, self.state.last_tx = rx, tx
        self.state.last_health = health

        if health == Health.HEALTHY:
            self._bad_streak = 0
            return

        if health == Health.UNKNOWN:
            # First sample or no traffic at all — wait one more tick before judging.
            return

        # Bad outcomes accumulate; we only switch after N consecutive bad ticks
        # to avoid flapping on transient blips.
        self._bad_streak += 1
        if self._bad_streak < self.dcfg.consecutive_bad_to_switch:
            return

        self._mark_dead_and_switch(r, pool)

    def _mark_dead_and_switch(self, r: Router, pool: list[PeerEntry]) -> None:
        dead = self.state.current_peer
        if dead:
            self.state.dead[dead] = self._clock()
            log.warning("daemon: marking %s DEAD (health=%s)", dead, self.state.last_health.value)
            _run_hook(self.dcfg.on_fail_cmd, dead)

        nxt = pick_next(
            pool, self.state.dead, skip=dead, now=self._clock(), dead_ttl=self.dcfg.dead_ttl
        )
        if nxt is None:
            log.warning(
                "daemon: no more candidates, sleeping %ds then resetting",
                self.dcfg.cooldown_seconds,
            )
            self.state.dead.clear()
            self.state.current_peer = None
            self._sleep(self.dcfg.cooldown_seconds)
            return

        self._switch_to(r, nxt)


def to_dict(state: DaemonState) -> dict:
    return {
        "current_peer": state.current_peer,
        "last_rx": state.last_rx,
        "last_tx": state.last_tx,
        "last_health": state.last_health.value,
        "dead": dict(state.dead),
    }


def persist_state(state: DaemonState, path: Path) -> None:
    """Save state to disk so a restart resumes the dead-cache."""
    path.write_text(json.dumps(to_dict(state)), encoding="utf-8")


def load_state(path: Path) -> DaemonState:
    if not path.exists():
        return DaemonState()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return DaemonState()
    return DaemonState(
        current_peer=data.get("current_peer"),
        last_rx=int(data.get("last_rx", 0)),
        last_tx=int(data.get("last_tx", 0)),
        last_health=Health(data.get("last_health", Health.UNKNOWN.value)),
        dead={k: float(v) for k, v in (data.get("dead") or {}).items()},
    )
