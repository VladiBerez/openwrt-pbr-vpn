"""Logging + output formatting.

Design:
- Progress / status messages go through `logging` → stderr. Users see them
  by default; programs that pipe stdout never get polluted.
- Final command results are *returned* from handler functions and emitted
  by the CLI: pretty text in normal mode, machine-readable JSON when
  `--json` is set.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Any

LOGGER_NAME = "ovpn_pbr"


def setup_logging(verbose: bool = False, quiet: bool = False) -> logging.Logger:
    """Configure root logger and return our app logger."""
    if quiet:
        level = logging.WARNING
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO

    # Don't double-configure if called twice (e.g. tests + main)
    root = logging.getLogger()
    if not getattr(root, "_ovpn_pbr_configured", False):
        handler = logging.StreamHandler(stream=sys.stderr)
        handler.setFormatter(logging.Formatter("%(message)s"))
        root.addHandler(handler)
        root._ovpn_pbr_configured = True  # type: ignore[attr-defined]

    root.setLevel(level)
    return logging.getLogger(LOGGER_NAME)


def get_logger(module: str | None = None) -> logging.Logger:
    """Logger for a submodule."""
    if module:
        return logging.getLogger(f"{LOGGER_NAME}.{module}")
    return logging.getLogger(LOGGER_NAME)


def emit_result(result: Any, *, as_json: bool, human: str | None = None) -> None:
    """Print the command result.

    - JSON mode: `result` is serialized as JSON to stdout.
    - Human mode: `human` (already-formatted text) is printed; if None,
      the JSON form is printed instead so users always see *something*.
    """
    if as_json:
        json.dump(result, sys.stdout, indent=2, ensure_ascii=False, default=str)
        sys.stdout.write("\n")
        return
    if human is not None:
        print(human)
    elif result is not None:
        json.dump(result, sys.stdout, indent=2, ensure_ascii=False, default=str)
        sys.stdout.write("\n")


def fmt_bytes(n: int) -> str:
    """Human-readable byte count: 12.3 MiB style."""
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    f = float(n)
    for u in units:
        if f < 1024 or u == units[-1]:
            return f"{f:.2f} {u}" if u != "B" else f"{int(f)} B"
        f /= 1024
    return f"{n} B"


def fmt_age(seconds: int | float) -> str:
    """'5m 3s ago' / 'just now' / '2h 12m ago'."""
    s = int(seconds)
    if s < 5:
        return "just now"
    if s < 60:
        return f"{s}s ago"
    m, s = divmod(s, 60)
    if m < 60:
        return f"{m}m {s}s ago"
    h, m = divmod(m, 60)
    if h < 24:
        return f"{h}h {m}m ago"
    d, h = divmod(h, 24)
    return f"{d}d {h}h ago"
