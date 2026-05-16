"""SSH wrapper around paramiko for OpenWrt routers.

dropbear (the default SSH server on OpenWrt) does not include an SFTP
subsystem, so file upload is done through `cat > path` over an exec channel
instead of `client.open_sftp()`.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import paramiko

from .config import Config


@dataclass
class CommandResult:
    cmd: str
    rc: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.rc == 0


class Router:
    """Connection to an OpenWrt router. Use as a context manager."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._client: paramiko.SSHClient | None = None

    def __enter__(self) -> Router:
        self.connect()
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def connect(self) -> None:
        if self._client is not None:
            return
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs: dict = dict(
            hostname=self.cfg.host,
            port=self.cfg.port,
            username=self.cfg.user,
            look_for_keys=False,
            allow_agent=False,
            timeout=15,
        )
        if self.cfg.ssh_key and self.cfg.ssh_key.exists():
            kwargs["key_filename"] = str(self.cfg.ssh_key)
        elif self.cfg.password:
            kwargs["password"] = self.cfg.password
        else:
            raise RuntimeError("No SSH credentials in Config")
        c.connect(**kwargs)
        self._client = c

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    @property
    def client(self) -> paramiko.SSHClient:
        if self._client is None:
            raise RuntimeError("Router not connected — call connect() or use as context manager")
        return self._client

    # ------------------------------------------------------------------
    # Command execution
    # ------------------------------------------------------------------
    def run(self, cmd: str, timeout: int = 60, check: bool = False) -> CommandResult:
        """Run a single shell command. Returns CommandResult."""
        _, stdout, stderr = self.client.exec_command(cmd, timeout=timeout)
        rc = stdout.channel.recv_exit_status()
        out = stdout.read().decode(errors="ignore")
        err = stderr.read().decode(errors="ignore")
        result = CommandResult(cmd=cmd, rc=rc, stdout=out, stderr=err)
        if check and not result.ok:
            raise RuntimeError(f"Command failed (rc={rc}): {cmd}\nstdout: {out}\nstderr: {err}")
        return result

    def run_many(self, cmds: list[str], timeout: int = 60) -> list[CommandResult]:
        return [self.run(c, timeout=timeout) for c in cmds]

    # ------------------------------------------------------------------
    # File transfer (works with dropbear — no SFTP)
    # ------------------------------------------------------------------
    def upload_bytes(self, data: bytes, remote: str, mode: int = 0o755, timeout: int = 60) -> int:
        """Stream bytes to a remote file through `cat`. Returns bytes written.

        CRLF → LF normalization is applied so files copied from Windows don't
        break shell parsing on the router (`sed -i 's/\\r//' …` is also a
        belt-and-braces safety net done by callers).
        """
        data = data.replace(b"\r\n", b"\n")
        stdin, stdout, stderr = self.client.exec_command(
            f"cat > {remote} && chmod {mode:o} {remote}", timeout=timeout
        )
        stdin.write(data)
        stdin.channel.shutdown_write()
        rc = stdout.channel.recv_exit_status()
        if rc != 0:
            err = stderr.read().decode(errors="ignore").strip()
            raise RuntimeError(f"upload to {remote} failed (rc={rc}): {err}")
        return len(data)

    def upload_file(self, local: Path, remote: str, mode: int = 0o755) -> int:
        return self.upload_bytes(local.read_bytes(), remote, mode=mode)

    def read_text(self, remote: str) -> str:
        """Read a remote text file via cat."""
        result = self.run(f"cat {remote}", check=True)
        return result.stdout

    def exists(self, remote: str) -> bool:
        return self.run(f"test -e {remote}").ok

    # ------------------------------------------------------------------
    # UCI helpers
    # ------------------------------------------------------------------
    def uci_get(self, path: str) -> str | None:
        r = self.run(f"uci -q get {path}")
        return r.stdout.strip() if r.ok else None

    def uci_set(self, path: str, value: str) -> None:
        # Quote single quotes inside value
        v = value.replace("'", "'\\''")
        self.run(f"uci set {path}='{v}'", check=True)

    def uci_delete(self, path: str) -> None:
        self.run(f"uci -q delete {path}")

    def uci_add_list(self, path: str, value: str) -> None:
        v = value.replace("'", "'\\''")
        self.run(f"uci add_list {path}='{v}'", check=True)

    def uci_commit(self, package: str) -> None:
        self.run(f"uci commit {package}", check=True)

    # ------------------------------------------------------------------
    # Backups
    # ------------------------------------------------------------------
    def backup(self, remote_paths: list[str]) -> str:
        """Copy listed config files to .bak.<timestamp>. Returns the timestamp."""
        ts_result = self.run("date +%s", check=True)
        ts = ts_result.stdout.strip()
        for p in remote_paths:
            self.run(f"[ -e {p} ] && cp {p} {p}.bak.{ts} || true")
        return ts


@contextlib.contextmanager
def open_router(cfg: Config) -> Iterator[Router]:
    """Convenience context manager."""
    r = Router(cfg)
    r.connect()
    try:
        yield r
    finally:
        r.close()
