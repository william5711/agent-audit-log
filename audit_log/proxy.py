"""Tool proxy: the only path from the agent to the shell.

The proxy executes each command itself and logs what it *actually* ran and what *actually* came
back, before handing the result to the agent. Whatever the agent later writes in its own transcript,
the audit log holds the ground truth to cross-check it against (see :mod:`audit_log.crosscheck`).

``ToolProxy`` runs in-process and is what the tests and experiments use directly.
``ProxyClient`` runs the same proxy in a separate process and gives the agent only a pipe to it,
so the agent's process never holds the logger's key or the log/anchor file handles.

Process separation alone is not enough: commands run as the same OS user, so ``cat key.hex`` would
work. Every path in ``protected_paths`` (normally the logger directory) is therefore blocked for
reading and writing inside the command's sandbox (macOS ``sandbox-exec``). The proxy refuses to
run unsandboxed when protected paths are set, rather than silently weakening the threat model.
"""

import multiprocessing
import os
import shutil
import subprocess
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import List, Optional, Sequence

from .anchor import AnchorStore
from .log import AuditLog, load_or_create_key

DEFAULT_TIMEOUT_S = 30.0
DEFAULT_MAX_OUTPUT_BYTES = 64 * 1024
TIMEOUT_EXIT_CODE = -1
SANDBOX_EXEC = "/usr/bin/sandbox-exec"


class SandboxUnavailable(RuntimeError):
    pass


def _sb_string(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def sandbox_profile(protected_paths: Sequence[Path]) -> str:
    """SBPL profile: allow everything except reading or writing the protected paths.

    Paths are resolved first (e.g. /var -> /private/var on macOS), since the sandbox matches real
    paths; this also means symlinks pointing into a protected path are blocked too.
    """
    rules = " ".join("(subpath %s)" % _sb_string(os.path.realpath(str(p))) for p in protected_paths)
    return "(version 1)(allow default)(deny file-read* file-write* %s)" % rules


def sandboxed_argv(command: str, protected_paths: Sequence[Path]) -> List[str]:
    if not protected_paths:
        return ["/bin/sh", "-c", command]
    if not (os.path.exists(SANDBOX_EXEC) or shutil.which("sandbox-exec")):
        raise SandboxUnavailable(
            "protected_paths is set but sandbox-exec is not available; refusing to run unsandboxed"
        )
    return [SANDBOX_EXEC, "-p", sandbox_profile(protected_paths), "/bin/sh", "-c", command]


@dataclass
class ToolResult:
    call_id: str
    command: str
    output: str
    exit_code: int
    duration_s: float
    truncated: bool


class ToolProxy:
    def __init__(
        self,
        workdir: Path,
        log: AuditLog,
        anchors: Optional[AnchorStore] = None,
        anchor_every: int = 5,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
        protected_paths: Sequence[Path] = (),
    ):
        self.workdir = Path(workdir)
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.log = log
        self.anchors = anchors
        self.anchor_every = anchor_every
        self.timeout_s = timeout_s
        self.max_output_bytes = max_output_bytes
        self.protected_paths = list(protected_paths)
        sandboxed_argv("true", self.protected_paths)  # fail at construction, not on the first call

    def run(self, command: str, call_id: Optional[str] = None) -> ToolResult:
        call_id = call_id or uuid.uuid4().hex[:12]
        start = time.perf_counter()
        try:
            proc = subprocess.run(
                sandboxed_argv(command, self.protected_paths),
                cwd=str(self.workdir),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=self.timeout_s,
            )
            raw, exit_code = proc.stdout, proc.returncode
        except subprocess.TimeoutExpired as exc:
            raw, exit_code = (exc.stdout or b"") + b"\n[timed out]\n", TIMEOUT_EXIT_CODE
        duration = time.perf_counter() - start

        truncated = len(raw) > self.max_output_bytes
        output = raw[: self.max_output_bytes].decode("utf-8", errors="replace")
        result = ToolResult(call_id, command, output, exit_code, round(duration, 6), truncated)

        # Log before returning, so the agent never sees a result that isn't already recorded.
        self.log.append({"tool": "bash", **asdict(result)})
        if self.anchors is not None and self.log.length % self.anchor_every == 0:
            self.anchor()
        return result

    def anchor(self):
        if self.anchors is not None:
            return self.anchors.record(self.log.length, self.log.head_hash)

    def close(self):
        self.anchor()


def _serve(conn, workdir, log_path, key_path, anchor_path, anchor_every):
    log = AuditLog(Path(log_path), load_or_create_key(Path(key_path)))
    protected = sorted({str(Path(p).parent) for p in (log_path, key_path, anchor_path)})
    proxy = ToolProxy(Path(workdir), log, AnchorStore(Path(anchor_path)), anchor_every, protected_paths=protected)
    try:
        while True:
            msg = conn.recv()
            if msg is None:
                break
            command, call_id = msg
            conn.send(asdict(proxy.run(command, call_id)))
    finally:
        proxy.close()
        conn.close()


class ProxyClient:
    """Agent-side handle to a ToolProxy running in its own process."""

    def __init__(self, workdir: Path, log_path: Path, key_path: Path, anchor_path: Path, anchor_every: int = 5):
        ctx = multiprocessing.get_context("spawn")
        self._conn, child = ctx.Pipe()
        self._proc = ctx.Process(
            target=_serve,
            args=(child, str(workdir), str(log_path), str(key_path), str(anchor_path), anchor_every),
            daemon=True,
        )
        self._proc.start()
        child.close()

    def run(self, command: str, call_id: Optional[str] = None) -> ToolResult:
        self._conn.send((command, call_id))
        return ToolResult(**self._conn.recv())

    def close(self):
        if self._proc.is_alive():
            self._conn.send(None)
            self._proc.join(timeout=10)
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
