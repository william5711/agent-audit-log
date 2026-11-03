"""Append-only, hash-chained, HMAC-signed log of agent tool calls.

Each line of the log file is one JSON entry:

    {"seq": 0, "ts": ..., "data": {...}, "prev_hash": "...", "hash": "...", "mac": "..."}

- ``hash`` = SHA-256 over ``prev_hash`` and the canonical JSON of (seq, ts, data), so changing,
  removing or reordering any entry breaks every hash after it.
- ``mac`` = HMAC-SHA256 of ``hash`` under a key the agent cannot read, so an agent that edits an
  entry cannot simply recompute the chain to cover its tracks.
"""

import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any, Dict, Optional

GENESIS_HASH = "0" * 64
KEY_BYTES = 32


def canonical_json(obj: Any) -> str:
    """Deterministic JSON so the same entry always hashes the same way."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def entry_hash(prev_hash: str, seq: int, ts: float, data: Dict[str, Any]) -> str:
    body = canonical_json({"seq": seq, "ts": ts, "data": data})
    return hashlib.sha256((prev_hash + body).encode("utf-8")).hexdigest()


def entry_mac(key: bytes, hash_hex: str) -> str:
    return hmac.new(key, hash_hex.encode("utf-8"), hashlib.sha256).hexdigest()


def load_or_create_key(path: Path) -> bytes:
    """Load the logger's secret key, creating it (owner-only permissions) on first use."""
    path = Path(path)
    if path.exists():
        return bytes.fromhex(path.read_text().strip())
    path.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(KEY_BYTES)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(key.hex())
    return key


class AuditLog:
    """Writer side of the log. Only the logger process should hold an instance."""

    def __init__(self, path: Path, key: bytes):
        self.path = Path(path)
        self.key = key
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)
        self._next_seq, self._head_hash = self._load_tail()

    def _load_tail(self):
        last: Optional[Dict[str, Any]] = None
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last = json.loads(line)
        if last is None:
            return 0, GENESIS_HASH
        return last["seq"] + 1, last["hash"]

    @property
    def head_hash(self) -> str:
        """Hash of the newest entry; publishing this elsewhere lets a verifier detect rollback."""
        return self._head_hash

    @property
    def length(self) -> int:
        return self._next_seq

    def append(self, data: Dict[str, Any], ts: Optional[float] = None) -> Dict[str, Any]:
        seq = self._next_seq
        ts = time.time() if ts is None else ts
        h = entry_hash(self._head_hash, seq, ts, data)
        entry = {
            "seq": seq,
            "ts": ts,
            "data": data,
            "prev_hash": self._head_hash,
            "hash": h,
            "mac": entry_mac(self.key, h),
        }
        with self.path.open("a", encoding="utf-8") as f:
            f.write(canonical_json(entry) + "\n")
            f.flush()
            os.fsync(f.fileno())
        self._next_seq = seq + 1
        self._head_hash = h
        return entry
