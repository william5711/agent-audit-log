"""Anchors: periodic snapshots of the log's (length, head hash), kept outside the agent's reach.

A hash chain can't tell a shortened or rolled-back log from a genuine shorter one. Anchors can:
if an anchor says "entry 41 had hash X", any log without that entry at that position was cut or
replaced. In a real deployment the anchor store would be a separate machine or a write-once
bucket; here it is an append-only file in a directory the agent can't write to.
"""

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from .log import canonical_json


@dataclass(frozen=True)
class Anchor:
    length: int  # number of entries in the log when the anchor was taken
    head: str  # hash of entry ``length - 1`` (GENESIS_HASH when length == 0)
    ts: float


class AnchorStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)

    def record(self, length: int, head: str, ts: Optional[float] = None) -> Anchor:
        anchor = Anchor(length=length, head=head, ts=time.time() if ts is None else ts)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(canonical_json(anchor.__dict__) + "\n")
            f.flush()
            os.fsync(f.fileno())
        return anchor

    def all(self) -> List[Anchor]:
        lines = self.path.read_text(encoding="utf-8").splitlines()
        return [Anchor(**json.loads(l)) for l in lines if l.strip()]

    def latest(self) -> Optional[Anchor]:
        anchors = self.all()
        return anchors[-1] if anchors else None
