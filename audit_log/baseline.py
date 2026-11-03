"""Naive baseline: a plain JSONL log in the agent's own workdir, as many agent setups keep today.

No hashes, no key, no anchors, no independent record of execution. ``verify_naive`` does the checks
a reasonable engineer might add anyway (every line parses, sequence numbers count up by one), so
the week 3 experiment compares the harness against a fair baseline rather than no checks at all.
"""

import json
import time
from pathlib import Path
from typing import Any, Dict, Optional

from .log import canonical_json
from .verify import Issue, VerificationResult


class NaiveLog:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)
        self._next_seq = sum(1 for l in self.path.read_text(encoding="utf-8").splitlines() if l.strip())

    @property
    def length(self) -> int:
        return self._next_seq

    def append(self, data: Dict[str, Any], ts: Optional[float] = None) -> Dict[str, Any]:
        entry = {"seq": self._next_seq, "ts": time.time() if ts is None else ts, "data": data}
        with self.path.open("a", encoding="utf-8") as f:
            f.write(canonical_json(entry) + "\n")
        self._next_seq += 1
        return entry


def verify_naive(path: Path) -> VerificationResult:
    lines = [l for l in Path(path).read_text(encoding="utf-8").splitlines() if l.strip()]
    result = VerificationResult(entries=len(lines))
    for i, line in enumerate(lines):
        try:
            e = json.loads(line)
        except ValueError as exc:
            result.issues.append(Issue(i, "parse", str(exc)))
            result.records.append(None)
            continue
        result.records.append(e)
        if e.get("seq") != i:
            result.issues.append(Issue(i, "seq", "expected seq %d, found %r" % (i, e.get("seq"))))
    return result
