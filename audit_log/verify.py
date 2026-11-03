"""Verifier for logs written by :class:`audit_log.log.AuditLog`.

Checks every entry for:

- ``parse``      the line is not valid JSON or is missing fields
- ``seq``        sequence numbers are not 0, 1, 2, ... (deletion, reordering, insertion)
- ``chain``      ``prev_hash`` does not match the previous entry's hash
- ``hash``       the stored hash does not match the entry's contents (edited entry)
- ``mac``        the HMAC does not match (entry forged or re-hashed without the key)
- ``head``       the log does not end at the expected head hash / length (truncation, rollback)
- ``anchor``     an entry recorded by an earlier anchor is missing or different (truncation, rollback)

A hash chain alone cannot tell that entries were cut off the *end* of the log, because the remaining
prefix is still a valid chain. Passing ``expected_head`` / ``expected_length``, or ``anchors`` taken
while the log was being written (see :mod:`audit_log.anchor`), closes that gap.
"""

import hmac
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Sequence

from .anchor import Anchor
from .log import GENESIS_HASH, entry_hash, entry_mac

REQUIRED_FIELDS = ("seq", "ts", "data", "prev_hash", "hash", "mac")


@dataclass
class Issue:
    line: int  # 0-based line index in the file
    kind: str
    detail: str


@dataclass
class VerificationResult:
    entries: int
    issues: List[Issue] = field(default_factory=list)
    records: List[Optional[dict]] = field(default_factory=list)  # parsed entries; None if unreadable

    @property
    def ok(self) -> bool:
        return not self.issues

    @property
    def first_bad_line(self) -> Optional[int]:
        return self.issues[0].line if self.issues else None

    def kinds(self) -> set:
        return {i.kind for i in self.issues}


def verify_log(
    path: Path,
    key: bytes,
    expected_head: Optional[str] = None,
    expected_length: Optional[int] = None,
    anchors: Sequence[Anchor] = (),
) -> VerificationResult:
    lines = [l for l in Path(path).read_text(encoding="utf-8").splitlines() if l.strip()]
    result = VerificationResult(entries=len(lines))

    prev_hash = GENESIS_HASH
    for i, line in enumerate(lines):
        try:
            e = json.loads(line)
            missing = [k for k in REQUIRED_FIELDS if k not in e]
            if missing:
                raise ValueError("missing fields: %s" % ", ".join(missing))
        except ValueError as exc:  # json.JSONDecodeError is a ValueError
            result.issues.append(Issue(i, "parse", str(exc)))
            result.records.append(None)
            prev_hash = None  # can't link the next entry to an unreadable one
            continue
        result.records.append(e)

        if e["seq"] != i:
            result.issues.append(Issue(i, "seq", "expected seq %d, found %r" % (i, e["seq"])))
        if prev_hash is not None and e["prev_hash"] != prev_hash:
            result.issues.append(Issue(i, "chain", "prev_hash does not match previous entry"))

        recomputed = entry_hash(e["prev_hash"], e["seq"], e["ts"], e["data"])
        if recomputed != e["hash"]:
            result.issues.append(Issue(i, "hash", "stored hash does not match contents"))
        if not hmac.compare_digest(entry_mac(key, e["hash"]), e["mac"]):
            result.issues.append(Issue(i, "mac", "HMAC does not verify"))

        # Follow the stored hash so a single edit is reported once, not on every later line.
        prev_hash = e["hash"]

    if expected_length is not None and len(lines) != expected_length:
        result.issues.append(
            Issue(len(lines), "head", "expected %d entries, found %d" % (expected_length, len(lines)))
        )
    if expected_head is not None:
        actual_head = prev_hash if lines else GENESIS_HASH
        if actual_head != expected_head:
            result.issues.append(Issue(len(lines), "head", "log does not end at the anchored head hash"))

    # Unlike expected_head, an anchor is a point in the past: the log may have grown since, but
    # it must still contain the anchored entry, unchanged, at the anchored position.
    for a in anchors:
        if a.length == 0:
            continue
        idx = a.length - 1
        rec = result.records[idx] if idx < len(result.records) else None
        if rec is None or rec["hash"] != a.head:
            result.issues.append(
                Issue(idx, "anchor", "entry %d missing or differs from anchor taken at ts=%s" % (idx, a.ts))
            )

    return result
