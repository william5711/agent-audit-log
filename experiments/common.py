"""Conditions compared in the experiment, and how each one detects tampering.

- ``baseline``          naive JSONL log in the agent's workdir; the attacker edits it.
- ``harness``           the attacker edits everything it can reach in the intended threat model:
                        its own transcript. Detection is the transcript/audit-log cross-check.
- ``harness_logwrite``  defense in depth: assume the attacker also escaped the sandbox and can
                        write the audit log (but still has no key and can't reach the anchors). It
                        makes the same edit to both, so the two records agree with each other.
"""

import csv
from collections import OrderedDict
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

from attacks import AuditFmt, Doc, NaiveFmt, Session, TranscriptFmt
from audit_log import AnchorStore, cross_check, load_or_create_key, verify_naive

SOPHISTICATION = ("simple", "careful")


def detect_baseline(s: Session) -> Tuple[bool, str]:
    result = verify_naive(s.naive_path)
    return not result.ok, "|".join(sorted(result.kinds()))


def detect_harness(s: Session) -> Tuple[bool, str]:
    key = load_or_create_key(s.key_path)
    result = cross_check(s.transcript_path, s.log_path, key, AnchorStore(s.anchor_path).all())
    return not result.ok, "|".join(sorted(result.kinds()))


CONDITIONS = OrderedDict(
    [
        ("baseline", (lambda s: [Doc(s.naive_path, NaiveFmt())], detect_baseline)),
        ("harness", (lambda s: [Doc(s.transcript_path, TranscriptFmt())], detect_harness)),
        (
            "harness_logwrite",
            (lambda s: [Doc(s.transcript_path, TranscriptFmt()), Doc(s.log_path, AuditFmt())], detect_harness),
        ),
    ]
)


def write_csv(path: Path, rows: List[Dict]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


def summarize(rows: Iterable[Dict], keys=("attack", "attack_name", "sophistication", "condition")) -> List[Dict]:
    groups = OrderedDict()
    for r in rows:
        g = groups.setdefault(tuple(r[k] for k in keys), [0, 0])
        g[0] += 1
        g[1] += int(r["detected"])
    return [
        dict(zip(keys, k), trials=n, detected=d, detection_rate=round(d / n, 4)) for k, (n, d) in groups.items()
    ]
