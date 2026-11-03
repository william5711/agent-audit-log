"""Adapters that let one attack edit any of the three log formats the same way.

Every format stores, per tool call, a payload with at least ``call_id``, ``command``, ``output`` and
``exit_code``. An attack picks positions once and applies the same edit to each document it is
allowed to touch, then calls ``fix`` to cover its tracks as well as that format allows:

- naive log:   careful attackers renumber ``seq``
- transcript:  has no integrity fields, so there is nothing to fix
- audit log:   careful attackers renumber and recompute the hash chain (but have no key for the MACs)
"""

import json
import secrets
from pathlib import Path
from typing import List

from audit_log.log import GENESIS_HASH, canonical_json, entry_hash


class Doc:
    def __init__(self, path: Path, fmt: "Fmt"):
        self.path = Path(path)
        self.fmt = fmt
        self.rows = [json.loads(l) for l in self.path.read_text().splitlines() if l.strip()]

    def payload(self, i: int) -> dict:
        return self.fmt.payload(self.rows[i])

    def insert_forged(self, i: int, payload: dict):
        self.rows.insert(i, self.fmt.forge(self.rows, i, payload))

    def save(self, careful: bool):
        self.rows = self.fmt.fix(self.rows, careful)
        self.path.write_text("".join(canonical_json(r) + "\n" for r in self.rows))


def _neighbor_ts(rows: List[dict], i: int) -> float:
    if not rows:
        return 0.0
    return rows[i - 1]["ts"] + 0.001 if i > 0 else rows[0]["ts"] - 0.001


class Fmt:
    def payload(self, row: dict) -> dict:
        raise NotImplementedError

    def forge(self, rows: List[dict], i: int, payload: dict) -> dict:
        raise NotImplementedError

    def fix(self, rows: List[dict], careful: bool) -> List[dict]:
        return rows


class NaiveFmt(Fmt):
    def payload(self, row):
        return row["data"]

    def forge(self, rows, i, payload):
        return {"seq": i, "ts": _neighbor_ts(rows, i), "data": dict(payload)}

    def fix(self, rows, careful):
        if careful:
            for i, r in enumerate(rows):
                r["seq"] = i
        return rows


class TranscriptFmt(Fmt):
    def payload(self, row):
        return row

    def forge(self, rows, i, payload):
        return dict(payload)


class AuditFmt(Fmt):
    def payload(self, row):
        return row["data"]

    def forge(self, rows, i, payload):
        prev = rows[i - 1]["hash"] if i > 0 else GENESIS_HASH
        ts = _neighbor_ts(rows, i)
        data = {"tool": "bash", "duration_s": 0.004, "truncated": False, **payload}
        return {
            "seq": i,
            "ts": ts,
            "data": data,
            "prev_hash": prev,
            "hash": entry_hash(prev, i, ts, data),
            "mac": secrets.token_hex(32),  # no key: the best the attacker can do
        }

    def fix(self, rows, careful):
        if careful:
            prev = GENESIS_HASH
            for i, r in enumerate(rows):
                r["seq"], r["prev_hash"] = i, prev
                r["hash"] = prev = entry_hash(prev, i, r["ts"], r["data"])
        return rows
