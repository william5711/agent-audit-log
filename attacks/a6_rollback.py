"""A6: restore an earlier copy of the log saved mid-session (retroactive cleanup).

The copy is valid on its own; it is just older. Anchors live outside the attacker's reach, so they
still remember the later entries.
"""

import json

from .base import Attack


def plan(rng, n_calls):
    return {"snapshot_at": rng.randrange(1, n_calls)}


def apply(docs, rng, session):
    for d in docs:
        snap = session.snapshot_dir / d.path.name
        d.rows = [json.loads(l) for l in snap.read_text().splitlines() if l.strip()]
    return {"position": session.snapshot_at}


ATTACK = Attack("A6", "roll back log", "Replace the log with a valid copy saved earlier.", apply, plan)
