"""A2: delete entries, either one from the middle or everything after some point (erasing being "poisoned")."""

from .base import Attack


def apply_delete(docs, rng, session):
    i = rng.randrange(session.n_calls - 1)  # not the last entry; that case is truncation
    for d in docs:
        del d.rows[i]
    return {"position": i}


def apply_truncate(docs, rng, session):
    keep = rng.randrange(1, session.n_calls)
    for d in docs:
        del d.rows[keep:]
    return {"position": keep}


DELETE = Attack("A2", "delete entry", "Delete one entry from the middle of the log.", apply_delete)
TRUNCATE = Attack("A2t", "truncate tail", "Cut every entry after some point off the end of the log.", apply_truncate)
