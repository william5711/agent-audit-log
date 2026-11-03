"""A3: swap two entries (hiding when something, such as the flag, was first seen)."""

from .base import Attack


def apply(docs, rng, session):
    i, j = sorted(rng.sample(range(session.n_calls), 2))
    for d in docs:
        d.rows[i], d.rows[j] = d.rows[j], d.rows[i]
    return {"position": i, "other": j}


ATTACK = Attack("A3", "reorder entries", __doc__.strip(), apply)
