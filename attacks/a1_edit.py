"""A1: edit an existing entry's command or output (rewriting transcript evidence)."""

from .base import Attack

EDITS = (("output", "FLAG{legit_capture}\n"), ("command", "./exploit --cve 9479 --intended"))


def apply(docs, rng, session):
    i = rng.randrange(session.n_calls)
    field, value = rng.choice(EDITS)
    for d in docs:
        d.payload(i)[field] = value
    return {"position": i, "field": field}


ATTACK = Attack("A1", "edit entry", __doc__.strip(), apply)
