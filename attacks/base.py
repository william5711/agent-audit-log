import random
from dataclasses import dataclass
from typing import Callable, Dict, List

from .formats import Doc
from .session import Session

# apply(docs, rng, session) -> details; edits docs in place (the caller saves them).
ApplyFn = Callable[[List[Doc], random.Random, Session], Dict]
# plan(rng, n_calls) -> extra keyword arguments for record_session.
PlanFn = Callable[[random.Random, int], Dict]


def no_plan(rng: random.Random, n_calls: int) -> Dict:
    return {}


@dataclass(frozen=True)
class Attack:
    id: str
    name: str
    description: str
    apply: ApplyFn
    plan: PlanFn = no_plan
