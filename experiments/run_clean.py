"""Run untampered sessions through every detector to measure false positives.

    python3 -m experiments.run_clean --runs 100
"""

import argparse
import random
import tempfile
import time
from pathlib import Path

from attacks import record_session

from .common import CONDITIONS, summarize, write_csv
from .run_attacks import MAX_CALLS, MIN_CALLS


def run(runs: int, seed: int, conditions=CONDITIONS):
    rows = []
    for t in range(runs):
        rng = random.Random("%d/clean/%d" % (seed, t))
        n_calls = rng.randint(MIN_CALLS, MAX_CALLS)
        with tempfile.TemporaryDirectory() as tmp:
            s = record_session(Path(tmp) / "base", rng, n_calls)
            # Untampered, harness and harness_logwrite are the same check; report each name anyway.
            for cond, (_, detect) in conditions.items():
                detected, kinds = detect(s)
                rows.append(
                    {"condition": cond, "run": t, "n_calls": n_calls, "detected": int(detected), "issue_kinds": kinds}
                )
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--runs", type=int, default=100)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", type=Path, default=Path("results"))
    args = ap.parse_args()

    start = time.time()
    rows = run(args.runs, args.seed)
    summary = summarize(rows, keys=("condition",))
    write_csv(args.out / "clean_runs.csv", rows)
    write_csv(args.out / "clean_summary.csv", summary)

    for r in summary:
        print("%-17s false positives: %d/%d" % (r["condition"], r["detected"], r["trials"]))
    print("\n%d runs in %.0fs -> %s" % (args.runs, time.time() - start, args.out))


if __name__ == "__main__":
    main()
