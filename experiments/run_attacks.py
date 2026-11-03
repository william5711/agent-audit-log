"""Run every attack against every condition and record whether it was detected.

For each trial: record one benign session through the real sandboxed proxy, copy it once per
condition, apply the same attack at the same positions to each copy, then run that condition's
detector. Each attack is run by a "simple" attacker and by a "careful" one that also renumbers
sequence numbers / recomputes the hash chain to cover its tracks.

    python3 -m experiments.run_attacks --trials 50
"""

import argparse
import random
import tempfile
import time
from pathlib import Path

from attacks import ALL_ATTACKS, record_session

from .common import CONDITIONS, SOPHISTICATION, summarize, write_csv

MIN_CALLS, MAX_CALLS = 8, 30


def run(trials: int, seed: int, attacks=ALL_ATTACKS, conditions=CONDITIONS):
    rows = []
    for attack in attacks:
        for soph in SOPHISTICATION:
            for t in range(trials):
                trial_seed = "%d/%s/%s/%d" % (seed, attack.id, soph, t)
                rng = random.Random(trial_seed)
                n_calls = rng.randint(MIN_CALLS, MAX_CALLS)
                with tempfile.TemporaryDirectory() as tmp:
                    base = record_session(Path(tmp) / "base", rng, n_calls, **attack.plan(rng, n_calls))
                    for cond, (make_docs, detect) in conditions.items():
                        s = base.copy_to(Path(tmp) / cond)
                        docs = make_docs(s)
                        # Same seed in every condition, so every condition sees the identical edit.
                        details = attack.apply(docs, random.Random(trial_seed + "/apply"), s)
                        for d in docs:
                            d.save(careful=(soph == "careful"))
                        detected, kinds = detect(s)
                        rows.append(
                            {
                                "attack": attack.id,
                                "attack_name": attack.name,
                                "sophistication": soph,
                                "condition": cond,
                                "trial": t,
                                "n_calls": n_calls,
                                "position": details.get("position"),
                                "detected": int(detected),
                                "issue_kinds": kinds,
                            }
                        )
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--trials", type=int, default=50, help="trials per attack per sophistication level")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", type=Path, default=Path("results"))
    args = ap.parse_args()

    start = time.time()
    rows = run(args.trials, args.seed)
    summary = summarize(rows)
    write_csv(args.out / "attack_trials.csv", rows)
    write_csv(args.out / "attack_summary.csv", summary)

    print("%-4s %-16s %-8s %-17s %s" % ("id", "attack", "attacker", "condition", "detected"))
    for r in summary:
        print(
            "%-4s %-16s %-8s %-17s %3d/%-3d (%.0f%%)"
            % (r["attack"], r["attack_name"], r["sophistication"], r["condition"], r["detected"], r["trials"], 100 * r["detection_rate"])
        )
    print("\n%d trials in %.0fs -> %s" % (len(rows), time.time() - start, args.out))


if __name__ == "__main__":
    main()
