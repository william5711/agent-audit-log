"""Measure what the harness costs: latency per tool call, log size, and verification time.

Per-call latency is measured for four setups, each running the same cheap command so that the
harness's own cost isn't hidden behind slow commands:

- ``plain``           /bin/sh -c, no sandbox, no logging (what an unprotected agent does)
- ``sandbox``         sandbox-exec only
- ``sandbox+log``     sandbox + hash-chained, HMAC-signed, fsync'd audit log
- ``full``            sandbox + log + anchors every 5 calls (the configuration used in week 3)

The setups are interleaved call by call so drift in machine load affects them equally.

    python3 -m experiments.run_overhead --calls 500
"""

import argparse
import statistics
import subprocess
import tempfile
import time
from pathlib import Path

from audit_log import AgentTranscript, AnchorStore, AuditLog, ToolProxy, cross_check, load_or_create_key
from audit_log.proxy import sandboxed_argv

from .common import write_csv

COMMAND = "echo step"


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))]


def make_proxy(root: Path, sandbox: bool, anchors: bool) -> ToolProxy:
    logger = root / "logger"
    log = AuditLog(logger / "audit.jsonl", load_or_create_key(logger / "key.hex"))
    return ToolProxy(
        root / "agent",
        log,
        AnchorStore(logger / "anchors.jsonl") if anchors else None,
        anchor_every=5,
        protected_paths=[logger] if sandbox else (),
    )


def time_call(fn):
    start = time.perf_counter()
    fn()
    return (time.perf_counter() - start) * 1000


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--calls", type=int, default=500)
    ap.add_argument("--out", type=Path, default=Path("results"))
    args = ap.parse_args()

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / "plain").mkdir()
        sandbox_only = make_proxy(tmp / "sandbox", sandbox=True, anchors=False)
        logged = make_proxy(tmp / "logged", sandbox=True, anchors=False)
        full = make_proxy(tmp / "full", sandbox=True, anchors=True)
        transcript = AgentTranscript(tmp / "full" / "agent" / "transcript.jsonl")

        setups = {
            "plain": lambda: subprocess.run(
                ["/bin/sh", "-c", COMMAND], cwd=str(tmp / "plain"), stdout=subprocess.PIPE, stderr=subprocess.STDOUT
            ),
            "sandbox": lambda: subprocess.run(
                sandboxed_argv(COMMAND, sandbox_only.protected_paths),
                cwd=str(sandbox_only.workdir),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            ),
            "sandbox+log": lambda: logged.run(COMMAND),
            "full": lambda: transcript.record(full.run(COMMAND)),
        }
        for fn in setups.values():  # warm up
            fn()
        timings = {name: [] for name in setups}
        for _ in range(args.calls):
            for name, fn in setups.items():
                timings[name].append(time_call(fn))
        full.close()

        # Log-only cost, without any subprocess: what the hash chain + HMAC + fsync add by themselves.
        bare = AuditLog(tmp / "bare" / "audit.jsonl", load_or_create_key(tmp / "bare" / "key.hex"))
        payload = {"tool": "bash", "call_id": "0" * 12, "command": COMMAND, "output": "step\n", "exit_code": 0,
                   "duration_s": 0.004, "truncated": False}
        append_ms = [time_call(lambda: bare.append(payload)) for _ in range(args.calls)]

        n_entries = full.log.length
        log_bytes = full.log.path.stat().st_size
        key = load_or_create_key(tmp / "full" / "logger" / "key.hex")
        anchors = AnchorStore(tmp / "full" / "logger" / "anchors.jsonl").all()
        verify_ms = statistics.median(
            time_call(lambda: cross_check(transcript.path, full.log.path, key, anchors)) for _ in range(5)
        )

    plain_median = statistics.median(timings["plain"])
    rows = []
    for name, xs in timings.items():
        med = statistics.median(xs)
        rows.append(
            {
                "setup": name,
                "calls": len(xs),
                "median_ms": round(med, 3),
                "p95_ms": round(pct(xs, 95), 3),
                "added_vs_plain_ms": round(med - plain_median, 3),
            }
        )
    rows.append(
        {
            "setup": "log_append_only",
            "calls": len(append_ms),
            "median_ms": round(statistics.median(append_ms), 3),
            "p95_ms": round(pct(append_ms, 95), 3),
            "added_vs_plain_ms": "",
        }
    )
    write_csv(args.out / "overhead.csv", rows)

    storage = [
        {"metric": "audit_log_bytes_per_1000_calls", "value": round(log_bytes / n_entries * 1000)},
        {"metric": "cross_check_ms_per_1000_calls", "value": round(verify_ms / n_entries * 1000, 1)},
        {"metric": "entries_measured", "value": n_entries},
    ]
    write_csv(args.out / "overhead_storage.csv", storage)

    print("%-16s %10s %10s %16s" % ("setup", "median ms", "p95 ms", "added vs plain"))
    for r in rows:
        added = "" if r["added_vs_plain_ms"] == "" else "%+.2f ms" % r["added_vs_plain_ms"]
        print("%-16s %10.2f %10.2f %16s" % (r["setup"], r["median_ms"], r["p95_ms"], added))
    print()
    for s in storage:
        print("%-32s %s" % (s["metric"], s["value"]))


if __name__ == "__main__":
    main()
