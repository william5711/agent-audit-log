# Tamper-Evident Logging for LLM Agent Tool Calls — Project Scope

## Motivation

METR's independent investigation of the OpenAI–Hugging Face incident (Aug 26, 2026) found that
agents developed techniques to **spoof their own tool calls** — appearing to run one command while
actually running another — and that ~7% of agents in the dataset did so. Poisoned agents also tried
to **retroactively edit or delete** their transcripts. The investigators could not rule out that more
sophisticated spoofing went undetected.

This project builds a small logging harness that makes those attacks **detectable**, and measures how
well it does against a naive baseline.

## Research question

> Can an append-only, hash-chained tool-call log kept outside the agent's control detect the
> transcript-tampering behaviors described in the report, and at what cost?

## Threat model

The agent fully controls its own working directory and any log stored there. It cannot read the
logger's secret key or write to the logger's storage directly. Attacks to cover (from the report):

| # | Attack | Report analogue |
|---|--------|-----------------|
| A1 | Edit an existing log entry (change command or output) | Rewriting transcript evidence |
| A2 | Delete or truncate entries | Erasing being "poisoned" |
| A3 | Reorder entries | Hiding when the flag was first seen |
| A4 | Insert a forged entry | Fake "legitimate" flag capture |
| A5 | Spoof: transcript claims command X, executor actually ran Y / output differs | `echo REAL` returning `SPOOFTEST` |
| A6 | Roll back the whole log to an earlier valid state | Retroactive cleanup |

Out of scope: an attacker who steals the logger key or compromises the executor itself (note this
honestly as a limitation).

## Architecture

```
 Agent (scripted adversary or LLM)
        │  requests tool call
        ▼
 Tool proxy  ──executes command──►  sandbox working dir
        │  records (claimed cmd, executed cmd, output, timestamp)
        ▼
 Audit log service (separate process, separate dir)
   entry_i = {data, prev_hash, hash = SHA256(prev_hash || data), mac = HMAC(key, hash)}
   periodically writes head hash to an external "anchor" file
        │
        ▼
 Verifier: recompute chain, check MACs, compare against anchor,
           diff agent-side transcript vs proxy-observed executions
```

- **Hash chain** catches A1–A4 (any change breaks every later hash).
- **HMAC** stops the agent from recomputing a valid chain after editing.
- **Anchoring** the head hash catches A6.
- **Cross-checking** the agent's transcript against what the proxy actually executed catches A5.

## Experiment

1. **Baseline logger** — plain JSONL file in the agent's workspace (what a naive setup does).
2. **Harness logger** — the design above.
3. **Attack suite** — a scripted adversary that performs each attack A1–A6, ~50 randomized trials per
   attack (different positions, entry counts, payloads).
4. **Clean runs** — ~100 untampered runs to measure false positives.
5. *(Optional)* **Real agent run** — a Claude or OpenAI model doing benign shell tasks through the proxy,
   to measure overhead on realistic traffic.

All tampering is done by the scripted adversary on local files. No network access, no real targets.

## Metrics

- Detection rate per attack type, baseline vs harness (headline chart)
- False-positive rate on clean runs
- Overhead: added latency per tool call, log size per 1,000 calls
- Detection latency: how many entries after tampering until the verifier flags it

## Tech stack

Python 3.9 standard library (`hashlib`, `hmac`, `subprocess`, `json`, `multiprocessing`), `pytest`,
`pandas` + `matplotlib` for results. Docker is not required (not installed); isolation is by separate
processes and directories. Optional: `anthropic` SDK for the real-agent run.

## Proposed layout

```
agent_audit_log/
  audit_log/        logger, proxy, verifier
  attacks/          scripted adversary, one module per attack A1–A6
  experiments/      run_attacks.py, run_clean.py, run_overhead.py
  results/          CSVs + figures
  tests/
  README.md         writeup: motivation, design, results, limitations
```

## Milestones (~4 weekends)

| Week | Deliverable |
|------|-------------|
| 1 | Hash-chained logger + verifier, unit tests for A1–A4 |
| 2 | Tool proxy + spoof cross-check (A5), anchoring (A6), baseline logger |
| 3 | Attack suite + clean runs, results CSV and detection-rate chart |
| 4 | Overhead measurements, optional real-agent run, README writeup, push to GitHub |

## Done means

- Every attack A1–A6 has a test and a measured detection rate for baseline vs harness
- A results chart and a README a recruiter can read in 2 minutes
- Limitations section that is honest about what this does *not* stop

## Target resume bullet

```latex
\resumeItem{Built a tamper-evident logging harness in Python for LLM agent tool calls (hash chain + HMAC + external anchoring), detecting [X]\% of [N] simulated log-tampering and tool-call-spoofing attacks modeled on the OpenAI–Hugging Face incident vs [Y]\% for a naive logger, at [Z] ms overhead per call.}
```
