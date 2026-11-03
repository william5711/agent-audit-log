"""Cross-check the agent's own transcript against the proxy's audit log (attack A5: spoofing).

In the METR report, agents rigged the tool-call machinery so their transcript showed one command
(``echo REAL; sleep``) while another ran and returned ``SPOOFTEST``. Here the agent keeps its own
transcript (which it fully controls), and the proxy keeps the audit log of what really executed.
Any disagreement between the two is reported:

- ``spoof_command``    transcript shows a different command than the one executed
- ``spoof_output``     transcript shows a different output than the one returned
- ``spoof_exit_code``  transcript shows a different exit code
- ``fabricated_call``  transcript contains a call the proxy never executed
- ``hidden_call``      the proxy executed a call the transcript leaves out
- ``reordered_call``   the transcript lists calls in a different order than they executed
- ``transcript_parse`` a transcript line is unreadable
"""

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import List, Sequence

from .anchor import Anchor
from .log import canonical_json
from .proxy import ToolResult
from .verify import Issue, VerificationResult, verify_log

COMPARED_FIELDS = (("command", "spoof_command"), ("output", "spoof_output"), ("exit_code", "spoof_exit_code"))


class AgentTranscript:
    """The agent's own record of its tool calls. Lives in the agent's workdir; the agent can edit it."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)

    def record(self, result: ToolResult):
        entry = {k: v for k, v in asdict(result).items() if k in ("call_id", "command", "output", "exit_code")}
        with self.path.open("a", encoding="utf-8") as f:
            f.write(canonical_json(entry) + "\n")


@dataclass
class CrossCheckResult:
    log: VerificationResult
    issues: List[Issue] = field(default_factory=list)  # line = transcript line, except hidden_call

    @property
    def ok(self) -> bool:
        return self.log.ok and not self.issues

    def kinds(self) -> set:
        return {i.kind for i in self.issues} | self.log.kinds()


def cross_check(
    transcript_path: Path,
    log_path: Path,
    key: bytes,
    anchors: Sequence[Anchor] = (),
) -> CrossCheckResult:
    log_result = verify_log(log_path, key, anchors=anchors)
    result = CrossCheckResult(log=log_result)

    # Only trust audit entries that individually verified; tampered ones are already reported.
    bad_lines = {i.line for i in log_result.issues if i.kind in ("parse", "hash", "mac")}
    executed = {}
    for i, rec in enumerate(log_result.records):
        if rec is not None and i not in bad_lines:
            executed[rec["data"]["call_id"]] = (i, rec["data"])

    seen = set()
    last_log_line = -1
    lines = [l for l in Path(transcript_path).read_text(encoding="utf-8").splitlines() if l.strip()]
    for i, line in enumerate(lines):
        try:
            claimed = json.loads(line)
            call_id = claimed["call_id"]
        except (ValueError, KeyError, TypeError) as exc:
            result.issues.append(Issue(i, "transcript_parse", str(exc)))
            continue

        if call_id not in executed:
            result.issues.append(Issue(i, "fabricated_call", "call %s was never executed by the proxy" % call_id))
            continue
        seen.add(call_id)
        log_line, actual = executed[call_id]
        if log_line < last_log_line:
            result.issues.append(
                Issue(i, "reordered_call", "call %s appears after a call that executed later" % call_id)
            )
        last_log_line = max(last_log_line, log_line)
        for fld, kind in COMPARED_FIELDS:
            if claimed.get(fld) != actual[fld]:
                result.issues.append(
                    Issue(i, kind, "call %s: transcript %s=%r, executed %r" % (call_id, fld, claimed.get(fld), actual[fld]))
                )

    for call_id, (log_line, data) in executed.items():
        if call_id not in seen:
            result.issues.append(
                Issue(log_line, "hidden_call", "audit line %d: %r ran but is not in the transcript" % (log_line, data["command"]))
            )

    return result
