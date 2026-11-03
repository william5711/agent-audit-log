"""Week 1 tests: the logger, the verifier, and attacks A1-A4 from SCOPE.md.

Each attack test plays the agent: it edits the log file directly, with no access to the key.
Run with:  python3 -m unittest discover -s tests   (from the agent_audit_log/ folder)
"""

import json
import secrets
import tempfile
import unittest
from pathlib import Path

from audit_log import AuditLog, load_or_create_key, verify_log
from audit_log.log import canonical_json, entry_hash

N_ENTRIES = 10


def tool_call(i):
    return {"tool": "bash", "command": "echo step-%d" % i, "output": "step-%d\n" % i, "exit_code": 0}


def read_entries(path):
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


def write_entries(path, entries):
    path.write_text("".join(canonical_json(e) + "\n" for e in entries))


def rechain_without_key(entries):
    """What a careful attacker does after tampering: renumber and recompute every hash.

    It has no key, so it can't produce valid MACs. Only the HMAC should catch this.
    """
    prev = "0" * 64
    for i, e in enumerate(entries):
        e["seq"] = i
        e["prev_hash"] = prev
        e["hash"] = entry_hash(prev, i, e["ts"], e["data"])
        prev = e["hash"]
    return entries


class LogTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.key = load_or_create_key(root / "logger" / "key.hex")
        self.path = root / "logger" / "audit.jsonl"
        self.log = AuditLog(self.path, self.key)
        for i in range(N_ENTRIES):
            self.log.append(tool_call(i), ts=1000.0 + i)
        self.anchor = {"head": self.log.head_hash, "length": self.log.length}

    def tearDown(self):
        self._tmp.cleanup()

    def verify(self, anchored=False):
        if anchored:
            return verify_log(self.path, self.key, self.anchor["head"], self.anchor["length"])
        return verify_log(self.path, self.key)


class CleanLogTests(LogTestCase):
    def test_untampered_log_verifies(self):
        result = self.verify(anchored=True)
        self.assertTrue(result.ok, result.issues)
        self.assertEqual(result.entries, N_ENTRIES)

    def test_reopening_continues_the_chain(self):
        reopened = AuditLog(self.path, self.key)
        self.assertEqual(reopened.length, N_ENTRIES)
        reopened.append(tool_call(N_ENTRIES))
        self.assertTrue(verify_log(self.path, self.key).ok)

    def test_key_is_reused_not_regenerated(self):
        key_path = Path(self._tmp.name) / "logger" / "key.hex"
        self.assertEqual(load_or_create_key(key_path), self.key)

    def test_wrong_key_fails_every_entry(self):
        result = verify_log(self.path, secrets.token_bytes(32))
        self.assertEqual(result.kinds(), {"mac"})
        self.assertEqual(len(result.issues), N_ENTRIES)

    def test_empty_log_verifies(self):
        empty = Path(self._tmp.name) / "empty.jsonl"
        AuditLog(empty, self.key)
        self.assertTrue(verify_log(empty, self.key, expected_head="0" * 64, expected_length=0).ok)


class A1EditTests(LogTestCase):
    def test_edit_output(self):
        entries = read_entries(self.path)
        entries[4]["data"]["output"] = "SPOOFTEST\n"
        write_entries(self.path, entries)

        result = self.verify()
        self.assertIn("hash", result.kinds())
        self.assertEqual(result.first_bad_line, 4)

    def test_edit_command_and_rechain(self):
        entries = read_entries(self.path)
        entries[4]["data"]["command"] = "echo REAL; sleep 1"
        write_entries(self.path, rechain_without_key(entries))

        result = self.verify()
        # Hashes and links are internally consistent again; only the MACs give it away.
        self.assertEqual(result.kinds(), {"mac"})
        self.assertEqual(result.first_bad_line, 4)

    def test_corrupted_line(self):
        lines = self.path.read_text().splitlines()
        lines[2] = lines[2][:-10]
        self.path.write_text("\n".join(lines) + "\n")

        result = self.verify()
        self.assertIn("parse", result.kinds())
        self.assertEqual(result.first_bad_line, 2)


class A2DeleteTests(LogTestCase):
    def test_delete_middle_entry(self):
        entries = read_entries(self.path)
        del entries[3]
        write_entries(self.path, entries)

        result = self.verify()
        self.assertTrue({"seq", "chain"} <= result.kinds())
        self.assertEqual(result.first_bad_line, 3)

    def test_delete_middle_entry_and_rechain(self):
        entries = read_entries(self.path)
        del entries[3]
        write_entries(self.path, rechain_without_key(entries))

        result = self.verify()
        self.assertEqual(result.kinds(), {"mac"})

    def test_truncate_tail_is_invisible_without_anchor(self):
        # Known limitation of a bare hash chain: a valid prefix is still a valid chain.
        write_entries(self.path, read_entries(self.path)[:6])
        self.assertTrue(self.verify().ok)

    def test_truncate_tail_is_caught_with_anchor(self):
        write_entries(self.path, read_entries(self.path)[:6])
        result = self.verify(anchored=True)
        self.assertEqual(result.kinds(), {"head"})


class A3ReorderTests(LogTestCase):
    def test_swap_two_entries(self):
        entries = read_entries(self.path)
        entries[2], entries[6] = entries[6], entries[2]
        write_entries(self.path, entries)

        result = self.verify()
        self.assertTrue({"seq", "chain"} <= result.kinds())
        self.assertEqual(result.first_bad_line, 2)

    def test_swap_and_rechain(self):
        entries = read_entries(self.path)
        entries[2], entries[6] = entries[6], entries[2]
        write_entries(self.path, rechain_without_key(entries))

        result = self.verify()
        self.assertEqual(result.kinds(), {"mac"})


class A4ForgeTests(LogTestCase):
    def _forged_entry(self, after):
        prev = after["hash"]
        data = {"tool": "bash", "command": "./exploit --cve 9479", "output": "FLAG{...}\n", "exit_code": 0}
        seq = after["seq"] + 1
        return {
            "seq": seq,
            "ts": after["ts"] + 0.5,
            "data": data,
            "prev_hash": prev,
            "hash": entry_hash(prev, seq, after["ts"] + 0.5, data),
            "mac": secrets.token_hex(32),  # best guess without the key
        }

    def test_append_forged_entry(self):
        entries = read_entries(self.path)
        entries.append(self._forged_entry(entries[-1]))
        write_entries(self.path, entries)

        result = self.verify()
        self.assertEqual(result.kinds(), {"mac"})
        self.assertEqual(result.first_bad_line, N_ENTRIES)

    def test_insert_forged_entry_and_rechain(self):
        entries = read_entries(self.path)
        entries.insert(5, self._forged_entry(entries[4]))
        write_entries(self.path, rechain_without_key(entries))

        result = self.verify()
        self.assertEqual(result.kinds(), {"mac"})
        self.assertEqual(result.first_bad_line, 5)

    def test_copy_valid_mac_from_another_entry(self):
        entries = read_entries(self.path)
        forged = self._forged_entry(entries[-1])
        forged["mac"] = entries[-1]["mac"]
        entries.append(forged)
        write_entries(self.path, entries)

        self.assertEqual(self.verify().kinds(), {"mac"})


if __name__ == "__main__":
    unittest.main()
