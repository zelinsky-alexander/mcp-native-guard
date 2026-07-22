import importlib.util
import json
import pathlib
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).parents[1] / "scripts" / "audit_health_summary.py"
SPEC = importlib.util.spec_from_file_location("audit_health_summary", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class AuditSummaryTests(unittest.TestCase):
    def test_clean_session_and_counters(self):
        records = [
            {"ts":"2026-01-01T00:00:00Z","event":"session_start","server_label":"x","downstream_executable":"s","policy_hash":"fnv1a64:a"},
            {"timestamp":"2026-01-01T00:00:01Z","event":"tools/call","decision":"allow"},
            {"ts":"2026-01-01T00:00:02Z","event":"session_end","server_label":"x","downstream_executable":"s","policy_hash":"fnv1a64:a","clean_shutdown":True},
        ]
        with tempfile.NamedTemporaryFile("w", delete=False) as stream:
            for record in records: stream.write(json.dumps(record) + "\n")
            path = stream.name
        summary, missing = MODULE.summarize([path])
        self.assertFalse(missing)
        self.assertEqual(summary["total_sessions"], 1)
        self.assertEqual(summary["clean_sessions"], 1)
        self.assertEqual(summary["allowed_tool_calls"], 1)
        self.assertEqual(summary["unmatched_session_starts"], 0)

    def test_invalid_truncated_final_line(self):
        with tempfile.NamedTemporaryFile("wb", delete=False) as stream:
            stream.write(b'{"event":"session_start"')
            path = stream.name
        summary, _ = MODULE.summarize([path])
        self.assertEqual(summary["invalid_json_lines"], 1)
        self.assertEqual(summary["truncated_final_lines"], 1)

    def test_missing_file(self):
        _, missing = MODULE.summarize(["/definitely/missing/mng-audit.jsonl"])
        self.assertEqual(len(missing), 1)


if __name__ == "__main__":
    unittest.main()
