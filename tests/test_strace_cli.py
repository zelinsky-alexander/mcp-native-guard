"""Integration checks for the optional strace wrapper without a ptrace dependency."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


GUARD = sys.argv[1]
MCP_SERVER = sys.argv[2]


class StraceCliTests(unittest.TestCase):
    def test_run_and_inspect_with_mock_tracer(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mng-strace-test-") as root:
            directory = Path(root)
            shim = directory / "strace"
            shim.write_text(
                "#!/usr/bin/env python3\n"
                "import os, pathlib, sys\n"
                "args = sys.argv[1:]\n"
                "assert args[:8] == [\"-f\", \"-qq\", \"-s\", \"256\", \"-e\", "
                "\"trace=%file,%process,%network\", \"-o\", args[7]]\n"
                "assert args[8] == \"--\"\n"
                "pathlib.Path(args[7]).write_text(\"test tracer invoked\\n\")\n"
                "os.execvp(args[9], args[9:])\n",
                encoding="utf-8",
            )
            shim.chmod(0o700)
            environment = dict(os.environ)
            environment["PATH"] = f"{directory}:{os.environ.get('PATH', '')}"

            run_trace = directory / "run.log"
            run = subprocess.run(
                [GUARD, "run", "--strace-file", str(run_trace), "--", "/bin/cat"],
                input='{"jsonrpc":"2.0","id":1,"method":"ping"}\n',
                capture_output=True,
                text=True,
                timeout=12,
                env=environment,
                check=False,
            )
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertIn('"method":"ping"', run.stdout)
            self.assertEqual(run_trace.read_text(), "test tracer invoked\n")

            inspect_trace = directory / "inspect.log"
            inspect = subprocess.run(
                [GUARD, "inspect", "--timeout", "5", "--strace-file",
                 str(inspect_trace), "--", MCP_SERVER, "--mode", "healthy"],
                capture_output=True,
                text=True,
                timeout=12,
                env=environment,
                check=False,
            )
            self.assertEqual(inspect.returncode, 0, inspect.stderr)
            self.assertEqual(json.loads(inspect.stdout)["inventory_version"], 1)
            self.assertEqual(inspect_trace.read_text(), "test tracer invoked\n")

    def test_invalid_trace_paths(self) -> None:
        for subcommand in ("run", "inspect"):
            with self.subTest(subcommand=subcommand):
                result = subprocess.run(
                    [GUARD, subcommand, "--strace-file", "-", "--", "/bin/cat"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
