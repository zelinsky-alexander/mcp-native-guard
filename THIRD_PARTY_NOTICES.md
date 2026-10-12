# Third-party notices

The current source tree does not include or link third-party libraries beyond the C++ standard library
and the selected compiler/runtime toolchain.

Future dependencies must be documented here with package name, version or baseline, licence, purpose,
maintenance status, attribution requirements, and material security or licensing concerns.

## Optional external tracing tool

- **Name:** `strace` (installed and maintained separately by the operator).
- **Licence:** upstream utility LGPL-2.1-or-later; distribution packages and
  test suites may include other licensed components.
- **Purpose:** optional Linux file/process/network syscall tracing when
  `--strace-file` is selected.
- **Maintenance:** active upstream project, https://github.com/strace/strace.
- **Integration:** launched as a separate executable; its source or binary is
  not included or linked in this repository.
- **Risks:** ptrace security restrictions and attack surface, sensitive
  arguments and paths in trace logs, high performance overhead, unbounded
  trace file growth, and redistribution/licence review if packaged together.

See `docs/adr/0001-optional-external-strace.md`. Manual licence, security,
similarity and legal review remains necessary before commercial use.
