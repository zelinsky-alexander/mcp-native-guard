# ADR 0001: Optional external strace for Linux runtime diagnosis

## Status

Accepted for opt-in development and research use. Not approved for automatic
production tracing or redistribution of any third-party binary.

## Decision

Support `--strace-file PATH` in Native Guard `run` and `inspect`.
Only on explicit local operator request, execute the installed `strace`
program as a direct subprocess and pass the existing downstream command
as arguments. Follow child processes and capture only file, process, and
network-related syscalls in a separate file.

Continue to provide protocol-level enforcement without `strace` when the
option is not requested. If it is requested but cannot start, fail rather
than silently running an untraced server.

## Dependency assessment

- Name: `strace`; optional Linux userspace tracing executable.
- Licence: upstream main utility LGPL-2.1-or-later. Test suites and
  distribution packages may contain other licences.
- Purpose: capture syscall evidence for selected untrusted MCP runtime
  experiments, especially file and network access attempts.
- Maintenance: actively maintained at https://github.com/strace/strace.
- Integration: separate executable, not linked, vendored, bundled, or
  built by this repository.
- Performance: ptrace suspends traced tasks and can materially increase
  syscall-heavy workload latency. No performance claim without benchmarks.
- Security concerns: ptrace attack surface, interaction with container
  seccomp/LSM policies, sensitive trace arguments and paths, unlimited
  trace-file growth, and tracing-affected timing.
- Licensing concerns: downstream redistributors must separately assess
  packaging and attribution obligations, especially if they bundle strace.

## Alternatives considered

- `ptrace` implementation in native code: greater complexity and
  implementation risk for this diagnostic milestone.
- eBPF: scalable and lower overhead for event collection, but requires
  kernel feature testing and a separate telemetry contract.
- Audit subsystem: suitable for host-level telemetry but less convenient
  for isolated developer sessions.

## Consequences

The operator must install a compatible, trusted `strace` executable,
provide an output path with appropriate filesystem permissions and
retention, and verify ptrace availability. Docker seccomp or AppArmor
must not be disabled automatically to enable tracing. An explicit
sandbox/evidence integration is a separate milestone.

No third-party source was adapted in this implementation. Perform
manual licence, similarity, security, and legal review before
distribution or commercial use.
