# Optional strace observation (Linux)

Native Guard can invoke an **externally installed** `strace` executable for
selected local `run` and `inspect` sessions. This is **opt-in** diagnostic
tracing, not an OS sandbox, an enforcement policy, or proof of server safety.

## Usage

Install `strace` separately through the host Linux distribution. It must be
available in the process PATH. For example:

```sh
mcp-native-guard inspect --strace-file /tmp/mcp-inspect.trace -- node server.js
mcp-native-guard run --strace-file /tmp/mcp-run.trace -- node server.js
```

The guard runs `strace -f -qq -s 256 -e trace=%file,%process,%network -o
<chosen-file> -- <server> [args...]`, without a shell. The command follows
descendants and records file-related, process, and network syscalls, including
failed attempts. It does not record file contents or every read/write call.
The MCP protocol continues over the server's existing stdin/stdout pipes; the
trace is written to the requested file, never MCP stdout.

When tracing is requested, a missing `strace` executable, a ptrace
restriction, or an unwritable trace destination must result in a failed
session. No untraced fallback is intended. If a command fails, inspect
stderr and the trace file before trusting any results.

## Operational and security limitations

- `strace` is not bundled or linked into Native Guard. Installation is optional.
  Production runs remain untraced unless explicitly requested.
- Traces can reveal file paths, command-line arguments, network destinations,
  and sometimes sensitive syscall arguments. Store in a protected directory,
  remove after review, and never publish raw traces automatically.
- Traces can grow without an intrinsic file-size cap. Use bounded-duration
  inspections or an external quota/retention policy; tracing long-lived `run`
  sessions is not recommended without those controls.
- Tracing alters performance and scheduling. The Linux kernel must permit
  `ptrace` and the sandbox/container must allow the required operations.
  Docker's built-in seccomp profile may still interact with tracing depending
  on the kernel and security configuration. **Do not disable seccomp or
  privilege isolation merely to make tracing work.**
- Child-process lifecycle controls are unchanged. In particular, `run` does
  not yet guarantee cleanup of the entire descendant process tree.
- In Observatory, `inspect` runs inside a restricted runtime container.
  Its runtime image does not include `strace` by default. Native Guard does
  not enable tracing for Observatory unless orchestration is separately
  configured with an appropriate verified image and trace-evidence contract.

## Dependency and licensing assessment

- Package/tool: `strace`, an optional external Linux diagnostic executable.
- Licence: LGPL-2.1-or-later for the main upstream utility. Some packaged
  sources and tests contain additional licences; validate the exact package
  when redistributing.
- Purpose: syscall tracing of selected untrusted MCP subprocesses.
- Maintenance: actively maintained upstream at https://github.com/strace/strace.
- Integration: executable invoked via documented CLI; no third-party source is
  copied, linked, or distributed here.
- Risks: sensitive trace data, overhead, ptrace restrictions, and potential
  kernel attack surface in untrusted-code experiments.
- Review: manually assess licences, similarity, package integrity, and
  security before commercial distribution or adoption.
