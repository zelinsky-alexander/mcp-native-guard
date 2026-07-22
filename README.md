# mcp-native-guard

A modern C++ security boundary for Model Context Protocol traffic, designed for bounded resource use,
low overhead, and native endpoint enforcement.

> **Status:** early functional Linux prototype; not production hardened. Linux `run` support is functional for local stdio child processes, but this project is not ready to serve as a production security boundary.

## Why this project exists

Most MCP gateways focus on routing and centralized policy. This project is aimed at a smaller native
execution firewall that can eventually bind an exposed tool to the executable, process policy, and
runtime restrictions that implement it.

The first MVP will support local `stdio` proxying, strict MCP/JSON-RPC validation, discovery-time and
call-time policy enforcement, tool-definition baselines, and an append-only audit chain.

## What is implemented now

- C++20 core library and CLI target.
- Bounded newline-delimited stdio framer.
- Zero-copy delivery for complete messages already present in an input chunk.
- Immutable sorted tool-policy table with allocation-free lookup.
- Deterministic policy-decision core with relaxed atomic counters.
- Linux stdio child supervision with bounded, nonblocking relay buffers.
- Bounded one-time loading of version 1 local JSON tool policies.
- Repeatable command-line deny rules for `tools/call` enforcement and `tools/list` visibility.
- Optional bounded JSONL enforcement audit output to a local file or stderr.
- Focused dependency-free tests.
- Optional dependency-free framing microbenchmark.
- Debug, sanitizer, and performance CMake presets.

No GitHub Actions workflow is included at this stage; validation is intentionally local and focused.

## Build

Requirements:

- CMake 3.24 or newer.
- Ninja.
- A C++20 compiler such as Clang 17+, GCC 13+, or a recent MSVC toolset.

```bash
cmake --preset dev-debug
cmake --build --preset dev-debug
ctest --preset dev-debug
```

Clean Release build command:

```bash
cmake --preset release
cmake --build --preset release
```

Run the early framing harness:

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"ping"}' \
  | ./build/dev-debug/mcp-native-guard relay
```

The `relay` command is only a framing-path harness. It is not the security proxy MVP. The `run` proxy is currently Linux-only; Windows process isolation is not implemented.

Run a downstream test MCP server with a local policy and an optional command-line deny override:

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":"list-1","method":"tools/list"}' \
  '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"allowed.tool"}}' \
  '{"jsonrpc":"2.0","id":"blocked-2","method":"tools/call","params":{"name":"blocked.tool"}}' \
  '{"jsonrpc":"2.0","id":3,"method":"initialize","params":{}}' \
  | ./build/dev-debug/mcp-native-guard run \
      --policy examples/policy.json \
      --deny-tool blocked.tool \
      --max-message-bytes 1048576 \
      --max-nesting-depth 64 \
      --max-pending-tools-list 64 \
      -- ./build/dev-debug/test_servers/mng_test_mcp_server
```

Write structured enforcement decisions to a local JSONL audit file:

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"allowed.tool"}}' \
  | ./build/dev-debug/mcp-native-guard run \
      --policy examples/policy.json \
      --audit-file /tmp/mng-audit.jsonl \
      -- ./build/dev-debug/test_servers/mng_test_mcp_server
```

Use `--audit-stderr` instead to emit the same compact JSONL records on stderr. Audit is disabled by
default, and `--audit-file` and `--audit-stderr` cannot be combined. Audit output never uses stdout
and never includes tool arguments or complete JSON-RPC messages; records may still include tool names, raw request IDs, timestamps, and message sizes. Audit files are opened in append
mode before the child starts. If a runtime audit write fails, the proxy reports the failure once on
stderr, disables later audit writes, and continues enforcing policy.

Policy format version 1 uses explicit defaults and per-tool visibility/invocation access:

```json
{
  "version": 1,
  "defaults": {
    "visibility": "allow",
    "invocation": "allow"
  },
  "tools": [
    {
      "name": "filesystem.write_file",
      "visibility": "deny",
      "invocation": "deny"
    }
  ]
}
```

The file is read and parsed once, before the downstream process starts. Tool names containing JSON
escapes are rejected in this version, including escaped names in policy files and security-relevant protocol fields; write tool names as unescaped JSON strings. Repeated
`--deny-tool NAME` options are applied after file loading and deny both visibility and invocation.

Denied requests are not sent to the child. They currently receive project-specific JSON-RPC error
code `-32001` with message `Tool call denied by policy`; this code is temporary until the project's
public error contract is finalized. Denied notifications are silently dropped. Invalid
`tools/call` parameters with a usable request ID receive `-32602`.

The proxy correlates bounded outstanding `tools/list` requests with server responses and removes
denied tool definitions while preserving unrelated response fields and allowed definitions.

The `run` command accepts configurable runtime security limits:

- `--max-message-bytes N` bounds each newline-delimited MCP message in both directions; default: `1048576`.
- `--max-nesting-depth N` bounds security-relevant runtime JSON scanners and extractors; default: `64`.
- `--max-pending-tools-list N` bounds outstanding `tools/list` request/response correlations; default: `64`.

Numeric limit values must be unsigned nonzero decimal integers. Malformed values, signed-looking
values, overflow, and duplicate occurrences of the same limit option are rejected at startup.

When the `tools/list` correlation table is full, the proxy does not forward another untrackable
request. Requests with a usable ID receive compact JSON-RPC error code `-32002`; this
project-specific code is temporary until the project's public runtime-limit error contract is
finalized. Notifications or messages without a usable ID are dropped. If audit is enabled, the
proxy emits a resource-limit audit record and remains available for later traffic.

Audit records cover allowed, denied, and invalid `tools/call` messages; removed `tools/list`
definitions; oversized messages; and pending-correlation capacity exhaustion. Each record includes
a UTC timestamp, event, decision, reason, and only the applicable tool name, raw request ID, and
encoded message size.

## Compatibility limits for 0.1

- Runtime proxy support is Linux-only for local stdio child processes.
- Stdio framing assumes one complete JSON-RPC message per newline (JSONL); HTTP-style `Content-Length` framing is not supported.
- Denied `tools/call` requests currently use temporary JSON-RPC error code `-32001`.
- Exhausted `tools/list` correlation capacity currently uses temporary JSON-RPC error code `-32002`.
- Escaped tool names in security-relevant JSON strings are rejected in this version.
- Audit records omit full arguments and full JSON-RPC payloads but may include tool names, request IDs, timestamps, and message sizes.
- Runtime defaults are `--max-message-bytes 1048576`, `--max-nesting-depth 64`, and `--max-pending-tools-list 64`.
- HTTP transports, OAuth, TLS termination, Windows process isolation, policy hot reload, wildcard rules, dashboards, metrics, and log rotation are not implemented.

## Real MCP server smoke test

A repeatable external smoke harness is available for JSONL-compatible Linux stdio MCP servers:

```bash
scripts/smoke_real_mcp.sh -- npx -y @modelcontextprotocol/server-filesystem@2026.7.10 {sandbox}
```

See [`docs/real-mcp-smoke-test.md`](docs/real-mcp-smoke-test.md).

## Performance measurement

```bash
cmake --preset perf
cmake --build --preset perf
./build/perf/benchmarks/mng_framer_benchmark
```

Results are meaningful only with hardware, compiler, flags, and workload recorded. See
[`docs/performance-plan.md`](docs/performance-plan.md).

## Near-term milestones

1. Select and benchmark an authoritative JSON parser under an approved permissive licence.
2. Implement typed JSON-RPC and MCP request/response validation.
3. Canonicalize and fingerprint approved tool definitions.
4. Add an append-only hash-chained audit sink.
5. Add Windows Job Object and Linux process-control backends.

## Engineering principles

- Fail closed on malformed security-relevant protocol state.
- Bound attacker-controlled memory, concurrency, and execution time.
- Keep protocol stdout free of diagnostics.
- Do not put an LLM in the enforcement path.
- Benchmark before claiming performance.
- Prefer clear native code over template cleverness.

## Dependencies and licensing

The current production and test targets use only the C++ standard library and operating-system toolchain.
No third-party source code is included. See [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

The project is licensed under Apache License 2.0. The scaffold is an original implementation based on
project requirements and standard C++/CMake facilities. Before publication in a commercial product,
perform manual licence, similarity, security, and legal review.
