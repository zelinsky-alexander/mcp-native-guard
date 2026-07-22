# mcp-native-guard

A modern C++ security boundary for Model Context Protocol traffic, designed for bounded resource use,
low overhead, and native endpoint enforcement.

> **Status:** architectural scaffold. This repository does not yet implement a production MCP proxy.

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
- Repeatable command-line deny rules for `tools/call` enforcement and `tools/list` visibility.
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

Run the early framing harness:

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"ping"}' \
  | ./build/dev-debug/mcp-native-guard relay
```

The `relay` command is only a framing-path harness. It is not the security proxy MVP.

Run a downstream test MCP server while denying selected tools:

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":"list-1","method":"tools/list"}' \
  '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"allowed.tool"}}' \
  '{"jsonrpc":"2.0","id":"blocked-2","method":"tools/call","params":{"name":"blocked.tool"}}' \
  '{"jsonrpc":"2.0","id":3,"method":"initialize","params":{}}' \
  | ./build/dev-debug/mcp-native-guard run \
      --deny-tool blocked.tool \
      -- ./build/dev-debug/test_servers/mng_test_mcp_server
```

Denied requests are not sent to the child. They currently receive project-specific JSON-RPC error
code `-32001` with message `Tool call denied by policy`; this code is temporary until the project's
public error contract is finalized. Denied notifications are silently dropped. Invalid
`tools/call` parameters with a usable request ID receive `-32602`.

The proxy correlates bounded outstanding `tools/list` requests with server responses and removes
denied tool definitions while preserving unrelated response fields and allowed definitions.

The `run` command accepts in-memory CLI deny rules only. It does not load policy files.

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
