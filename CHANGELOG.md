# Changelog

## Unreleased

- Add the real MCP server smoke-test workflow and 0.1 release-hardening documentation.

## 0.1.0 - Unreleased

- Establish the modern C++20 project structure and `mcp-native-guard` CLI at version `0.1.0`.
- Add Linux stdio child-process supervision for the `run` proxy command.
- Add bounded newline-delimited JSON-RPC/MCP framing with configurable message-size limits.
- Add configurable runtime nesting-depth and pending `tools/list` correlation limits.
- Add bounded local JSON policy loading with explicit per-tool visibility and invocation decisions.
- Add `tools/list` filtering and `tools/call` blocking for explicitly named tools.
- Add structured JSONL audit output that omits full messages and tool arguments.
- Add focused unit tests, Linux integration tests, sanitizer preset, Release preset, and optional benchmarks.
