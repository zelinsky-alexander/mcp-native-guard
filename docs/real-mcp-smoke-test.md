# Real MCP server smoke test

`scripts/smoke_real_mcp.sh` is a repeatable external smoke harness for running
`mcp-native-guard` in front of a real Linux stdio MCP server. It uses a temporary
sandbox directory, a temporary policy, and a temporary JSONL audit file, then
removes them on normal exit and signals.

## Framing assumption

The current proxy accepts one complete JSON-RPC message per newline on stdin and
emits one complete JSON-RPC message per newline on stdout. The smoke harness
therefore validates only MCP stdio servers that are JSONL-compatible. If a server
uses `Content-Length` headers or another stdio framing style, record that as an
observed incompatibility for this milestone; do not add an ad hoc protocol
adapter to the harness or proxy.

## Tested server target

The checked-in filesystem example policy is tied to:

- Package/project: `@modelcontextprotocol/server-filesystem`.
- Tested version target: `2026.7.10`.
- License: MIT, as reported by the npm package metadata.
- Purpose: constrained file read/write/list operations for directories supplied
  on the command line.
- Maintenance status: actively maintained official MCP server package, with a
  recent npm release in July 2026.
- Known licensing or security concern: it intentionally exposes filesystem
  operations inside configured roots, so run it only with a temporary sandbox;
  no third-party source is copied into this repository.

The example denies `write_file` and leaves `read_file` visible/invocable. The
harness still checks the actual filtered `tools/list` result from the selected
server and fails clearly if the expected tool names do not match that server.

## Build the proxy

```bash
cmake --preset dev-debug
cmake --build --preset dev-debug
```

## Run against the documented filesystem server

The downstream command is supplied after `--`. Use `{sandbox}` where the harness
should substitute its temporary sandbox path:

```bash
scripts/smoke_real_mcp.sh -- \
  npx -y @modelcontextprotocol/server-filesystem@2026.7.10 {sandbox}
```

Override paths and tool names when validating another JSONL-compatible server:

```bash
scripts/smoke_real_mcp.sh \
  --guard ./build/dev-debug/mcp-native-guard \
  --timeout 20 \
  --allowed-tool read_file \
  --denied-tool write_file \
  -- your-server-command {sandbox}
```

## What the harness proves

The harness sends `initialize`, `notifications/initialized`, `tools/list`, one
allowed `tools/call`, and one denied `tools/call`. It validates that:

- `initialize` returns a JSON-RPC result;
- `tools/list` returns a JSON-RPC result;
- the denied tool is absent from the filtered tool list;
- the allowed tool call reaches the downstream server by reading a fixture file;
- the denied call returns error code `-32001` with `Tool call denied by policy`;
- the denied write creates no sandbox side-effect file;
- audit contains allow, deny, and hidden-tool records;
- audit does not include full tool arguments or JSON-RPC payloads;
- protocol stdout contains only JSON-RPC messages, not diagnostics or audit;
- the proxy and child exit cleanly after client stdin closes.

Timeouts fail with captured stdout/stderr diagnostics rather than hanging.
