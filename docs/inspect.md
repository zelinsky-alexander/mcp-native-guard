# inspect — discovery-only tool inventory

`inspect` launches one local stdio MCP server, performs MCP initialization and
`tools/list`, and writes a deterministic JSON tool inventory. It never invokes a
tool and never sends `tools/call`, resources, prompts, sampling, elicitation, or
completion requests.

Inspection does **not** prove that a server is safe. It does **not** provide
OS-level containment. Protocol discovery alone cannot stop a hostile downstream
process from accessing the filesystem, network, or environment outside MCP.

## Command

Built executable name today:

```bash
mcp-native-guard inspect [inspect options] -- <server command> [args...]
```

Intended future CLI alias (not built as a separate binary in this milestone):

```bash
mcpg inspect [inspect options] -- <server command> [args...]
```

Example against the bundled fixture:

```bash
./build/dev-debug/mcp-native-guard inspect -- \
  ./build/dev-debug/test_servers/mng_test_mcp_server
```

## Outputs

- **Inventory** — compact deterministic JSON on stdout by default, or to
  `--output PATH` when provided. `--output` writes via a temporary file in the
  destination directory and atomically renames over the destination after a
  successful full write, so an existing inventory is preserved on failure.
- **Diagnostics** — status and failure lines from `mcp-native-guard` on stderr
  only. Diagnostics never mix into inventory stdout.
- **Child stderr** — the inspected child's stderr is redirected to `/dev/null`
  during inspect so unbounded server/npm diagnostics cannot block the session
  or contaminate inventory stdout. Guard diagnostics still use the parent
  stderr.

On success stderr includes:

```text
inspect result: success
shutdown: clean
```

or `shutdown: forced` when the child did not exit within the shutdown deadline
and the process group was terminated.

On failure stderr includes a `FAIL …` stage and `inspect result: failure`. No
inventory is written.

## Inventory shape

```json
{
  "inventory_version": 1,
  "server": {
    "downstream_executable": "npx"
  },
  "tools": [
    {
      "name": "read_file",
      "description": "...",
      "inputSchema": {},
      "annotations": {}
    }
  ]
}
```

Rules:

- Tools are sorted by exact UTF-8 bytewise `name`.
- Per-tool members are emitted in fixed order: `name`, then optional
  `description`, `inputSchema`, and `annotations` when present in the server
  response.
- `inputSchema` and `annotations` are recursively canonicalized before emit:
  object members are sorted by exact UTF-8 bytewise key, arrays keep element
  order, and insignificant whitespace is removed. Duplicate object member names
  inside those values are rejected.
- Number tokens are preserved as written; spellings such as `1`, `1.0`, and
  `1e0` are not normalized in this milestone.
- Missing fields are omitted; nothing is invented.
- Only the downstream executable basename is recorded. Absolute paths, full
  arguments, environment variables, secrets, and tool-call arguments are not
  included.
- Equivalent tool definitions produce byte-identical inventory output regardless
  of `tools/list` ordering, tool-object member ordering, or nested
  schema/annotation object member ordering and whitespace.

## Limits and defaults

| Option | Default | Meaning |
|--------|---------|---------|
| `--timeout SECONDS` | `5` (max `300`) | Overall discovery deadline |
| `--shutdown-timeout-ms N` | `2000` | Wait for clean child exit after stdin close |
| `--max-message-bytes N` | `1048576` | Maximum newline-delimited message size |
| `--max-nesting-depth N` | `64` | Maximum JSON nesting depth |
| `--max-tools N` | `256` | Maximum tools in one inventory |
| `--max-tool-name-bytes N` | `256` | Maximum tool name length |
| `--max-tool-description-bytes N` | `8192` | Maximum description string contents length |
| `--max-tool-schema-bytes N` | `65536` | Maximum retained `inputSchema` or `annotations` value bytes per tool |
| `--output PATH` | (stdout) | Optional inventory file destination |

Numeric options must be nonzero unsigned decimal integers. Duplicate occurrences
of the same option are rejected. Policy and audit options (`--policy`,
`--deny-tool`, `--audit-file`, `--audit-stderr`) are rejected: inspect is
discovery-only.

## Validation behavior

Fail closed (nonzero exit, process group terminated) on:

- malformed JSON or JSON-RPC envelopes;
- wrong JSON-RPC version;
- wrong response id (distinct from unsolicited non-response messages);
- unsolicited notifications or requests;
- missing or error initialize / tools/list results;
- missing, non-array, or invalid `tools`;
- missing, non-string, empty, escaped, duplicate-member, or oversized tool names;
- duplicate tool names across the array;
- duplicate object members inside retained `inputSchema` or `annotations`;
- oversized description or schema values;
- excessive tool count, nesting, or message size;
- timeout or early child exit.

### Escaped tool names

Escaped tool names in security-relevant JSON strings remain unsupported in this
version and are rejected, matching the existing policy and `tools/call`
extractor limitation. Write tool names as unescaped JSON strings.

## Process model

Inspect spawns exactly one local stdio child in its own process group. On
timeout or failure it signals the process group (`SIGTERM`, then `SIGKILL` after
the shutdown deadline). The `run` proxy path does not yet use process-group
termination; that remains a later containment milestone.

## What inspect does not do

- Does not invoke tools.
- Does not generate policy.
- Does not classify tools as read/write.
- Does not compute a cryptographic trust baseline.
- Does not claim the inspected server is safe or sandboxed.
