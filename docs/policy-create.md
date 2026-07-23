# policy create — deterministic default-deny policy generation

`policy create` reads exactly one version-1 inspect inventory document and
generates a deterministic version-1 policy document. It never launches a
server, never performs inspection itself, and never classifies tool safety.
It only encodes the caller's explicit allow list into policy rules.

Policy generation does **not** prove that any tool is safe. It does **not**
classify tools as read-only or dangerous based on their names, descriptions,
input schemas, or annotations. Only tools named explicitly with `--allow-tool`
become allowed; every other tool — including every tool if `--allow-tool` is
never used — is denied by default. Inspecting a server's inventory does not
prove the server is safe, and a generated policy still provides no OS-level
containment on its own; it only bounds MCP protocol traffic routed through
`mcp-native-guard run`.

## Command

Built executable name today:

```bash
mcp-native-guard policy create --from INVENTORY [--allow-tool NAME ...] [--output PATH]
```

Intended future CLI alias (not built as a separate binary in this milestone):

```bash
mcpg policy create --from INVENTORY [--allow-tool NAME ...] [--output PATH]
```

Example against a bundled fixture inventory:

```bash
./build/dev-debug/mcp-native-guard inspect -- \
  ./build/dev-debug/test_servers/mng_test_mcp_server > /tmp/inventory.json

./build/dev-debug/mcp-native-guard policy create \
  --from /tmp/inventory.json \
  --allow-tool allowed.tool \
  --output /tmp/policy.json
```

## Options

| Option | Required | Meaning |
|--------|----------|---------|
| `--from INVENTORY` | yes, exactly once | Path to a version-1 inspect inventory document. |
| `--allow-tool NAME` | no, repeatable | One explicit allow rule per occurrence. Each `NAME` must exist in the inventory and must not repeat. |
| `--output PATH` | no, at most once | Optional policy file destination. Written atomically. Defaults to stdout. |

Unknown options, a missing `--from`, a repeated `--from`/`--output`, or a
missing option value are rejected before the inventory is even read.

## Outputs

- **Policy** — compact deterministic version-1 policy JSON on stdout by
  default, or to `--output PATH` when provided. `--output` writes via a
  temporary file in the destination directory and atomically renames it over
  the destination after a successful full write, so an existing policy file
  is preserved on any failure and no temporary file is left behind.
- **Diagnostics** — status and failure lines from `mcp-native-guard` on
  stderr only. Diagnostics never mix into policy JSON on stdout.

On success stderr includes:

```text
policy create result: success
```

On failure, stderr names the specific validation problem (for example
`policy create: unknown_allow_tool (name)`), no policy JSON is written, and
the process exits with a nonzero status.

## Semantics

- Only inventory format version 1 is supported; the generated policy is
  always format version 1.
- Generated defaults are always `"visibility":"deny"` and
  `"invocation":"deny"`.
- Each `--allow-tool NAME` produces exactly one explicit rule with
  `"visibility":"allow"` and `"invocation":"allow"`.
- A name is only accepted if it exists in the supplied inventory; an unknown
  `--allow-tool` name fails closed with no output.
- Duplicate `--allow-tool` values fail closed with no output.
- No `--allow-tool` arguments produce a valid deny-all policy
  (`"tools":[]`).
- `policy create` never merges with, or implicitly modifies, an existing
  policy file — `--output` always replaces the destination wholesale, only
  on success.

## Determinism

- Tool rules are sorted by exact UTF-8 bytewise `name`.
- `--allow-tool` argument order never affects output bytes.
- Inventory tool order never affects output bytes, because only the
  explicitly allowed subset of tools is ever emitted.
- Output uses fixed member order and compact JSON; there are no comments,
  timestamps, hashes, or classifications.
- Descriptions, input schemas, annotations, executable paths, command
  arguments, and environment variables are never read into, or emitted by,
  the generated policy.

## Validation behavior

Fail closed (nonzero exit, no policy JSON on stdout, an existing `--output`
destination preserved) on:

- malformed JSON, or an inventory larger than the bounded input-size limit;
- excessive nesting depth;
- a missing or unsupported `inventory_version` (only `1` is supported), or a
  duplicate `inventory_version`/`server`/`tools` member;
- a missing or non-object `server` value;
- missing, non-array, or oversized `tools`;
- a missing, non-string, empty, escaped, duplicate-member, or oversized tool
  name, or duplicate tool names across the inventory;
- an `--allow-tool` name absent from the inventory, or repeated on the
  command line.

Fields not needed for policy generation (`description`, `inputSchema`,
`annotations`, and any other inventory member) are safely skipped rather
than rejected, and are never retained past validation.

### Escaped tool names

Escaped tool names remain unsupported in this version, matching the existing
`inspect` and policy-loader limitation. Write tool names as unescaped JSON
strings.

## Platform

`policy create` is available wherever `mcp-native-guard run`, `doctor`, and
`inspect` are available (currently Linux). `--output` uses the same
POSIX atomic-replace mechanism as `inspect --output`.

## What policy create does not do

- Does not launch a server or perform inspection.
- Does not classify tools as read-only or dangerous.
- Does not merge with, or implicitly modify, an existing policy file.
- Does not prove that an allowed tool is safe to invoke.
- Does not provide OS-level containment.
