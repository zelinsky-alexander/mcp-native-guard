# Runtime observation contract v1

This document defines the machine-readable boundary consumed by `mcp-observatory`
when `mcp-native-guard inspect` is used inside a separately managed operating-system
sandbox.

## Scope

Version 1 is discovery-only. The guard sends `initialize`,
`notifications/initialized`, and `tools/list`; it never sends `tools/call` and does
not classify a server as safe or malicious.

The outer worker, not `mcp-native-guard`, owns package installation, container or
microVM isolation, network policy, filesystem policy, resource limits, and evidence
persistence.

## Inventory

A successful invocation emits the existing deterministic inventory:

```json
{
  "inventory_version": 1,
  "server": {"downstream_executable": "node"},
  "tools": []
}
```

Consumers MUST validate the inventory against
`schemas/tool-inventory-v1.schema.json`. Unknown top-level members are rejected in
version 1 so that a producer change cannot silently alter the evidence contract.

The canonical inventory bytes are the exact UTF-8 bytes emitted by `inspect`, with
a single trailing newline removed before hashing. The inventory digest is:

```text
sha256(canonical inventory bytes)
```

Tool definitions are already deterministic: tools are sorted by name, members use
a fixed order, and `inputSchema` and `annotations` are recursively canonicalized.
Descriptions remain significant.

## Observatory envelope

The outer sandbox worker wraps the validated inventory in an observation envelope:

```json
{
  "observation_version": 1,
  "status": "completed",
  "artifact_sha256": "<64 lowercase hex>",
  "launch_profile_sha256": "<64 lowercase hex>",
  "sandbox_image": "<immutable image reference>",
  "guard_version": "<version>",
  "inventory_sha256": "<64 lowercase hex>",
  "inventory": {}
}
```

This envelope is intentionally produced and signed or persisted by Observatory,
not by the inspected process. The inspected process never receives a database,
evidence directory, cloud credential, Docker socket, or writable host path.

## Failure semantics

No inventory is accepted when `inspect` exits non-zero, times out, is terminated,
produces malformed JSON, exceeds an output limit, or fails schema validation. The
outer worker records a bounded failure stage and destroys the sandbox.

## Comparison semantics

Two observations compare canonical tool definitions by exact tool name:

- `added`: name appears only in the newer inventory;
- `removed`: name appears only in the older inventory;
- `modified`: name appears in both but the complete canonical tool object differs;
- `unchanged`: complete canonical tool objects are byte-equivalent.

A difference is evidence of interface drift, not automatically a security finding.

## Security statement

A successful discovery observation proves only that one exact artifact, launch
profile, guard version, and sandbox image completed the bounded discovery protocol.
It does not prove absence of malicious behavior and does not exercise tool effects.
