# Architecture

## Objective

`mcp-native-guard` is intended to become a native security boundary between an MCP client and a
locally launched or remote MCP server. The first supported data path will be newline-delimited
`stdio` traffic.

## Module boundaries

```text
client stdio
    -> bounded line framer
    -> typed JSON-RPC envelope classifier
    -> bounded tools/call parameter extractor
    -> immutable policy snapshot
    -> tool-definition baseline verifier     [next milestone]
    -> Linux downstream process transport
    -> response inspection and audit          [next milestone]
    -> client stdio
```

The current Linux path frames client JSONL, classifies JSON-RPC envelopes, extracts `tools/call`
parameters without a DOM, and applies an immutable in-memory deny policy before forwarding. Server
stdout is relayed transparently. Other MCP methods are not yet policy-filtered.

## Invariants

1. Input size is checked before an attacker-controlled message can grow without limit.
2. A message view never outlives the framing callback that receives it.
3. Policy lookup performs no dynamic allocation.
4. Policy tables are immutable once published to worker threads.
5. Protocol parsing will be authoritative; security decisions will not use substring matching.
6. Logging and metrics must use stderr or a separate sink and must never corrupt MCP stdout.
7. Every future concurrency boundary must define ownership and cancellation behaviour.
8. A denied `tools/call` request is answered locally with temporary project code `-32001`; a denied
   notification is dropped without a response.

## Hot-path model

```text
read chunk -> locate newline -> decode once -> evaluate sorted policy -> forward bytes
```

Copies are acceptable when a message spans input chunks or must be rewritten. Contiguous complete
messages should remain views into the read buffer through validation and decision making.

## Planned platform layer

- Windows: `CreateProcess`, restricted handle inheritance, Job Objects, and overlapped pipes.
- Linux: `posix_spawn` behind a narrow RAII wrapper, then namespaces/seccomp in a later milestone.

The platform layer will not leak OS handles into protocol or policy modules.
