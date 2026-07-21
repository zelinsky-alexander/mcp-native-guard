# Initial threat model

## Protected assets

- Integrity of the tools shown to the MCP client.
- Authorization decisions for tool invocation.
- Confidentiality of tool arguments and results.
- Availability of the proxy process and downstream server.
- Integrity of future audit evidence.

## Initial attacker capabilities

The first MVP assumes a downstream MCP server can send malformed, oversized, inconsistent, or
unexpected protocol messages. It also assumes the client can invoke unknown or denied tools.

The current scaffold mitigates only one narrow class: unbounded newline-delimited message growth.
It also provides the policy data structure that later validated protocol fields will use.

## Out of scope for the scaffold

- Complete JSON-RPC or MCP validation.
- Tool-definition canonicalization and cryptographic fingerprints.
- Child-process sandboxing and network egress control.
- Authentication, OAuth, or remote HTTP transport.
- Secret detection and semantic prompt-injection analysis.
- Tamper-evident audit chains.

These are planned work, not current security claims.
