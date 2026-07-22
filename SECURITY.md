# Security Policy

## Status

`mcp-native-guard` is an early functional Linux prototype. It is not production
hardened and should not be the only security boundary for untrusted MCP traffic.

Current unsupported areas include HTTP transports, OAuth, TLS termination,
Windows process isolation, policy hot reload, and process sandboxing. The stdio
proxy currently assumes one complete JSON-RPC message per newline.

## Reporting vulnerabilities

Please report suspected vulnerabilities privately to the project maintainers
before public disclosure. Include:

- affected version or commit;
- operating system and compiler;
- reproduction steps;
- expected and observed behavior;
- logs or audit snippets with secrets removed.

Maintainers should acknowledge receipt, triage severity, coordinate fixes, and
publish an advisory or release note when a fix is available.

## Privacy note

Audit records are designed to omit full JSON-RPC messages and tool argument
payloads. They may still contain tool names, request IDs, timestamps, and message
sizes, so treat audit files as operational security logs.
