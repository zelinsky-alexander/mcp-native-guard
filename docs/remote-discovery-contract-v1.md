# Declared remote discovery contract v1

This profile extends the Observatory runtime schedule to registry-declared remote MCP endpoints without changing Native Guard's current local `stdio` execution boundary.

## Scope

The contract is represented by `profiles/observatory-remote-discovery-v1.json`.

The probe is discovery-only:

1. connect to the exact HTTP(S) URL already declared by the Registry record;
2. send `initialize`;
3. send `notifications/initialized`;
4. send `tools/list`;
5. canonicalize complete tool definitions;
6. persist the observation and compare it with an earlier compatible remote observation.

It never invokes a tool.

## Network boundary

The first implementation lives in `mcp-observatory/tools/remote_runtime_discovery.py` because Native Guard does not yet provide a native TLS/Streamable-HTTP transport. The remote runner:

- accepts only the Registry's exact declared URL;
- supports HTTP(S) only;
- does not guess alternate MCP paths;
- does not follow redirects;
- rejects embedded URL credentials;
- rejects destinations resolving to non-public IP addresses;
- performs no address-space or port scanning;
- uses normal TLS certificate verification for HTTPS;
- sends no credentials;
- keeps responses bounded.

Native Guard remains the deterministic local `stdio` MCP sensor. A future native HTTP transport can replace the Observatory transport runner while retaining the same profile identity and persisted observation semantics.

## Observation semantics

Remote observations are facts, not safety verdicts. Terminal outcomes are recorded as:

- `completed`: the endpoint initialized and returned a valid canonical tool inventory;
- `blocked`: authentication is required and no credential was supplied;
- `inconclusive`: the endpoint could not be meaningfully reached within the bounded probe;
- `failed`: a reached endpoint returned protocol-invalid data;
- `unsupported`: the declared transport is outside this profile;
- `unresolvable`: the Registry record lacks a usable exact HTTP(S) URL.

The Observatory owns scheduling, persistence, longitudinal comparison and portal publication.
