# mcp-native-guard Revised Roadmap

## Product Positioning

`mcp-native-guard` should remain a focused, native execution boundary for local `stdio` MCP servers rather than evolve into a general-purpose enterprise MCP gateway.

Primary product promise:

> Safely launch, constrain, observe, and verify local MCP server processes with deterministic enforcement and no LLM in the enforcement path.

The project should focus on:

- local `stdio` MCP servers;
- bounded resource usage;
- deterministic policy enforcement;
- process supervision and containment;
- trust continuity across server changes;
- small, dependency-light native deployment;
- local audit evidence.

It should not initially compete with full enterprise MCP gateways in areas such as centralized routing, multi-tenant policy, dashboards, SIEM integration, remote HTTP mediation, organizational RBAC, or compliance reporting.

---

## Phase 1 — Usable Local Wrapper

Goal:

> A new user can protect a local MCP server without manually writing JSON policy files or shell launchers.

### Deliverables

- Provide installable release binaries for Linux x86-64.
- Add a simple installation method.
- Add an `inspect` command that:
  - launches a server through the normal bounded execution path;
  - performs `initialize`;
  - requests `tools/list`;
  - records tool names, descriptions, schemas, and annotations;
  - does not invoke tools.
- Add default-deny policy support.
- Add policy generation from an inspection result.
- Add initial policy profiles:
  - filesystem read-only;
  - filesystem project-write;
  - Git read-only;
  - database read-only.
- Add launcher generation for:
  - Cursor;
  - VS Code.
- Add a client configuration audit that:
  - finds direct local MCP entries;
  - identifies entries that bypass the guard;
  - offers a migration command;
  - remains advisory.
- Add automated public CI:
  - GCC build and tests;
  - Clang build and tests;
  - ASan/UBSan;
  - Release build;
  - smoke tests.
- Publish a compatibility matrix for tested MCP servers.

### Suggested CLI

```bash
mng inspect -- npx -y @modelcontextprotocol/server-filesystem /path
mng policy create --profile filesystem-readonly --from inspection.json
mng configure cursor filesystem
mng configure vscode filesystem
mng client audit cursor
mng client audit vscode
```

### Success Criteria

- A user can inspect and protect a filesystem MCP server without manually editing policy JSON.
- Cursor and VS Code can launch the guarded server using generated configuration.
- Direct duplicate unguarded entries are detected and clearly reported.
- Allowed reads and denied writes are verified using a real MCP client and the existing smoke test.

---

## Phase 2 — Trust Continuity

Goal:

> Detect when an MCP server that was previously reviewed and approved becomes materially different.

### Deliverables

- Canonicalize tool definitions:
  - name;
  - description;
  - input schema;
  - annotations;
  - relevant protocol metadata.
- Generate a deterministic baseline fingerprint.
- Store the approved baseline locally.
- Detect:
  - added tools;
  - removed tools;
  - renamed tools;
  - description changes;
  - schema changes;
  - annotation changes.
- Capture downstream identity:
  - executable path or identity;
  - executable hash where practical;
  - package name and pinned version where available;
  - launch command fingerprint.
- Add an explicit approval workflow.
- Produce a human-readable drift report.
- Fail closed or require approval for material drift, depending on policy.
- Add regression tests for:
  - harmless ordering differences;
  - JSON formatting differences;
  - meaningful schema changes;
  - newly introduced write-capable tools;
  - executable replacement.

### Suggested CLI

```bash
mng baseline create filesystem
mng baseline verify filesystem
mng baseline diff filesystem
mng baseline approve filesystem
```

### Success Criteria

- Reordering and formatting changes do not trigger false drift.
- New or changed capabilities are reported clearly.
- A changed server cannot silently inherit an old approval.
- Audit records identify the baseline and effective policy used during the session.

---

## Phase 3 — Local Process Containment

Goal:

> Prevent a protected MCP server from bypassing protocol policy by directly abusing operating-system access.

Protocol filtering alone cannot stop malicious server code from directly reading files, opening network connections, reading environment secrets, or spawning subprocesses.

### Deliverables

Design a platform-neutral containment interface, then implement the Linux backend first.

Linux controls should include:

- restricted filesystem access;
- explicit read-only and writable paths;
- network deny or allowlist policy;
- environment-variable filtering;
- removal of common secret-bearing variables;
- controlled working directory;
- process-group ownership;
- reliable process-tree termination;
- CPU limits;
- memory limits;
- open-file limits;
- execution timeout;
- child-process restrictions where practical.

Candidate Linux mechanisms should be evaluated carefully:

- Landlock;
- namespaces;
- `seccomp`;
- resource limits;
- controlled environment construction.

Do not claim complete isolation until adversarial tests demonstrate the intended guarantees.

### Suggested CLI

```bash
mng run   --sandbox   --fs-read /home/alex/project   --fs-write-none   --network deny   --env-clean   -- npx -y some-mcp-server
```

### Adversarial Test Server

Create a deliberately hostile local MCP server that attempts to:

- read files outside the approved root;
- write outside the approved root;
- read environment secrets;
- open outbound network connections;
- spawn children;
- ignore termination;
- exhaust memory;
- exhaust output buffers;
- emit malformed MCP traffic.

### Success Criteria

- The hostile test server cannot access resources outside its declared scope.
- The guard reliably terminates the entire process tree.
- Resource exhaustion remains bounded.
- Protocol stdout remains uncontaminated.
- Containment failures are visible in audit evidence.

---

## Phase 4 — Native Windows Backend

Goal:

> Remove WSL as a deployment requirement for Windows users after the Linux product workflow is validated.

### Deliverables

- Native Windows process creation.
- Secure pipe inheritance.
- Job Object containment.
- Process-tree termination.
- Windows path handling.
- Environment filtering.
- Resource controls.
- Windows-native launcher generation.
- Cursor and VS Code integration.
- Equivalent Windows compatibility and adversarial tests.

### Success Criteria

- The same policy and audit model works across Linux and Windows.
- Windows users can install and run one native binary.
- Native Windows behavior is functionally comparable to the Linux backend.
- WSL remains an optional compatibility route, not a requirement.

---

## Supporting Feature — Client Configuration Audit

This feature should remain small and advisory rather than becoming a full enterprise control plane.

### Responsibilities

- Locate supported Cursor and VS Code MCP configuration files.
- Enumerate registered local MCP servers.
- Classify entries as:
  - guarded;
  - direct and unguarded;
  - malformed;
  - duplicate;
  - missing launcher;
  - missing policy;
  - changed since approval.
- Warn when a direct server bypasses `mcp-native-guard`.
- Generate a safe migration plan.
- Back up configuration before any requested rewrite.
- Provide dry-run output.

### Non-Goals

- Universal prevention of arbitrary local process execution.
- Organization-wide centralized policy.
- Silent rewriting of user configuration.
- Claiming that unguarded servers are blocked when the endpoint remains unrestricted.

---

## Explicit Non-Goals for the Near Term

Do not build these until the local product is mature:

- centralized cloud control plane;
- remote HTTP MCP gateway;
- multi-tenant management;
- enterprise RBAC;
- SIEM integration;
- compliance dashboards;
- Kubernetes deployment;
- threat-intelligence feeds;
- LLM-based runtime classification;
- broad policy-language complexity;
- universal monitoring of all agent tools;
- control over Cursor or VS Code built-in editor and terminal capabilities.

---

## Security Boundaries

The project should communicate these boundaries clearly:

1. The protocol proxy controls only MCP traffic routed through it.
2. Directly configured MCP servers bypass protocol enforcement.
3. Client configuration auditing can detect bypasses but cannot universally prevent them.
4. The AI client's built-in terminal, editor, and file tools are outside the guard's scope.
5. Protocol policy alone does not contain malicious server implementation code.
6. OS-level containment is required before claiming resistance to a hostile downstream process.
7. Local audit evidence supports investigation and health checking but does not prove complete endpoint safety.

---

## Recommended Next Milestone

Implement the first part of Phase 1:

> A bounded `inspect` command that safely launches one MCP server, performs initialization and `tools/list`, and writes a deterministic tool inventory without invoking any tool.

Follow it with:

1. default-deny policy generation;
2. a tested filesystem read-only profile;
3. Cursor launcher/configuration generation;
4. CI and packaged Linux release.

This sequence converts the current engineering prototype into a usable local security tool without expanding into the full enterprise MCP gateway market.
