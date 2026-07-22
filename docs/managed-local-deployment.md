# Managed local deployment and session health

The guard remains one process per MCP stdio session. The MCP client launches the guard, the guard
launches exactly one downstream server, and both exit with the session. This preserves stdio process
ownership and signal behavior; a persistent daemon would add an unrelated transport, shared state,
and a larger security boundary.

## Session identity and audit semantics

`--server-label LABEL` adds an optional operator-selected identity. Labels are 1–128 bytes, may not
contain ASCII control characters, are JSON-escaped, and never influence policy. An omitted label is
recorded as `unlabeled`. Only the downstream executable basename is recorded; its path, arguments,
environment, policy contents, and protocol/tool arguments are excluded.

After CLI validation, effective-policy construction, and audit opening, `session_start` is emitted
immediately after the downstream `posix_spawnp` succeeds. Launch failure emits no session event.
Every post-launch exit attempts one `session_end`. Both contain `ts`, `event`, `guard_version`,
`server_label`, `downstream_executable`, and `policy_hash`. Start also contains configured
`runtime_limits`; end contains `child_exit_status`, `proxy_exit_status`, `termination_reason`,
monotonic `duration_ms`, and `clean_shutdown`.

The `fnv1a64:` policy value fingerprints the sorted effective rules and defaults after command-line
overrides. It is deterministic and insensitive to input rule ordering/JSON formatting. FNV-1a is
non-cryptographic: the value is useful for configuration correlation, not tamper proofing or
collision resistance.

## Launcher and doctor

Copy a template from `examples/launchers/`, replace every marked placeholder with an absolute local
path, make the copy executable, and point the MCP client at it. Remove any parallel unguarded server
entry first. The templates use `exec` to preserve process/signal semantics.

Preflight a configured server without calling any tool:

```bash
/opt/mcp-native-guard/bin/mcp-native-guard doctor \
  --server-label filesystem-readonly \
  --policy /home/USER/.config/mcp-native-guard/filesystem-readonly.json \
  --audit-file /home/USER/.local/state/mcp-native-guard/filesystem.jsonl \
  --doctor-timeout 10 -- \
  /usr/bin/npx -y @modelcontextprotocol/server-filesystem@2026.7.10 \
  /home/USER/mcp-safe-workspace
```

Doctor uses the normal `run` enforcement path, sends only initialize,
`notifications/initialized`, and `tools/list`, enforces a 1 MiB response bound and strict timeout,
and terminates the child on failure. It returns zero only after clean shutdown. It complements—not
replaces—the real smoke test, which exercises permitted and denied calls.

## Scheduled real smoke test (systemd user timer)

Edit the absolute paths in `examples/systemd/mcp-native-guard-smoke.service`, then:

```bash
mkdir -p ~/.config/systemd/user
cp examples/systemd/mcp-native-guard-smoke.{service,timer} ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now mcp-native-guard-smoke.timer
systemctl --user status mcp-native-guard-smoke.timer
journalctl --user -u mcp-native-guard-smoke.service
```

Disable and remove it with:

```bash
systemctl --user disable --now mcp-native-guard-smoke.timer
rm ~/.config/systemd/user/mcp-native-guard-smoke.{service,timer}
systemctl --user daemon-reload
```

Nothing in the repository installs or enables these units automatically; no root access is needed.

## Audit health summary

```bash
python3 scripts/audit_health_summary.py ~/.local/state/mcp-native-guard/*.jsonl
python3 scripts/audit_health_summary.py --json ~/.local/state/mcp-native-guard/*.jsonl
```

The standard-library-only script streams files and returns nonzero for missing files, invalid JSON
(including a truncated invalid final line), an unclean session, or an unmatched start. Unknown future
events are ignored. There is intentionally no override that masks unhealthy evidence. A runtime
audit sink failure is currently reported once on diagnostic stderr. The summary increments
`audit_write_failures` only when an `audit_write_failure` event is actually present in an input
file; the active sink cannot reliably record its own failure after its destination has become
unusable.

Audit and doctor results are operational health evidence only. They do not prove complete endpoint
safety, downstream correctness, policy completeness, absence of compromise, or OS-level isolation.
