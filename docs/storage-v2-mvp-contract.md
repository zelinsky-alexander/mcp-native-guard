# Storage v2 MVP Native Guard contract

The Storage v2 side-by-side MVP intentionally reuses the existing discovery-only `inspect` path. No broader tool invocation is introduced by this branch.

For the production-side test, Observatory remains responsible for exact artifact selection, launch preparation, sandbox lifecycle, observation persistence, compatibility identity and longitudinal comparison. Native Guard remains the MCP-aware sensor inside that bounded runtime.

The compatible runtime observation identity must bind at minimum:

```text
artifact_sha256
launch_profile_sha256
guard build/version identity
sandbox image identity
probe profile identity
```

The current MVP test is limited to exact npm packages using `stdio`, with network disabled during installation/runtime discovery, read-only runtime mounts, bounded process/memory/CPU/output limits, and no `tools/call` execution.

A successful observation supports only the claim that the exact artifact initialized under the recorded profile and exposed the recorded MCP interface. It is not a claim that the server is safe.

This branch exists so all three repositories can be cloned and built from the same `storage-v2-foundation` ref during side-by-side production testing. Runtime observation schema v2, tamper-evident audit chaining, controlled behavioral profiles and stronger worker isolation remain later milestones.
