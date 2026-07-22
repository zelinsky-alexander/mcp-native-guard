# 0.1 release checklist

Manual checklist for preparing a 0.1.x release:

- [ ] Confirm project and CLI versions are consistently `0.1.0`.
- [ ] Clean Debug configure: `cmake --preset dev-debug`.
- [ ] Clean Debug build: `cmake --build --preset dev-debug`.
- [ ] Debug tests: `ctest --preset dev-debug`.
- [ ] ASan/UBSan configure: `cmake --preset asan`.
- [ ] ASan/UBSan build: `cmake --build --preset asan`.
- [ ] ASan/UBSan tests: `ctest --preset asan`.
- [ ] Clean Release build: `cmake --preset release && cmake --build --preset release`.
- [ ] Record benchmark hardware/compiler/details: `cmake --preset perf && cmake --build --preset perf && ./build/perf/benchmarks/mng_framer_benchmark`.
- [ ] Real MCP smoke test: `scripts/smoke_real_mcp.sh -- npx -y @modelcontextprotocol/server-filesystem@2026.7.10 {sandbox}`.
- [ ] Documentation review for Linux-only support, JSONL framing, temporary error codes, escaped tool-name limits, audit privacy, runtime defaults, and unsupported HTTP/OAuth/TLS/Windows isolation.
- [ ] License and `THIRD_PARTY_NOTICES.md` review.
- [ ] Create the signed git tag manually.
- [ ] Create the GitHub release manually.
