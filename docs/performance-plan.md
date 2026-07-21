# Performance plan

Performance is a design constraint, not a marketing adjective. Measurements must include compiler,
flags, CPU, operating system, input distribution, and whether logging is enabled.

## Initial measurement

```bash
cmake --preset perf
cmake --build --preset perf
./build/perf/benchmarks/mng_framer_benchmark
```

The optional benchmark measures bounded line framing only; it is not an end-to-end MCP claim.

## MVP budgets

- No unbounded allocation from stdin.
- No allocation for steady-state policy lookup.
- At most one full JSON decode for an unchanged forwarded request.
- No global lock in the single-session data path.
- Bounded outstanding request map.
- Audit I/O kept off the request thread or explicitly measured when synchronous.

## Benchmark families to add

1. Framing: sizes, split locations, CRLF, and malformed streams.
2. Parsing: valid and adversarial JSON-RPC messages.
3. Policy: tool-table sizes and allow/deny distributions.
4. Rewriting: filtered `tools/list` responses.
5. End-to-end: client-proxy-server round trips over local pipes.
6. Resource pressure: memory ceiling, cancellation, and slow downstream readers.

End-to-end reports must include P50/P95/P99 latency, peak resident memory, CPU time, and malformed-input
failure behaviour.
