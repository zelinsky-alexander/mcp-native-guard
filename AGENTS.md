# Engineering instructions

## Product direction

This repository implements a native MCP security boundary. The hot path must remain bounded,
measurable, and independent of cloud services or an LLM.

## C++ rules

- Use C++20 until a newer language level provides a measured benefit on supported compilers.
- Prefer value types, RAII, `std::span`, `std::string_view`, and explicit ownership.
- Avoid allocation in message-routing and policy-lookup paths where practical.
- Keep transport, protocol parsing, policy evaluation, and platform isolation separate.
- Do not add clever template metaprogramming without a benchmark and a readability argument.
- Every attacker-controlled buffer must have an explicit upper bound.
- Security decisions must not depend on heuristic substring matching.

## Dependency rules

- Do not add a dependency until its licence, maintenance status, security history, binary-size cost,
  and benchmark impact are documented in an ADR.
- GPL, AGPL, SSPL, source-available, and similarly restrictive dependencies require explicit owner
  approval.
- Keep `THIRD_PARTY_NOTICES.md` current.

## Validation

Run focused local checks only unless explicitly asked to run broader CI:

```bash
cmake --preset dev-debug
cmake --build --preset dev-debug
ctest --preset dev-debug
```

For parser or framing changes, also run the sanitizer preset. Performance claims require the
`perf` preset and recorded hardware/compiler details.

## Originality

Implement from requirements, standards, and documented public APIs. Do not copy repository or
tutorial code. Code intended for release must receive manual licence and similarity review.
