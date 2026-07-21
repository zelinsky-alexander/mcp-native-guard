# mcp-native-guard — Design Document

## 1. What the project is

`mcp-native-guard` is a native C++20 security boundary that sits between an MCP (Model Context
Protocol) client and one or more locally-launched MCP server processes. Its goal is a small,
measurable enforcement process that operates entirely on the local machine without an LLM or a
cloud service in the enforcement path.

The current codebase is an architectural scaffold (~2,200 LOC). The production pipeline is not yet
end-to-end, but every hot-path building block is implemented, tested, and benchmarked.

---

## 2. Module structure

The codebase is layered horizontally. Each layer has a single concern and explicit public-API
boundaries enforced through the `include/mcp_native_guard/` header tree.

```
┌─────────────────────────────────────────────────┐
│  CLI (src/main.cpp)                              │
│  relay harness · run subcommand                  │
├─────────────────────────────────────────────────┤
│  Proxy core  (proxy/)                            │
│  Size check · PolicyTable lookup · Counters      │
├──────────────────────┬──────────────────────────┤
│  Protocol (protocol/)│  Security (security/)     │
│  JSON-RPC envelope   │  ToolRule · PolicyTable   │
│  classifier          │  sorted vector + binary   │
│                      │  search                   │
├──────────────────────┴──────────────────────────┤
│  I/O (io/)                                       │
│  LineFramer — bounded NDJSON framing             │
├─────────────────────────────────────────────────┤
│  Process (process/)   [Linux-only]               │
│  run_stdio_child — posix_spawn + poll relay      │
├─────────────────────────────────────────────────┤
│  Core (core/)                                    │
│  Status · StatusCode                             │
└─────────────────────────────────────────────────┘
```

The planned full pipeline (from `docs/architecture.md`) is:

```
client stdio
  → bounded line framer          [done]
  → strict JSON-RPC/MCP decoder  [milestone 2]
  → immutable policy snapshot    [done]
  → tool-definition verifier     [milestone 5]
  → downstream process transport [done, transparent relay]
  → response inspection + audit  [milestone 6]
  → client stdio
```

---

## 3. Component deep-dives

### 3.1 `core/status.hpp` — Error result type

A lightweight, non-throwing error value.

```cpp
enum class StatusCode : std::uint8_t { ok, invalid_argument, message_too_large, ... };

struct Status final {
    StatusCode code{StatusCode::ok};
    std::string_view message{};
    [[nodiscard]] constexpr bool is_ok() const noexcept;
    [[nodiscard]] constexpr explicit operator bool() const noexcept;
    [[nodiscard]] static constexpr Status success() noexcept;
};
```

Key properties: value type, 26 bytes, zero allocation, `constexpr`. The `string_view message` is
always a string literal (static storage), so it never dangles. The `explicit operator bool` means
callers must opt in to the boolean conversion — accidental discards are surfaced by `[[nodiscard]]`.

---

### 3.2 `io/line_framer.hpp` + `line_framer.cpp` — Bounded NDJSON framing

`LineFramer` segments an arbitrary byte stream into newline-delimited messages. It provides the
first and most critical security invariant: **no message can grow without bound**.

Architecture:

- **`feed(span<const char>, Sink&&)`** — template sink (callback) pattern. No virtual dispatch.
  When the incoming chunk already contains a complete message and the internal buffer is empty, the
  message is passed as a `string_view` directly into the read buffer — **zero copy**.
- **`std::memchr`** locates newlines in O(n) on the current chunk, delegating to the platform's
  optimised `memchr` (often SIMD-accelerated).
- **`std::pmr::vector<char>`** backs the accumulation buffer when a message spans chunk boundaries.
  PMR lets callers provide a monotonic or pool allocator for latency-sensitive contexts without
  changing the API.
- **Sticky failure state** — once a framing error is recorded, all subsequent `feed` calls return
  the same error immediately. This prevents partial-message handling after the boundary is violated.
- CRLF trimming (`\r` before `\n`) is configurable via `Config::trim_carriage_return`.

The `Sink` template avoids the overhead of `std::function` while keeping the call site ergonomic
(lambdas, function pointers, and callable objects all work).

---

### 3.3 `protocol/json_rpc_envelope.hpp` + `.cpp` — Envelope classifier

A hand-rolled, stack-only JSON-RPC 2.0 scanner that classifies the **top-level** envelope without
building a parse tree.

Design decisions:

- **`classify(string_view) const noexcept`** — the entire method is marked `noexcept`. No
  exceptions, no allocation, no output parameters beyond the returned `Envelope`.
- **Structural skipping** (`skip_value`) handles nested objects and arrays recursively up to a
  configurable `max_nesting_depth`. This prevents infinite recursion on adversarial input and bounds
  stack depth.
- **Escape rejection** — top-level member names and the `method` value must not contain `\` escape
  sequences. Returned `string_view` slices are canonical raw bytes of the input, making downstream
  string comparison safe and unambiguous (`"method":"tools\/call"` is rejected).
- **Duplicate member detection** — boolean flags (`saw_jsonrpc`, `saw_method`, `saw_id`, etc.)
  detect duplicated keys without a hash table, making the check collision-resistant by construction.
- **Size bound** checked before any other work; malformed inputs are always rejected before the
  inner scanner sees them.

The classifier recognises three envelope kinds:

- **Request**: has `jsonrpc`, `method`, and `id`.
- **Notification**: has `jsonrpc` and `method`, no `id`.
- **Response**: has `jsonrpc`, `id`, and exactly one of `result`/`error`.

---

### 3.4 `security/policy.hpp` + `policy.cpp` — Tool policy table

`PolicyTable` is **immutable after `build()`**. Rules are stored in a `std::vector<ToolRule>`
sorted by tool name.

Design decisions:

- **`std::lower_bound`** replaces a hash map. Binary search is O(log n) and has no worst-case
  collision behaviour that an attacker could exploit by crafting tool names (hash flooding). For the
  expected table sizes (tens to low hundreds of tools), binary search is also cache-friendly and
  avoids per-lookup allocation.
- **Fail-closed defaults** — `PolicyDefaults` initialises both `visible` and `callable` to
  `Access::deny`. An unknown tool name falls back to the default, never to `allow`.
- **`build()` as a factory** — the constructor is `default`. The named factory validates rules
  (empty names, duplicates), sorts them, and moves the result into the output parameter only on
  success. This ensures a `PolicyTable` is always either default-empty or fully valid; partial
  initialisation is not observable.
- **`string_view`-based lookup** — `find(string_view)` compares against `rule.name` without
  copying either string.

---

### 3.5 `proxy/proxy_core.hpp` + `proxy_core.cpp` — Decision core

`ProxyCore` is the hot-path junction: it takes already-validated fields and produces a
deterministic `Decision`.

```
authorize_tool_call(tool_name, encoded_message_bytes) noexcept
  → size check → empty name check → policy lookup → Decision{Action, Reason}
```

Design decisions:

- **Protocol parsing is external.** `ProxyCore` never sees raw JSON. The caller extracts
  `tool_name` and message size via the envelope classifier and passes them as validated scalars.
  This keeps the decision core small, testable in isolation, and free of parser state.
- **`std::atomic<uint64_t>` counters with `memory_order_relaxed`** — counters are observational
  metrics, not synchronisation. `relaxed` ordering avoids memory barrier overhead on the hot path.
  Reads in `counters()` also use `relaxed`; the snapshot may be slightly stale but is always
  consistent per counter.
- **`[[nodiscard]]`** on both `authorize_*` methods — discarding a `Decision` is almost certainly a
  bug, and the compiler enforces this.

---

### 3.6 `process/linux_stdio_relay.hpp` + `linux_stdio_relay.cpp` — Transparent stdio relay

`run_stdio_child` launches one downstream MCP server and bidirectionally relays bytes between the
proxy's stdin/stdout and the child's stdin/stdout. It does **not** inspect or rewrite the byte
stream — that is the next pipeline layer's job.

Architecture:

- **`posix_spawnp`** with explicit file-action tables and attribute sets. The child inherits only
  `stdin`/`stdout`. All other file descriptors have `FD_CLOEXEC`. Signal dispositions for `SIGINT`,
  `SIGTERM`, and `SIGPIPE` are reset to default in the child via `POSIX_SPAWN_SETSIGDEF`.
- **Non-blocking pipes + `poll`** with a 50 ms timeout. The event loop serves up to 4 descriptors:
  stdin read, child-stdout read, child-stdin write, stdout write.
- **Two fixed-capacity relay buffers** (`std::vector<char>` with `reserve`). Capacity is set once
  at startup; no further allocation occurs in steady state.
- **Pipe capacity tuning** — `F_SETPIPE_SZ` requests a larger kernel pipe buffer (default 64 KiB),
  reducing the number of `poll` wakeups needed to fill a message.
- **Graceful shutdown**: on `SIGTERM`/`SIGINT`, forward `SIGTERM` to the child; if the child has
  not exited within 1 second, send `SIGKILL`. Exit code is `128 + signal_number` if the proxy
  received a signal, or the child's exit code otherwise — matching standard POSIX shell conventions.
- **RAII wrappers**: `FileDescriptor` (closes on destruction), `SignalScope` (restores signal
  handlers on destruction), `ChildReaper` (sends `SIGKILL` and waits on destruction). All three
  cover every early-exit path without `goto` or duplicated cleanup.

---

## 4. Build system

| Preset | Config | Features |
|---|---|---|
| `dev-debug` | Debug + tests | Default for development |
| `asan` | Debug + ASan + UBSan | All sanitizers on |
| `perf` | Release + benchmarks, tests off | LTO-eligible |

CMake options: `MNG_BUILD_TESTS`, `MNG_BUILD_BENCHMARKS`, `MNG_ENABLE_SANITIZERS`,
`MNG_ENABLE_LTO`, `MNG_WARNINGS_AS_ERRORS`.

The Linux relay is guarded by `if(CMAKE_SYSTEM_NAME STREQUAL "Linux")` and compiled into the core
library only on Linux, exposing the `MNG_HAS_LINUX_STDIO_RELAY` preprocessor definition to
consumer targets. No `#ifdef` soup leaks into headers.

Zero third-party dependencies. Standard library and POSIX only.

---

## 5. Testing approach

No third-party test framework. Tests use a hand-rolled `CHECK` macro that records failures and lets
the suite run to completion before returning a non-zero exit code.

**Unit tests** (`tests/test_main.cpp`) cover:

- Framer: empty chunks, split-boundary messages, CRLF trim, oversized rejection, truncation
  detection.
- Classifier: request/notification/response classification, escape rejection, duplicate member
  detection, version mismatch, size/nesting limits.
- Policy: allow/deny lookup, unknown-tool defaults, empty name rejection, duplicate rule rejection.
- Proxy: authorisation decisions and counter increments.

**Integration tests** (`tests/run_integration_test.cpp`, Linux-only):

- Byte-preserving relay: the echo server receives and re-emits; the relay must pass through
  unchanged bytes.
- Stderr isolation: child stderr must not appear on proxy stdout.
- Early server exit: relay exits cleanly when child exits.
- Invalid argument handling: exit code 2 on bad CLI arguments.
- SIGTERM escalation: relay sends SIGTERM, then SIGKILL; exits with `128 + SIGTERM` within
  3 seconds.

**Benchmarks** (`benchmarks/`): two microbenchmarks that time the full pipeline (frame → classify
→ extract tool name → authorize). No external framework — plain wall-clock loops with iteration
counts printed to stdout.

---

## 6. C++ techniques and standards used

### Language standard: C++20

Enabled via `target_compile_features(... cxx_std_20)`.

### Features actively used

| Feature | Where | Purpose |
|---|---|---|
| `std::span<const char>` | `LineFramer::feed`, `run_stdio_child` | Non-owning buffer view; no copy, no lifetime confusion |
| `std::string_view` | All APIs; `Status::message`; `classify()` return | Zero-copy string handles; compared without allocation |
| `[[nodiscard]]` | All `Status`-, `Decision`-, and `bool`-returning APIs | Forces error-return handling at compile time |
| `noexcept` | `classify`, `authorize_*`, `run_stdio_child`, RAII destructors | Communicates guaranteed non-throwing contracts |
| `constexpr` | `Status::is_ok`, `Status::success`, `Decision::should_forward` | Evaluated at compile time when used in constant expressions |
| `final` | All public classes | Prevents accidental subclassing; enables devirtualisation |
| Designated initialisers | `Envelope{.error = ...}`, `pollfd{...}` | C++20 aggregate init with named fields |
| `std::from_chars` | `parse_size()` in `main.cpp` | Locale-independent, allocation-free integer parsing |
| `std::pmr::vector` | `LineFramer` | Polymorphic memory resource; caller-supplied arena without API change |
| `std::atomic` + `memory_order_relaxed` | `ProxyCore` counters | Lock-free metrics; avoids acquire/release barriers on hot path |
| `std::chrono::steady_clock` | Signal grace period in relay | Monotonic clock; unaffected by wall-clock adjustments |
| `std::exchange` | `FileDescriptor` move operations | Moves value and resets source to sentinel in one expression |
| Template sink (`Sink&&`) | `LineFramer::feed`, `emit` | Avoids `std::function` overhead; enables lambda inlining |
| `std::lower_bound` with lambda comparator | `PolicyTable::find` | Allocation-free binary search on sorted vector |
| `std::adjacent_find` | `PolicyTable::build` | O(n) duplicate detection after sort |
| `std::sort` with lambda | `PolicyTable::build` | Sorts `ToolRule` by name |
| Scoped enums (`enum class`) | All enumerations | Prevents implicit integer conversions; forces explicit qualification |
| `uint8_t` / `unsigned char` enum backing | `StatusCode`, `Access`, `Action`, `Reason`, `EnvelopeKind` | Explicit narrow storage; clear ABI |
| Unnamed namespaces | All `.cpp` translation units | Internal linkage without `static`; replaces TU-local `static` |
| `std::array` | Read buffer in relay, pipe array in spawn | Stack allocation with known compile-time size |

### Patterns and idioms

**RAII throughout** — `FileDescriptor`, `SignalScope`, `ChildReaper` all release resources in
destructors. No `goto`, no `finally`, no manual `close()` outside `reset()`.

**Value semantics** — `Status`, `Decision`, `Envelope`, `CounterSnapshot` are trivially copyable
value types. No heap indirection for small results.

**Fail-closed defaults** — every enum, struct default, and policy default initialises to the most
restrictive (deny) state. Forgetting to set a field means deny, not allow.

**Factory pattern for immutable aggregates** — `PolicyTable::build()` returns `Status` and writes
into an out-parameter only on success. This avoids two-phase initialisation and prevents a
partially-built table from being observed.

**Protocol parsing separated from decisions** — `ProxyCore` never sees JSON. Security decisions
are not made by pattern-matching on strings.

**Sticky failure state** — `LineFramer` sets a `failed_` flag and stores the first error. All
subsequent calls return that error immediately, preventing any partial processing after a boundary
violation.

**`extern "C"` signal handler** — `record_termination` is declared `extern "C"`. This is required
for signal handlers called by the C runtime. `volatile sig_atomic_t` is the only correct type for
a variable written in a signal handler.

**`std::ios::sync_with_stdio(false)` + `cin.tie(nullptr)`** — decouples C and C++ stdio for
throughput; unties `cin` from `cout` to remove the implicit flush before each read.

---

## 7. Architectural invariants

These invariants are explicitly stated in `docs/architecture.md` and enforced throughout the code:

1. Input size is checked before any attacker-controlled message can grow.
2. A `string_view` into framed message data never outlives the framing callback.
3. Policy lookup performs no dynamic allocation.
4. `PolicyTable` is immutable once moved into `ProxyCore`.
5. Security decisions do not use substring matching or heuristics.
6. All diagnostics go to stderr; MCP stdout is reserved for protocol traffic.
7. Every future concurrency boundary must define ownership and cancellation behaviour.

---

## 8. Suggestions for next steps

Listed in order of dependency — each milestone unlocks the next.

### Milestone 1 — Select a JSON parser (blocker for all validation)

Choose a permissive-licensed, zero-dependency JSON library. Candidates are `nlohmann/json`,
`simdjson`, and `yyjson`. Before adopting any of them, write an ADR (required by `AGENTS.md`)
documenting: licence, maintenance status, security history, binary-size cost, and a benchmark
comparison against the current hand-rolled scanner. `simdjson` is the strongest candidate for the
hot path (SIMD, streaming API), but requires a minimum ISA that must be pinned and documented.

### Milestone 2 — Typed JSON-RPC and MCP request/response validation

Use the chosen parser to validate request parameters (`tools/call` → `name` field extraction),
`tools/list` responses (iterate the returned tool array), and `initialize` handshake fields. The
envelope classifier already identifies the kind and method; the next step is validating the
`params` body. Produce a `ValidatedRequest` value type that carries the extracted `tool_name` as
an owned or borrowed string — this is what `ProxyCore::authorize_tool_call` should consume.

### Milestone 3 — Policy JSON loader

The schema is already designed (`examples/policy.json`). Write a
`load_policy(string_view json) → Status` function that parses the JSON and calls
`PolicyTable::build`. Validate `version`, `defaults`, `limits`, and the `tools` array. Add
fuzz-corpus tests — the loader is directly attacker-adjacent.

### Milestone 4 — `tools/list` response filtering

When the downstream server replies with `tools/list`, parse the tool array and remove any entry
whose `name` is denied by `PolicyTable::visibility_for`. Rewrite the response before forwarding to
the client. This requires: (a) the typed parser from milestone 2, (b) a JSON serialiser, (c) a
response-rewriting path in the relay loop.

### Milestone 5 — Tool-definition baseline and fingerprinting

At `initialize` time, read `tools/list` from the downstream server and canonicalise each tool
definition (sorted keys, normalised whitespace). Hash each definition with a deterministic
algorithm (SHA-256 or BLAKE3 — needs ADR). Store these hashes. On any subsequent `tools/list`
reply, verify that the fingerprints match. Alert (and optionally block) on definition drift. This
closes the most critical threat: a compromised server injecting a newly-visible or redefined tool.

### Milestone 6 — Append-only audit chain

Every `tools/call` decision (forwarded or blocked), tool name, message hash, timestamp, and
outcome should be appended to an audit log. For tamper evidence, each entry should include the hash
of the previous entry (hash chain). The audit sink should run on a separate thread or file-write
path so it does not add latency to the hot path. Define the format first (ADR or schema document).

### Milestone 7 — Windows process backend

`CreateProcess` with restricted handle inheritance and a Job Object (for memory and CPU limits, and
guaranteed child termination on proxy exit). The Linux and Windows backends should expose the same
narrow interface already defined by `run_stdio_child`. Add a `CMakeLists.txt` guard mirroring the
existing Linux guard.

### Milestone 8 — Linux namespace and seccomp sandbox

After the relay is stable, optionally place the child process in a PID namespace and apply a
seccomp-BPF filter (via `libseccomp` — needs ADR for the dependency) that allows only the syscalls
the child actually needs. This bounds blast radius if the downstream MCP server is compromised.

### CI and code-quality improvements

- Add a GitHub Actions workflow running at minimum: `cmake --preset dev-debug &&
  cmake --build --preset dev-debug && ctest --preset dev-debug`, and the `asan` preset on Linux.
- Enable `MNG_WARNINGS_AS_ERRORS` in CI.
- Add a fuzz target for `JsonRpcEnvelopeClassifier::classify` and `LineFramer::feed` using
  libFuzzer. Both consume attacker-controlled byte streams.
- Add `clang-tidy` to CI using the existing `.clang-tidy` configuration.

### Benchmark families to add

Per `docs/performance-plan.md`:

1. Framing: various message sizes, split positions, CRLF variants, adversarial streams.
2. Parsing: valid and adversarial JSON-RPC messages through the full classifier.
3. Policy: table sizes from 1 to 1 000 tools, allow/deny distributions.
4. Rewriting: `tools/list` filtering for tables of different sizes.
5. End-to-end: client–proxy–server round-trip over local pipes (P50/P95/P99 latency, peak RSS,
   CPU time, malformed-input failure behaviour).
