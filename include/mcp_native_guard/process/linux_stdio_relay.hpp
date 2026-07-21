#pragma once

#include <cstddef>
#include <span>

namespace mng::process {

struct RunConfig final {
    std::size_t pipe_capacity_bytes{64U * 1024U};
    std::size_t relay_buffer_bytes{64U * 1024U};
};

// Starts one downstream process and transparently relays its JSONL byte stream
// between the caller's standard input and standard output. This Linux-only
// transport layer does not inspect or rewrite protocol messages.
[[nodiscard]] int run_stdio_child(
    std::span<char* const> command,
    RunConfig config = {}) noexcept;

} // namespace mng::process
