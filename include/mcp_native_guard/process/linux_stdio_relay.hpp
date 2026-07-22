#pragma once

#include "mcp_native_guard/process/client_message_handler.hpp"
#include "mcp_native_guard/protocol/runtime_limits.hpp"

#include <cstddef>
#include <span>

namespace mng::process {

struct RunConfig final {
    std::size_t pipe_capacity_bytes{64U * 1024U};
    std::size_t relay_buffer_bytes{64U * 1024U};
    protocol::RuntimeLimits runtime{};
};

struct RunResult final {
    int proxy_exit_status{4};
    int child_exit_status{-1};
    bool child_started{false};
    bool clean_shutdown{false};
    const char* termination_reason{"startup_failure"};
};

class RunObserver {
public:
    virtual ~RunObserver() = default;
    virtual void child_started() noexcept = 0;
    virtual void child_finished(const RunResult& result) noexcept = 0;
};

// Starts one downstream process and transparently relays its JSONL byte stream
// between the caller's standard input and standard output. This Linux-only
// transport layer does not inspect or rewrite protocol messages.
[[nodiscard]] int run_stdio_child(
    std::span<char* const> command,
    ClientMessageHandler* client_message_handler = nullptr,
    RunConfig config = {},
    RunObserver* observer = nullptr) noexcept;

} // namespace mng::process
