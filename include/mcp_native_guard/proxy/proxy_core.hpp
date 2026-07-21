#pragma once

#include "mcp_native_guard/security/policy.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace mng::proxy {

enum class Action : unsigned char { forward = 0, block = 1 };
enum class Reason : unsigned char {
    policy_allowed = 0,
    policy_denied,
    message_too_large,
    empty_tool_name,
};

struct Decision final {
    Action action{Action::block};
    Reason reason{Reason::policy_denied};
    [[nodiscard]] constexpr bool should_forward() const noexcept {
        return action == Action::forward;
    }
};

struct Limits final { std::size_t max_message_bytes{1024U * 1024U}; };

struct CounterSnapshot final {
    std::uint64_t forwarded{};
    std::uint64_t blocked{};
    std::uint64_t oversized{};
};

// Protocol parsing is deliberately outside this class. The core receives validated fields and
// performs a small, deterministic policy decision suitable for the hot path.
class ProxyCore final {
public:
    ProxyCore(security::PolicyTable policy, Limits limits);

    [[nodiscard]] Decision authorize_tool_call(
        std::string_view tool_name,
        std::size_t encoded_message_bytes) noexcept;
    [[nodiscard]] Decision authorize_tool_visibility(std::string_view tool_name) noexcept;
    [[nodiscard]] CounterSnapshot counters() const noexcept;

private:
    void record(const Decision& decision) noexcept;

    security::PolicyTable policy_;
    Limits limits_;
    std::atomic<std::uint64_t> forwarded_{0};
    std::atomic<std::uint64_t> blocked_{0};
    std::atomic<std::uint64_t> oversized_{0};
};

} // namespace mng::proxy
