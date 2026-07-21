#pragma once

#include <cstdint>
#include <string_view>

namespace mng {

enum class StatusCode : std::uint8_t {
    ok = 0,
    invalid_argument,
    message_too_large,
    truncated_message,
    duplicate_rule,
    io_error,
};

struct Status final {
    StatusCode code{StatusCode::ok};
    std::string_view message{};

    [[nodiscard]] constexpr bool is_ok() const noexcept { return code == StatusCode::ok; }
    [[nodiscard]] constexpr explicit operator bool() const noexcept { return is_ok(); }
    [[nodiscard]] static constexpr Status success() noexcept { return {}; }
};

} // namespace mng
