#pragma once

#include "mcp_native_guard/core/status.hpp"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <memory_resource>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace mng::io {

// Frames newline-delimited MCP stdio messages from arbitrary input chunks.
// A view passed to the sink is valid only for the duration of that sink call.
class LineFramer final {
public:
    struct Config final {
        std::size_t max_message_bytes{1024U * 1024U};
        std::size_t initial_capacity{4096U};
        bool trim_carriage_return{true};
    };

    LineFramer();
    explicit LineFramer(
        Config config,
        std::pmr::memory_resource* memory = std::pmr::get_default_resource());

    template <typename Sink>
    [[nodiscard]] Status feed(std::span<const char> bytes, Sink&& sink) {
        if (failed_) {
            return failure_;
        }
        if (bytes.empty()) {
            return Status::success();
        }

        const char* cursor = bytes.data();
        const char* const end = bytes.data() + bytes.size();

        while (cursor != end) {
            const auto remaining = static_cast<std::size_t>(end - cursor);
            const void* const delimiter = std::memchr(cursor, '\n', remaining);

            if (delimiter == nullptr) {
                return append(std::span<const char>{cursor, remaining});
            }

            const auto* const newline = static_cast<const char*>(delimiter);
            const auto segment_size = static_cast<std::size_t>(newline - cursor);

            if (buffer_.empty()) {
                if (segment_size > config_.max_message_bytes) {
                    return fail(StatusCode::message_too_large, "message exceeds configured limit");
                }
                emit(std::string_view{cursor, segment_size}, sink);
            } else {
                const Status append_status = append(std::span<const char>{cursor, segment_size});
                if (!append_status) {
                    return append_status;
                }
                emit(std::string_view{buffer_.data(), buffer_.size()}, sink);
                buffer_.clear();
            }

            cursor = newline + 1;
        }

        return Status::success();
    }

    [[nodiscard]] Status finish() noexcept;
    void reset() noexcept;

    [[nodiscard]] std::size_t buffered_bytes() const noexcept { return buffer_.size(); }
    [[nodiscard]] std::size_t max_message_bytes() const noexcept {
        return config_.max_message_bytes;
    }

private:
    template <typename Sink>
    void emit(std::string_view message, Sink&& sink) {
        if (config_.trim_carriage_return && !message.empty() && message.back() == '\r') {
            message.remove_suffix(1);
        }
        std::forward<Sink>(sink)(message);
    }

    [[nodiscard]] Status append(std::span<const char> bytes);
    [[nodiscard]] Status fail(StatusCode code, std::string_view message) noexcept;

    Config config_;
    std::pmr::vector<char> buffer_;
    bool failed_{false};
    Status failure_{};
};

} // namespace mng::io
