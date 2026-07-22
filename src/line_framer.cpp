#include "mcp_native_guard/io/line_framer.hpp"

#include <stdexcept>

namespace mng::io {

LineFramer::LineFramer() : LineFramer(Config{}) {}

LineFramer::LineFramer(Config config, std::pmr::memory_resource* memory)
    : config_{config}, buffer_{memory} {
    if (config_.max_message_bytes == 0U) {
        throw std::invalid_argument{"max_message_bytes must be greater than zero"};
    }
    const auto reserve_size = std::min(config_.initial_capacity, config_.max_message_bytes);
    buffer_.reserve(reserve_size);
}

Status LineFramer::append(std::span<const char> bytes) {
    if (bytes.size() > config_.max_message_bytes - buffer_.size()) {
        return fail(
            StatusCode::message_too_large,
            "message exceeds configured limit",
            buffer_.size() + bytes.size());
    }
    buffer_.insert(buffer_.end(), bytes.begin(), bytes.end());
    return Status::success();
}

Status LineFramer::finish() noexcept {
    if (failed_) {
        return failure_;
    }
    if (!buffer_.empty()) {
        return fail(StatusCode::truncated_message, "input ended before newline delimiter");
    }
    return Status::success();
}

void LineFramer::reset() noexcept {
    buffer_.clear();
    failed_ = false;
    failure_ = Status::success();
    failed_message_bytes_ = 0U;
}

Status LineFramer::fail(
    StatusCode code,
    std::string_view message,
    std::size_t failed_message_bytes) noexcept {
    buffer_.clear();
    failed_ = true;
    failure_ = Status{code, message};
    failed_message_bytes_ = failed_message_bytes;
    return failure_;
}

} // namespace mng::io
