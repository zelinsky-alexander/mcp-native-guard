#include "mcp_native_guard/protocol/tool_call_filter.hpp"

#include "json_scanner.hpp"

#include <algorithm>
#include <string_view>
#include <utility>

namespace mng::protocol {
namespace {

constexpr int denied_tool_error_code = -32001;
constexpr int invalid_params_error_code = -32602;
constexpr std::string_view denied_tool_error_message = "Tool call denied by policy";
constexpr std::string_view invalid_params_error_message = "Invalid tools/call parameters";

using internal::StringToken;
using internal::scan_string;
using internal::skip_value;
using internal::skip_whitespace;

enum class RewriteStatus : unsigned char { rewritten, passthrough, malformed };

[[nodiscard]] bool parse_tool(
    std::string_view message,
    std::size_t& offset,
    std::size_t max_depth,
    std::string_view& name) noexcept {
    if (max_depth < 4U || offset >= message.size() || message[offset++] != '{') {
        return false;
    }
    bool saw_name = false;
    skip_whitespace(message, offset);
    if (offset < message.size() && message[offset] == '}') {
        return false;
    }
    while (offset < message.size()) {
        StringToken key;
        if (!scan_string(message, offset, key) || key.has_escape) {
            return false;
        }
        skip_whitespace(message, offset);
        if (offset >= message.size() || message[offset++] != ':') {
            return false;
        }
        skip_whitespace(message, offset);
        if (key.contents == "name") {
            if (saw_name) {
                return false;
            }
            saw_name = true;
            StringToken value;
            if (!scan_string(message, offset, value) || value.has_escape || value.contents.empty()) {
                return false;
            }
            name = value.contents;
        } else if (!skip_value(message, offset, 4U, max_depth)) {
            return false;
        }
        skip_whitespace(message, offset);
        if (offset >= message.size()) {
            return false;
        }
        if (message[offset] == '}') {
            ++offset;
            return saw_name;
        }
        if (message[offset++] != ',') {
            return false;
        }
        skip_whitespace(message, offset);
    }
    return false;
}

[[nodiscard]] bool parse_tools_array(
    std::string_view message,
    std::size_t& offset,
    std::size_t max_depth,
    proxy::ProxyCore& proxy,
    std::string& rewritten,
    std::size_t& array_close) {
    if (max_depth < 3U || offset >= message.size() || message[offset++] != '[') {
        return false;
    }
    rewritten.assign(message.data(), offset);
    bool wrote_tool = false;
    skip_whitespace(message, offset);
    if (offset < message.size() && message[offset] == ']') {
        array_close = offset++;
        return true;
    }
    while (offset < message.size()) {
        const std::size_t tool_begin = offset;
        std::string_view name;
        if (!parse_tool(message, offset, max_depth, name)) {
            return false;
        }
        if (proxy.authorize_tool_visibility(name).should_forward()) {
            if (wrote_tool) {
                rewritten.push_back(',');
            }
            rewritten.append(message.data() + tool_begin, offset - tool_begin);
            wrote_tool = true;
        }
        skip_whitespace(message, offset);
        if (offset >= message.size()) {
            return false;
        }
        if (message[offset] == ']') {
            array_close = offset++;
            return true;
        }
        if (message[offset++] != ',') {
            return false;
        }
        skip_whitespace(message, offset);
    }
    return false;
}

[[nodiscard]] bool parse_result(
    std::string_view message,
    std::size_t& offset,
    std::size_t max_depth,
    proxy::ProxyCore& proxy,
    std::string& rewritten,
    std::size_t& array_close) {
    if (max_depth < 2U || offset >= message.size() || message[offset++] != '{') {
        return false;
    }
    bool saw_tools = false;
    skip_whitespace(message, offset);
    if (offset < message.size() && message[offset] == '}') {
        return false;
    }
    while (offset < message.size()) {
        StringToken key;
        if (!scan_string(message, offset, key) || key.has_escape) {
            return false;
        }
        skip_whitespace(message, offset);
        if (offset >= message.size() || message[offset++] != ':') {
            return false;
        }
        skip_whitespace(message, offset);
        if (key.contents == "tools") {
            if (saw_tools || !parse_tools_array(
                                 message, offset, max_depth, proxy, rewritten, array_close)) {
                return false;
            }
            saw_tools = true;
        } else if (!skip_value(message, offset, 2U, max_depth)) {
            return false;
        }
        skip_whitespace(message, offset);
        if (offset >= message.size()) {
            return false;
        }
        if (message[offset] == '}') {
            ++offset;
            return saw_tools;
        }
        if (message[offset++] != ',') {
            return false;
        }
        skip_whitespace(message, offset);
    }
    return false;
}

[[nodiscard]] RewriteStatus rewrite_tools_list_response(
    std::string_view message,
    std::size_t max_depth,
    proxy::ProxyCore& proxy,
    std::string& rewritten) {
    std::size_t offset = 0;
    std::size_t array_close = 0;
    bool saw_result = false;
    bool saw_error = false;
    skip_whitespace(message, offset);
    if (offset >= message.size() || message[offset++] != '{') {
        return RewriteStatus::malformed;
    }
    skip_whitespace(message, offset);
    while (offset < message.size() && message[offset] != '}') {
        StringToken key;
        if (!scan_string(message, offset, key) || key.has_escape) {
            return RewriteStatus::malformed;
        }
        skip_whitespace(message, offset);
        if (offset >= message.size() || message[offset++] != ':') {
            return RewriteStatus::malformed;
        }
        skip_whitespace(message, offset);
        if (key.contents == "result") {
            if (saw_result || !parse_result(
                                  message, offset, max_depth, proxy, rewritten, array_close)) {
                return RewriteStatus::malformed;
            }
            saw_result = true;
        } else {
            if (key.contents == "error") {
                if (saw_error) {
                    return RewriteStatus::malformed;
                }
                saw_error = true;
            }
            if (!skip_value(message, offset, 1U, max_depth)) {
                return RewriteStatus::malformed;
            }
        }
        skip_whitespace(message, offset);
        if (offset >= message.size()) {
            return RewriteStatus::malformed;
        }
        if (message[offset] == '}') {
            break;
        }
        if (message[offset++] != ',') {
            return RewriteStatus::malformed;
        }
        skip_whitespace(message, offset);
    }
    if (offset >= message.size() || message[offset++] != '}') {
        return RewriteStatus::malformed;
    }
    skip_whitespace(message, offset);
    if (offset != message.size() || saw_result == saw_error) {
        return RewriteStatus::malformed;
    }
    if (saw_error) {
        return RewriteStatus::passthrough;
    }
    rewritten.append(message.data() + array_close, message.size() - array_close);
    return RewriteStatus::rewritten;
}

} // namespace

ToolCallFilter::ToolCallFilter(security::PolicyTable policy) noexcept
    : ToolCallFilter(std::move(policy), Config{}) {}

ToolCallFilter::ToolCallFilter(security::PolicyTable policy, Config config) noexcept
    : classifier_{{config.max_message_bytes, config.max_nesting_depth}},
      extractor_{{config.max_message_bytes, config.max_nesting_depth}},
      proxy_{std::move(policy), {config.max_message_bytes}},
      config_{config} {}

process::ClientMessageDecision ToolCallFilter::inspect(std::string_view message) noexcept {
    const Envelope envelope = classifier_.classify(message);
    if (!envelope) {
        if (envelope.method == "tools/call" && !envelope.id_json.empty()) {
            return {
                process::ClientMessageAction::respond_with_error,
                envelope.id_json,
                invalid_params_error_code,
                invalid_params_error_message,
            };
        }
        return {process::ClientMessageAction::drop};
    }
    if (envelope.method != "tools/call") {
        if (envelope.method == "tools/list" && envelope.kind == EnvelopeKind::request &&
            !add_pending(envelope.id_json)) {
            return {process::ClientMessageAction::drop};
        }
        return {};
    }

    const ToolCallParams params = extractor_.extract(message);
    if (!params) {
        if (envelope.kind == EnvelopeKind::request) {
            return {
                process::ClientMessageAction::respond_with_error,
                envelope.id_json,
                invalid_params_error_code,
                invalid_params_error_message,
            };
        }
        return {process::ClientMessageAction::drop};
    }

    const proxy::Decision decision = proxy_.authorize_tool_call(params.name, message.size());
    if (decision.should_forward()) {
        return {};
    }
    if (envelope.kind == EnvelopeKind::request) {
        return {
            process::ClientMessageAction::respond_with_error,
            envelope.id_json,
            denied_tool_error_code,
            denied_tool_error_message,
        };
    }
    return {process::ClientMessageAction::drop};
}

process::ServerMessageDecision ToolCallFilter::inspect_server(std::string_view message) noexcept {
    rewritten_response_.clear();
    const Envelope envelope = classifier_.classify(message);
    if (!envelope) {
        if (!envelope.id_json.empty()) {
            (void)remove_pending(envelope.id_json);
        }
        return {process::ServerMessageAction::drop};
    }
    if (envelope.kind != EnvelopeKind::response || !remove_pending(envelope.id_json)) {
        return {};
    }

    try {
        rewritten_response_.reserve(message.size());
        const RewriteStatus status = rewrite_tools_list_response(
            message, config_.max_nesting_depth, proxy_, rewritten_response_);
        if (status == RewriteStatus::rewritten) {
            return {process::ServerMessageAction::replace, rewritten_response_};
        }
        if (status == RewriteStatus::passthrough) {
            return {};
        }
    } catch (...) {
        rewritten_response_.clear();
    }
    return {process::ServerMessageAction::drop};
}

bool ToolCallFilter::add_pending(std::string_view id_json) noexcept {
    const std::size_t capacity = std::min(config_.max_pending_requests, pending_.size());
    if (id_json.empty() || id_json.size() > config_.max_pending_id_bytes ||
        pending_count_ >= capacity ||
        id_json.size() > config_.max_pending_total_id_bytes - pending_id_bytes_) {
        return false;
    }
    for (std::size_t index = 0; index < pending_count_; ++index) {
        if (pending_[index].id_json == id_json) {
            return false;
        }
    }
    try {
        pending_[pending_count_].id_json.assign(id_json);
    } catch (...) {
        return false;
    }
    pending_id_bytes_ += id_json.size();
    ++pending_count_;
    return true;
}

bool ToolCallFilter::remove_pending(std::string_view id_json) noexcept {
    for (std::size_t index = 0; index < pending_count_; ++index) {
        if (pending_[index].id_json != id_json) {
            continue;
        }
        pending_id_bytes_ -= pending_[index].id_json.size();
        const std::size_t last = pending_count_ - 1U;
        if (index != last) {
            pending_[index].id_json = std::move(pending_[last].id_json);
        }
        std::string{}.swap(pending_[last].id_json);
        --pending_count_;
        return true;
    }
    return false;
}

void ToolCallFilter::connection_closed() noexcept {
    for (std::size_t index = 0; index < pending_count_; ++index) {
        std::string{}.swap(pending_[index].id_json);
    }
    pending_count_ = 0;
    pending_id_bytes_ = 0;
    std::string{}.swap(rewritten_response_);
}

} // namespace mng::protocol
