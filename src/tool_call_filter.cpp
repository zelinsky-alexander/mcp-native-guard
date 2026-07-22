#include "mcp_native_guard/protocol/tool_call_filter.hpp"

#include "json_scanner.hpp"

#include <algorithm>
#include <string_view>
#include <utility>
#include <vector>

namespace mng::protocol {
namespace {

constexpr int denied_tool_error_code = -32001;
constexpr int invalid_params_error_code = -32602;
// Temporary project-specific code until the public runtime-limit error contract is finalized.
constexpr int correlation_capacity_error_code = -32002;
constexpr std::string_view denied_tool_error_message = "Tool call denied by policy";
constexpr std::string_view invalid_params_error_message = "Invalid tools/call parameters";
constexpr std::string_view correlation_capacity_error_message = "tools/list correlation capacity exhausted";

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
    std::vector<std::string_view>& removed_tools,
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
        const proxy::Decision visibility = proxy.authorize_tool_visibility(name);
        if (visibility.should_forward()) {
            if (wrote_tool) {
                rewritten.push_back(',');
            }
            rewritten.append(message.data() + tool_begin, offset - tool_begin);
            wrote_tool = true;
        } else {
            removed_tools.push_back(name);
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
    std::vector<std::string_view>& removed_tools,
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
                                 message,
                                 offset,
                                 max_depth,
                                 proxy,
                                 removed_tools,
                                 rewritten,
                                 array_close)) {
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
    std::vector<std::string_view>& removed_tools,
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
                                  message,
                                  offset,
                                  max_depth,
                                  proxy,
                                  removed_tools,
                                  rewritten,
                                  array_close)) {
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

ToolCallFilter::ToolCallFilter(
    security::PolicyTable policy,
    audit::AuditSink* audit_sink)
    : ToolCallFilter(std::move(policy), Config{}, audit_sink) {}

ToolCallFilter::ToolCallFilter(
    security::PolicyTable policy,
    Config config,
    audit::AuditSink* audit_sink)
    : classifier_{config.runtime},
      extractor_{config.runtime},
      proxy_{std::move(policy), {config.runtime.max_message_bytes}},
      config_{config},
      pending_(config.runtime.max_pending_tools_list),
      audit_sink_{audit_sink} {}

process::ClientMessageDecision ToolCallFilter::inspect(std::string_view message) noexcept {
    const Envelope envelope = classifier_.classify(message);
    if (!envelope) {
        if (audit_sink_ != nullptr) {
            const bool oversized = envelope.error == ClassificationError::message_too_large;
            audit_sink_->record({
                envelope.method == "tools/call" ? audit::EventType::tool_call
                                                : audit::EventType::message_rejected,
                audit::Decision::deny,
                oversized ? audit::Reason::message_too_large
                          : audit::Reason::malformed_message,
                {},
                envelope.id_json,
                message.size(),
                true,
            });
        }
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
        if (envelope.method == "tools/list") {
            if (envelope.kind != EnvelopeKind::request) {
                if (pending_count_ >= pending_.size()) {
                    if (audit_sink_ != nullptr) {
                        audit_sink_->record({
                            audit::EventType::correlation_exhausted,
                            audit::Decision::deny,
                            audit::Reason::capacity_exhausted,
                            {},
                            envelope.id_json,
                            message.size(),
                            true,
                        });
                    }
                    return {process::ClientMessageAction::drop};
                }
                return {};
            }
            const PendingStatus pending = add_pending(envelope.id_json);
            if (pending != PendingStatus::added) {
                if (pending == PendingStatus::capacity_exhausted && audit_sink_ != nullptr) {
                    audit_sink_->record({
                        audit::EventType::correlation_exhausted,
                        audit::Decision::deny,
                        audit::Reason::capacity_exhausted,
                        {},
                        envelope.id_json,
                        message.size(),
                        true,
                    });
                }
                if (pending == PendingStatus::capacity_exhausted && !envelope.id_json.empty()) {
                    return {
                        process::ClientMessageAction::respond_with_error,
                        envelope.id_json,
                        correlation_capacity_error_code,
                        correlation_capacity_error_message,
                    };
                }
                return {process::ClientMessageAction::drop};
            }
        }
        return {};
    }

    const ToolCallParams params = extractor_.extract(message);
    if (!params) {
        if (audit_sink_ != nullptr) {
            audit_sink_->record({
                audit::EventType::tool_call,
                audit::Decision::deny,
                audit::Reason::invalid_parameters,
                params.name,
                envelope.id_json,
                message.size(),
                true,
            });
        }
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
    if (audit_sink_ != nullptr) {
        audit_sink_->record({
            audit::EventType::tool_call,
            decision.should_forward() ? audit::Decision::allow : audit::Decision::deny,
            decision.should_forward() ? audit::Reason::policy_allowed
                                      : audit::Reason::policy_denied,
            params.name,
            envelope.id_json,
            message.size(),
            true,
        });
    }
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
        std::vector<std::string_view> removed_tools;
        const RewriteStatus status = rewrite_tools_list_response(
            message,
            config_.runtime.max_nesting_depth,
            proxy_,
            removed_tools,
            rewritten_response_);
        if (status == RewriteStatus::rewritten) {
            if (audit_sink_ != nullptr) {
                for (const std::string_view name : removed_tools) {
                    audit_sink_->record({
                        audit::EventType::tool_hidden,
                        audit::Decision::deny,
                        audit::Reason::policy_denied,
                        name,
                        envelope.id_json,
                        message.size(),
                        true,
                    });
                }
            }
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

ToolCallFilter::PendingStatus ToolCallFilter::add_pending(std::string_view id_json) noexcept {
    const std::size_t capacity = pending_.size();
    for (std::size_t index = 0; index < pending_count_; ++index) {
        if (pending_[index].id_json == id_json) {
            return PendingStatus::duplicate;
        }
    }
    if (id_json.empty() || id_json.size() > config_.max_pending_id_bytes ||
        pending_count_ >= capacity ||
        pending_id_bytes_ > config_.max_pending_total_id_bytes ||
        id_json.size() > config_.max_pending_total_id_bytes - pending_id_bytes_) {
        return PendingStatus::capacity_exhausted;
    }
    try {
        pending_[pending_count_].id_json.assign(id_json);
    } catch (...) {
        return PendingStatus::capacity_exhausted;
    }
    pending_id_bytes_ += id_json.size();
    ++pending_count_;
    return PendingStatus::added;
}

void ToolCallFilter::message_too_large(
    process::MessageDirection,
    std::size_t encoded_message_bytes) noexcept {
    if (audit_sink_ != nullptr) {
        audit_sink_->record({
            audit::EventType::message_rejected,
            audit::Decision::deny,
            audit::Reason::message_too_large,
            {},
            {},
            encoded_message_bytes,
            true,
        });
    }
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
