#include "mcp_native_guard/protocol/tool_call_filter.hpp"

#include <string_view>
#include <utility>

namespace mng::protocol {
namespace {

constexpr int denied_tool_error_code = -32001;
constexpr int invalid_params_error_code = -32602;
constexpr std::string_view denied_tool_error_message = "Tool call denied by policy";
constexpr std::string_view invalid_params_error_message = "Invalid tools/call parameters";

} // namespace

ToolCallFilter::ToolCallFilter(security::PolicyTable policy) noexcept
    : ToolCallFilter(std::move(policy), Config{}) {}

ToolCallFilter::ToolCallFilter(security::PolicyTable policy, Config config) noexcept
    : classifier_{{config.max_message_bytes, config.max_nesting_depth}},
      extractor_{{config.max_message_bytes, config.max_nesting_depth}},
      proxy_{std::move(policy), {config.max_message_bytes}} {}

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

} // namespace mng::protocol
