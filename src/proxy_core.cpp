#include "mcp_native_guard/proxy/proxy_core.hpp"

#include <utility>

namespace mng::proxy {

ProxyCore::ProxyCore(security::PolicyTable policy, Limits limits)
    : policy_{std::move(policy)}, limits_{limits} {}

Decision ProxyCore::authorize_tool_call(
    std::string_view tool_name,
    std::size_t encoded_message_bytes) noexcept {
    Decision decision{};
    if (encoded_message_bytes > limits_.max_message_bytes) {
        decision = {Action::block, Reason::message_too_large};
    } else if (tool_name.empty()) {
        decision = {Action::block, Reason::empty_tool_name};
    } else if (policy_.invocation_for(tool_name) == security::Access::allow) {
        decision = {Action::forward, Reason::policy_allowed};
    } else {
        decision = {Action::block, Reason::policy_denied};
    }
    record(decision);
    return decision;
}

Decision ProxyCore::authorize_tool_visibility(std::string_view tool_name) noexcept {
    Decision decision{};
    if (tool_name.empty()) {
        decision = {Action::block, Reason::empty_tool_name};
    } else if (policy_.visibility_for(tool_name) == security::Access::allow) {
        decision = {Action::forward, Reason::policy_allowed};
    } else {
        decision = {Action::block, Reason::policy_denied};
    }
    record(decision);
    return decision;
}

CounterSnapshot ProxyCore::counters() const noexcept {
    return {
        forwarded_.load(std::memory_order_relaxed),
        blocked_.load(std::memory_order_relaxed),
        oversized_.load(std::memory_order_relaxed),
    };
}

void ProxyCore::record(const Decision& decision) noexcept {
    if (decision.should_forward()) {
        forwarded_.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    blocked_.fetch_add(1, std::memory_order_relaxed);
    if (decision.reason == Reason::message_too_large) {
        oversized_.fetch_add(1, std::memory_order_relaxed);
    }
}

} // namespace mng::proxy
