#include "mcp_native_guard/security/policy.hpp"

#include <algorithm>
#include <utility>

namespace mng::security {

Status PolicyTable::build(
    std::vector<ToolRule> rules,
    PolicyDefaults defaults,
    PolicyTable& output) {
    for (const ToolRule& rule : rules) {
        if (rule.name.empty()) {
            return {StatusCode::invalid_argument, "tool rule name must not be empty"};
        }
    }

    std::sort(rules.begin(), rules.end(), [](const ToolRule& left, const ToolRule& right) {
        return left.name < right.name;
    });
    const auto duplicate = std::adjacent_find(
        rules.begin(), rules.end(), [](const ToolRule& left, const ToolRule& right) {
            return left.name == right.name;
        });
    if (duplicate != rules.end()) {
        return {StatusCode::duplicate_rule, "duplicate tool rule"};
    }

    PolicyTable candidate;
    candidate.rules_ = std::move(rules);
    candidate.defaults_ = defaults;
    output = std::move(candidate);
    return Status::success();
}

Access PolicyTable::visibility_for(std::string_view tool_name) const noexcept {
    const ToolRule* const rule = find(tool_name);
    return rule == nullptr ? defaults_.visible : rule->visible;
}

Access PolicyTable::invocation_for(std::string_view tool_name) const noexcept {
    const ToolRule* const rule = find(tool_name);
    return rule == nullptr ? defaults_.callable : rule->callable;
}

const ToolRule* PolicyTable::find(std::string_view tool_name) const noexcept {
    const auto position = std::lower_bound(
        rules_.begin(), rules_.end(), tool_name,
        [](const ToolRule& rule, std::string_view requested_name) {
            return std::string_view{rule.name} < requested_name;
        });
    if (position == rules_.end() || std::string_view{position->name} != tool_name) {
        return nullptr;
    }
    return &*position;
}

} // namespace mng::security
