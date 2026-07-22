#include "mcp_native_guard/security/policy.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdint>
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

std::string PolicyTable::fingerprint() const {
    std::uint64_t value = 14695981039346656037ULL;
    const auto consume = [&value](std::string_view bytes) {
        for (const unsigned char byte : bytes) {
            value ^= byte;
            value *= 1099511628211ULL;
        }
    };
    consume("mng-effective-policy-v1\0");
    const char defaults[] = {
        static_cast<char>(defaults_.visible), static_cast<char>(defaults_.callable)};
    consume({defaults, sizeof(defaults)});
    for (const auto& rule : rules_) {
        std::array<char, 32> length{};
        const auto result = std::to_chars(length.data(), length.data() + length.size(), rule.name.size());
        consume({length.data(), static_cast<std::size_t>(result.ptr - length.data())});
        consume(":");
        consume(rule.name);
        const char access[] = {static_cast<char>(rule.visible), static_cast<char>(rule.callable)};
        consume({access, sizeof(access)});
    }
    std::array<char, 16> encoded{};
    constexpr char hex[] = "0123456789abcdef";
    for (std::size_t index = 0; index < encoded.size(); ++index) {
        encoded[encoded.size() - index - 1U] = hex[value & 0x0fU];
        value >>= 4U;
    }
    return "fnv1a64:" + std::string{encoded.data(), encoded.size()};
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
