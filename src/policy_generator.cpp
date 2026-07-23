#include "mcp_native_guard/security/policy_generator.hpp"

#include "json_scanner.hpp"
#include "mcp_native_guard/security/policy.hpp"

#include <array>
#include <utility>

namespace mng::security {
namespace {

using protocol::internal::StringToken;
using protocol::internal::scan_number;
using protocol::internal::scan_string;
using protocol::internal::skip_value;
using protocol::internal::skip_whitespace;

[[nodiscard]] PolicyGenerateResult fail(PolicyGenerateError error) noexcept {
    PolicyGenerateResult result;
    result.error = error;
    return result;
}

// Lightweight bracket-depth pre-scan over the whole document, ignoring string
// contents. Bounds recursion in the structured parse below: once this passes,
// every skip_value call site in the structured parse operates within
// max_depth, so a later skip_value failure can only be malformed JSON.
[[nodiscard]] bool exceeds_nesting(std::string_view json, std::size_t max_depth) noexcept {
    std::size_t offset = 0;
    std::size_t depth = 0;
    while (offset < json.size()) {
        if (json[offset] == '"') {
            StringToken token;
            if (!scan_string(json, offset, token)) {
                return false;
            }
            continue;
        }
        if (json[offset] == '{' || json[offset] == '[') {
            ++depth;
            if (depth > max_depth) {
                return true;
            }
        } else if ((json[offset] == '}' || json[offset] == ']') && depth > 0U) {
            --depth;
        }
        ++offset;
    }
    return false;
}

// Defensive JSON string escaper for tool names in generated output. Names
// that survive validation below can never contain characters that require
// escaping (any escape sequence is rejected as escaped_tool_name, and an
// unescaped '"' would already have ended the scanned string), but this keeps
// emission correct independent of that invariant.
void append_json_escaped_string(std::string& output, std::string_view value) {
    constexpr std::array<char, 16> hex{
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    output.push_back('"');
    for (const char character_value : value) {
        const auto byte = static_cast<unsigned char>(character_value);
        if (byte == '"' || byte == '\\') {
            output.push_back('\\');
            output.push_back(static_cast<char>(byte));
        } else if (byte == '\b' || byte == '\f' || byte == '\n' || byte == '\r' || byte == '\t') {
            char escape = 'b';
            if (byte == '\f') {
                escape = 'f';
            } else if (byte == '\n') {
                escape = 'n';
            } else if (byte == '\r') {
                escape = 'r';
            } else if (byte == '\t') {
                escape = 't';
            }
            output.push_back('\\');
            output.push_back(escape);
        } else if (byte < 0x20U) {
            output.push_back('\\');
            output.push_back('u');
            output.push_back('0');
            output.push_back('0');
            output.push_back(hex[byte >> 4U]);
            output.push_back(hex[byte & 0x0fU]);
        } else {
            output.push_back(static_cast<char>(byte));
        }
    }
    output.push_back('"');
}

[[nodiscard]] PolicyGenerateError parse_tool_name(
    std::string_view json,
    std::size_t& offset,
    const PolicyGeneratorLimits& limits,
    std::string& name) {
    if (offset >= json.size() || json[offset++] != '{') {
        return PolicyGenerateError::malformed_inventory_json;
    }

    bool saw_name = false;
    skip_whitespace(json, offset);
    if (offset < json.size() && json[offset] == '}') {
        ++offset;
        return PolicyGenerateError::missing_tool_name;
    }

    while (offset < json.size()) {
        StringToken key;
        if (!scan_string(json, offset, key) || key.has_escape) {
            return PolicyGenerateError::malformed_inventory_json;
        }
        skip_whitespace(json, offset);
        if (offset >= json.size() || json[offset++] != ':') {
            return PolicyGenerateError::malformed_inventory_json;
        }
        skip_whitespace(json, offset);

        if (key.contents == "name") {
            if (saw_name) {
                return PolicyGenerateError::duplicate_member;
            }
            saw_name = true;
            if (offset >= json.size() || json[offset] != '"') {
                return PolicyGenerateError::non_string_tool_name;
            }
            StringToken value;
            if (!scan_string(json, offset, value)) {
                return PolicyGenerateError::malformed_inventory_json;
            }
            if (value.has_escape) {
                return PolicyGenerateError::escaped_tool_name;
            }
            if (value.contents.empty()) {
                return PolicyGenerateError::empty_tool_name;
            }
            if (value.contents.size() > limits.max_tool_name_bytes) {
                return PolicyGenerateError::oversized_tool_name;
            }
            name.assign(value.contents.data(), value.contents.size());
        } else if (!skip_value(json, offset, 3U, limits.max_nesting_depth)) {
            return PolicyGenerateError::malformed_inventory_json;
        }

        skip_whitespace(json, offset);
        if (offset >= json.size()) {
            return PolicyGenerateError::malformed_inventory_json;
        }
        if (json[offset] == '}') {
            ++offset;
            return saw_name ? PolicyGenerateError::none : PolicyGenerateError::missing_tool_name;
        }
        if (json[offset++] != ',') {
            return PolicyGenerateError::malformed_inventory_json;
        }
        skip_whitespace(json, offset);
        if (offset < json.size() && json[offset] == '}') {
            return PolicyGenerateError::malformed_inventory_json;
        }
    }
    return PolicyGenerateError::malformed_inventory_json;
}

[[nodiscard]] PolicyGenerateError parse_tools_array(
    std::string_view json,
    std::size_t& offset,
    const PolicyGeneratorLimits& limits,
    std::vector<std::string>& names) {
    if (offset >= json.size() || json[offset++] != '[') {
        return PolicyGenerateError::tools_not_array;
    }
    skip_whitespace(json, offset);
    if (offset < json.size() && json[offset] == ']') {
        ++offset;
        return PolicyGenerateError::none;
    }

    while (offset < json.size()) {
        if (names.size() >= limits.max_tools) {
            return PolicyGenerateError::excessive_tool_count;
        }
        std::string name;
        const auto status = parse_tool_name(json, offset, limits, name);
        if (status != PolicyGenerateError::none) {
            return status;
        }
        for (const auto& existing : names) {
            if (existing == name) {
                return PolicyGenerateError::duplicate_tool_name;
            }
        }
        names.push_back(std::move(name));

        skip_whitespace(json, offset);
        if (offset >= json.size()) {
            return PolicyGenerateError::malformed_inventory_json;
        }
        if (json[offset] == ']') {
            ++offset;
            return PolicyGenerateError::none;
        }
        if (json[offset++] != ',') {
            return PolicyGenerateError::malformed_inventory_json;
        }
        skip_whitespace(json, offset);
        if (offset < json.size() && json[offset] == ']') {
            return PolicyGenerateError::malformed_inventory_json;
        }
    }
    return PolicyGenerateError::malformed_inventory_json;
}

[[nodiscard]] PolicyGenerateError parse_inventory_document(
    std::string_view json,
    const PolicyGeneratorLimits& limits,
    std::vector<std::string>& tool_names) {
    std::size_t offset = 0;
    bool saw_version = false;
    bool saw_server = false;
    bool saw_tools = false;

    skip_whitespace(json, offset);
    if (offset >= json.size() || json[offset++] != '{') {
        return PolicyGenerateError::malformed_inventory_json;
    }
    skip_whitespace(json, offset);
    if (offset < json.size() && json[offset] == '}') {
        ++offset;
    } else {
        while (offset < json.size()) {
            StringToken key;
            if (!scan_string(json, offset, key) || key.has_escape) {
                return PolicyGenerateError::malformed_inventory_json;
            }
            skip_whitespace(json, offset);
            if (offset >= json.size() || json[offset++] != ':') {
                return PolicyGenerateError::malformed_inventory_json;
            }
            skip_whitespace(json, offset);

            if (key.contents == "inventory_version") {
                if (saw_version) {
                    return PolicyGenerateError::duplicate_member;
                }
                saw_version = true;
                const std::size_t version_begin = offset;
                if (!scan_number(json, offset) ||
                    json.substr(version_begin, offset - version_begin) != "1") {
                    return PolicyGenerateError::unsupported_inventory_version;
                }
            } else if (key.contents == "server") {
                if (saw_server) {
                    return PolicyGenerateError::duplicate_member;
                }
                saw_server = true;
                if (offset >= json.size() || json[offset] != '{') {
                    return PolicyGenerateError::invalid_server;
                }
                if (!skip_value(json, offset, 1U, limits.max_nesting_depth)) {
                    return PolicyGenerateError::malformed_inventory_json;
                }
            } else if (key.contents == "tools") {
                if (saw_tools) {
                    return PolicyGenerateError::duplicate_member;
                }
                saw_tools = true;
                if (offset >= json.size() || json[offset] != '[') {
                    return PolicyGenerateError::tools_not_array;
                }
                const auto status = parse_tools_array(json, offset, limits, tool_names);
                if (status != PolicyGenerateError::none) {
                    return status;
                }
            } else if (!skip_value(json, offset, 1U, limits.max_nesting_depth)) {
                return PolicyGenerateError::malformed_inventory_json;
            }

            skip_whitespace(json, offset);
            if (offset >= json.size()) {
                return PolicyGenerateError::malformed_inventory_json;
            }
            if (json[offset] == '}') {
                ++offset;
                break;
            }
            if (json[offset++] != ',') {
                return PolicyGenerateError::malformed_inventory_json;
            }
            skip_whitespace(json, offset);
            if (offset < json.size() && json[offset] == '}') {
                return PolicyGenerateError::malformed_inventory_json;
            }
        }
    }

    skip_whitespace(json, offset);
    if (offset != json.size()) {
        return PolicyGenerateError::malformed_inventory_json;
    }
    if (!saw_version) {
        return PolicyGenerateError::missing_inventory_version;
    }
    if (!saw_server) {
        return PolicyGenerateError::missing_server;
    }
    if (!saw_tools) {
        return PolicyGenerateError::missing_tools;
    }
    return PolicyGenerateError::none;
}

} // namespace

PolicyGenerateResult generate_policy_from_inventory(
    std::string_view inventory_json,
    const std::vector<std::string_view>& allow_tool_names,
    const PolicyGeneratorLimits& limits) {
    if (inventory_json.size() > limits.max_inventory_bytes) {
        return fail(PolicyGenerateError::inventory_too_large);
    }
    if (exceeds_nesting(inventory_json, limits.max_nesting_depth)) {
        return fail(PolicyGenerateError::excessive_nesting);
    }

    try {
        std::vector<std::string> tool_names;
        const auto parse_status = parse_inventory_document(inventory_json, limits, tool_names);
        if (parse_status != PolicyGenerateError::none) {
            return fail(parse_status);
        }

        for (std::size_t left = 0; left < allow_tool_names.size(); ++left) {
            for (std::size_t right = left + 1U; right < allow_tool_names.size(); ++right) {
                if (allow_tool_names[left] == allow_tool_names[right]) {
                    PolicyGenerateResult result = fail(PolicyGenerateError::duplicate_allow_tool);
                    result.offending_tool_name.assign(
                        allow_tool_names[left].data(), allow_tool_names[left].size());
                    return result;
                }
            }
        }

        std::vector<ToolRule> rules;
        rules.reserve(allow_tool_names.size());
        for (const std::string_view requested : allow_tool_names) {
            bool found = false;
            for (const auto& known : tool_names) {
                if (known == requested) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                PolicyGenerateResult result = fail(PolicyGenerateError::unknown_allow_tool);
                result.offending_tool_name.assign(requested.data(), requested.size());
                return result;
            }
            rules.push_back(ToolRule{
                std::string{requested.data(), requested.size()}, Access::allow, Access::allow});
        }

        PolicyTable table;
        const auto build_status = PolicyTable::build(
            std::move(rules), PolicyDefaults{Access::deny, Access::deny}, table);
        if (!build_status) {
            return fail(PolicyGenerateError::duplicate_allow_tool);
        }

        std::string json;
        json.reserve(64U + table.rule_count() * 48U);
        json.append(R"({"version":1,"defaults":{"visibility":"deny","invocation":"deny"},"tools":[)");
        bool first = true;
        for (const ToolRule& rule : table.rules()) {
            if (!first) {
                json.push_back(',');
            }
            first = false;
            json.append(R"({"name":)");
            append_json_escaped_string(json, rule.name);
            json.append(R"(,"visibility":"allow","invocation":"allow"})");
        }
        json.append("]}");

        PolicyGenerateResult result;
        result.policy_json = std::move(json);
        return result;
    } catch (...) {
        return fail(PolicyGenerateError::allocation_failure);
    }
}

const char* policy_generate_error_name(PolicyGenerateError error) noexcept {
    switch (error) {
    case PolicyGenerateError::none:
        return "none";
    case PolicyGenerateError::inventory_too_large:
        return "inventory_too_large";
    case PolicyGenerateError::excessive_nesting:
        return "excessive_nesting";
    case PolicyGenerateError::malformed_inventory_json:
        return "malformed_inventory_json";
    case PolicyGenerateError::missing_inventory_version:
        return "missing_inventory_version";
    case PolicyGenerateError::unsupported_inventory_version:
        return "unsupported_inventory_version";
    case PolicyGenerateError::duplicate_member:
        return "duplicate_member";
    case PolicyGenerateError::missing_server:
        return "missing_server";
    case PolicyGenerateError::invalid_server:
        return "invalid_server";
    case PolicyGenerateError::missing_tools:
        return "missing_tools";
    case PolicyGenerateError::tools_not_array:
        return "tools_not_array";
    case PolicyGenerateError::missing_tool_name:
        return "missing_tool_name";
    case PolicyGenerateError::non_string_tool_name:
        return "non_string_tool_name";
    case PolicyGenerateError::escaped_tool_name:
        return "escaped_tool_name";
    case PolicyGenerateError::empty_tool_name:
        return "empty_tool_name";
    case PolicyGenerateError::oversized_tool_name:
        return "oversized_tool_name";
    case PolicyGenerateError::duplicate_tool_name:
        return "duplicate_tool_name";
    case PolicyGenerateError::excessive_tool_count:
        return "excessive_tool_count";
    case PolicyGenerateError::duplicate_allow_tool:
        return "duplicate_allow_tool";
    case PolicyGenerateError::unknown_allow_tool:
        return "unknown_allow_tool";
    case PolicyGenerateError::allocation_failure:
        return "allocation_failure";
    }
    return "unknown";
}

} // namespace mng::security
