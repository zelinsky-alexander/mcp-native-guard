#include "mcp_native_guard/security/policy_loader.hpp"

#include "json_scanner.hpp"

#include <algorithm>
#include <fstream>
#include <limits>
#include <string>
#include <utility>

namespace mng::security {
namespace {

using protocol::internal::StringToken;
using protocol::internal::scan_number;
using protocol::internal::scan_string;
using protocol::internal::skip_value;
using protocol::internal::skip_whitespace;

[[nodiscard]] constexpr PolicyLoadResult fail(
    PolicyLoadError error,
    std::string_view message) noexcept {
    return {error, message};
}

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

[[nodiscard]] PolicyLoadResult parse_access(
    std::string_view json,
    std::size_t& offset,
    Access& output) noexcept {
    StringToken value;
    if (!scan_string(json, offset, value) || value.has_escape) {
        return fail(PolicyLoadError::invalid_access, "access must be 'allow' or 'deny'");
    }
    if (value.contents == "allow") {
        output = Access::allow;
        return {};
    }
    if (value.contents == "deny") {
        output = Access::deny;
        return {};
    }
    return fail(PolicyLoadError::invalid_access, "access must be 'allow' or 'deny'");
}

[[nodiscard]] PolicyLoadResult parse_defaults(
    std::string_view json,
    std::size_t& offset,
    std::size_t max_depth,
    PolicyDefaults& defaults) noexcept {
    if (max_depth < 2U || offset >= json.size() || json[offset++] != '{') {
        return fail(PolicyLoadError::missing_defaults, "defaults must be an object");
    }
    bool saw_visibility = false;
    bool saw_invocation = false;
    skip_whitespace(json, offset);
    while (offset < json.size() && json[offset] != '}') {
        StringToken key;
        if (!scan_string(json, offset, key) || key.has_escape) {
            return fail(PolicyLoadError::malformed_json, "malformed policy JSON");
        }
        skip_whitespace(json, offset);
        if (offset >= json.size() || json[offset++] != ':') {
            return fail(PolicyLoadError::malformed_json, "malformed policy JSON");
        }
        skip_whitespace(json, offset);
        if (key.contents == "visibility") {
            if (saw_visibility) {
                return fail(PolicyLoadError::duplicate_member, "duplicate defaults.visibility");
            }
            saw_visibility = true;
            const auto result = parse_access(json, offset, defaults.visible);
            if (!result) {
                return result;
            }
        } else if (key.contents == "invocation") {
            if (saw_invocation) {
                return fail(PolicyLoadError::duplicate_member, "duplicate defaults.invocation");
            }
            saw_invocation = true;
            const auto result = parse_access(json, offset, defaults.callable);
            if (!result) {
                return result;
            }
        } else if (!skip_value(json, offset, 2U, max_depth)) {
            return fail(PolicyLoadError::malformed_json, "malformed policy JSON");
        }
        skip_whitespace(json, offset);
        if (offset >= json.size()) {
            return fail(PolicyLoadError::malformed_json, "malformed policy JSON");
        }
        if (json[offset] == '}') {
            break;
        }
        if (json[offset++] != ',') {
            return fail(PolicyLoadError::malformed_json, "malformed policy JSON");
        }
        skip_whitespace(json, offset);
        if (offset < json.size() && json[offset] == '}') {
            return fail(PolicyLoadError::malformed_json, "malformed policy JSON");
        }
    }
    if (offset >= json.size() || json[offset++] != '}') {
        return fail(PolicyLoadError::malformed_json, "malformed policy JSON");
    }
    if (!saw_visibility || !saw_invocation) {
        return fail(
            PolicyLoadError::missing_defaults,
            "defaults.visibility and defaults.invocation are required");
    }
    return {};
}

[[nodiscard]] PolicyLoadResult parse_tool(
    std::string_view json,
    std::size_t& offset,
    std::size_t max_depth,
    ToolRule& tool) {
    if (max_depth < 3U || offset >= json.size() || json[offset++] != '{') {
        return fail(PolicyLoadError::invalid_tool, "each tools entry must be an object");
    }
    bool saw_name = false;
    bool saw_visibility = false;
    bool saw_invocation = false;
    skip_whitespace(json, offset);
    while (offset < json.size() && json[offset] != '}') {
        StringToken key;
        if (!scan_string(json, offset, key) || key.has_escape) {
            return fail(PolicyLoadError::malformed_json, "malformed policy JSON");
        }
        skip_whitespace(json, offset);
        if (offset >= json.size() || json[offset++] != ':') {
            return fail(PolicyLoadError::malformed_json, "malformed policy JSON");
        }
        skip_whitespace(json, offset);
        if (key.contents == "name") {
            if (saw_name) {
                return fail(PolicyLoadError::duplicate_member, "duplicate tool name member");
            }
            saw_name = true;
            StringToken name;
            if (!scan_string(json, offset, name)) {
                return fail(PolicyLoadError::invalid_tool, "tool name must be a non-empty string");
            }
            if (name.has_escape) {
                return fail(
                    PolicyLoadError::escaped_tool_name,
                    "escaped tool names are not supported");
            }
            if (name.contents.empty()) {
                return fail(PolicyLoadError::invalid_tool, "tool name must not be empty");
            }
            tool.name.assign(name.contents);
        } else if (key.contents == "visibility") {
            if (saw_visibility) {
                return fail(PolicyLoadError::duplicate_member, "duplicate tool visibility member");
            }
            saw_visibility = true;
            const auto result = parse_access(json, offset, tool.visible);
            if (!result) {
                return result;
            }
        } else if (key.contents == "invocation") {
            if (saw_invocation) {
                return fail(PolicyLoadError::duplicate_member, "duplicate tool invocation member");
            }
            saw_invocation = true;
            const auto result = parse_access(json, offset, tool.callable);
            if (!result) {
                return result;
            }
        } else if (!skip_value(json, offset, 3U, max_depth)) {
            return fail(PolicyLoadError::malformed_json, "malformed policy JSON");
        }
        skip_whitespace(json, offset);
        if (offset >= json.size()) {
            return fail(PolicyLoadError::malformed_json, "malformed policy JSON");
        }
        if (json[offset] == '}') {
            break;
        }
        if (json[offset++] != ',') {
            return fail(PolicyLoadError::malformed_json, "malformed policy JSON");
        }
        skip_whitespace(json, offset);
        if (offset < json.size() && json[offset] == '}') {
            return fail(PolicyLoadError::malformed_json, "malformed policy JSON");
        }
    }
    if (offset >= json.size() || json[offset++] != '}') {
        return fail(PolicyLoadError::malformed_json, "malformed policy JSON");
    }
    if (!saw_name || !saw_visibility || !saw_invocation) {
        return fail(
            PolicyLoadError::invalid_tool,
            "tool name, visibility, and invocation are required");
    }
    return {};
}

[[nodiscard]] PolicyLoadResult parse_tools(
    std::string_view json,
    std::size_t& offset,
    std::size_t max_depth,
    std::vector<ToolRule>& tools) {
    if (max_depth < 2U || offset >= json.size() || json[offset++] != '[') {
        return fail(PolicyLoadError::tools_not_array, "tools must be an array");
    }
    skip_whitespace(json, offset);
    if (offset < json.size() && json[offset] == ']') {
        ++offset;
        return {};
    }
    while (offset < json.size()) {
        ToolRule tool;
        const auto result = parse_tool(json, offset, max_depth, tool);
        if (!result) {
            return result;
        }
        tools.push_back(std::move(tool));
        skip_whitespace(json, offset);
        if (offset >= json.size()) {
            return fail(PolicyLoadError::malformed_json, "malformed policy JSON");
        }
        if (json[offset] == ']') {
            ++offset;
            return {};
        }
        if (json[offset++] != ',') {
            return fail(PolicyLoadError::malformed_json, "malformed policy JSON");
        }
        skip_whitespace(json, offset);
        if (offset < json.size() && json[offset] == ']') {
            return fail(PolicyLoadError::malformed_json, "malformed policy JSON");
        }
    }
    return fail(PolicyLoadError::malformed_json, "malformed policy JSON");
}

} // namespace

PolicyLoader::PolicyLoader() : PolicyLoader(Config{}) {}

PolicyLoader::PolicyLoader(Config config) noexcept : config_{config} {}

PolicyLoadResult PolicyLoader::load_file(
    std::string_view path,
    PolicyDefinition& output) const {
    if (path.empty() || config_.max_file_bytes == 0U ||
        config_.max_file_bytes >= static_cast<std::size_t>(std::numeric_limits<std::streamsize>::max())) {
        return fail(PolicyLoadError::io_error, "invalid policy file configuration");
    }
    try {
        std::ifstream input{std::string{path}, std::ios::binary};
        if (!input) {
            return fail(PolicyLoadError::io_error, "cannot open policy file");
        }
        std::string json(config_.max_file_bytes + 1U, '\0');
        input.read(json.data(), static_cast<std::streamsize>(json.size()));
        const auto received = input.gcount();
        if (received < 0 || input.bad()) {
            return fail(PolicyLoadError::io_error, "failed to read policy file");
        }
        if (static_cast<std::size_t>(received) > config_.max_file_bytes) {
            return fail(PolicyLoadError::file_too_large, "policy file exceeds configured size limit");
        }
        json.resize(static_cast<std::size_t>(received));
        return parse(json, output);
    } catch (...) {
        return fail(PolicyLoadError::allocation_failure, "failed to allocate policy storage");
    }
}

PolicyLoadResult PolicyLoader::parse(
    std::string_view json,
    PolicyDefinition& output) const {
    if (json.size() > config_.max_file_bytes) {
        return fail(PolicyLoadError::file_too_large, "policy exceeds configured size limit");
    }
    if (exceeds_nesting(json, config_.max_nesting_depth)) {
        return fail(PolicyLoadError::excessive_nesting, "policy exceeds configured nesting limit");
    }

    try {
        PolicyDefinition candidate;
        std::size_t offset = 0;
        bool saw_version = false;
        bool saw_defaults = false;
        bool saw_tools = false;
        skip_whitespace(json, offset);
        if (offset >= json.size() || json[offset++] != '{') {
            return fail(PolicyLoadError::malformed_json, "policy must be a JSON object");
        }
        skip_whitespace(json, offset);
        while (offset < json.size() && json[offset] != '}') {
            StringToken key;
            if (!scan_string(json, offset, key) || key.has_escape) {
                return fail(PolicyLoadError::malformed_json, "malformed policy JSON");
            }
            skip_whitespace(json, offset);
            if (offset >= json.size() || json[offset++] != ':') {
                return fail(PolicyLoadError::malformed_json, "malformed policy JSON");
            }
            skip_whitespace(json, offset);
            if (key.contents == "version") {
                if (saw_version) {
                    return fail(PolicyLoadError::duplicate_member, "duplicate policy version");
                }
                saw_version = true;
                const std::size_t version_begin = offset;
                if (!scan_number(json, offset) || json.substr(version_begin, offset - version_begin) != "1") {
                    return fail(PolicyLoadError::unsupported_version, "policy version must be 1");
                }
            } else if (key.contents == "defaults") {
                if (saw_defaults) {
                    return fail(PolicyLoadError::duplicate_member, "duplicate policy defaults");
                }
                saw_defaults = true;
                const auto result = parse_defaults(
                    json, offset, config_.max_nesting_depth, candidate.defaults);
                if (!result) {
                    return result;
                }
            } else if (key.contents == "tools") {
                if (saw_tools) {
                    return fail(PolicyLoadError::duplicate_member, "duplicate policy tools");
                }
                saw_tools = true;
                const auto result = parse_tools(
                    json, offset, config_.max_nesting_depth, candidate.rules);
                if (!result) {
                    return result;
                }
            } else if (!skip_value(json, offset, 1U, config_.max_nesting_depth)) {
                return fail(PolicyLoadError::malformed_json, "malformed policy JSON");
            }
            skip_whitespace(json, offset);
            if (offset >= json.size()) {
                return fail(PolicyLoadError::malformed_json, "malformed policy JSON");
            }
            if (json[offset] == '}') {
                break;
            }
            if (json[offset++] != ',') {
                return fail(PolicyLoadError::malformed_json, "malformed policy JSON");
            }
            skip_whitespace(json, offset);
            if (offset < json.size() && json[offset] == '}') {
                return fail(PolicyLoadError::malformed_json, "malformed policy JSON");
            }
        }
        if (offset >= json.size() || json[offset++] != '}') {
            return fail(PolicyLoadError::malformed_json, "malformed policy JSON");
        }
        skip_whitespace(json, offset);
        if (offset != json.size()) {
            return fail(PolicyLoadError::malformed_json, "trailing data after policy object");
        }
        if (!saw_version) {
            return fail(PolicyLoadError::unsupported_version, "policy version must be 1");
        }
        if (!saw_defaults) {
            return fail(PolicyLoadError::missing_defaults, "policy defaults are required");
        }

        std::sort(candidate.rules.begin(), candidate.rules.end(), [](const ToolRule& left, const ToolRule& right) {
            return left.name < right.name;
        });
        const auto duplicate = std::adjacent_find(
            candidate.rules.begin(), candidate.rules.end(), [](const ToolRule& left, const ToolRule& right) {
                return left.name == right.name;
            });
        if (duplicate != candidate.rules.end()) {
            return fail(PolicyLoadError::duplicate_tool_name, "duplicate tool name in policy");
        }
        output = std::move(candidate);
        return {};
    } catch (...) {
        return fail(PolicyLoadError::allocation_failure, "failed to allocate parsed policy");
    }
}

PolicyLoadResult apply_deny_overrides(
    std::vector<std::string> denied_tools,
    PolicyDefinition& policy) {
    try {
        for (std::string& denied_name : denied_tools) {
            const auto rule = std::find_if(
                policy.rules.begin(),
                policy.rules.end(),
                [&](const ToolRule& candidate) { return candidate.name == denied_name; });
            if (rule == policy.rules.end()) {
                policy.rules.push_back({
                    std::move(denied_name),
                    Access::deny,
                    Access::deny,
                });
            } else {
                rule->visible = Access::deny;
                rule->callable = Access::deny;
            }
        }
        return {};
    } catch (...) {
        return fail(PolicyLoadError::allocation_failure, "failed to allocate deny overrides");
    }
}

} // namespace mng::security
