#include "mcp_native_guard/protocol/tool_inventory.hpp"

#include "json_scanner.hpp"

#include <algorithm>
#include <array>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace mng::protocol {
namespace {

using internal::StringToken;
using internal::scan_string;
using internal::skip_value;
using internal::skip_whitespace;

[[nodiscard]] bool append_bytes(
    std::string& output,
    std::string_view value,
    std::size_t limit) {
    if (output.size() > limit || value.size() > limit - output.size()) {
        return false;
    }
    output.append(value);
    return true;
}

[[nodiscard]] bool append_json_string(
    std::string& output,
    std::string_view value,
    std::size_t limit) {
    constexpr std::array<char, 16> hex{
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    if (!append_bytes(output, "\"", limit)) {
        return false;
    }
    for (const char character_value : value) {
        const auto byte = static_cast<unsigned char>(character_value);
        if (byte == '"' || byte == '\\') {
            const std::array<char, 2> escaped{'\\', static_cast<char>(byte)};
            if (!append_bytes(output, {escaped.data(), escaped.size()}, limit)) {
                return false;
            }
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
            const std::array<char, 2> escaped{'\\', escape};
            if (!append_bytes(output, {escaped.data(), escaped.size()}, limit)) {
                return false;
            }
        } else if (byte < 0x20U) {
            const std::array<char, 6> escaped{
                '\\', 'u', '0', '0', hex[byte >> 4U], hex[byte & 0x0fU]};
            if (!append_bytes(output, {escaped.data(), escaped.size()}, limit)) {
                return false;
            }
        } else {
            const char character = static_cast<char>(byte);
            if (!append_bytes(output, std::string_view{&character, 1U}, limit)) {
                return false;
            }
        }
    }
    return append_bytes(output, "\"", limit);
}

struct ResponseShape final {
    bool saw_result{false};
    bool saw_error{false};
    std::string_view id_json{};
    InventoryError error{InventoryError::none};
};

[[nodiscard]] ResponseShape classify_response_shape(
    std::string_view message,
    std::size_t max_nesting_depth) noexcept {
    ResponseShape shape;
    if (message.size() == 0U) {
        shape.error = InventoryError::malformed_json;
        return shape;
    }
    std::size_t offset = 0;
    skip_whitespace(message, offset);
    if (offset >= message.size() || message[offset++] != '{') {
        shape.error = InventoryError::malformed_json;
        return shape;
    }

    bool saw_jsonrpc = false;
    bool saw_id = false;
    bool saw_method = false;
    skip_whitespace(message, offset);
    if (offset < message.size() && message[offset] == '}') {
        ++offset;
    } else {
        while (offset < message.size()) {
            StringToken key;
            if (!scan_string(message, offset, key) || key.has_escape) {
                shape.error = InventoryError::malformed_json;
                return shape;
            }
            skip_whitespace(message, offset);
            if (offset >= message.size() || message[offset++] != ':') {
                shape.error = InventoryError::malformed_json;
                return shape;
            }
            skip_whitespace(message, offset);

            if (key.contents == "jsonrpc") {
                if (saw_jsonrpc) {
                    shape.error = InventoryError::duplicate_member;
                    return shape;
                }
                saw_jsonrpc = true;
                StringToken version;
                if (!scan_string(message, offset, version) || version.has_escape ||
                    version.contents != "2.0") {
                    shape.error = InventoryError::unsupported_jsonrpc_version;
                    return shape;
                }
            } else if (key.contents == "id") {
                if (saw_id) {
                    shape.error = InventoryError::duplicate_member;
                    return shape;
                }
                saw_id = true;
                const std::size_t id_begin = offset;
                if (offset < message.size() && message[offset] == '"') {
                    StringToken value;
                    if (!scan_string(message, offset, value)) {
                        shape.error = InventoryError::malformed_json;
                        return shape;
                    }
                } else if (
                    (offset < message.size() && message[offset] == 'n' &&
                     internal::scan_literal(message, offset, "null")) ||
                    internal::scan_number(message, offset)) {
                    // accepted
                } else {
                    shape.error = InventoryError::invalid_envelope;
                    return shape;
                }
                shape.id_json = message.substr(id_begin, offset - id_begin);
            } else if (key.contents == "method") {
                if (saw_method) {
                    shape.error = InventoryError::duplicate_member;
                    return shape;
                }
                saw_method = true;
                StringToken value;
                if (!scan_string(message, offset, value) || value.has_escape || value.contents.empty()) {
                    shape.error = InventoryError::invalid_envelope;
                    return shape;
                }
            } else if (key.contents == "result") {
                if (shape.saw_result) {
                    shape.error = InventoryError::duplicate_member;
                    return shape;
                }
                shape.saw_result = true;
                if (!skip_value(message, offset, 1U, max_nesting_depth)) {
                    shape.error = InventoryError::excessive_nesting;
                    return shape;
                }
            } else if (key.contents == "error") {
                if (shape.saw_error) {
                    shape.error = InventoryError::duplicate_member;
                    return shape;
                }
                shape.saw_error = true;
                if (!skip_value(message, offset, 1U, max_nesting_depth)) {
                    shape.error = InventoryError::excessive_nesting;
                    return shape;
                }
            } else if (!skip_value(message, offset, 1U, max_nesting_depth)) {
                shape.error = InventoryError::excessive_nesting;
                return shape;
            }

            skip_whitespace(message, offset);
            if (offset >= message.size()) {
                shape.error = InventoryError::malformed_json;
                return shape;
            }
            if (message[offset] == '}') {
                ++offset;
                break;
            }
            if (message[offset++] != ',') {
                shape.error = InventoryError::malformed_json;
                return shape;
            }
            skip_whitespace(message, offset);
        }
    }

    skip_whitespace(message, offset);
    if (offset != message.size()) {
        shape.error = InventoryError::malformed_json;
        return shape;
    }
    if (!saw_jsonrpc || saw_method || !saw_id || (shape.saw_result == shape.saw_error)) {
        shape.error = InventoryError::invalid_envelope;
        return shape;
    }
    return shape;
}

[[nodiscard]] bool append_limited(
    std::string& output,
    std::string_view value,
    std::size_t max_bytes) {
    if (output.size() > max_bytes || value.size() > max_bytes - output.size()) {
        return false;
    }
    output.append(value);
    return true;
}

[[nodiscard]] InventoryError canonicalize_value(
    std::string_view message,
    std::size_t& offset,
    std::size_t depth,
    std::size_t max_depth,
    std::size_t max_bytes,
    std::string& output);

[[nodiscard]] InventoryError canonicalize_object(
    std::string_view message,
    std::size_t& offset,
    std::size_t depth,
    std::size_t max_depth,
    std::size_t max_bytes,
    std::string& output) {
    if (depth > max_depth) {
        return InventoryError::excessive_nesting;
    }
    struct Member final {
        std::string key_contents{};
        std::string key_json{};
        std::string value_json{};
    };
    std::vector<Member> members;
    skip_whitespace(message, offset);
    if (offset < message.size() && message[offset] == '}') {
        ++offset;
        if (!append_limited(output, "{}", max_bytes)) {
            return InventoryError::oversized_schema;
        }
        return InventoryError::none;
    }
    while (offset < message.size()) {
        if (offset >= message.size() || message[offset] != '"') {
            return InventoryError::malformed_json;
        }
        const std::size_t key_begin = offset;
        StringToken key;
        if (!scan_string(message, offset, key)) {
            return InventoryError::malformed_json;
        }
        const std::string key_json{message.data() + key_begin, offset - key_begin};
        for (const auto& existing : members) {
            if (existing.key_contents == key.contents) {
                return InventoryError::duplicate_member;
            }
        }
        skip_whitespace(message, offset);
        if (offset >= message.size() || message[offset++] != ':') {
            return InventoryError::malformed_json;
        }
        skip_whitespace(message, offset);
        Member member;
        member.key_contents.assign(key.contents.data(), key.contents.size());
        member.key_json = key_json;
        const auto status = canonicalize_value(
            message, offset, depth + 1U, max_depth, max_bytes, member.value_json);
        if (status != InventoryError::none) {
            return status;
        }
        members.push_back(std::move(member));

        skip_whitespace(message, offset);
        if (offset >= message.size()) {
            return InventoryError::malformed_json;
        }
        if (message[offset] == '}') {
            ++offset;
            break;
        }
        if (message[offset++] != ',') {
            return InventoryError::malformed_json;
        }
        skip_whitespace(message, offset);
    }

    std::sort(members.begin(), members.end(), [](const Member& left, const Member& right) {
        return left.key_contents < right.key_contents;
    });

    if (!append_limited(output, "{", max_bytes)) {
        return InventoryError::oversized_schema;
    }
    for (std::size_t index = 0; index < members.size(); ++index) {
        if (index != 0U && !append_limited(output, ",", max_bytes)) {
            return InventoryError::oversized_schema;
        }
        if (!append_limited(output, members[index].key_json, max_bytes) ||
            !append_limited(output, ":", max_bytes) ||
            !append_limited(output, members[index].value_json, max_bytes)) {
            return InventoryError::oversized_schema;
        }
    }
    if (!append_limited(output, "}", max_bytes)) {
        return InventoryError::oversized_schema;
    }
    return InventoryError::none;
}

[[nodiscard]] InventoryError canonicalize_array(
    std::string_view message,
    std::size_t& offset,
    std::size_t depth,
    std::size_t max_depth,
    std::size_t max_bytes,
    std::string& output) {
    if (depth > max_depth) {
        return InventoryError::excessive_nesting;
    }
    if (!append_limited(output, "[", max_bytes)) {
        return InventoryError::oversized_schema;
    }
    skip_whitespace(message, offset);
    if (offset < message.size() && message[offset] == ']') {
        ++offset;
        if (!append_limited(output, "]", max_bytes)) {
            return InventoryError::oversized_schema;
        }
        return InventoryError::none;
    }
    bool first = true;
    while (offset < message.size()) {
        if (!first && !append_limited(output, ",", max_bytes)) {
            return InventoryError::oversized_schema;
        }
        first = false;
        const auto status =
            canonicalize_value(message, offset, depth + 1U, max_depth, max_bytes, output);
        if (status != InventoryError::none) {
            return status;
        }
        skip_whitespace(message, offset);
        if (offset >= message.size()) {
            return InventoryError::malformed_json;
        }
        if (message[offset] == ']') {
            ++offset;
            if (!append_limited(output, "]", max_bytes)) {
                return InventoryError::oversized_schema;
            }
            return InventoryError::none;
        }
        if (message[offset++] != ',') {
            return InventoryError::malformed_json;
        }
        skip_whitespace(message, offset);
    }
    return InventoryError::malformed_json;
}

[[nodiscard]] InventoryError canonicalize_value(
    std::string_view message,
    std::size_t& offset,
    std::size_t depth,
    std::size_t max_depth,
    std::size_t max_bytes,
    std::string& output) {
    if (depth > max_depth || offset >= message.size()) {
        return InventoryError::excessive_nesting;
    }
    if (message[offset] == '"') {
        const std::size_t begin = offset;
        StringToken token;
        if (!scan_string(message, offset, token)) {
            return InventoryError::malformed_json;
        }
        if (!append_limited(output, message.substr(begin, offset - begin), max_bytes)) {
            return InventoryError::oversized_schema;
        }
        return InventoryError::none;
    }
    if (message[offset] == '{') {
        ++offset;
        return canonicalize_object(message, offset, depth, max_depth, max_bytes, output);
    }
    if (message[offset] == '[') {
        ++offset;
        return canonicalize_array(message, offset, depth, max_depth, max_bytes, output);
    }
    if (message[offset] == 't') {
        if (!internal::scan_literal(message, offset, "true")) {
            return InventoryError::malformed_json;
        }
        if (!append_limited(output, "true", max_bytes)) {
            return InventoryError::oversized_schema;
        }
        return InventoryError::none;
    }
    if (message[offset] == 'f') {
        if (!internal::scan_literal(message, offset, "false")) {
            return InventoryError::malformed_json;
        }
        if (!append_limited(output, "false", max_bytes)) {
            return InventoryError::oversized_schema;
        }
        return InventoryError::none;
    }
    if (message[offset] == 'n') {
        if (!internal::scan_literal(message, offset, "null")) {
            return InventoryError::malformed_json;
        }
        if (!append_limited(output, "null", max_bytes)) {
            return InventoryError::oversized_schema;
        }
        return InventoryError::none;
    }
    const std::size_t begin = offset;
    if (!internal::scan_number(message, offset)) {
        return InventoryError::malformed_json;
    }
    if (!append_limited(output, message.substr(begin, offset - begin), max_bytes)) {
        return InventoryError::oversized_schema;
    }
    return InventoryError::none;
}

[[nodiscard]] InventoryError capture_canonical_value(
    std::string_view message,
    std::size_t& offset,
    std::size_t depth,
    std::size_t max_depth,
    std::size_t max_bytes,
    std::string& stored) {
    stored.clear();
    skip_whitespace(message, offset);
    const auto status =
        canonicalize_value(message, offset, depth, max_depth, max_bytes, stored);
    if (status != InventoryError::none) {
        stored.clear();
        return status;
    }
    if (stored.size() > max_bytes) {
        stored.clear();
        return InventoryError::oversized_schema;
    }
    return InventoryError::none;
}

[[nodiscard]] InventoryError parse_tool_object(
    std::string_view message,
    std::size_t& offset,
    const InventoryLimits& limits,
    ToolInventoryEntry& entry) {
    if (offset >= message.size() || message[offset++] != '{') {
        return InventoryError::malformed_json;
    }

    bool saw_name = false;
    bool saw_description = false;
    bool saw_input_schema = false;
    bool saw_annotations = false;

    skip_whitespace(message, offset);
    if (offset < message.size() && message[offset] == '}') {
        ++offset;
        return InventoryError::missing_tool_name;
    }

    while (offset < message.size()) {
        StringToken key;
        if (!scan_string(message, offset, key) || key.has_escape) {
            return InventoryError::malformed_json;
        }
        skip_whitespace(message, offset);
        if (offset >= message.size() || message[offset++] != ':') {
            return InventoryError::malformed_json;
        }
        skip_whitespace(message, offset);

        if (key.contents == "name") {
            if (saw_name) {
                return InventoryError::duplicate_member;
            }
            saw_name = true;
            if (offset >= message.size() || message[offset] != '"') {
                return InventoryError::non_string_tool_name;
            }
            StringToken value;
            if (!scan_string(message, offset, value)) {
                return InventoryError::malformed_json;
            }
            if (value.has_escape) {
                return InventoryError::escaped_tool_name;
            }
            if (value.contents.empty()) {
                return InventoryError::empty_tool_name;
            }
            if (value.contents.size() > limits.max_tool_name_bytes) {
                return InventoryError::oversized_tool_name;
            }
            entry.name.assign(value.contents.data(), value.contents.size());
        } else if (key.contents == "description") {
            if (saw_description) {
                return InventoryError::duplicate_member;
            }
            saw_description = true;
            if (offset >= message.size() || message[offset] != '"') {
                return InventoryError::malformed_json;
            }
            const std::size_t begin = offset;
            StringToken value;
            if (!scan_string(message, offset, value)) {
                return InventoryError::malformed_json;
            }
            const std::size_t size = offset - begin;
            if (value.contents.size() > limits.max_tool_description_bytes) {
                return InventoryError::oversized_description;
            }
            entry.description_json.assign(message.data() + begin, size);
        } else if (key.contents == "inputSchema") {
            if (saw_input_schema) {
                return InventoryError::duplicate_member;
            }
            saw_input_schema = true;
            const auto status = capture_canonical_value(
                message,
                offset,
                4U,
                limits.max_nesting_depth,
                limits.max_tool_schema_bytes,
                entry.input_schema_json);
            if (status != InventoryError::none) {
                return status;
            }
        } else if (key.contents == "annotations") {
            if (saw_annotations) {
                return InventoryError::duplicate_member;
            }
            saw_annotations = true;
            const auto status = capture_canonical_value(
                message,
                offset,
                4U,
                limits.max_nesting_depth,
                limits.max_tool_schema_bytes,
                entry.annotations_json);
            if (status != InventoryError::none) {
                return status;
            }
        } else if (!skip_value(message, offset, 4U, limits.max_nesting_depth)) {
            return InventoryError::excessive_nesting;
        }

        skip_whitespace(message, offset);
        if (offset >= message.size()) {
            return InventoryError::malformed_json;
        }
        if (message[offset] == '}') {
            ++offset;
            return saw_name ? InventoryError::none : InventoryError::missing_tool_name;
        }
        if (message[offset++] != ',') {
            return InventoryError::malformed_json;
        }
        skip_whitespace(message, offset);
    }
    return InventoryError::malformed_json;
}

[[nodiscard]] InventoryError parse_tools_array(
    std::string_view message,
    std::size_t& offset,
    const InventoryLimits& limits,
    std::vector<ToolInventoryEntry>& tools) {
    if (offset >= message.size() || message[offset++] != '[') {
        return InventoryError::tools_not_array;
    }
    skip_whitespace(message, offset);
    if (offset < message.size() && message[offset] == ']') {
        ++offset;
        return InventoryError::none;
    }

    while (offset < message.size()) {
        if (tools.size() >= limits.max_tools) {
            return InventoryError::excessive_tool_count;
        }
        ToolInventoryEntry entry;
        const auto status = parse_tool_object(message, offset, limits, entry);
        if (status != InventoryError::none) {
            return status;
        }
        for (const auto& existing : tools) {
            if (existing.name == entry.name) {
                return InventoryError::duplicate_tool_name;
            }
        }
        tools.push_back(std::move(entry));

        skip_whitespace(message, offset);
        if (offset >= message.size()) {
            return InventoryError::malformed_json;
        }
        if (message[offset] == ']') {
            ++offset;
            return InventoryError::none;
        }
        if (message[offset++] != ',') {
            return InventoryError::malformed_json;
        }
        skip_whitespace(message, offset);
    }
    return InventoryError::malformed_json;
}

[[nodiscard]] InventoryError parse_result_object(
    std::string_view message,
    std::size_t& offset,
    const InventoryLimits& limits,
    std::vector<ToolInventoryEntry>& tools) {
    if (offset >= message.size() || message[offset++] != '{') {
        return InventoryError::malformed_json;
    }

    bool saw_tools = false;
    skip_whitespace(message, offset);
    if (offset < message.size() && message[offset] == '}') {
        ++offset;
        return InventoryError::missing_tools;
    }

    while (offset < message.size()) {
        StringToken key;
        if (!scan_string(message, offset, key) || key.has_escape) {
            return InventoryError::malformed_json;
        }
        skip_whitespace(message, offset);
        if (offset >= message.size() || message[offset++] != ':') {
            return InventoryError::malformed_json;
        }
        skip_whitespace(message, offset);

        if (key.contents == "tools") {
            if (saw_tools) {
                return InventoryError::duplicate_member;
            }
            saw_tools = true;
            if (offset >= message.size() || message[offset] != '[') {
                return InventoryError::tools_not_array;
            }
            const auto status = parse_tools_array(message, offset, limits, tools);
            if (status != InventoryError::none) {
                return status;
            }
        } else if (!skip_value(message, offset, 2U, limits.max_nesting_depth)) {
            return InventoryError::excessive_nesting;
        }

        skip_whitespace(message, offset);
        if (offset >= message.size()) {
            return InventoryError::malformed_json;
        }
        if (message[offset] == '}') {
            ++offset;
            return saw_tools ? InventoryError::none : InventoryError::missing_tools;
        }
        if (message[offset++] != ',') {
            return InventoryError::malformed_json;
        }
        skip_whitespace(message, offset);
    }
    return InventoryError::malformed_json;
}

} // namespace

InventoryError validate_initialize_response(
    std::string_view message,
    std::string_view expected_id_json,
    const InventoryLimits& limits) noexcept {
    if (message.size() > limits.max_message_bytes) {
        return InventoryError::message_too_large;
    }
    const ResponseShape shape = classify_response_shape(message, limits.max_nesting_depth);
    if (shape.error != InventoryError::none) {
        return shape.error;
    }
    if (shape.id_json != expected_id_json) {
        return InventoryError::wrong_response_id;
    }
    if (shape.saw_error) {
        return InventoryError::error_result;
    }
    if (!shape.saw_result) {
        return InventoryError::missing_result;
    }
    return InventoryError::none;
}

InventoryParseResult parse_tools_list_response(
    std::string_view message,
    std::string_view expected_id_json,
    std::string_view downstream_executable,
    const InventoryLimits& limits) {
    InventoryParseResult result;
    if (message.size() > limits.max_message_bytes) {
        result.error = InventoryError::message_too_large;
        return result;
    }

    std::size_t offset = 0;
    skip_whitespace(message, offset);
    if (offset >= message.size() || message[offset++] != '{') {
        result.error = InventoryError::malformed_json;
        return result;
    }

    bool saw_jsonrpc = false;
    bool saw_id = false;
    bool saw_result = false;
    bool saw_error = false;
    bool saw_method = false;
    std::string_view id_json;
    std::vector<ToolInventoryEntry> tools;

    skip_whitespace(message, offset);
    if (offset < message.size() && message[offset] == '}') {
        result.error = InventoryError::invalid_envelope;
        return result;
    }

    while (offset < message.size()) {
        StringToken key;
        if (!scan_string(message, offset, key) || key.has_escape) {
            result.error = InventoryError::malformed_json;
            return result;
        }
        skip_whitespace(message, offset);
        if (offset >= message.size() || message[offset++] != ':') {
            result.error = InventoryError::malformed_json;
            return result;
        }
        skip_whitespace(message, offset);

        if (key.contents == "jsonrpc") {
            if (saw_jsonrpc) {
                result.error = InventoryError::duplicate_member;
                return result;
            }
            saw_jsonrpc = true;
            StringToken version;
            if (!scan_string(message, offset, version) || version.has_escape ||
                version.contents != "2.0") {
                result.error = InventoryError::unsupported_jsonrpc_version;
                return result;
            }
        } else if (key.contents == "id") {
            if (saw_id) {
                result.error = InventoryError::duplicate_member;
                return result;
            }
            saw_id = true;
            const std::size_t id_begin = offset;
            if (offset < message.size() && message[offset] == '"') {
                StringToken value;
                if (!scan_string(message, offset, value)) {
                    result.error = InventoryError::malformed_json;
                    return result;
                }
            } else if (
                (offset < message.size() && message[offset] == 'n' &&
                 internal::scan_literal(message, offset, "null")) ||
                internal::scan_number(message, offset)) {
                // accepted
            } else {
                result.error = InventoryError::invalid_envelope;
                return result;
            }
            id_json = message.substr(id_begin, offset - id_begin);
        } else if (key.contents == "method") {
            if (saw_method) {
                result.error = InventoryError::duplicate_member;
                return result;
            }
            saw_method = true;
            StringToken value;
            if (!scan_string(message, offset, value)) {
                result.error = InventoryError::malformed_json;
                return result;
            }
        } else if (key.contents == "result") {
            if (saw_result) {
                result.error = InventoryError::duplicate_member;
                return result;
            }
            saw_result = true;
            if (offset >= message.size() || message[offset] != '{') {
                result.error = InventoryError::malformed_json;
                return result;
            }
            const auto status = parse_result_object(message, offset, limits, tools);
            if (status != InventoryError::none) {
                result.error = status;
                return result;
            }
        } else if (key.contents == "error") {
            if (saw_error) {
                result.error = InventoryError::duplicate_member;
                return result;
            }
            saw_error = true;
            if (!skip_value(message, offset, 1U, limits.max_nesting_depth)) {
                result.error = InventoryError::excessive_nesting;
                return result;
            }
        } else if (!skip_value(message, offset, 1U, limits.max_nesting_depth)) {
            result.error = InventoryError::excessive_nesting;
            return result;
        }

        skip_whitespace(message, offset);
        if (offset >= message.size()) {
            result.error = InventoryError::malformed_json;
            return result;
        }
        if (message[offset] == '}') {
            ++offset;
            break;
        }
        if (message[offset++] != ',') {
            result.error = InventoryError::malformed_json;
            return result;
        }
        skip_whitespace(message, offset);
    }

    skip_whitespace(message, offset);
    if (offset != message.size()) {
        result.error = InventoryError::malformed_json;
        return result;
    }
    if (!saw_jsonrpc || saw_method || !saw_id || (saw_result == saw_error)) {
        result.error = InventoryError::invalid_envelope;
        return result;
    }
    if (id_json != expected_id_json) {
        result.error = InventoryError::wrong_response_id;
        return result;
    }
    if (saw_error) {
        result.error = InventoryError::error_result;
        return result;
    }
    if (!saw_result) {
        result.error = InventoryError::missing_result;
        return result;
    }

    std::sort(
        tools.begin(),
        tools.end(),
        [](const ToolInventoryEntry& left, const ToolInventoryEntry& right) {
            return left.name < right.name;
        });

    result.inventory.downstream_executable.assign(
        downstream_executable.data(), downstream_executable.size());
    result.inventory.tools = std::move(tools);
    result.error = InventoryError::none;
    return result;
}

bool emit_inventory_json(
    const ToolInventory& inventory,
    std::string& output,
    std::size_t max_output_bytes) {
    output.clear();
    if (!append_bytes(output, R"({"inventory_version":)", max_output_bytes) ||
        !append_bytes(output, std::to_string(ToolInventory::version), max_output_bytes) ||
        !append_bytes(output, R"(,"server":{"downstream_executable":)", max_output_bytes) ||
        !append_json_string(output, inventory.downstream_executable, max_output_bytes) ||
        !append_bytes(output, R"(},"tools":[)", max_output_bytes)) {
        return false;
    }

    bool first = true;
    for (const auto& tool : inventory.tools) {
        if (!first && !append_bytes(output, ",", max_output_bytes)) {
            return false;
        }
        first = false;
        if (!append_bytes(output, R"({"name":)", max_output_bytes) ||
            !append_json_string(output, tool.name, max_output_bytes)) {
            return false;
        }
        if (!tool.description_json.empty()) {
            if (!append_bytes(output, R"(,"description":)", max_output_bytes) ||
                !append_bytes(output, tool.description_json, max_output_bytes)) {
                return false;
            }
        }
        if (!tool.input_schema_json.empty()) {
            if (!append_bytes(output, R"(,"inputSchema":)", max_output_bytes) ||
                !append_bytes(output, tool.input_schema_json, max_output_bytes)) {
                return false;
            }
        }
        if (!tool.annotations_json.empty()) {
            if (!append_bytes(output, R"(,"annotations":)", max_output_bytes) ||
                !append_bytes(output, tool.annotations_json, max_output_bytes)) {
                return false;
            }
        }
        if (!append_bytes(output, "}", max_output_bytes)) {
            return false;
        }
    }
    return append_bytes(output, "]}", max_output_bytes);
}

const char* inventory_error_name(InventoryError error) noexcept {
    switch (error) {
    case InventoryError::none:
        return "none";
    case InventoryError::message_too_large:
        return "message_too_large";
    case InventoryError::malformed_json:
        return "malformed_json";
    case InventoryError::invalid_envelope:
        return "invalid_envelope";
    case InventoryError::unsupported_jsonrpc_version:
        return "unsupported_jsonrpc_version";
    case InventoryError::duplicate_member:
        return "duplicate_member";
    case InventoryError::wrong_response_id:
        return "wrong_response_id";
    case InventoryError::missing_result:
        return "missing_result";
    case InventoryError::error_result:
        return "error_result";
    case InventoryError::missing_tools:
        return "missing_tools";
    case InventoryError::tools_not_array:
        return "tools_not_array";
    case InventoryError::missing_tool_name:
        return "missing_tool_name";
    case InventoryError::non_string_tool_name:
        return "non_string_tool_name";
    case InventoryError::escaped_tool_name:
        return "escaped_tool_name";
    case InventoryError::empty_tool_name:
        return "empty_tool_name";
    case InventoryError::oversized_tool_name:
        return "oversized_tool_name";
    case InventoryError::oversized_description:
        return "oversized_description";
    case InventoryError::oversized_schema:
        return "oversized_schema";
    case InventoryError::duplicate_tool_name:
        return "duplicate_tool_name";
    case InventoryError::excessive_tool_count:
        return "excessive_tool_count";
    case InventoryError::excessive_nesting:
        return "excessive_nesting";
    }
    return "unknown";
}

} // namespace mng::protocol
