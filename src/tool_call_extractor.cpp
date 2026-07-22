#include "mcp_native_guard/protocol/tool_call_extractor.hpp"

#include "json_scanner.hpp"

#include <cstddef>
#include <string_view>

namespace mng::protocol {
namespace {

using internal::StringToken;
using internal::scan_string;
using internal::skip_value;
using internal::skip_whitespace;

[[nodiscard]] constexpr ToolCallParams fail(ExtractionError error) noexcept {
    return {.error = error};
}

// Parses the params object whose opening '{' is at message[offset].
// Advances offset to one past the closing '}'.
// max_depth is forwarded to skip_value for nested structures inside arguments.
//
// Depth accounting: the params object itself is at depth 1 from the
// top-level perspective; member values inside params are at depth 2, so
// skip_value is called with depth = 2.
[[nodiscard]] ToolCallParams parse_params(
    std::string_view message,
    std::size_t& offset,
    std::size_t max_depth) noexcept {
    // Consume the opening '{'.
    if (offset >= message.size() || message[offset++] != '{') {
        return fail(ExtractionError::malformed_json);
    }

    bool saw_name = false;
    bool saw_arguments = false;
    std::string_view name;
    std::string_view arguments_json;

    skip_whitespace(message, offset);

    if (offset < message.size() && message[offset] == '}') {
        ++offset;
        return fail(ExtractionError::missing_name);
    }

    while (offset < message.size()) {
        StringToken key;
        if (!scan_string(message, offset, key) || key.has_escape) {
            return fail(ExtractionError::malformed_json);
        }
        skip_whitespace(message, offset);
        if (offset >= message.size() || message[offset++] != ':') {
            return fail(ExtractionError::malformed_json);
        }
        skip_whitespace(message, offset);

        if (key.contents == "name") {
            if (saw_name) {
                return fail(ExtractionError::duplicate_name);
            }
            saw_name = true;

            if (offset >= message.size() || message[offset] != '"') {
                // Skip over the value (if it is syntactically valid JSON at
                // all) so we can distinguish a legal non-string value from
                // completely malformed input.
                if (!skip_value(message, offset, 2U, max_depth)) {
                    return fail(ExtractionError::malformed_json);
                }
                return fail(ExtractionError::non_string_name);
            }
            StringToken value;
            if (!scan_string(message, offset, value)) {
                return fail(ExtractionError::malformed_json);
            }
            if (value.has_escape) {
                return fail(ExtractionError::escaped_name);
            }
            name = value.contents;
        } else if (key.contents == "arguments") {
            if (saw_arguments) {
                return fail(ExtractionError::malformed_json);
            }
            saw_arguments = true;
            const std::size_t arg_start = offset;
            if (!skip_value(message, offset, 2U, max_depth)) {
                return fail(ExtractionError::malformed_json);
            }
            arguments_json = message.substr(arg_start, offset - arg_start);
        } else {
            if (!skip_value(message, offset, 2U, max_depth)) {
                return fail(ExtractionError::malformed_json);
            }
        }

        skip_whitespace(message, offset);
        if (offset >= message.size()) {
            return fail(ExtractionError::malformed_json);
        }
        if (message[offset] == '}') {
            ++offset;
            break;
        }
        if (message[offset++] != ',') {
            return fail(ExtractionError::malformed_json);
        }
        skip_whitespace(message, offset);
    }

    if (!saw_name) {
        return fail(ExtractionError::missing_name);
    }

    return {name, arguments_json, ExtractionError::none};
}

} // namespace

ToolCallExtractor::ToolCallExtractor() : ToolCallExtractor(Config{}) {}

ToolCallExtractor::ToolCallExtractor(Config config) noexcept : config_{config} {}

ToolCallParams ToolCallExtractor::extract(std::string_view message) const noexcept {
    if (message.size() > config_.max_message_bytes) {
        return fail(ExtractionError::message_too_large);
    }

    std::size_t offset = 0;
    skip_whitespace(message, offset);

    if (offset >= message.size() || message[offset++] != '{') {
        return fail(ExtractionError::malformed_json);
    }

    bool saw_params = false;
    ToolCallParams result{};

    skip_whitespace(message, offset);

    if (offset < message.size() && message[offset] == '}') {
        ++offset;
    } else {
        while (offset < message.size()) {
            StringToken key;
            if (!scan_string(message, offset, key) || key.has_escape) {
                return fail(ExtractionError::malformed_json);
            }
            skip_whitespace(message, offset);
            if (offset >= message.size() || message[offset++] != ':') {
                return fail(ExtractionError::malformed_json);
            }
            skip_whitespace(message, offset);

            if (key.contents == "params") {
                if (saw_params) {
                    return fail(ExtractionError::duplicate_params);
                }
                saw_params = true;

                if (offset >= message.size() || message[offset] != '{') {
                    // params is present but not an object; skip and reject.
                    if (!skip_value(message, offset, 1U, config_.max_nesting_depth)) {
                        return fail(ExtractionError::malformed_json);
                    }
                    return fail(ExtractionError::malformed_json);
                }

                auto params_result =
                    parse_params(message, offset, config_.max_nesting_depth);
                if (!params_result) {
                    return params_result;
                }
                result = params_result;
            } else {
                if (!skip_value(message, offset, 1U, config_.max_nesting_depth)) {
                    return fail(ExtractionError::malformed_json);
                }
            }

            skip_whitespace(message, offset);
            if (offset >= message.size()) {
                return fail(ExtractionError::malformed_json);
            }
            if (message[offset] == '}') {
                ++offset;
                break;
            }
            if (message[offset++] != ',') {
                return fail(ExtractionError::malformed_json);
            }
            skip_whitespace(message, offset);
        }
    }

    skip_whitespace(message, offset);
    if (offset != message.size()) {
        return fail(ExtractionError::malformed_json);
    }

    if (!saw_params) {
        return fail(ExtractionError::missing_params);
    }

    return result;
}

} // namespace mng::protocol
