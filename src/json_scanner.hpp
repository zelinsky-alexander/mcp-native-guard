// Internal shared JSON scanning primitives.
//
// This header is included by json_rpc_envelope.cpp and tool_call_extractor.cpp.
// All functions are inline to avoid a separate translation unit for what are
// essentially small, hot utilities. They carry no allocation and no state.
//
// Not part of the public mcp_native_guard API.
#pragma once

#include <cstddef>
#include <string_view>

namespace mng::protocol::internal {

struct StringToken final {
    std::string_view contents{};
    bool has_escape{false};
};

[[nodiscard]] inline bool is_whitespace(char value) noexcept {
    return value == ' ' || value == '\n' || value == '\r' || value == '\t';
}

inline void skip_whitespace(std::string_view input, std::size_t& offset) noexcept {
    while (offset < input.size() && is_whitespace(input[offset])) {
        ++offset;
    }
}

[[nodiscard]] inline bool is_hex_digit(char value) noexcept {
    return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f') ||
           (value >= 'A' && value <= 'F');
}

// Scans a JSON string starting at input[offset] (the leading '"').
// On success advances offset past the closing '"' and fills token.
// Rejects control characters (U+0000..U+001F) and malformed escape sequences.
[[nodiscard]] inline bool scan_string(
    std::string_view input,
    std::size_t& offset,
    StringToken& token) noexcept {
    if (offset >= input.size() || input[offset] != '"') {
        return false;
    }

    const std::size_t begin = ++offset;
    bool has_escape = false;
    while (offset < input.size()) {
        const char value = input[offset++];
        if (value == '"') {
            token = {input.substr(begin, offset - begin - 1U), has_escape};
            return true;
        }
        if (static_cast<unsigned char>(value) < 0x20U) {
            return false;
        }
        if (value != '\\') {
            continue;
        }

        has_escape = true;
        if (offset == input.size()) {
            return false;
        }
        const char escape = input[offset++];
        if (escape == 'u') {
            if (input.size() - offset < 4U) {
                return false;
            }
            for (std::size_t index = 0; index < 4U; ++index) {
                if (!is_hex_digit(input[offset + index])) {
                    return false;
                }
            }
            offset += 4U;
        } else if (escape != '"' && escape != '\\' && escape != '/' && escape != 'b' &&
                   escape != 'f' && escape != 'n' && escape != 'r' && escape != 't') {
            return false;
        }
    }
    return false;
}

// Advances offset past a JSON number. Returns false if no number is present.
[[nodiscard]] inline bool scan_number(
    std::string_view input,
    std::size_t& offset) noexcept {
    const std::size_t begin = offset;
    if (offset < input.size() && input[offset] == '-') {
        ++offset;
    }
    if (offset == input.size()) {
        return false;
    }
    if (input[offset] == '0') {
        ++offset;
    } else if (input[offset] >= '1' && input[offset] <= '9') {
        do {
            ++offset;
        } while (offset < input.size() && input[offset] >= '0' && input[offset] <= '9');
    } else {
        return false;
    }
    if (offset < input.size() && input[offset] == '.') {
        ++offset;
        const std::size_t fraction_begin = offset;
        while (offset < input.size() && input[offset] >= '0' && input[offset] <= '9') {
            ++offset;
        }
        if (offset == fraction_begin) {
            return false;
        }
    }
    if (offset < input.size() && (input[offset] == 'e' || input[offset] == 'E')) {
        ++offset;
        if (offset < input.size() && (input[offset] == '+' || input[offset] == '-')) {
            ++offset;
        }
        const std::size_t exponent_begin = offset;
        while (offset < input.size() && input[offset] >= '0' && input[offset] <= '9') {
            ++offset;
        }
        if (offset == exponent_begin) {
            return false;
        }
    }
    return offset != begin;
}

// Returns true and advances offset iff the next bytes equal literal exactly.
[[nodiscard]] inline bool scan_literal(
    std::string_view input,
    std::size_t& offset,
    std::string_view literal) noexcept {
    if (input.size() - offset < literal.size() ||
        input.substr(offset, literal.size()) != literal) {
        return false;
    }
    offset += literal.size();
    return true;
}

// Skips one complete JSON value at the given nesting depth.
// depth is the caller's notion of how deep we already are (1-based from
// the perspective of skip_value callers: top-level member values are depth 1).
// Returns false if depth > max_depth or the value is malformed.
[[nodiscard]] inline bool skip_value(
    std::string_view input,
    std::size_t& offset,
    std::size_t depth,
    std::size_t max_depth) noexcept {
    if (depth > max_depth || offset == input.size()) {
        return false;
    }

    if (input[offset] == '"') {
        StringToken token;
        return scan_string(input, offset, token);
    }
    if (input[offset] == '{') {
        ++offset;
        skip_whitespace(input, offset);
        if (offset < input.size() && input[offset] == '}') {
            ++offset;
            return true;
        }
        while (offset < input.size()) {
            StringToken key;
            if (!scan_string(input, offset, key)) {
                return false;
            }
            skip_whitespace(input, offset);
            if (offset == input.size() || input[offset++] != ':') {
                return false;
            }
            skip_whitespace(input, offset);
            if (!skip_value(input, offset, depth + 1U, max_depth)) {
                return false;
            }
            skip_whitespace(input, offset);
            if (offset == input.size()) {
                return false;
            }
            if (input[offset] == '}') {
                ++offset;
                return true;
            }
            if (input[offset++] != ',') {
                return false;
            }
            skip_whitespace(input, offset);
        }
        return false;
    }
    if (input[offset] == '[') {
        ++offset;
        skip_whitespace(input, offset);
        if (offset < input.size() && input[offset] == ']') {
            ++offset;
            return true;
        }
        while (offset < input.size()) {
            if (!skip_value(input, offset, depth + 1U, max_depth)) {
                return false;
            }
            skip_whitespace(input, offset);
            if (offset == input.size()) {
                return false;
            }
            if (input[offset] == ']') {
                ++offset;
                return true;
            }
            if (input[offset++] != ',') {
                return false;
            }
            skip_whitespace(input, offset);
        }
        return false;
    }
    if (input[offset] == 't') {
        return scan_literal(input, offset, "true");
    }
    if (input[offset] == 'f') {
        return scan_literal(input, offset, "false");
    }
    if (input[offset] == 'n') {
        return scan_literal(input, offset, "null");
    }
    return scan_number(input, offset);
}

} // namespace mng::protocol::internal
