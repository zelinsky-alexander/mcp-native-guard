#include "mcp_native_guard/protocol/json_rpc_envelope.hpp"

#include <cstddef>
#include <string_view>

namespace mng::protocol {
namespace {

struct StringToken final {
    std::string_view contents{};
    bool has_escape{false};
};

[[nodiscard]] bool is_whitespace(char value) noexcept {
    return value == ' ' || value == '\n' || value == '\r' || value == '\t';
}

void skip_whitespace(std::string_view input, std::size_t& offset) noexcept {
    while (offset < input.size() && is_whitespace(input[offset])) {
        ++offset;
    }
}

[[nodiscard]] bool is_hex_digit(char value) noexcept {
    return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f') ||
           (value >= 'A' && value <= 'F');
}

[[nodiscard]] bool scan_string(
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

[[nodiscard]] bool scan_number(std::string_view input, std::size_t& offset) noexcept {
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

[[nodiscard]] bool scan_literal(
    std::string_view input,
    std::size_t& offset,
    std::string_view literal) noexcept {
    if (input.size() - offset < literal.size() || input.substr(offset, literal.size()) != literal) {
        return false;
    }
    offset += literal.size();
    return true;
}

[[nodiscard]] bool skip_value(
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

[[nodiscard]] Envelope failure(ClassificationError error) noexcept {
    return {.error = error};
}

} // namespace

JsonRpcEnvelopeClassifier::JsonRpcEnvelopeClassifier() : JsonRpcEnvelopeClassifier(Config{}) {}

JsonRpcEnvelopeClassifier::JsonRpcEnvelopeClassifier(Config config) noexcept : config_{config} {}

Envelope JsonRpcEnvelopeClassifier::classify(std::string_view message) const noexcept {
    if (message.size() > config_.max_message_bytes) {
        return failure(ClassificationError::message_too_large);
    }

    std::size_t offset = 0;
    skip_whitespace(message, offset);
    if (offset == message.size() || message[offset++] != '{') {
        return failure(ClassificationError::malformed_json);
    }

    bool saw_jsonrpc = false;
    bool saw_method = false;
    bool saw_id = false;
    bool saw_result = false;
    bool saw_error = false;
    IdKind id_kind = IdKind::absent;
    std::string_view method;

    skip_whitespace(message, offset);
    if (offset < message.size() && message[offset] == '}') {
        ++offset;
    } else {
        while (offset < message.size()) {
            StringToken key;
            if (!scan_string(message, offset, key) || key.has_escape) {
                return failure(ClassificationError::malformed_json);
            }
            skip_whitespace(message, offset);
            if (offset == message.size() || message[offset++] != ':') {
                return failure(ClassificationError::malformed_json);
            }
            skip_whitespace(message, offset);

            if (key.contents == "jsonrpc") {
                StringToken version;
                if (saw_jsonrpc) {
                    return failure(ClassificationError::duplicate_member);
                }
                saw_jsonrpc = true;
                if (!scan_string(message, offset, version) || version.has_escape ||
                    version.contents != "2.0") {
                    return failure(ClassificationError::unsupported_jsonrpc_version);
                }
            } else if (key.contents == "method") {
                StringToken value;
                if (saw_method) {
                    return failure(ClassificationError::duplicate_member);
                }
                saw_method = true;
                if (!scan_string(message, offset, value) || value.has_escape || value.contents.empty()) {
                    return failure(ClassificationError::invalid_envelope);
                }
                method = value.contents;
            } else if (key.contents == "id") {
                if (saw_id) {
                    return failure(ClassificationError::duplicate_member);
                }
                saw_id = true;
                if (scan_literal(message, offset, "null")) {
                    id_kind = IdKind::null_value;
                } else if (offset < message.size() && message[offset] == '"') {
                    StringToken value;
                    if (!scan_string(message, offset, value)) {
                        return failure(ClassificationError::malformed_json);
                    }
                    id_kind = IdKind::string;
                } else if (scan_number(message, offset)) {
                    id_kind = IdKind::number;
                } else {
                    return failure(ClassificationError::invalid_envelope);
                }
            } else if (key.contents == "result") {
                if (saw_result) {
                    return failure(ClassificationError::duplicate_member);
                }
                saw_result = true;
                if (!skip_value(message, offset, 1U, config_.max_nesting_depth)) {
                    return failure(ClassificationError::malformed_json);
                }
            } else if (key.contents == "error") {
                if (saw_error) {
                    return failure(ClassificationError::duplicate_member);
                }
                saw_error = true;
                if (!skip_value(message, offset, 1U, config_.max_nesting_depth)) {
                    return failure(ClassificationError::malformed_json);
                }
            } else if (!skip_value(message, offset, 1U, config_.max_nesting_depth)) {
                return failure(ClassificationError::malformed_json);
            }

            skip_whitespace(message, offset);
            if (offset == message.size()) {
                return failure(ClassificationError::malformed_json);
            }
            if (message[offset] == '}') {
                ++offset;
                break;
            }
            if (message[offset++] != ',') {
                return failure(ClassificationError::malformed_json);
            }
            skip_whitespace(message, offset);
        }
    }

    skip_whitespace(message, offset);
    if (offset != message.size()) {
        return failure(ClassificationError::malformed_json);
    }
    if (!saw_jsonrpc) {
        return failure(ClassificationError::invalid_envelope);
    }
    if (saw_method) {
        if (saw_result || saw_error) {
            return failure(ClassificationError::invalid_envelope);
        }
        return {saw_id ? EnvelopeKind::request : EnvelopeKind::notification, id_kind, method, {}};
    }
    if (saw_id && (saw_result != saw_error)) {
        return {EnvelopeKind::response, id_kind, {}, {}};
    }
    return failure(ClassificationError::invalid_envelope);
}

} // namespace mng::protocol
