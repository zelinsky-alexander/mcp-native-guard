#include "mcp_native_guard/protocol/json_rpc_envelope.hpp"

#include "json_scanner.hpp"

#include <cstddef>
#include <string_view>

namespace mng::protocol {
namespace {

using internal::StringToken;
using internal::scan_literal;
using internal::scan_number;
using internal::scan_string;
using internal::skip_value;
using internal::skip_whitespace;

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
