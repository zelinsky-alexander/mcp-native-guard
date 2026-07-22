#pragma once

#include "mcp_native_guard/protocol/runtime_limits.hpp"

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace mng::protocol {

enum class ExtractionError : std::uint8_t {
    none = 0,
    message_too_large,
    malformed_json,
    missing_params,
    missing_name,
    duplicate_params,
    duplicate_name,
    non_string_name,
    // Limitation: tool name values that contain JSON escape sequences are
    // rejected rather than decoded.  Names with characters that require
    // escaping (e.g. backslash, code points above U+007E) cannot be used
    // until a decoding step is added.  Common naming conventions that use
    // only ASCII letters, digits, '.', '-', and '_' are unaffected.
    escaped_name,
};

// Zero-copy result of a successful or failed extraction.  On success all
// string_views alias the original message buffer; they are invalidated when
// that buffer is freed or overwritten.
struct ToolCallParams final {
    // params.name – non-empty, escape-free on success.
    std::string_view name{};
    // Raw JSON slice of params.arguments, including surrounding braces/brackets.
    // Empty when the key is absent from params.
    std::string_view arguments_json{};
    ExtractionError error{ExtractionError::none};

    [[nodiscard]] constexpr explicit operator bool() const noexcept {
        return error == ExtractionError::none;
    }
};

// Extracts params.name and (optionally) params.arguments from a
// tools/call JSON-RPC message without allocating or building a DOM.
//
// Operates on a single complete, newline-free message.  The caller is
// responsible for framing (e.g. via LineFramer) and envelope classification
// (e.g. via JsonRpcEnvelopeClassifier) before calling extract().
//
// Correctness properties:
//  - Accepts any top-level member ordering and any params-member ordering.
//  - Rejects: oversized messages, malformed JSON, missing params, missing
//    name, duplicate params key, duplicate name key, non-string name,
//    escaped top-level member names, escaped name values.
//  - No heap allocation on the successful hot path.
//  - No JSON value tree is built.
class ToolCallExtractor final {
public:
    using Config = RuntimeLimits;

    ToolCallExtractor();
    explicit ToolCallExtractor(Config config) noexcept;

    // Returns ToolCallParams with error == ExtractionError::none on success.
    // noexcept: all error conditions are reported via ExtractionError.
    [[nodiscard]] ToolCallParams extract(std::string_view message) const noexcept;

private:
    Config config_;
};

} // namespace mng::protocol
