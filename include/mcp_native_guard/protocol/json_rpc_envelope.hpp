#pragma once

#include "mcp_native_guard/protocol/runtime_limits.hpp"

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace mng::protocol {

enum class EnvelopeKind : std::uint8_t {
    invalid = 0,
    request,
    notification,
    response,
};

enum class IdKind : std::uint8_t {
    absent = 0,
    null_value,
    string,
    number,
};

enum class ClassificationError : std::uint8_t {
    none = 0,
    message_too_large,
    malformed_json,
    unsupported_jsonrpc_version,
    duplicate_member,
    invalid_envelope,
};

struct Envelope final {
    EnvelopeKind kind{EnvelopeKind::invalid};
    IdKind id_kind{IdKind::absent};
    // Raw JSON token for id, including string quotes when present. It aliases
    // the classified input and is empty when the id member was not usable.
    // A rejected envelope may retain fields scanned before the error so a
    // caller can fail closed with the original request ID.
    std::string_view id_json{};
    std::string_view method{};
    ClassificationError error{ClassificationError::none};

    [[nodiscard]] constexpr explicit operator bool() const noexcept {
        return error == ClassificationError::none;
    }
};

// Classifies only the top-level JSON-RPC envelope. Nested values are scanned
// structurally so they can be skipped; no JSON value tree is created. Escaped
// top-level member names and method values are rejected so returned views are
// canonical slices of the input.
class JsonRpcEnvelopeClassifier final {
public:
    using Config = RuntimeLimits;

    JsonRpcEnvelopeClassifier();
    explicit JsonRpcEnvelopeClassifier(Config config) noexcept;

    [[nodiscard]] Envelope classify(std::string_view message) const noexcept;

private:
    Config config_;
};

} // namespace mng::protocol
