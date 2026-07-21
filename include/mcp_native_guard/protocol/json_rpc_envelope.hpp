#pragma once

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
    struct Config final {
        std::size_t max_message_bytes{1024U * 1024U};
        std::size_t max_nesting_depth{64U};
    };

    JsonRpcEnvelopeClassifier();
    explicit JsonRpcEnvelopeClassifier(Config config) noexcept;

    [[nodiscard]] Envelope classify(std::string_view message) const noexcept;

private:
    Config config_;
};

} // namespace mng::protocol
