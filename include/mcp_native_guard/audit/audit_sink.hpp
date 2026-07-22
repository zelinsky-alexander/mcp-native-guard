#pragma once

#include <cstddef>
#include <cstdint>
#include <iosfwd>
#include <string_view>

namespace mng::audit {

enum class EventType : std::uint8_t {
    tool_call = 0,
    tool_hidden,
    message_rejected,
    correlation_exhausted,
};

enum class Decision : std::uint8_t { allow = 0, deny };

enum class Reason : std::uint8_t {
    policy_allowed = 0,
    policy_denied,
    invalid_parameters,
    malformed_message,
    message_too_large,
    capacity_exhausted,
};

struct AuditEvent final {
    EventType type{EventType::message_rejected};
    Decision decision{Decision::deny};
    Reason reason{Reason::malformed_message};
    std::string_view tool_name{};
    // A validated raw JSON value. String IDs include their original quotes.
    std::string_view id_json{};
    std::size_t encoded_message_bytes{};
    bool include_message_size{false};
};

class AuditSink {
public:
    virtual ~AuditSink() = default;
    virtual void record(const AuditEvent& event) noexcept = 0;
};

// Formats one bounded compact JSON object per line. A formatting or output
// failure disables later writes and reports the failure once to diagnostics.
class JsonlAuditSink final : public AuditSink {
public:
    struct Config final { std::size_t max_record_bytes{2U * 1024U * 1024U}; };

    JsonlAuditSink(std::ostream& destination, std::ostream& diagnostics);
    JsonlAuditSink(std::ostream& destination, std::ostream& diagnostics, Config config);

    void record(const AuditEvent& event) noexcept override;

    [[nodiscard]] bool failed() const noexcept { return failed_; }

private:
    void report_failure() noexcept;

    std::ostream* destination_;
    std::ostream* diagnostics_;
    Config config_;
    bool failed_{false};
};

} // namespace mng::audit
