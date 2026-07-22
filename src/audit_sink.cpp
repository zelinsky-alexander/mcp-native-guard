#include "mcp_native_guard/audit/audit_sink.hpp"

#include <array>
#include <charconv>
#include <chrono>
#include <ctime>
#include <ostream>
#include <string>

namespace mng::audit {
namespace {

[[nodiscard]] constexpr std::string_view event_name(EventType type) noexcept {
    switch (type) {
    case EventType::tool_call:
        return "tools/call";
    case EventType::tool_hidden:
        return "tools/list_tool_removed";
    case EventType::message_rejected:
        return "message_rejected";
    case EventType::correlation_exhausted:
        return "tools/list_correlation";
    }
    return "unknown";
}

[[nodiscard]] constexpr std::string_view decision_name(Decision decision) noexcept {
    return decision == Decision::allow ? "allow" : "deny";
}

[[nodiscard]] constexpr std::string_view reason_name(Reason reason) noexcept {
    switch (reason) {
    case Reason::policy_allowed:
        return "policy_allowed";
    case Reason::policy_denied:
        return "policy_denied";
    case Reason::invalid_parameters:
        return "invalid_parameters";
    case Reason::malformed_message:
        return "malformed_message";
    case Reason::message_too_large:
        return "message_too_large";
    case Reason::capacity_exhausted:
        return "capacity_exhausted";
    }
    return "unknown";
}

[[nodiscard]] bool append(std::string& output, std::string_view value, std::size_t limit) {
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
    if (!append(output, "\"", limit)) {
        return false;
    }
    for (const char character_value : value) {
        const auto byte = static_cast<unsigned char>(character_value);
        if (byte == '"' || byte == '\\') {
            const std::array<char, 2> escaped{'\\', static_cast<char>(byte)};
            if (!append(output, {escaped.data(), escaped.size()}, limit)) {
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
            if (!append(output, {escaped.data(), escaped.size()}, limit)) {
                return false;
            }
        } else if (byte < 0x20U) {
            const std::array<char, 6> escaped{
                '\\', 'u', '0', '0', hex[byte >> 4U], hex[byte & 0x0fU]};
            if (!append(output, {escaped.data(), escaped.size()}, limit)) {
                return false;
            }
        } else {
            const char character = static_cast<char>(byte);
            if (!append(output, std::string_view{&character, 1U}, limit)) {
                return false;
            }
        }
    }
    return append(output, "\"", limit);
}

[[nodiscard]] bool append_timestamp(std::string& output, std::size_t limit) noexcept {
    const std::time_t now = std::chrono::system_clock::to_time_t(
        std::chrono::system_clock::now());
    std::tm utc{};
#if defined(_WIN32)
    if (::gmtime_s(&utc, &now) != 0) {
        return false;
    }
#else
    if (::gmtime_r(&now, &utc) == nullptr) {
        return false;
    }
#endif
    std::array<char, 32> timestamp{};
    const std::size_t length = std::strftime(
        timestamp.data(), timestamp.size(), "%Y-%m-%dT%H:%M:%SZ", &utc);
    return length != 0U && append(output, {timestamp.data(), length}, limit);
}

[[nodiscard]] bool format_record(
    const AuditEvent& event,
    std::size_t limit,
    std::string& output) {
    if (limit == 0U) {
        return false;
    }
    output.clear();
    if (!append(output, R"({"timestamp":")", limit) ||
        !append_timestamp(output, limit) ||
        !append(output, R"(","event":")", limit) ||
        !append(output, event_name(event.type), limit) ||
        !append(output, R"(","decision":")", limit) ||
        !append(output, decision_name(event.decision), limit) ||
        !append(output, R"(","reason":")", limit) ||
        !append(output, reason_name(event.reason), limit) ||
        !append(output, "\"", limit)) {
        return false;
    }
    if (!event.tool_name.empty() &&
        (!append(output, R"(,"tool":)", limit) ||
         !append_json_string(output, event.tool_name, limit))) {
        return false;
    }
    if (!event.id_json.empty() &&
        (!append(output, R"(,"request_id":)", limit) ||
         !append(output, event.id_json, limit))) {
        return false;
    }
    if (event.include_message_size) {
        std::array<char, 32> number{};
        const auto result = std::to_chars(
            number.data(), number.data() + number.size(), event.encoded_message_bytes);
        if (result.ec != std::errc{} ||
            !append(output, R"(,"message_size":)", limit) ||
            !append(output, {number.data(), static_cast<std::size_t>(result.ptr - number.data())}, limit)) {
            return false;
        }
    }
    return append(output, "}", limit);
}

template <typename Integer>
[[nodiscard]] bool append_number(std::string& output, Integer value, std::size_t limit) {
    std::array<char, 32> number{};
    const auto result = std::to_chars(number.data(), number.data() + number.size(), value);
    return result.ec == std::errc{} && append(
        output, {number.data(), static_cast<std::size_t>(result.ptr - number.data())}, limit);
}

[[nodiscard]] bool format_session_start(
    const SessionIdentity& identity, std::size_t limit, std::string& output) {
    output.clear();
    return append(output, R"({"ts":")", limit) && append_timestamp(output, limit) &&
           append(output, R"(","event":"session_start","guard_version":)", limit) &&
           append_json_string(output, identity.guard_version, limit) &&
           append(output, R"(,"server_label":)", limit) && append_json_string(output, identity.server_label, limit) &&
           append(output, R"(,"downstream_executable":)", limit) && append_json_string(output, identity.downstream_executable, limit) &&
           append(output, R"(,"policy_hash":)", limit) && append_json_string(output, identity.policy_hash, limit) &&
           append(output, R"(,"runtime_limits":{"max_message_bytes":)", limit) &&
           append_number(output, identity.limits.max_message_bytes, limit) &&
           append(output, R"(,"max_nesting_depth":)", limit) &&
           append_number(output, identity.limits.max_nesting_depth, limit) &&
           append(output, R"(,"max_pending_tools_list":)", limit) &&
           append_number(output, identity.limits.max_pending_tools_list, limit) && append(output, "}}", limit);
}

[[nodiscard]] bool format_session_end(
    const SessionIdentity& identity, const SessionEnd& end, std::size_t limit, std::string& output) {
    output.clear();
    return append(output, R"({"ts":")", limit) && append_timestamp(output, limit) &&
           append(output, R"(","event":"session_end","guard_version":)", limit) &&
           append_json_string(output, identity.guard_version, limit) &&
           append(output, R"(,"server_label":)", limit) && append_json_string(output, identity.server_label, limit) &&
           append(output, R"(,"downstream_executable":)", limit) && append_json_string(output, identity.downstream_executable, limit) &&
           append(output, R"(,"policy_hash":)", limit) && append_json_string(output, identity.policy_hash, limit) &&
           append(output, R"(,"child_exit_status":)", limit) && append_number(output, end.child_exit_status, limit) &&
           append(output, R"(,"proxy_exit_status":)", limit) && append_number(output, end.proxy_exit_status, limit) &&
           append(output, R"(,"termination_reason":)", limit) && append_json_string(output, end.termination_reason, limit) &&
           append(output, R"(,"duration_ms":)", limit) && append_number(output, end.duration_ms, limit) &&
           append(output, end.clean_shutdown ? R"(,"clean_shutdown":true})" : R"(,"clean_shutdown":false})", limit);
}

} // namespace

JsonlAuditSink::JsonlAuditSink(std::ostream& destination, std::ostream& diagnostics)
    : JsonlAuditSink(destination, diagnostics, Config{}) {}

JsonlAuditSink::JsonlAuditSink(
    std::ostream& destination,
    std::ostream& diagnostics,
    Config config)
    : destination_{&destination}, diagnostics_{&diagnostics}, config_{config} {}

void JsonlAuditSink::record(const AuditEvent& event) noexcept {
    if (failed_) {
        return;
    }
    try {
        std::string line;
        line.reserve(config_.max_record_bytes < 1024U ? config_.max_record_bytes : 1024U);
        if (!format_record(event, config_.max_record_bytes, line)) {
            report_failure();
            return;
        }
        destination_->write(line.data(), static_cast<std::streamsize>(line.size()));
        destination_->put('\n');
        destination_->flush();
        if (!*destination_) {
            report_failure();
        }
    } catch (...) {
        report_failure();
    }
}

void JsonlAuditSink::record_session_start(const SessionIdentity& identity) noexcept {
    if (failed_) return;
    try {
        std::string line;
        line.reserve(512U);
        if (!format_session_start(identity, config_.max_record_bytes, line)) { report_failure(); return; }
        *destination_ << line << '\n' << std::flush;
        if (!*destination_) report_failure();
    } catch (...) { report_failure(); }
}

void JsonlAuditSink::record_session_end(const SessionIdentity& identity, const SessionEnd& end) noexcept {
    if (failed_) return;
    try {
        std::string line;
        line.reserve(512U);
        if (!format_session_end(identity, end, config_.max_record_bytes, line)) { report_failure(); return; }
        *destination_ << line << '\n' << std::flush;
        if (!*destination_) report_failure();
    } catch (...) { report_failure(); }
}

void JsonlAuditSink::report_failure() noexcept {
    if (failed_) {
        return;
    }
    failed_ = true;
    try {
        *diagnostics_ << "audit write failed; enforcement remains active\n";
        diagnostics_->flush();
    } catch (...) {
    }
}

} // namespace mng::audit
