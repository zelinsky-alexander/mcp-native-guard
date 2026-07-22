#pragma once

#include "mcp_native_guard/audit/audit_sink.hpp"
#include "mcp_native_guard/process/client_message_handler.hpp"
#include "mcp_native_guard/protocol/json_rpc_envelope.hpp"
#include "mcp_native_guard/protocol/tool_call_extractor.hpp"
#include "mcp_native_guard/proxy/proxy_core.hpp"

#include <array>
#include <cstddef>
#include <string>

namespace mng::protocol {

// Enforces tools/call and correlates tools/list responses. Other successfully
// classified messages pass through unchanged. Classification and policy lookup
// allocate neither on their successful hot paths.
class ToolCallFilter final : public process::ClientMessageHandler {
public:
    struct Config final {
        std::size_t max_message_bytes{1024U * 1024U};
        std::size_t max_nesting_depth{64U};
        std::size_t max_pending_requests{64U};
        std::size_t max_pending_id_bytes{4096U};
        std::size_t max_pending_total_id_bytes{16U * 1024U};
    };

    explicit ToolCallFilter(
        security::PolicyTable policy,
        audit::AuditSink* audit_sink = nullptr) noexcept;
    ToolCallFilter(
        security::PolicyTable policy,
        Config config,
        audit::AuditSink* audit_sink = nullptr) noexcept;

    [[nodiscard]] process::ClientMessageDecision inspect(std::string_view message) noexcept override;
    [[nodiscard]] process::ServerMessageDecision inspect_server(std::string_view message) noexcept override;
    void message_too_large(
        process::MessageDirection direction,
        std::size_t encoded_message_bytes) noexcept override;
    void connection_closed() noexcept override;

    [[nodiscard]] std::size_t pending_request_count() const noexcept { return pending_count_; }

private:
    static constexpr std::size_t pending_storage_capacity = 64U;

    enum class PendingStatus : unsigned char { added, duplicate, capacity_exhausted };
    struct PendingRequest final { std::string id_json; };

    [[nodiscard]] PendingStatus add_pending(std::string_view id_json) noexcept;
    [[nodiscard]] bool remove_pending(std::string_view id_json) noexcept;

    JsonRpcEnvelopeClassifier classifier_;
    ToolCallExtractor extractor_;
    proxy::ProxyCore proxy_;
    Config config_;
    std::array<PendingRequest, pending_storage_capacity> pending_{};
    std::size_t pending_count_{0};
    std::size_t pending_id_bytes_{0};
    std::string rewritten_response_;
    audit::AuditSink* audit_sink_;
};

} // namespace mng::protocol
