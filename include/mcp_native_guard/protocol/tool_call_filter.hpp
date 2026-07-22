#pragma once

#include "mcp_native_guard/process/client_message_handler.hpp"
#include "mcp_native_guard/protocol/json_rpc_envelope.hpp"
#include "mcp_native_guard/protocol/tool_call_extractor.hpp"
#include "mcp_native_guard/proxy/proxy_core.hpp"

#include <cstddef>

namespace mng::protocol {

// Enforces only tools/call. All other complete client messages pass through
// unchanged. The filter allocates neither on successful classification nor on
// policy lookup.
class ToolCallFilter final : public process::ClientMessageHandler {
public:
    struct Config final {
        std::size_t max_message_bytes{1024U * 1024U};
        std::size_t max_nesting_depth{64U};
    };

    explicit ToolCallFilter(security::PolicyTable policy) noexcept;
    ToolCallFilter(security::PolicyTable policy, Config config) noexcept;

    [[nodiscard]] process::ClientMessageDecision inspect(std::string_view message) noexcept override;

private:
    JsonRpcEnvelopeClassifier classifier_;
    ToolCallExtractor extractor_;
    proxy::ProxyCore proxy_;
};

} // namespace mng::protocol
