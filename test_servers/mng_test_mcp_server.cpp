#include "mcp_native_guard/protocol/json_rpc_envelope.hpp"
#include "mcp_native_guard/protocol/tool_call_extractor.hpp"

#include <iostream>
#include <string>
#include <string_view>

int main() {
    mng::protocol::JsonRpcEnvelopeClassifier classifier;
    mng::protocol::ToolCallExtractor extractor;

    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.empty()) {
            continue;
        }
        const auto envelope = classifier.classify(line);
        if (!envelope || envelope.kind != mng::protocol::EnvelopeKind::request) {
            continue;
        }

        std::cout << R"({"jsonrpc":"2.0","id":)" << envelope.id_json;
        if (envelope.method == "initialize") {
            std::cout << R"(,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"mng-test-mcp-server","version":"0.1"}}})";
        } else if (envelope.method == "tools/list") {
            std::cout << R"(,"result":{"tools":[{"name":"allowed.tool","description":"allowed test tool","inputSchema":{"type":"object","properties":{"value":{"type":"string"}}}},{"name":"blocked.one","description":"denied test tool"},{"name":"blocked.two","description":"second denied test tool"}],"nextCursor":null}})";
        } else if (envelope.method == "tools/call") {
            const auto params = extractor.extract(line);
            if (!params) {
                std::cout << R"(,"error":{"code":-32602,"message":"test server invalid params"}})";
            } else {
                std::cout << R"(,"result":{"tool":")" << params.name << R"("}})";
            }
        } else {
            std::cout << R"(,"result":{"method":")" << envelope.method << R"("}})";
        }
        std::cout << '\n' << std::flush;
    }

    return std::cin.bad() ? 1 : 0;
}
