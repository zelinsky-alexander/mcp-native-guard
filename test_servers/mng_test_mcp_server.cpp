#include "mcp_native_guard/protocol/json_rpc_envelope.hpp"
#include "mcp_native_guard/protocol/tool_call_extractor.hpp"

#include <csignal>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <unistd.h>

int main(int argc, char** argv) {
    std::string_view mode = "healthy";
    if (argc >= 3 && std::string_view{argv[1]} == "--mode") {
        mode = argv[2];
    }
    if (argc >= 5 && std::string_view{argv[3]} == "--pid-file") {
        std::ofstream{argv[4]} << ::getpid() << '\n';
    }
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
            if (mode == "initialize-timeout") {
                while (true) (void)::pause();
            }
            if (mode == "malformed-initialize") {
                std::cout << "{malformed\n" << std::flush;
                while (true) (void)::pause();
            }
            std::cout << R"(,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"mng-test-mcp-server","version":"0.1"}}})";
        } else if (envelope.method == "tools/list") {
            if (mode == "tools-list-error") {
                std::cout << R"(,"error":{"code":-32603,"message":"fixture failure"}})";
            } else if (mode == "tools-list-missing") {
                std::cout << R"(,"result":{"nextCursor":null}})";
            } else if (mode == "tools-list-not-array") {
                std::cout << R"(,"result":{"tools":{},"nextCursor":null}})";
            } else {
                std::cout << R"(,"result":{"tools":[{"name":"allowed.tool","description":"allowed test tool","inputSchema":{"type":"object","properties":{"value":{"type":"string"}}}},{"name":"blocked.one","description":"denied test tool"},{"name":"blocked.two","description":"second denied test tool"}],"nextCursor":null}})";
            }
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
