#include "mcp_native_guard/protocol/json_rpc_envelope.hpp"
#include "mcp_native_guard/protocol/tool_call_extractor.hpp"

#include <csignal>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <unistd.h>
#include <vector>

namespace {

void ignore_term_and_pause() {
    struct sigaction action {};
    action.sa_handler = SIG_IGN;
    (void)::sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    (void)::sigaction(SIGTERM, &action, nullptr);
    while (true) {
        (void)::pause();
    }
}

void write_initialize_result(std::string_view id_json, std::string_view mode) {
    if (mode == "wrong-jsonrpc") {
        std::cout << R"({"jsonrpc":"1.0","id":)" << id_json
                  << R"(,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"mng-test-mcp-server","version":"0.1"}}})";
        return;
    }
    if (mode == "wrong-init-id") {
        std::cout << R"({"jsonrpc":"2.0","id":"other-id","result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"mng-test-mcp-server","version":"0.1"}}})";
        return;
    }
    if (mode == "missing-init-result") {
        std::cout << R"({"jsonrpc":"2.0","id":)" << id_json
                  << R"(,"error":{"code":-32603,"message":"fixture failure"}})";
        return;
    }
    std::cout << R"({"jsonrpc":"2.0","id":)" << id_json
              << R"(,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"mng-test-mcp-server","version":"0.1"}}})";
}

void write_tools_list_result(std::string_view id_json, std::string_view mode) {
    if (mode == "tools-list-error") {
        std::cout << R"({"jsonrpc":"2.0","id":)" << id_json
                  << R"(,"error":{"code":-32603,"message":"fixture failure"}})";
        return;
    }
    if (mode == "tools-list-missing") {
        std::cout << R"({"jsonrpc":"2.0","id":)" << id_json
                  << R"(,"result":{"nextCursor":null}})";
        return;
    }
    if (mode == "tools-list-not-array") {
        std::cout << R"({"jsonrpc":"2.0","id":)" << id_json
                  << R"(,"result":{"tools":{},"nextCursor":null}})";
        return;
    }
    if (mode == "tools-list-empty") {
        std::cout << R"({"jsonrpc":"2.0","id":)" << id_json
                  << R"(,"result":{"tools":[]}})";
        return;
    }
    if (mode == "tools-list-reordered") {
        std::cout << R"({"jsonrpc":"2.0","id":)" << id_json
                  << R"(,"result":{"tools":[{"name":"blocked.two","description":"second denied test tool"},{"name":"allowed.tool","description":"allowed test tool","inputSchema":{"type":"object","properties":{"value":{"type":"string"}}}},{"name":"blocked.one","description":"denied test tool"}]}})";
        return;
    }
    if (mode == "tools-list-member-reordered") {
        std::cout << R"({"jsonrpc":"2.0","id":)" << id_json
                  << R"(,"result":{"tools":[{"inputSchema":{"type":"object","properties":{"value":{"type":"string"}}},"description":"allowed test tool","name":"allowed.tool"},{"description":"denied test tool","name":"blocked.one"},{"name":"blocked.two","description":"second denied test tool"}]}})";
        return;
    }
    if (mode == "tools-list-schema-reordered") {
        std::cout << R"({"jsonrpc":"2.0","id":)" << id_json
                  << R"(,"result":{"tools":[{"name":"allowed.tool","description":"allowed test tool","inputSchema":{"properties":{"value":{"type":"string"}},"type":"object"}},{"name":"blocked.one","description":"denied test tool"},{"name":"blocked.two","description":"second denied test tool"}]}})";
        return;
    }
    if (mode == "tools-list-schema-whitespace") {
        std::cout << R"({"jsonrpc":"2.0","id":)" << id_json
                  << R"(,"result":{"tools":[{"name":"allowed.tool","description":"allowed test tool","inputSchema":{ "type" : "object" , "properties" : { "value" : { "type" : "string" } } }},{"name":"blocked.one","description":"denied test tool"},{"name":"blocked.two","description":"second denied test tool"}]}})";
        return;
    }
    if (mode == "tools-list-annotations-reordered") {
        std::cout << R"({"jsonrpc":"2.0","id":)" << id_json
                  << R"(,"result":{"tools":[{"name":"annotated","annotations":{"openWorldHint":false,"readOnlyHint":true},"inputSchema":{"type":"object"}}]}})";
        return;
    }
    if (mode == "tools-list-annotations-alt-order") {
        std::cout << R"({"jsonrpc":"2.0","id":)" << id_json
                  << R"(,"result":{"tools":[{"name":"annotated","annotations":{"readOnlyHint":true,"openWorldHint":false},"inputSchema":{"type":"object"}}]}})";
        return;
    }
    if (mode == "tools-list-schema-array-order") {
        std::cout << R"({"jsonrpc":"2.0","id":)" << id_json
                  << R"(,"result":{"tools":[{"name":"ordered","inputSchema":{"type":"object","required":["b","a"]}}]}})";
        return;
    }
    if (mode == "tools-list-schema-dup-member") {
        std::cout << R"({"jsonrpc":"2.0","id":)" << id_json
                  << R"(,"result":{"tools":[{"name":"bad","inputSchema":{"type":"object","type":"string"}}]}})";
        return;
    }
    if (mode == "tools-list-annotations-dup-member") {
        std::cout << R"({"jsonrpc":"2.0","id":)" << id_json
                  << R"(,"result":{"tools":[{"name":"bad","annotations":{"readOnlyHint":true,"readOnlyHint":false}}]}})";
        return;
    }
    if (mode == "tools-list-duplicate-names") {
        std::cout << R"({"jsonrpc":"2.0","id":)" << id_json
                  << R"(,"result":{"tools":[{"name":"dup.tool"},{"name":"dup.tool"}]}})";
        return;
    }
    if (mode == "tools-list-escaped-name") {
        std::cout << R"({"jsonrpc":"2.0","id":)" << id_json
                  << R"(,"result":{"tools":[{"name":"esc\"aped"}]}})";
        return;
    }
    if (mode == "tools-list-missing-name") {
        std::cout << R"({"jsonrpc":"2.0","id":)" << id_json
                  << R"(,"result":{"tools":[{"description":"no name"}]}})";
        return;
    }
    if (mode == "tools-list-non-string-name") {
        std::cout << R"({"jsonrpc":"2.0","id":)" << id_json
                  << R"(,"result":{"tools":[{"name":1}]}})";
        return;
    }
    if (mode == "tools-list-duplicate-name-member") {
        std::cout << R"({"jsonrpc":"2.0","id":)" << id_json
                  << R"(,"result":{"tools":[{"name":"a","name":"b"}]}})";
        return;
    }
    if (mode == "wrong-list-id") {
        std::cout << R"({"jsonrpc":"2.0","id":"other-list","result":{"tools":[]}})";
        return;
    }
    if (mode == "tools-list-timeout") {
        while (true) {
            (void)::pause();
        }
    }
    if (mode == "oversized-message") {
        std::string huge(2000U, 'x');
        std::cout << R"({"jsonrpc":"2.0","id":)" << id_json << R"(,"result":{"tools":[{"name":")"
                  << huge << R"("}]}})";
        return;
    }
    // Default healthy tool list (alphabetical order differs from sorted inventory).
    std::cout << R"({"jsonrpc":"2.0","id":)" << id_json
              << R"(,"result":{"tools":[{"name":"allowed.tool","description":"allowed test tool","inputSchema":{"type":"object","properties":{"value":{"type":"string"}}}},{"name":"blocked.one","description":"denied test tool"},{"name":"blocked.two","description":"second denied test tool"}],"nextCursor":null}})";
}

} // namespace

int main(int argc, char** argv) {
    std::string_view mode = "healthy";
    std::string method_log_path;
    std::string grandchild_pid_path;
    if (argc >= 3 && std::string_view{argv[1]} == "--mode") {
        mode = argv[2];
    }
    for (int index = 1; index + 1 < argc; ++index) {
        if (std::string_view{argv[index]} == "--pid-file") {
            std::ofstream{argv[index + 1]} << ::getpid() << '\n';
        }
        if (std::string_view{argv[index]} == "--method-log") {
            method_log_path = argv[index + 1];
        }
        if (std::string_view{argv[index]} == "--grandchild-pid-file") {
            grandchild_pid_path = argv[index + 1];
        }
    }

    mng::protocol::JsonRpcEnvelopeClassifier classifier;
    mng::protocol::ToolCallExtractor extractor;

    if (mode == "exit-early") {
        return 0;
    }

    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.empty()) {
            continue;
        }
        const auto envelope = classifier.classify(line);
        if (!envelope ||
            (envelope.kind != mng::protocol::EnvelopeKind::request &&
             envelope.kind != mng::protocol::EnvelopeKind::notification)) {
            continue;
        }

        if (!method_log_path.empty()) {
            std::ofstream log{method_log_path, std::ios::app};
            log << envelope.method << '\n';
        }

        if (envelope.kind == mng::protocol::EnvelopeKind::notification) {
            continue;
        }

        if (envelope.method == "initialize") {
            if (mode == "stderr-flood") {
                const std::string chunk(64U * 1024U, 'E');
                for (int i = 0; i < 64; ++i) {
                    std::cerr << chunk;
                }
                std::cerr.flush();
            }
            if (mode == "initialize-timeout") {
                while (true) {
                    (void)::pause();
                }
            }
            if (mode == "malformed-initialize") {
                std::cout << "{malformed\n" << std::flush;
                while (true) {
                    (void)::pause();
                }
            }
            if (mode == "unsolicited-before-init") {
                std::cout << R"({"jsonrpc":"2.0","method":"notifications/stderr","params":{}})" << '\n'
                          << std::flush;
            }
            write_initialize_result(envelope.id_json, mode);
            std::cout << '\n' << std::flush;
            continue;
        }

        if (envelope.method == "tools/list") {
            if (mode == "unsolicited-before-list") {
                std::cout << R"({"jsonrpc":"2.0","method":"notifications/progress","params":{}})" << '\n'
                          << std::flush;
            }
            write_tools_list_result(envelope.id_json, mode);
            std::cout << '\n' << std::flush;
            if (mode == "hang-after-list") {
                ignore_term_and_pause();
            }
            if (mode == "hang-with-grandchild") {
                const pid_t grandchild = ::fork();
                if (grandchild == 0) {
                    ignore_term_and_pause();
                }
                if (grandchild > 0 && !grandchild_pid_path.empty()) {
                    std::ofstream{grandchild_pid_path} << grandchild << '\n';
                }
                ignore_term_and_pause();
            }
            continue;
        }

        if (envelope.method == "tools/call") {
            const auto params = extractor.extract(line);
            if (!params) {
                std::cout << R"({"jsonrpc":"2.0","id":)" << envelope.id_json
                          << R"(,"error":{"code":-32602,"message":"test server invalid params"}})" << '\n'
                          << std::flush;
            } else {
                std::cout << R"({"jsonrpc":"2.0","id":)" << envelope.id_json
                          << R"(,"result":{"tool":")" << params.name << R"("}})" << '\n'
                          << std::flush;
            }
            continue;
        }

        std::cout << R"({"jsonrpc":"2.0","id":)" << envelope.id_json << R"(,"result":{"method":")"
                  << envelope.method << R"("}})" << '\n'
                  << std::flush;
    }

    return std::cin.bad() ? 1 : 0;
}
