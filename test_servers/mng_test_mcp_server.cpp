#include <iostream>
#include <string>

int main() {
    constexpr const char* initialize_response =
        R"({"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"mng-test-mcp-server","version":"0.1"}}})";

    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.empty()) {
            continue;
        }
        std::cout << initialize_response << '\n' << std::flush;
    }

    return std::cin.bad() ? 1 : 0;
}
