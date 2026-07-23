#include "mcp_native_guard/process/policy_create.hpp"

#include "mcp_native_guard/io/atomic_file_writer.hpp"
#include "mcp_native_guard/security/policy_generator.hpp"

#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace mng::process {
namespace {

void print_policy_create_usage(std::ostream& output) {
    output << "usage: mcp-native-guard policy create --from INVENTORY "
              "[--allow-tool NAME ...] [--output PATH]\n";
}

} // namespace

int run_policy_create(int argc, char** argv) noexcept {
    std::string_view from_path;
    std::string_view output_path;
    bool saw_from = false;
    bool saw_output = false;
    std::vector<std::string_view> allow_tools;

    for (int index = 3; index < argc; ++index) {
        const std::string_view argument{argv[index]};
        if (argument == "--from") {
            if (saw_from || index + 1 >= argc || std::string_view{argv[index + 1]}.empty()) {
                std::cerr << "invalid --from\n";
                print_policy_create_usage(std::cerr);
                return 2;
            }
            saw_from = true;
            from_path = argv[++index];
            continue;
        }
        if (argument == "--allow-tool") {
            if (index + 1 >= argc || std::string_view{argv[index + 1]}.empty()) {
                std::cerr << "invalid --allow-tool\n";
                print_policy_create_usage(std::cerr);
                return 2;
            }
            allow_tools.push_back(std::string_view{argv[++index]});
            continue;
        }
        if (argument == "--output") {
            if (saw_output || index + 1 >= argc || std::string_view{argv[index + 1]}.empty()) {
                std::cerr << "invalid --output\n";
                print_policy_create_usage(std::cerr);
                return 2;
            }
            saw_output = true;
            output_path = argv[++index];
            continue;
        }
        std::cerr << "unknown policy create option: " << argument << '\n';
        print_policy_create_usage(std::cerr);
        return 2;
    }

    if (!saw_from) {
        std::cerr << "missing --from\n";
        print_policy_create_usage(std::cerr);
        return 2;
    }

    const security::PolicyGeneratorLimits limits;
    std::string inventory_json;
    try {
        std::ifstream input{std::string{from_path}, std::ios::binary};
        if (!input) {
            std::cerr << "policy create: cannot open inventory file (" << from_path << ")\n";
            return 2;
        }
        inventory_json.assign(limits.max_inventory_bytes + 1U, '\0');
        input.read(inventory_json.data(), static_cast<std::streamsize>(inventory_json.size()));
        const auto received = input.gcount();
        if (received < 0 || input.bad()) {
            std::cerr << "policy create: failed to read inventory file (" << from_path << ")\n";
            return 2;
        }
        if (static_cast<std::size_t>(received) > limits.max_inventory_bytes) {
            std::cerr << "policy create: inventory exceeds configured size limit\n";
            return 2;
        }
        inventory_json.resize(static_cast<std::size_t>(received));
    } catch (...) {
        std::cerr << "policy create: failed to allocate inventory buffer\n";
        return 2;
    }

    const auto result =
        security::generate_policy_from_inventory(inventory_json, allow_tools, limits);
    if (!result) {
        std::cerr << "policy create: " << security::policy_generate_error_name(result.error);
        if (!result.offending_tool_name.empty()) {
            std::cerr << " (" << result.offending_tool_name << ")";
        }
        std::cerr << '\n';
        return 2;
    }

    if (output_path.empty()) {
        std::cout << result.policy_json << '\n';
        if (!std::cout) {
            std::cerr << "policy create: stdout write failed\n";
            return 2;
        }
    } else {
        std::string payload;
        payload.reserve(result.policy_json.size() + 1U);
        payload.assign(result.policy_json);
        payload.push_back('\n');
        const auto write_result = mng::io::write_file_atomic(output_path, payload, "mng-policy");
        if (!write_result) {
            std::cerr << "policy create: " << mng::io::atomic_write_error_name(write_result.error)
                       << '\n';
            return 2;
        }
    }

    std::cerr << "policy create result: success\n";
    return 0;
}

} // namespace mng::process
