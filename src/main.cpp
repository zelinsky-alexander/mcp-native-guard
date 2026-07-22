#include "mcp_native_guard/io/line_framer.hpp"
#if defined(MNG_HAS_LINUX_STDIO_RELAY)
#include "mcp_native_guard/process/linux_stdio_relay.hpp"
#include "mcp_native_guard/protocol/tool_call_filter.hpp"
#include "mcp_native_guard/security/policy.hpp"
#endif

#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

constexpr std::string_view version = "0.1.0";
constexpr std::size_t default_max_message_bytes = 1024U * 1024U;
constexpr std::size_t read_chunk_bytes = 64U * 1024U;

void print_help(std::ostream& output) {
    output << "mcp-native-guard " << version << '\n'
           << "\nUsage:\n"
           << "  mcp-native-guard --help\n"
           << "  mcp-native-guard --version\n"
           << "  mcp-native-guard relay [--discard] [--max-message-bytes N]\n\n"
           << "  mcp-native-guard run [--deny-tool TOOL_NAME ...] -- <server> [args...]\n\n"
           << "relay is an early framing-path harness. It validates bounded newline-delimited\n"
           << "messages and either forwards them to stdout or discards them for measurement.\n"
           << "It is not yet the security proxy MVP.\n\n"
           << "run launches one Linux stdio server. Each --deny-tool rule blocks invocation\n"
           << "and hides that tool from correlated tools/list responses.\n";
}

int run_child(int argc, char** argv) {
#if defined(MNG_HAS_LINUX_STDIO_RELAY)
    std::vector<mng::security::ToolRule> rules;
    int separator = -1;
    for (int index = 2; index < argc; ++index) {
        const std::string_view argument{argv[index]};
        if (argument == "--") {
            separator = index;
            break;
        }
        if (argument != "--deny-tool" || index + 1 >= argc ||
            std::string_view{argv[index + 1]}.empty() || std::string_view{argv[index + 1]} == "--") {
            std::cerr << "usage: mcp-native-guard run [--deny-tool TOOL_NAME ...] -- "
                         "<server> [args...]\n";
            return 2;
        }
        rules.push_back({
            std::string{argv[++index]},
            mng::security::Access::deny,
            mng::security::Access::deny,
        });
    }
    if (separator < 0 || separator + 1 >= argc) {
        std::cerr << "usage: mcp-native-guard run [--deny-tool TOOL_NAME ...] -- "
                     "<server> [args...]\n";
        return 2;
    }

    mng::security::PolicyTable policy;
    const auto policy_status = mng::security::PolicyTable::build(
        std::move(rules),
        {mng::security::Access::allow, mng::security::Access::allow},
        policy);
    if (!policy_status) {
        std::cerr << "invalid deny rules: " << policy_status.message << '\n';
        return 2;
    }

    mng::protocol::ToolCallFilter filter{std::move(policy)};
    return mng::process::run_stdio_child(
        std::span<char* const>{
            argv + separator + 1,
            static_cast<std::size_t>(argc - separator - 1)},
        &filter);
#else
    (void)argc;
    (void)argv;
    std::cerr << "run is supported only on Linux\n";
    return 2;
#endif
}

bool parse_size(std::string_view text, std::size_t& value) {
    if (text.empty()) {
        return false;
    }
    const char* const begin = text.data();
    const char* const end = begin + text.size();
    const auto result = std::from_chars(begin, end, value);
    return result.ec == std::errc{} && result.ptr == end && value != 0U;
}

int run_relay(int argc, char** argv) {
    std::size_t max_message_bytes = default_max_message_bytes;
    bool discard = false;

    for (int index = 2; index < argc; ++index) {
        const std::string_view argument{argv[index]};
        if (argument == "--discard") {
            discard = true;
            continue;
        }
        if (argument == "--max-message-bytes") {
            if (index + 1 >= argc || !parse_size(argv[index + 1], max_message_bytes)) {
                std::cerr << "invalid --max-message-bytes value\n";
                return 2;
            }
            ++index;
            continue;
        }

        std::cerr << "unknown argument: " << argument << '\n';
        return 2;
    }

    mng::io::LineFramer framer{{max_message_bytes, 4096U, true}};
    std::array<char, read_chunk_bytes> input{};
    std::uint64_t messages = 0;
    std::uint64_t payload_bytes = 0;

    while (std::cin) {
        std::cin.read(input.data(), static_cast<std::streamsize>(input.size()));
        const auto received = std::cin.gcount();
        if (received <= 0) {
            break;
        }

        const auto status = framer.feed(
            std::span<const char>{input.data(), static_cast<std::size_t>(received)},
            [&](std::string_view message) {
                ++messages;
                payload_bytes += message.size();
                if (!discard) {
                    std::cout.write(message.data(), static_cast<std::streamsize>(message.size()));
                    std::cout.put('\n');
                }
            });

        if (!status) {
            std::cerr << "framing error: " << status.message << '\n';
            return 3;
        }
        if (!std::cout) {
            std::cerr << "stdout write failed\n";
            return 4;
        }
    }

    if (std::cin.bad()) {
        std::cerr << "stdin read failed\n";
        return 4;
    }

    const auto finish_status = framer.finish();
    if (!finish_status) {
        std::cerr << "framing error: " << finish_status.message << '\n';
        return 3;
    }

    std::cerr << "messages=" << messages << " payload_bytes=" << payload_bytes << '\n';
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    std::ios::sync_with_stdio(false);
    std::cin.tie(nullptr);

    if (argc == 1 || std::string_view{argv[1]} == "--help") {
        print_help(std::cout);
        return 0;
    }
    if (std::string_view{argv[1]} == "--version") {
        std::cout << version << '\n';
        return 0;
    }
    if (std::string_view{argv[1]} == "relay") {
        return run_relay(argc, argv);
    }
    if (std::string_view{argv[1]} == "run") {
        return run_child(argc, argv);
    }

    std::cerr << "unknown command: " << argv[1] << '\n';
    print_help(std::cerr);
    return 2;
}
