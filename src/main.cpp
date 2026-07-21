#include "mcp_native_guard/io/line_framer.hpp"

#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <string_view>

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
           << "relay is an early framing-path harness. It validates bounded newline-delimited\n"
           << "messages and either forwards them to stdout or discards them for measurement.\n"
           << "It is not yet the security proxy MVP.\n";
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

    std::cerr << "unknown command: " << argv[1] << '\n';
    print_help(std::cerr);
    return 2;
}
