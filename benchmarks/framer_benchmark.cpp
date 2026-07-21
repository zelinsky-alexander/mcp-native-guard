#include "mcp_native_guard/io/line_framer.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <span>
#include <string>
#include <string_view>

int main() {
    constexpr std::size_t message_count = 500'000U;
    constexpr std::size_t chunk_size = 64U * 1024U;
    const std::string message =
        R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"demo.read"}})";

    std::string input;
    input.reserve(message_count * (message.size() + 1U));
    for (std::size_t index = 0; index < message_count; ++index) {
        input.append(message);
        input.push_back('\n');
    }

    mng::io::LineFramer framer{{1024U * 1024U, 4096U, true}};
    std::uint64_t observed_messages = 0;
    std::uint64_t checksum = 0;

    const auto start = std::chrono::steady_clock::now();
    for (std::size_t offset = 0; offset < input.size();) {
        const auto count = std::min(chunk_size, input.size() - offset);
        const auto status = framer.feed(
            std::span<const char>{input.data() + offset, count},
            [&](std::string_view value) {
                ++observed_messages;
                checksum += value.size();
            });
        if (!status) {
            std::cerr << status.message << '\n';
            return 1;
        }
        offset += count;
    }

    if (!framer.finish()) {
        std::cerr << "framer did not finish cleanly\n";
        return 1;
    }
    const auto stop = std::chrono::steady_clock::now();

    const auto seconds = std::chrono::duration<double>(stop - start).count();
    const auto mebibytes = static_cast<double>(input.size()) / (1024.0 * 1024.0);

    std::cout << std::fixed << std::setprecision(2)
              << "messages=" << observed_messages << '\n'
              << "payload_checksum=" << checksum << '\n'
              << "elapsed_seconds=" << seconds << '\n'
              << "throughput_mib_per_second=" << (mebibytes / seconds) << '\n'
              << "messages_per_second=" << (static_cast<double>(observed_messages) / seconds)
              << '\n';
    return observed_messages == message_count ? 0 : 1;
}
