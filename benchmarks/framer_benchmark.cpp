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
    constexpr std::size_t batch_message_count = 100'000U;
    constexpr std::size_t chunk_size = 64U * 1024U;
    constexpr auto minimum_duration = std::chrono::seconds{1};
    const std::string message =
        R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"demo.read"}})";

    std::string input;
    input.reserve(batch_message_count * (message.size() + 1U));
    for (std::size_t index = 0; index < batch_message_count; ++index) {
        input.append(message);
        input.push_back('\n');
    }

    std::uint64_t observed_messages = 0;
    std::uint64_t checksum = 0;
    std::uint64_t processed_bytes = 0;
    std::uint64_t batch_count = 0;

    const auto start = std::chrono::steady_clock::now();
    do {
        mng::io::LineFramer framer{{1024U * 1024U, 4096U, true}};
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

        processed_bytes += input.size();
        ++batch_count;
    } while (std::chrono::steady_clock::now() - start < minimum_duration);
    const auto stop = std::chrono::steady_clock::now();

    const auto seconds = std::chrono::duration<double>(stop - start).count();
    const auto mebibytes = static_cast<double>(processed_bytes) / (1024.0 * 1024.0);
    const auto expected_messages = batch_count * batch_message_count;

    std::cout << std::fixed << std::setprecision(6)
              << "elapsed_seconds=" << seconds << '\n'
              << "total_processed_bytes=" << processed_bytes << '\n'
              << "total_messages=" << observed_messages << '\n'
              << "payload_checksum=" << checksum << '\n'
              << "throughput_mib_per_second=" << (mebibytes / seconds) << '\n'
              << "messages_per_second=" << (static_cast<double>(observed_messages) / seconds)
              << '\n';
    return observed_messages == expected_messages ? 0 : 1;
}
