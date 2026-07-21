#include "mcp_native_guard/io/line_framer.hpp"
#include "mcp_native_guard/protocol/json_rpc_envelope.hpp"
#include "mcp_native_guard/proxy/proxy_core.hpp"
#include "mcp_native_guard/security/policy.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

[[nodiscard]] mng::security::PolicyTable build_policy() {
    std::vector<mng::security::ToolRule> rules{
        {"demo.read", mng::security::Access::allow, mng::security::Access::allow},
        {"demo.write", mng::security::Access::allow, mng::security::Access::deny},
    };
    mng::security::PolicyTable policy;
    const auto status = mng::security::PolicyTable::build(
        std::move(rules),
        {mng::security::Access::deny, mng::security::Access::deny},
        policy);
    if (!status) {
        std::cerr << status.message << '\n';
        std::exit(1);
    }
    return policy;
}

} // namespace

int main() {
    constexpr std::size_t batch_message_count = 100'000U;
    constexpr std::size_t chunk_size = 64U * 1024U;
    constexpr auto minimum_duration = std::chrono::seconds{1};
    constexpr std::string_view tool_name = "demo.read";
    constexpr std::string_view method_name = "tools/call";
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
    mng::protocol::JsonRpcEnvelopeClassifier classifier;
    mng::proxy::ProxyCore proxy{build_policy(), {1024U * 1024U}};

    const auto start = std::chrono::steady_clock::now();
    do {
        mng::io::LineFramer framer{{1024U * 1024U, 4096U, true}};
        bool processing_failed = false;
        for (std::size_t offset = 0; offset < input.size();) {
            const auto count = std::min(chunk_size, input.size() - offset);
            const auto status = framer.feed(
                std::span<const char>{input.data() + offset, count},
                [&](std::string_view value) {
                    const auto envelope = classifier.classify(value);
                    if (!envelope || envelope.kind != mng::protocol::EnvelopeKind::request ||
                        envelope.method != method_name) {
                        processing_failed = true;
                        return;
                    }

                    const auto decision = proxy.authorize_tool_call(tool_name, value.size());
                    if (!decision.should_forward()) {
                        processing_failed = true;
                        return;
                    }

                    ++observed_messages;
                    checksum += value.size() + envelope.method.size() + tool_name.size() +
                                static_cast<std::uint64_t>(envelope.id_kind) +
                                static_cast<std::uint64_t>(decision.reason);
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
        if (processing_failed) {
            std::cerr << "pipeline processing failed\n";
            return 1;
        }

        processed_bytes += input.size();
        ++batch_count;
    } while (std::chrono::steady_clock::now() - start < minimum_duration);
    const auto stop = std::chrono::steady_clock::now();

    const auto expected_messages = batch_count * batch_message_count;
    const auto counters = proxy.counters();
    if (observed_messages != expected_messages || counters.forwarded != expected_messages ||
        counters.blocked != 0U || counters.oversized != 0U) {
        std::cerr << "pipeline accounting failed\n";
        return 1;
    }

    const auto seconds = std::chrono::duration<double>(stop - start).count();
    const auto mebibytes = static_cast<double>(processed_bytes) / (1024.0 * 1024.0);
    std::cout << std::fixed << std::setprecision(6)
              << "elapsed_seconds=" << seconds << '\n'
              << "total_processed_bytes=" << processed_bytes << '\n'
              << "total_messages=" << observed_messages << '\n'
              << "payload_checksum=" << checksum << '\n'
              << "throughput_mib_per_second=" << (mebibytes / seconds) << '\n'
              << "messages_per_second=" << (static_cast<double>(observed_messages) / seconds)
              << '\n';
    return 0;
}
