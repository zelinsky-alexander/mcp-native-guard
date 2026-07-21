#include "mcp_native_guard/io/line_framer.hpp"
#include "mcp_native_guard/proxy/proxy_core.hpp"
#include "mcp_native_guard/security/policy.hpp"

#include <cstddef>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

int failures = 0;

void check(bool condition, std::string_view expression, int line) {
    if (!condition) {
        std::cerr << "line " << line << ": check failed: " << expression << '\n';
        ++failures;
    }
}

#define CHECK(expression) check(static_cast<bool>(expression), #expression, __LINE__)

void test_line_framer_accepts_empty_chunks() {
    mng::io::LineFramer framer;
    CHECK(framer.feed({}, [](std::string_view) {}));
    CHECK(framer.buffered_bytes() == 0U);
}

void test_line_framer_split_messages() {
    mng::io::LineFramer framer{{64U, 8U, true}};
    std::vector<std::string> messages;

    const std::string first = "{\"jsonrpc\":\"2.0\"}";
    const std::string input_a = first.substr(0, 8);
    const std::string input_b = first.substr(8) + "\n{}\r\n";

    CHECK(framer.feed(std::span<const char>{input_a.data(), input_a.size()},
                      [&](std::string_view value) { messages.emplace_back(value); }));
    CHECK(messages.empty());
    CHECK(framer.feed(std::span<const char>{input_b.data(), input_b.size()},
                      [&](std::string_view value) { messages.emplace_back(value); }));
    CHECK(framer.finish());
    CHECK(messages.size() == 2U);
    CHECK(messages[0] == first);
    CHECK(messages[1] == "{}");
}

void test_line_framer_rejects_oversized_message() {
    mng::io::LineFramer framer{{4U, 4U, true}};
    const std::string input = "12345\n";
    std::size_t emitted = 0;

    const auto status = framer.feed(
        std::span<const char>{input.data(), input.size()},
        [&](std::string_view) { ++emitted; });

    CHECK(!status);
    CHECK(status.code == mng::StatusCode::message_too_large);
    CHECK(emitted == 0U);
}

void test_line_framer_detects_truncation() {
    mng::io::LineFramer framer;
    const std::string input = "partial";
    CHECK(framer.feed(std::span<const char>{input.data(), input.size()}, [](std::string_view) {}));
    const auto status = framer.finish();
    CHECK(!status);
    CHECK(status.code == mng::StatusCode::truncated_message);
}

mng::security::PolicyTable build_policy() {
    std::vector<mng::security::ToolRule> rules{
        {"filesystem.write_file", mng::security::Access::allow, mng::security::Access::deny},
        {"filesystem.read_file", mng::security::Access::allow, mng::security::Access::allow},
    };
    mng::security::PolicyTable policy;
    const auto status = mng::security::PolicyTable::build(
        std::move(rules),
        {mng::security::Access::deny, mng::security::Access::deny},
        policy);
    CHECK(status);
    return policy;
}

void test_policy_lookup() {
    auto policy = build_policy();
    CHECK(policy.rule_count() == 2U);
    CHECK(policy.visibility_for("filesystem.read_file") == mng::security::Access::allow);
    CHECK(policy.invocation_for("filesystem.read_file") == mng::security::Access::allow);
    CHECK(policy.invocation_for("filesystem.write_file") == mng::security::Access::deny);
    CHECK(policy.visibility_for("unknown") == mng::security::Access::deny);
}

void test_policy_rejects_duplicates() {
    std::vector<mng::security::ToolRule> rules{
        {"same", mng::security::Access::allow, mng::security::Access::allow},
        {"same", mng::security::Access::deny, mng::security::Access::deny},
    };
    mng::security::PolicyTable policy;
    const auto status = mng::security::PolicyTable::build(std::move(rules), {}, policy);
    CHECK(!status);
    CHECK(status.code == mng::StatusCode::duplicate_rule);
}

void test_proxy_core_decisions_and_counters() {
    mng::proxy::ProxyCore proxy{build_policy(), {128U}};

    CHECK(proxy.authorize_tool_call("filesystem.read_file", 64U).should_forward());
    CHECK(!proxy.authorize_tool_call("filesystem.write_file", 64U).should_forward());
    CHECK(!proxy.authorize_tool_call("filesystem.read_file", 129U).should_forward());
    CHECK(proxy.authorize_tool_visibility("filesystem.write_file").should_forward());

    const auto counters = proxy.counters();
    CHECK(counters.forwarded == 2U);
    CHECK(counters.blocked == 2U);
    CHECK(counters.oversized == 1U);
}

} // namespace

int main() {
    test_line_framer_accepts_empty_chunks();
    test_line_framer_split_messages();
    test_line_framer_rejects_oversized_message();
    test_line_framer_detects_truncation();
    test_policy_lookup();
    test_policy_rejects_duplicates();
    test_proxy_core_decisions_and_counters();

    if (failures != 0) {
        std::cerr << failures << " test check(s) failed\n";
        return 1;
    }

    std::cout << "all focused tests passed\n";
    return 0;
}
