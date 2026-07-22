#include "mcp_native_guard/io/line_framer.hpp"
#include "mcp_native_guard/protocol/json_rpc_envelope.hpp"
#include "mcp_native_guard/protocol/tool_call_extractor.hpp"
#include "mcp_native_guard/protocol/tool_call_filter.hpp"
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

void test_json_rpc_envelope_classifies_request_notification_and_response() {
    mng::protocol::JsonRpcEnvelopeClassifier classifier;

    const std::string request_message =
        R"({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"demo.read"}})";
    const auto request = classifier.classify(request_message);
    CHECK(request);
    CHECK(request.kind == mng::protocol::EnvelopeKind::request);
    CHECK(request.id_kind == mng::protocol::IdKind::number);
    CHECK(request.id_json == "7");
    CHECK(request.id_json.data() >= request_message.data());
    CHECK(request.id_json.data() + request.id_json.size() <=
          request_message.data() + request_message.size());
    CHECK(request.method == "tools/call");

    const auto notification = classifier.classify(
        R"({"jsonrpc":"2.0","method":"notifications/progress","params":[1,2,3]})");
    CHECK(notification);
    CHECK(notification.kind == mng::protocol::EnvelopeKind::notification);
    CHECK(notification.id_kind == mng::protocol::IdKind::absent);
    CHECK(notification.id_json.empty());

    const auto string_request = classifier.classify(
        R"({"jsonrpc":"2.0","id":"abc","method":"ping"})");
    CHECK(string_request);
    CHECK(string_request.kind == mng::protocol::EnvelopeKind::request);
    CHECK(string_request.id_kind == mng::protocol::IdKind::string);
    CHECK(string_request.id_json == R"("abc")");

    const auto response = classifier.classify(
        R"({"jsonrpc":"2.0","id":12,"result":{"items":[true,null]}})");
    CHECK(response);
    CHECK(response.kind == mng::protocol::EnvelopeKind::response);
    CHECK(response.id_kind == mng::protocol::IdKind::number);
    CHECK(response.id_json == "12");
}

void test_json_rpc_envelope_extracts_null_id() {
    mng::protocol::JsonRpcEnvelopeClassifier classifier;
    const auto request = classifier.classify(
        R"({"jsonrpc":"2.0","id":null,"method":"tools/call","params":{"name":"demo"}})");
    CHECK(request);
    CHECK(request.id_kind == mng::protocol::IdKind::null_value);
    CHECK(request.id_json == "null");
}

void test_json_rpc_envelope_rejects_ambiguous_or_malformed_input() {
    mng::protocol::JsonRpcEnvelopeClassifier classifier;

    const auto duplicate = classifier.classify(
        R"({"jsonrpc":"2.0","method":"a","method":"b"})");
    CHECK(!duplicate);
    CHECK(duplicate.error == mng::protocol::ClassificationError::duplicate_member);

    const auto escaped_method = classifier.classify(
        R"({"jsonrpc":"2.0","method":"tools\/call"})");
    CHECK(!escaped_method);
    CHECK(escaped_method.error == mng::protocol::ClassificationError::invalid_envelope);

    const auto escaped_member = classifier.classify(
        R"({"jsonrpc":"2.0","m\u0065thod":"tools/call"})");
    CHECK(!escaped_member);
    CHECK(escaped_member.error == mng::protocol::ClassificationError::malformed_json);

    const auto nested_method = classifier.classify(
        R"({"jsonrpc":"2.0","params":{"method":"tools/call"}})");
    CHECK(!nested_method);
    CHECK(nested_method.error == mng::protocol::ClassificationError::invalid_envelope);

    const auto unsupported_version = classifier.classify(
        R"({"jsonrpc":"1.0","method":"tools/call"})");
    CHECK(!unsupported_version);
    CHECK(unsupported_version.error == mng::protocol::ClassificationError::unsupported_jsonrpc_version);

    const auto malformed = classifier.classify(R"({"jsonrpc":"2.0","method":"tools/call")");
    CHECK(!malformed);
    CHECK(malformed.error == mng::protocol::ClassificationError::malformed_json);
}

void test_json_rpc_envelope_respects_input_limit() {
    mng::protocol::JsonRpcEnvelopeClassifier classifier{{16U, 4U}};
    const auto envelope = classifier.classify(R"({"jsonrpc":"2.0","method":"x"})");
    CHECK(!envelope);
    CHECK(envelope.error == mng::protocol::ClassificationError::message_too_large);
}

void test_json_rpc_envelope_respects_nesting_limit() {
    mng::protocol::JsonRpcEnvelopeClassifier classifier{{1024U, 1U}};
    const auto envelope = classifier.classify(
        R"({"jsonrpc":"2.0","id":1,"result":{"items":[true]}})");
    CHECK(!envelope);
    CHECK(envelope.error == mng::protocol::ClassificationError::malformed_json);
}

// ---------------------------------------------------------------------------
// ToolCallExtractor tests
// ---------------------------------------------------------------------------

void test_tool_call_extractor_valid_basic() {
    mng::protocol::ToolCallExtractor extractor;
    const auto result = extractor.extract(
        R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"demo.read"}})");
    CHECK(result);
    CHECK(result.error == mng::protocol::ExtractionError::none);
    CHECK(result.name == "demo.read");
    CHECK(result.arguments_json.empty());
}

void test_tool_call_extractor_valid_with_arguments() {
    mng::protocol::ToolCallExtractor extractor;
    const std::string msg =
        R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fs.read","arguments":{"path":"/tmp","flags":0}}})";
    const auto result = extractor.extract(msg);
    CHECK(result);
    CHECK(result.name == "fs.read");
    // arguments_json is a raw slice inside the original message
    CHECK(result.arguments_json == R"({"path":"/tmp","flags":0})");
    CHECK(result.arguments_json.data() >= msg.data());
    CHECK(result.arguments_json.data() + result.arguments_json.size() <=
          msg.data() + msg.size());
}

void test_tool_call_extractor_valid_reordered_params_members() {
    // arguments appears before name inside params
    mng::protocol::ToolCallExtractor extractor;
    const auto result = extractor.extract(
        R"({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"arguments":{"x":1},"name":"tool.a"}})");
    CHECK(result);
    CHECK(result.name == "tool.a");
    CHECK(result.arguments_json == R"({"x":1})");
}

void test_tool_call_extractor_valid_reordered_top_level() {
    // params appears before method and jsonrpc at the top level
    mng::protocol::ToolCallExtractor extractor;
    const auto result = extractor.extract(
        R"({"params":{"name":"ns.op"},"method":"tools/call","jsonrpc":"2.0","id":3})");
    CHECK(result);
    CHECK(result.name == "ns.op");
}

void test_tool_call_extractor_valid_extra_params_members() {
    // params contains unknown members that should be skipped
    mng::protocol::ToolCallExtractor extractor;
    const auto result = extractor.extract(
        R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"_meta":{"progress":42},"name":"demo.write","arguments":null}})");
    CHECK(result);
    CHECK(result.name == "demo.write");
    CHECK(result.arguments_json == "null");
}

void test_tool_call_extractor_rejects_missing_params() {
    mng::protocol::ToolCallExtractor extractor;
    const auto result = extractor.extract(
        R"({"jsonrpc":"2.0","id":1,"method":"tools/call"})");
    CHECK(!result);
    CHECK(result.error == mng::protocol::ExtractionError::missing_params);
}

void test_tool_call_extractor_rejects_missing_name() {
    mng::protocol::ToolCallExtractor extractor;

    // params is an empty object
    const auto empty_params = extractor.extract(
        R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}})");
    CHECK(!empty_params);
    CHECK(empty_params.error == mng::protocol::ExtractionError::missing_name);

    // params has arguments but no name
    const auto no_name = extractor.extract(
        R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{"k":"v"}}})");
    CHECK(!no_name);
    CHECK(no_name.error == mng::protocol::ExtractionError::missing_name);
}

void test_tool_call_extractor_rejects_duplicate_params() {
    mng::protocol::ToolCallExtractor extractor;
    const auto result = extractor.extract(
        R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a"},"params":{"name":"b"}})");
    CHECK(!result);
    CHECK(result.error == mng::protocol::ExtractionError::duplicate_params);
}

void test_tool_call_extractor_rejects_duplicate_name() {
    mng::protocol::ToolCallExtractor extractor;
    const auto result = extractor.extract(
        R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a","name":"b"}})");
    CHECK(!result);
    CHECK(result.error == mng::protocol::ExtractionError::duplicate_name);
}

void test_tool_call_extractor_rejects_non_string_name() {
    mng::protocol::ToolCallExtractor extractor;

    const auto number_name = extractor.extract(
        R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":42}})");
    CHECK(!number_name);
    CHECK(number_name.error == mng::protocol::ExtractionError::non_string_name);

    const auto bool_name = extractor.extract(
        R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":true}})");
    CHECK(!bool_name);
    CHECK(bool_name.error == mng::protocol::ExtractionError::non_string_name);

    const auto object_name = extractor.extract(
        R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":{}}})");
    CHECK(!object_name);
    CHECK(object_name.error == mng::protocol::ExtractionError::non_string_name);
}

void test_tool_call_extractor_rejects_escaped_name() {
    mng::protocol::ToolCallExtractor extractor;

    // Forward-slash escape in value
    const auto escaped_slash = extractor.extract(
        R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"demo\/read"}})");
    CHECK(!escaped_slash);
    CHECK(escaped_slash.error == mng::protocol::ExtractionError::escaped_name);

    // \u-escape encoding a regular ASCII character
    const auto escaped_unicode = extractor.extract(
        R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"demo\u002Eread"}})");
    CHECK(!escaped_unicode);
    CHECK(escaped_unicode.error == mng::protocol::ExtractionError::escaped_name);
}

void test_tool_call_extractor_rejects_malformed_json() {
    mng::protocol::ToolCallExtractor extractor;

    // Missing closing brace on top-level object
    const auto truncated = extractor.extract(
        R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"})");
    CHECK(!truncated);
    CHECK(truncated.error == mng::protocol::ExtractionError::malformed_json);

    // Bare word instead of value
    const auto bare_word = extractor.extract(
        R"({"jsonrpc":"2.0","params":{"name":foo}})");
    CHECK(!bare_word);
    CHECK(bare_word.error == mng::protocol::ExtractionError::malformed_json);

    // Not an object at top level
    const auto not_object = extractor.extract(R"([1,2,3])");
    CHECK(!not_object);
    CHECK(not_object.error == mng::protocol::ExtractionError::malformed_json);
}

void test_tool_call_extractor_respects_message_size_limit() {
    mng::protocol::ToolCallExtractor extractor{{32U, 8U}};
    const auto result = extractor.extract(
        R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}})");
    CHECK(!result);
    CHECK(result.error == mng::protocol::ExtractionError::message_too_large);
}

void test_tool_call_extractor_respects_nesting_depth_limit() {
    // Depth accounting: skip_value is called with depth=2 for the arguments
    // value (top-level is depth 0; params members' values are at depth 2).
    // With max_nesting_depth=3, member values inside the arguments object are
    // at depth 3 (≤ limit) so a flat object is accepted; a doubly-nested
    // object would place a value at depth 4 (> limit) and is rejected.
    mng::protocol::ToolCallExtractor extractor{{1024U * 1024U, 3U}};

    // arguments={"k":1}: member value `1` is at depth 3 – accepted.
    const auto shallow = extractor.extract(
        R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":{"k":1}}})");
    CHECK(shallow);

    // arguments={"a":{"b":1}}: value `1` inside nested object is at depth 4 – rejected.
    const auto too_deep = extractor.extract(
        R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":{"a":{"b":1}}}})");
    CHECK(!too_deep);
    CHECK(too_deep.error == mng::protocol::ExtractionError::malformed_json);
}

// ---------------------------------------------------------------------------

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

mng::protocol::ToolCallFilter build_tool_call_filter(std::vector<std::string> denied_tools) {
    std::vector<mng::security::ToolRule> rules;
    rules.reserve(denied_tools.size());
    for (std::string& name : denied_tools) {
        rules.push_back({
            std::move(name),
            mng::security::Access::allow,
            mng::security::Access::deny,
        });
    }
    mng::security::PolicyTable policy;
    const auto status = mng::security::PolicyTable::build(
        std::move(rules),
        {mng::security::Access::allow, mng::security::Access::allow},
        policy);
    CHECK(status);
    return mng::protocol::ToolCallFilter{std::move(policy)};
}

void test_tool_call_filter_enforces_requests_and_notifications() {
    auto filter = build_tool_call_filter({"blocked.one", "blocked.two"});

    const auto denied_request = filter.inspect(
        R"({"jsonrpc":"2.0","id":"req-7","method":"tools/call","params":{"name":"blocked.one"}})");
    CHECK(denied_request.action == mng::process::ClientMessageAction::respond_with_error);
    CHECK(denied_request.id_json == R"("req-7")");
    CHECK(denied_request.error_code == -32001);
    CHECK(denied_request.error_message == "Tool call denied by policy");

    const auto denied_notification = filter.inspect(
        R"({"jsonrpc":"2.0","method":"tools/call","params":{"name":"blocked.two"}})");
    CHECK(denied_notification.action == mng::process::ClientMessageAction::drop);

    const auto allowed_request = filter.inspect(
        R"({"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"allowed.tool"}})");
    CHECK(allowed_request.action == mng::process::ClientMessageAction::forward);
}

void test_tool_call_filter_rejects_invalid_params_and_preserves_other_methods() {
    auto filter = build_tool_call_filter({"blocked"});

    const auto invalid = filter.inspect(
        R"({"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"arguments":{}}})");
    CHECK(invalid.action == mng::process::ClientMessageAction::respond_with_error);
    CHECK(invalid.id_json == "9");
    CHECK(invalid.error_code == -32602);
    CHECK(invalid.error_message == "Invalid tools/call parameters");

    const auto passthrough = filter.inspect(
        R"({"jsonrpc":"2.0","id":10,"method":"initialize","params":{}})");
    CHECK(passthrough.action == mng::process::ClientMessageAction::forward);

    const auto malformed = filter.inspect(
        R"({"jsonrpc":"2.0","id":11,"method":"tools/call","params":)");
    CHECK(malformed.action == mng::process::ClientMessageAction::respond_with_error);
    CHECK(malformed.id_json == "11");
    CHECK(malformed.error_code == -32602);

    const auto unusable = filter.inspect(R"({"jsonrpc":"2.0","method":"tools/call","params":)");
    CHECK(unusable.action == mng::process::ClientMessageAction::drop);
}

} // namespace

int main() {
    test_line_framer_accepts_empty_chunks();
    test_line_framer_split_messages();
    test_line_framer_rejects_oversized_message();
    test_line_framer_detects_truncation();
    test_json_rpc_envelope_classifies_request_notification_and_response();
    test_json_rpc_envelope_extracts_null_id();
    test_json_rpc_envelope_rejects_ambiguous_or_malformed_input();
    test_json_rpc_envelope_respects_input_limit();
    test_json_rpc_envelope_respects_nesting_limit();
    test_tool_call_extractor_valid_basic();
    test_tool_call_extractor_valid_with_arguments();
    test_tool_call_extractor_valid_reordered_params_members();
    test_tool_call_extractor_valid_reordered_top_level();
    test_tool_call_extractor_valid_extra_params_members();
    test_tool_call_extractor_rejects_missing_params();
    test_tool_call_extractor_rejects_missing_name();
    test_tool_call_extractor_rejects_duplicate_params();
    test_tool_call_extractor_rejects_duplicate_name();
    test_tool_call_extractor_rejects_non_string_name();
    test_tool_call_extractor_rejects_escaped_name();
    test_tool_call_extractor_rejects_malformed_json();
    test_tool_call_extractor_respects_message_size_limit();
    test_tool_call_extractor_respects_nesting_depth_limit();
    test_policy_lookup();
    test_policy_rejects_duplicates();
    test_proxy_core_decisions_and_counters();
    test_tool_call_filter_enforces_requests_and_notifications();
    test_tool_call_filter_rejects_invalid_params_and_preserves_other_methods();

    if (failures != 0) {
        std::cerr << failures << " test check(s) failed\n";
        return 1;
    }

    std::cout << "all focused tests passed\n";
    return 0;
}
