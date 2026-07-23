#include "mcp_native_guard/audit/audit_sink.hpp"
#include "mcp_native_guard/io/line_framer.hpp"
#include "mcp_native_guard/protocol/json_rpc_envelope.hpp"
#include "mcp_native_guard/protocol/tool_call_extractor.hpp"
#include "mcp_native_guard/protocol/tool_call_filter.hpp"
#include "mcp_native_guard/protocol/tool_inventory.hpp"
#include "mcp_native_guard/proxy/proxy_core.hpp"
#include "mcp_native_guard/security/policy.hpp"
#include "mcp_native_guard/security/policy_generator.hpp"
#include "mcp_native_guard/security/policy_loader.hpp"
#include "mcp_native_guard/version.hpp"

#include <algorithm>
#include <cstddef>
#include <iostream>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <streambuf>
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
    CHECK(framer.failed_message_bytes() == 5U);
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
    mng::protocol::JsonRpcEnvelopeClassifier classifier{{16U, 4U, 64U}};
    const auto envelope = classifier.classify(R"({"jsonrpc":"2.0","method":"x"})");
    CHECK(!envelope);
    CHECK(envelope.error == mng::protocol::ClassificationError::message_too_large);
}

void test_json_rpc_envelope_respects_nesting_limit() {
    mng::protocol::JsonRpcEnvelopeClassifier classifier{{1024U, 1U, 64U}};
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
    mng::protocol::ToolCallExtractor extractor{{32U, 8U, 64U}};
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
    mng::protocol::ToolCallExtractor extractor{{1024U * 1024U, 3U, 64U}};

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

mng::protocol::ToolCallFilter build_tool_call_filter(
    std::vector<std::string> denied_tools,
    mng::audit::AuditSink* audit_sink = nullptr) {
    std::vector<mng::security::ToolRule> rules;
    rules.reserve(denied_tools.size());
    for (std::string& name : denied_tools) {
        rules.push_back({
            std::move(name),
            mng::security::Access::deny,
            mng::security::Access::deny,
        });
    }
    mng::security::PolicyTable policy;
    const auto status = mng::security::PolicyTable::build(
        std::move(rules),
        {mng::security::Access::allow, mng::security::Access::allow},
        policy);
    CHECK(status);
    return mng::protocol::ToolCallFilter{std::move(policy), audit_sink};
}

std::size_t line_count(std::string_view text) {
    return static_cast<std::size_t>(std::count(text.begin(), text.end(), '\n'));
}

void test_audit_allowed_denied_ids_and_absent_id() {
    std::ostringstream output;
    std::ostringstream diagnostics;
    mng::audit::JsonlAuditSink audit{output, diagnostics};
    auto filter = build_tool_call_filter({"blocked"}, &audit);

    CHECK(filter.inspect(
              R"({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"allowed"}})")
              .action == mng::process::ClientMessageAction::forward);
    CHECK(filter.inspect(
              R"({"jsonrpc":"2.0","id":"deny-id","method":"tools/call","params":{"name":"blocked"}})")
              .action == mng::process::ClientMessageAction::respond_with_error);
    CHECK(filter.inspect(
              R"({"jsonrpc":"2.0","method":"tools/call","params":{"name":"allowed"}})")
              .action == mng::process::ClientMessageAction::forward);

    const std::string records = output.str();
    CHECK(records.find(
              R"("event":"tools/call","decision":"allow","reason":"policy_allowed","tool":"allowed","request_id":7)") !=
          std::string::npos);
    CHECK(records.find(
              R"("decision":"deny","reason":"policy_denied","tool":"blocked","request_id":"deny-id")") !=
          std::string::npos);
    CHECK(line_count(records) == 3U);
    const std::size_t notification = records.rfind(R"("tool":"allowed")");
    CHECK(notification != std::string::npos);
    CHECK(notification != std::string::npos &&
          records.find("request_id", notification) == std::string::npos);
    CHECK(diagnostics.str().empty());
}

void test_audit_hidden_tool_and_invalid_call() {
    std::ostringstream output;
    std::ostringstream diagnostics;
    mng::audit::JsonlAuditSink audit{output, diagnostics};
    auto filter = build_tool_call_filter({"hidden"}, &audit);

    CHECK(filter.inspect(R"({"jsonrpc":"2.0","id":"list-id","method":"tools/list"})").action ==
          mng::process::ClientMessageAction::forward);
    CHECK(filter.inspect_server(
              R"({"jsonrpc":"2.0","id":"list-id","result":{"tools":[{"name":"visible"},{"name":"hidden"}]}})")
              .action == mng::process::ServerMessageAction::replace);
    CHECK(filter.inspect(
              R"({"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"arguments":{"secret":"payload"}}})")
              .action == mng::process::ClientMessageAction::respond_with_error);
    CHECK(filter.inspect(
              R"({"jsonrpc":"2.0","id":10,"method":"tools/call","params":)")
              .action == mng::process::ClientMessageAction::respond_with_error);

    const std::string records = output.str();
    CHECK(records.find(
              R"("event":"tools/list_tool_removed","decision":"deny","reason":"policy_denied","tool":"hidden","request_id":"list-id")") !=
          std::string::npos);
    CHECK(records.find(
              R"("event":"tools/call","decision":"deny","reason":"invalid_parameters","request_id":9)") !=
          std::string::npos);
    CHECK(records.find(
              R"("event":"tools/call","decision":"deny","reason":"malformed_message","request_id":10)") !=
          std::string::npos);
    CHECK(records.find("secret") == std::string::npos);
    CHECK(records.find("payload") == std::string::npos);
    CHECK(records.find("params") == std::string::npos);
    CHECK(records.find("jsonrpc") == std::string::npos);
}

void test_audit_json_escaping_and_multiple_jsonl_records() {
    std::ostringstream output;
    std::ostringstream diagnostics;
    mng::audit::JsonlAuditSink audit{output, diagnostics};
    const std::string tool{"quote\"slash\\line\ncontrol\x01", 25U};
    audit.record({
        mng::audit::EventType::tool_call,
        mng::audit::Decision::deny,
        mng::audit::Reason::policy_denied,
        tool,
        R"("string-id")",
        42U,
        true,
    });
    audit.record({
        mng::audit::EventType::message_rejected,
        mng::audit::Decision::deny,
        mng::audit::Reason::message_too_large,
        {},
        {},
        1025U,
        true,
    });

    const std::string records = output.str();
    CHECK(records.find(R"("tool":"quote\"slash\\line\ncontrol\u0001")") !=
          std::string::npos);
    CHECK(records.find(R"("request_id":"string-id")") != std::string::npos);
    CHECK(records.find(R"("message_size":42)") != std::string::npos);
    CHECK(line_count(records) == 2U);
    std::istringstream lines{records};
    std::string line;
    while (std::getline(lines, line)) {
        CHECK(line.starts_with(R"({"timestamp":")"));
        CHECK(line.find('T') != std::string::npos);
        CHECK(line.find(R"(Z","event":)") != std::string::npos);
        CHECK(line.ends_with('}'));
    }
}

void test_audit_disabled_and_message_data_not_logged() {
    std::ostringstream unused;
    std::ostringstream diagnostics;
    mng::audit::JsonlAuditSink audit{unused, diagnostics};
    auto filter = build_tool_call_filter({"blocked"});
    const std::string request =
        R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"blocked","arguments":{"token":"never-audit-this"}}})";
    CHECK(filter.inspect(request).action ==
          mng::process::ClientMessageAction::respond_with_error);
    CHECK(unused.str().empty());
}

class FailingStreamBuffer final : public std::streambuf {
protected:
    std::streamsize xsputn(const char*, std::streamsize) override { return 0; }
    int_type overflow(int_type) override { return traits_type::eof(); }
};

void test_audit_write_failure_keeps_enforcement_active_and_reports_once() {
    FailingStreamBuffer buffer;
    std::ostream output{&buffer};
    std::ostringstream diagnostics;
    mng::audit::JsonlAuditSink audit{output, diagnostics};
    auto filter = build_tool_call_filter({"blocked"}, &audit);

    CHECK(filter.inspect(
              R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"allowed"}})")
              .action == mng::process::ClientMessageAction::forward);
    CHECK(filter.inspect(
              R"({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"blocked"}})")
              .action == mng::process::ClientMessageAction::respond_with_error);
    CHECK(audit.failed());
    CHECK(line_count(diagnostics.str()) == 1U);
    CHECK(diagnostics.str().find("enforcement remains active") != std::string::npos);
}

void test_audit_oversize_and_pending_capacity_events() {
    std::ostringstream output;
    std::ostringstream diagnostics;
    mng::audit::JsonlAuditSink audit{output, diagnostics};
    mng::security::PolicyTable policy;
    CHECK(mng::security::PolicyTable::build(
        {}, {mng::security::Access::allow, mng::security::Access::allow}, policy));
    mng::protocol::ToolCallFilter filter{
        std::move(policy), {{128U, 16U, 1U}, 8U, 8U}, &audit};

    filter.message_too_large(mng::process::MessageDirection::client_to_server, 129U);
    CHECK(filter.inspect(R"({"jsonrpc":"2.0","id":1,"method":"tools/list"})").action ==
          mng::process::ClientMessageAction::forward);
    const auto full = filter.inspect(R"({"jsonrpc":"2.0","id":2,"method":"tools/list"})");
    CHECK(full.action == mng::process::ClientMessageAction::respond_with_error);
    CHECK(full.error_code == -32002);

    const std::string records = output.str();
    CHECK(records.find(
              R"("event":"message_rejected","decision":"deny","reason":"message_too_large","message_size":129)") !=
          std::string::npos);
    CHECK(records.find(
              R"("event":"tools/list_correlation","decision":"deny","reason":"capacity_exhausted","request_id":2)") !=
          std::string::npos);
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

void test_tools_list_filter_removes_denied_tools_and_preserves_fields() {
    auto filter = build_tool_call_filter({"blocked.one"});
    CHECK(filter.inspect(R"({"jsonrpc":"2.0","id":1,"method":"tools/list"})").action ==
          mng::process::ClientMessageAction::forward);

    const std::string response =
        R"({"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"allowed.one","description":"kept","inputSchema":{"type":"object","properties":{"value":{"type":"string"}}}},{"name":"blocked.one","description":"removed"}],"nextCursor":"cursor-1"}})";
    const auto decision = filter.inspect_server(response);
    CHECK(decision.action == mng::process::ServerMessageAction::replace);
    CHECK(decision.replacement.find(R"("name":"allowed.one")") != std::string_view::npos);
    CHECK(decision.replacement.find(R"("description":"kept")") != std::string_view::npos);
    CHECK(decision.replacement.find(
              R"("inputSchema":{"type":"object","properties":{"value":{"type":"string"}}})") !=
          std::string_view::npos);
    CHECK(decision.replacement.find("blocked.one") == std::string_view::npos);
    CHECK(decision.replacement.find(R"("nextCursor":"cursor-1")") != std::string_view::npos);
    CHECK(filter.pending_request_count() == 0U);
}

void test_tools_list_filter_multiple_all_allowed_and_all_denied() {
    auto multiple = build_tool_call_filter({"blocked.one", "blocked.two"});
    CHECK(multiple.inspect(R"({"jsonrpc":"2.0","id":"multi","method":"tools/list"})").action ==
          mng::process::ClientMessageAction::forward);
    const auto multiple_result = multiple.inspect_server(
        R"({"jsonrpc":"2.0","id":"multi","result":{"tools":[{"name":"blocked.one"},{"name":"allowed"},{"name":"blocked.two"}]}})");
    CHECK(multiple_result.action == mng::process::ServerMessageAction::replace);
    CHECK(multiple_result.replacement.find("blocked.one") == std::string_view::npos);
    CHECK(multiple_result.replacement.find("blocked.two") == std::string_view::npos);
    CHECK(multiple_result.replacement.find(R"("name":"allowed")") != std::string_view::npos);

    auto all_allowed = build_tool_call_filter({"other"});
    CHECK(all_allowed.inspect(R"({"jsonrpc":"2.0","id":2,"method":"tools/list"})").action ==
          mng::process::ClientMessageAction::forward);
    const std::string allowed_response =
        R"({"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"one"},{"name":"two"}]}})";
    const auto allowed_result = all_allowed.inspect_server(allowed_response);
    CHECK(allowed_result.action == mng::process::ServerMessageAction::replace);
    CHECK(allowed_result.replacement == allowed_response);

    auto all_denied = build_tool_call_filter({"one", "two"});
    CHECK(all_denied.inspect(R"({"jsonrpc":"2.0","id":3,"method":"tools/list"})").action ==
          mng::process::ClientMessageAction::forward);
    const auto denied_result = all_denied.inspect_server(
        R"({"jsonrpc":"2.0","id":3,"result":{"tools":[{"name":"one"},{"name":"two"}]}})");
    CHECK(denied_result.action == mng::process::ServerMessageAction::replace);
    CHECK(denied_result.replacement == R"({"jsonrpc":"2.0","id":3,"result":{"tools":[]}})");
}

void test_tools_list_filter_reordered_and_unrelated_responses() {
    auto filter = build_tool_call_filter({"blocked"});
    const std::string unrelated = R"({"jsonrpc":"2.0","id":20,"result":{"value":true}})";
    CHECK(filter.inspect_server(unrelated).action == mng::process::ServerMessageAction::forward);

    CHECK(filter.inspect(R"({"jsonrpc":"2.0","id":"known","method":"tools/list"})").action ==
          mng::process::ClientMessageAction::forward);
    const std::string unknown =
        R"({"jsonrpc":"2.0","id":"unknown","result":{"tools":[{"name":"blocked"}]}})";
    CHECK(filter.inspect_server(unknown).action == mng::process::ServerMessageAction::forward);
    CHECK(filter.pending_request_count() == 1U);

    const auto reordered = filter.inspect_server(
        R"({"id":"known","result":{"nextCursor":null,"tools":[{"description":"x","name":"blocked"},{"name":"allowed"}]},"jsonrpc":"2.0"})");
    CHECK(reordered.action == mng::process::ServerMessageAction::replace);
    CHECK(reordered.replacement.find("blocked") == std::string_view::npos);
    CHECK(reordered.replacement.find(R"("name":"allowed")") != std::string_view::npos);
    CHECK(reordered.replacement.find(R"("nextCursor":null)") != std::string_view::npos);
    CHECK(filter.pending_request_count() == 0U);
}

void test_tools_list_filter_string_numeric_ids_and_duplicate_members() {
    auto ids = build_tool_call_filter({"blocked"});
    CHECK(ids.inspect(R"({"jsonrpc":"2.0","id":41,"method":"tools/list"})").action ==
          mng::process::ClientMessageAction::forward);
    CHECK(ids.inspect(R"({"jsonrpc":"2.0","id":"forty-two","method":"tools/list"})").action ==
          mng::process::ClientMessageAction::forward);
    CHECK(ids.pending_request_count() == 2U);
    CHECK(ids.inspect_server(
              R"({"jsonrpc":"2.0","id":41,"result":{"tools":[{"name":"allowed"}]}})")
              .action == mng::process::ServerMessageAction::replace);
    CHECK(ids.inspect_server(
              R"({"jsonrpc":"2.0","id":"forty-two","result":{"tools":[{"name":"allowed"}]}})")
              .action == mng::process::ServerMessageAction::replace);

    auto duplicate_pending = build_tool_call_filter({"blocked"});
    CHECK(duplicate_pending.inspect(R"({"jsonrpc":"2.0","id":5,"method":"tools/list"})").action ==
          mng::process::ClientMessageAction::forward);
    CHECK(duplicate_pending.inspect(R"({"jsonrpc":"2.0","id":5,"method":"tools/list"})").action ==
          mng::process::ClientMessageAction::drop);

    const auto rejects_response = [](std::string_view response) {
        auto filter = build_tool_call_filter({"blocked"});
        CHECK(filter.inspect(R"({"jsonrpc":"2.0","id":7,"method":"tools/list"})").action ==
              mng::process::ClientMessageAction::forward);
        CHECK(filter.inspect_server(response).action == mng::process::ServerMessageAction::drop);
    };
    rejects_response(
        R"({"jsonrpc":"2.0","id":7,"id":7,"result":{"tools":[{"name":"allowed"}]}})");
    rejects_response(
        R"({"jsonrpc":"2.0","id":7,"result":{"tools":[]},"result":{"tools":[]}})");
    rejects_response(
        R"({"jsonrpc":"2.0","id":7,"result":{"tools":[],"tools":[]}})");
    rejects_response(
        R"({"jsonrpc":"2.0","id":7,"result":{"tools":[{"name":"a","name":"b"}]}})");
}

void test_tools_list_filter_rejects_malformed_oversized_and_deep_responses() {
    auto malformed = build_tool_call_filter({"blocked"});
    CHECK(malformed.inspect(R"({"jsonrpc":"2.0","id":8,"method":"tools/list"})").action ==
          mng::process::ClientMessageAction::forward);
    CHECK(malformed.inspect_server(
              R"({"jsonrpc":"2.0","id":8,"result":{"tools":[{"name":"allowed"}]})")
              .action == mng::process::ServerMessageAction::drop);

    mng::security::PolicyTable policy;
    CHECK(mng::security::PolicyTable::build(
        {}, {mng::security::Access::allow, mng::security::Access::allow}, policy));
    mng::protocol::ToolCallFilter bounded{std::move(policy), {{128U, 4U, 1U}, 16U, 16U}};
    CHECK(bounded.inspect(R"({"jsonrpc":"2.0","id":1,"method":"tools/list"})").action ==
          mng::process::ClientMessageAction::forward);
    const std::string oversized =
        R"({"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"allowed","description":")" +
        std::string(128U, 'x') + R"("}]}})";
    CHECK(bounded.inspect_server(oversized).action == mng::process::ServerMessageAction::drop);

    auto deep = build_tool_call_filter({"blocked"});
    CHECK(deep.inspect(R"({"jsonrpc":"2.0","id":9,"method":"tools/list"})").action ==
          mng::process::ClientMessageAction::forward);
    const auto deep_response = deep.inspect_server(
        R"({"jsonrpc":"2.0","id":9,"result":{"tools":[{"name":"allowed","inputSchema":{"a":{"b":{"c":{"d":{"e":1}}}}}}]}})");
    CHECK(deep_response.action == mng::process::ServerMessageAction::replace);

    mng::security::PolicyTable shallow_policy;
    CHECK(mng::security::PolicyTable::build(
        {}, {mng::security::Access::allow, mng::security::Access::allow}, shallow_policy));
    mng::protocol::ToolCallFilter shallow{std::move(shallow_policy), {{1024U, 5U, 4U}, 32U, 64U}};
    CHECK(shallow.inspect(R"({"jsonrpc":"2.0","id":10,"method":"tools/list"})").action ==
          mng::process::ClientMessageAction::forward);
    CHECK(shallow.inspect_server(
              R"({"jsonrpc":"2.0","id":10,"result":{"tools":[{"name":"allowed","inputSchema":{"a":{"b":1}}}]}})")
              .action == mng::process::ServerMessageAction::drop);
}

void test_tools_list_pending_capacity_and_cleanup() {
    mng::security::PolicyTable policy;
    CHECK(mng::security::PolicyTable::build(
        {}, {mng::security::Access::allow, mng::security::Access::allow}, policy));
    mng::protocol::ToolCallFilter filter{std::move(policy), {{1024U, 16U, 1U}, 8U, 8U}};
    CHECK(filter.inspect(R"({"jsonrpc":"2.0","id":1,"method":"tools/list"})").action ==
          mng::process::ClientMessageAction::forward);
    const auto full = filter.inspect(R"({"jsonrpc":"2.0","id":2,"method":"tools/list"})");
    CHECK(full.action == mng::process::ClientMessageAction::respond_with_error);
    CHECK(full.error_code == -32002);
    CHECK(filter.pending_request_count() == 1U);
    CHECK(filter.inspect_server(R"({"jsonrpc":"2.0","id":1,"result":{"tools":[]}})").action ==
          mng::process::ServerMessageAction::replace);
    CHECK(filter.pending_request_count() == 0U);
    CHECK(filter.inspect(R"({"jsonrpc":"2.0","id":2,"method":"tools/list"})").action ==
          mng::process::ClientMessageAction::forward);
    filter.connection_closed();
    CHECK(filter.pending_request_count() == 0U);

    mng::security::PolicyTable aggregate_policy;
    CHECK(mng::security::PolicyTable::build(
        {}, {mng::security::Access::allow, mng::security::Access::allow}, aggregate_policy));
    mng::protocol::ToolCallFilter aggregate{
        std::move(aggregate_policy), {{1024U, 16U, 4U}, 8U, 2U}};
    CHECK(aggregate.inspect(R"({"jsonrpc":"2.0","id":1,"method":"tools/list"})").action ==
          mng::process::ClientMessageAction::forward);
    CHECK(aggregate.inspect(R"({"jsonrpc":"2.0","id":2,"method":"tools/list"})").action ==
          mng::process::ClientMessageAction::forward);
    CHECK(aggregate.inspect(R"({"jsonrpc":"2.0","id":3,"method":"tools/list"})").action ==
          mng::process::ClientMessageAction::respond_with_error);
}

void test_runtime_limits_exact_boundaries_and_untrackable_tools_list() {
    mng::security::PolicyTable policy;
    CHECK(mng::security::PolicyTable::build(
        {}, {mng::security::Access::allow, mng::security::Access::allow}, policy));
    const std::string call =
        R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"allowed"}})";
    mng::protocol::ToolCallFilter exact{
        std::move(policy), {{call.size(), 64U, 1U}, 32U, 64U}};
    CHECK(exact.inspect(call).action == mng::process::ClientMessageAction::forward);

    mng::security::PolicyTable small_policy;
    CHECK(mng::security::PolicyTable::build(
        {}, {mng::security::Access::allow, mng::security::Access::allow}, small_policy));
    mng::protocol::ToolCallFilter one_byte_small{
        std::move(small_policy), {{call.size() - 1U, 64U, 1U}, 32U, 64U}};
    CHECK(one_byte_small.inspect(call).action == mng::process::ClientMessageAction::drop);

    mng::security::PolicyTable depth_policy;
    CHECK(mng::security::PolicyTable::build(
        {}, {mng::security::Access::allow, mng::security::Access::allow}, depth_policy));
    mng::protocol::ToolCallFilter depth{
        std::move(depth_policy), {{1024U, 3U, 1U}, 32U, 64U}};
    CHECK(depth.inspect(
              R"({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"allowed","arguments":{"k":1}}})")
              .action == mng::process::ClientMessageAction::forward);
    CHECK(depth.inspect(
              R"({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"allowed","arguments":{"a":{"b":1}}}})")
              .action == mng::process::ClientMessageAction::respond_with_error);

    mng::security::PolicyTable pending_policy;
    CHECK(mng::security::PolicyTable::build(
        {}, {mng::security::Access::allow, mng::security::Access::allow}, pending_policy));
    mng::protocol::ToolCallFilter none{
        std::move(pending_policy), {{1024U, 64U, 1U}, 32U, 64U}};
    CHECK(none.inspect(R"({"jsonrpc":"2.0","id":1,"method":"tools/list"})").action ==
          mng::process::ClientMessageAction::forward);
    CHECK(none.inspect(R"({"jsonrpc":"2.0","method":"tools/list"})").action ==
          mng::process::ClientMessageAction::drop);
    CHECK(none.pending_request_count() == 1U);
}

const mng::security::ToolRule* find_rule(
    const mng::security::PolicyDefinition& policy,
    std::string_view name) {
    for (const auto& rule : policy.rules) {
        if (rule.name == name) {
            return &rule;
        }
    }
    return nullptr;
}

void test_policy_loader_valid_policy_and_access_values() {
    mng::security::PolicyDefinition policy;
    const mng::security::PolicyLoader loader;
    const auto result = loader.parse(
        R"({"version":1,"defaults":{"visibility":"allow","invocation":"deny"},"tools":[{"name":"filesystem.read_file","visibility":"allow","invocation":"deny"},{"name":"filesystem.write_file","visibility":"deny","invocation":"allow"}]})",
        policy);
    CHECK(result);
    CHECK(policy.defaults.visible == mng::security::Access::allow);
    CHECK(policy.defaults.callable == mng::security::Access::deny);
    CHECK(policy.rules.size() == 2U);
    const auto* read = find_rule(policy, "filesystem.read_file");
    const auto* write = find_rule(policy, "filesystem.write_file");
    CHECK(read != nullptr);
    CHECK(read != nullptr && read->visible == mng::security::Access::allow);
    CHECK(read != nullptr && read->callable == mng::security::Access::deny);
    CHECK(write != nullptr);
    CHECK(write != nullptr && write->visible == mng::security::Access::deny);
    CHECK(write != nullptr && write->callable == mng::security::Access::allow);
}

void test_policy_loader_allow_and_deny_defaults() {
    const mng::security::PolicyLoader loader;
    mng::security::PolicyDefinition allowed;
    CHECK(loader.parse(
        R"({"version":1,"defaults":{"visibility":"allow","invocation":"allow"}})",
        allowed));
    CHECK(allowed.defaults.visible == mng::security::Access::allow);
    CHECK(allowed.defaults.callable == mng::security::Access::allow);
    mng::security::PolicyTable allow_table;
    CHECK(mng::security::PolicyTable::build(
        std::move(allowed.rules), allowed.defaults, allow_table));
    CHECK(allow_table.visibility_for("unlisted") == mng::security::Access::allow);
    CHECK(allow_table.invocation_for("unlisted") == mng::security::Access::allow);

    mng::security::PolicyDefinition denied;
    CHECK(loader.parse(
        R"({"defaults":{"invocation":"deny","visibility":"deny"},"version":1,"tools":[]})",
        denied));
    CHECK(denied.defaults.visible == mng::security::Access::deny);
    CHECK(denied.defaults.callable == mng::security::Access::deny);
    mng::security::PolicyTable deny_table;
    CHECK(mng::security::PolicyTable::build(
        std::move(denied.rules), denied.defaults, deny_table));
    CHECK(deny_table.visibility_for("unlisted") == mng::security::Access::deny);
    CHECK(deny_table.invocation_for("unlisted") == mng::security::Access::deny);
}

void test_policy_loader_rejects_duplicates_and_malformed_json() {
    const mng::security::PolicyLoader loader;
    mng::security::PolicyDefinition policy;
    CHECK(loader.parse(
              R"({"version":1,"defaults":{"visibility":"allow","invocation":"allow"},"tools":[{"name":"same","visibility":"allow","invocation":"allow"},{"name":"same","visibility":"deny","invocation":"deny"}]})",
              policy)
              .error == mng::security::PolicyLoadError::duplicate_tool_name);
    CHECK(loader.parse(
              R"({"version":1,"version":1,"defaults":{"visibility":"allow","invocation":"allow"}})",
              policy)
              .error == mng::security::PolicyLoadError::duplicate_member);
    CHECK(loader.parse(
              R"({"version":1,"defaults":{"visibility":"allow","visibility":"deny","invocation":"allow"}})",
              policy)
              .error == mng::security::PolicyLoadError::duplicate_member);
    CHECK(loader.parse(
              R"({"version":1,"defaults":{"visibility":"allow","invocation":"allow"},"tools":[{"name":"x","name":"y","visibility":"allow","invocation":"allow"}]})",
              policy)
              .error == mng::security::PolicyLoadError::duplicate_member);
    CHECK(loader.parse(
              R"({"version":1,"defaults":{"visibility":"allow","invocation":"allow"},})",
              policy)
              .error == mng::security::PolicyLoadError::malformed_json);
}

void test_policy_loader_rejects_invalid_required_values() {
    const mng::security::PolicyLoader loader;
    mng::security::PolicyDefinition policy;
    CHECK(loader.parse(
              R"({"version":2,"defaults":{"visibility":"allow","invocation":"allow"}})",
              policy)
              .error == mng::security::PolicyLoadError::unsupported_version);
    CHECK(loader.parse(R"({"version":1})", policy).error ==
          mng::security::PolicyLoadError::missing_defaults);
    CHECK(loader.parse(
              R"({"version":1,"defaults":{"visibility":"allow"}})", policy)
              .error == mng::security::PolicyLoadError::missing_defaults);
    CHECK(loader.parse(
              R"({"version":1,"defaults":{"visibility":"sometimes","invocation":"allow"}})",
              policy)
              .error == mng::security::PolicyLoadError::invalid_access);
    CHECK(loader.parse(
              R"({"version":1,"defaults":{"visibility":"allow","invocation":"allow"},"tools":[{"name":"x","visibility":"allow","invocation":"sometimes"}]})",
              policy)
              .error == mng::security::PolicyLoadError::invalid_access);
    CHECK(loader.parse(
              R"({"version":1,"defaults":{"visibility":"allow","invocation":"allow"},"tools":{}})",
              policy)
              .error == mng::security::PolicyLoadError::tools_not_array);
    CHECK(loader.parse(
              R"({"version":1,"defaults":{"visibility":"allow","invocation":"allow"},"tools":[{"visibility":"allow","invocation":"allow"}]})",
              policy)
              .error == mng::security::PolicyLoadError::invalid_tool);
    CHECK(loader.parse(
              R"({"version":1,"defaults":{"visibility":"allow","invocation":"allow"},"tools":[{"name":"","visibility":"allow","invocation":"allow"}]})",
              policy)
              .error == mng::security::PolicyLoadError::invalid_tool);
    CHECK(loader.parse(
              R"({"version":1,"defaults":{"visibility":"allow","invocation":"allow"},"tools":[{"name":"escaped\u002ename","visibility":"allow","invocation":"allow"}]})",
              policy)
              .error == mng::security::PolicyLoadError::escaped_tool_name);
}

void test_policy_loader_enforces_size_and_depth_bounds() {
    mng::security::PolicyDefinition policy;
    const mng::security::PolicyLoader small{{64U, 16U}};
    CHECK(small.parse(
              R"({"version":1,"defaults":{"visibility":"allow","invocation":"allow"}})",
              policy)
              .error == mng::security::PolicyLoadError::file_too_large);

    const mng::security::PolicyLoader shallow{{1024U, 2U}};
    CHECK(shallow.parse(
              R"({"version":1,"defaults":{"visibility":"allow","invocation":"allow"},"tools":[{"name":"x","visibility":"allow","invocation":"allow"}]})",
              policy)
              .error == mng::security::PolicyLoadError::excessive_nesting);
}

void test_cli_deny_overrides_file_policy() {
    const mng::security::PolicyLoader loader;
    mng::security::PolicyDefinition policy;
    CHECK(loader.parse(
        R"({"version":1,"defaults":{"visibility":"allow","invocation":"allow"},"tools":[{"name":"existing","visibility":"allow","invocation":"allow"}]})",
        policy));
    CHECK(mng::security::apply_deny_overrides({"existing", "new", "new"}, policy));
    const auto* existing = find_rule(policy, "existing");
    const auto* added = find_rule(policy, "new");
    CHECK(existing != nullptr && existing->visible == mng::security::Access::deny);
    CHECK(existing != nullptr && existing->callable == mng::security::Access::deny);
    CHECK(added != nullptr && added->visible == mng::security::Access::deny);
    CHECK(added != nullptr && added->callable == mng::security::Access::deny);
    CHECK(policy.rules.size() == 2U);
}

void test_effective_policy_fingerprint_is_canonical_and_sensitive() {
    using mng::security::Access;
    using mng::security::PolicyTable;
    PolicyTable first, reordered, changed;
    CHECK(PolicyTable::build({{"b", Access::deny, Access::allow}, {"a", Access::allow, Access::deny}},
                             {Access::allow, Access::deny}, first));
    CHECK(PolicyTable::build({{"a", Access::allow, Access::deny}, {"b", Access::deny, Access::allow}},
                             {Access::allow, Access::deny}, reordered));
    CHECK(PolicyTable::build({{"a", Access::allow, Access::deny}, {"b", Access::deny, Access::deny}},
                             {Access::allow, Access::deny}, changed));
    CHECK(first.fingerprint() == reordered.fingerprint());
    CHECK(first.fingerprint().starts_with("fnv1a64:"));
    CHECK(first.fingerprint() != changed.fingerprint());
}

void test_session_audit_format_is_bounded_and_safe() {
    std::ostringstream destination;
    std::ostringstream diagnostics;
    mng::audit::JsonlAuditSink sink{destination, diagnostics};
    const mng::audit::SessionIdentity identity{
        mng::version, "label-\"safe", "server", "fnv1a64:1234", {1024U, 8U, 4U}};
    sink.record_session_start(identity);
    sink.record_session_end(identity, {7, 7, 42U, false, "child_nonzero_exit"});
    const std::string output = destination.str();
    CHECK(output.find(R"("event":"session_start")") != std::string::npos);
    CHECK(output.find(R"("event":"session_end")") != std::string::npos);
    CHECK(output.find(R"("server_label":"label-\"safe")") != std::string::npos);
    CHECK(output.find(R"("guard_version":"0.1.0")") != std::string::npos);
    CHECK(output.find(R"("duration_ms":42)") != std::string::npos);
    CHECK(output.find(R"("child_exit_status":7)") != std::string::npos);
    CHECK(output.find(R"("clean_shutdown":false)") != std::string::npos);
    CHECK(output.find("secret-argument") == std::string::npos);
    CHECK(output.find("policy contents") == std::string::npos);
}

void test_tool_inventory_valid_and_empty() {
    const auto parsed = mng::protocol::parse_tools_list_response(
        R"({"jsonrpc":"2.0","id":"inspect-list","result":{"tools":[{"name":"b","description":"bee","inputSchema":{"type":"object"},"annotations":{"readOnlyHint":true}},{"name":"a"}]}})",
        R"("inspect-list")",
        "fixture",
        {});
    CHECK(parsed);
    CHECK(parsed.inventory.tools.size() == 2U);
    CHECK(parsed.inventory.tools[0].name == "a");
    CHECK(parsed.inventory.tools[1].name == "b");
    CHECK(parsed.inventory.tools[1].description_json == R"("bee")");
    CHECK(parsed.inventory.tools[1].input_schema_json == R"({"type":"object"})");
    CHECK(parsed.inventory.tools[1].annotations_json == R"({"readOnlyHint":true})");

    std::string emitted;
    CHECK(mng::protocol::emit_inventory_json(parsed.inventory, emitted, 1U << 20));
    CHECK(emitted.find(R"("name":"a")") != std::string::npos);
    CHECK(emitted.find(R"("name":"a")") < emitted.find(R"("name":"b")"));
    CHECK(emitted.find(R"("inventory_version":1)") != std::string::npos);
    CHECK(emitted.find(R"("downstream_executable":"fixture")") != std::string::npos);

    const auto empty = mng::protocol::parse_tools_list_response(
        R"({"jsonrpc":"2.0","id":"inspect-list","result":{"tools":[]}})",
        R"("inspect-list")",
        "fixture",
        {});
    CHECK(empty);
    CHECK(empty.inventory.tools.empty());
    std::string empty_json;
    CHECK(mng::protocol::emit_inventory_json(empty.inventory, empty_json, 1U << 20));
    CHECK(empty_json ==
          R"({"inventory_version":1,"server":{"downstream_executable":"fixture"},"tools":[]})");
}

void test_tool_inventory_reorders_tools_and_members() {
    const auto first = mng::protocol::parse_tools_list_response(
        R"({"jsonrpc":"2.0","id":"inspect-list","result":{"tools":[{"name":"z","description":"zee","inputSchema":{"type":"object"}},{"name":"a","description":"aye"}]}})",
        R"("inspect-list")",
        "srv",
        {});
    const auto reordered_tools = mng::protocol::parse_tools_list_response(
        R"({"jsonrpc":"2.0","id":"inspect-list","result":{"tools":[{"name":"a","description":"aye"},{"name":"z","description":"zee","inputSchema":{"type":"object"}}]}})",
        R"("inspect-list")",
        "srv",
        {});
    const auto reordered_members = mng::protocol::parse_tools_list_response(
        R"({"jsonrpc":"2.0","id":"inspect-list","result":{"tools":[{"inputSchema":{"type":"object"},"description":"zee","name":"z"},{"description":"aye","name":"a"}]}})",
        R"("inspect-list")",
        "srv",
        {});
    CHECK(first);
    CHECK(reordered_tools);
    CHECK(reordered_members);
    std::string a;
    std::string b;
    std::string c;
    CHECK(mng::protocol::emit_inventory_json(first.inventory, a, 1U << 20));
    CHECK(mng::protocol::emit_inventory_json(reordered_tools.inventory, b, 1U << 20));
    CHECK(mng::protocol::emit_inventory_json(reordered_members.inventory, c, 1U << 20));
    CHECK(a == b);
    CHECK(a == c);
}

void test_tool_inventory_canonicalizes_nested_schema_and_annotations() {
    const auto schema_a = mng::protocol::parse_tools_list_response(
        R"({"jsonrpc":"2.0","id":"inspect-list","result":{"tools":[{"name":"t","inputSchema":{"type":"object","properties":{"value":{"type":"string"}}},"annotations":{"openWorldHint":false,"readOnlyHint":true}}]}})",
        R"("inspect-list")",
        "srv",
        {});
    const auto schema_b = mng::protocol::parse_tools_list_response(
        R"({"jsonrpc":"2.0","id":"inspect-list","result":{"tools":[{"name":"t","inputSchema":{"properties":{"value":{"type":"string"}},"type":"object"},"annotations":{"readOnlyHint":true,"openWorldHint":false}}]}})",
        R"("inspect-list")",
        "srv",
        {});
    const auto schema_ws = mng::protocol::parse_tools_list_response(
        R"({"jsonrpc":"2.0","id":"inspect-list","result":{"tools":[{"name":"t","inputSchema":{ "type" : "object" , "properties" : { "value" : { "type" : "string" } } },"annotations":{ "openWorldHint" : false , "readOnlyHint" : true }}]}})",
        R"("inspect-list")",
        "srv",
        {});
    CHECK(schema_a);
    CHECK(schema_b);
    CHECK(schema_ws);
    CHECK(schema_a.inventory.tools[0].input_schema_json ==
          R"({"properties":{"value":{"type":"string"}},"type":"object"})");
    CHECK(schema_a.inventory.tools[0].annotations_json ==
          R"({"openWorldHint":false,"readOnlyHint":true})");
    std::string out_a;
    std::string out_b;
    std::string out_ws;
    CHECK(mng::protocol::emit_inventory_json(schema_a.inventory, out_a, 1U << 20));
    CHECK(mng::protocol::emit_inventory_json(schema_b.inventory, out_b, 1U << 20));
    CHECK(mng::protocol::emit_inventory_json(schema_ws.inventory, out_ws, 1U << 20));
    CHECK(out_a == out_b);
    CHECK(out_a == out_ws);

    const auto array_order = mng::protocol::parse_tools_list_response(
        R"({"jsonrpc":"2.0","id":"inspect-list","result":{"tools":[{"name":"t","inputSchema":{"required":["b","a"],"type":"object"}}]}})",
        R"("inspect-list")",
        "srv",
        {});
    CHECK(array_order);
    CHECK(array_order.inventory.tools[0].input_schema_json ==
          R"({"required":["b","a"],"type":"object"})");

    const auto dup_schema = mng::protocol::parse_tools_list_response(
        R"({"jsonrpc":"2.0","id":"inspect-list","result":{"tools":[{"name":"t","inputSchema":{"type":"object","type":"string"}}]}})",
        R"("inspect-list")",
        "srv",
        {});
    CHECK(!dup_schema);
    CHECK(dup_schema.error == mng::protocol::InventoryError::duplicate_member);

    const auto dup_annotations = mng::protocol::parse_tools_list_response(
        R"({"jsonrpc":"2.0","id":"inspect-list","result":{"tools":[{"name":"t","annotations":{"readOnlyHint":true,"readOnlyHint":false}}]}})",
        R"("inspect-list")",
        "srv",
        {});
    CHECK(!dup_annotations);
    CHECK(dup_annotations.error == mng::protocol::InventoryError::duplicate_member);
}

void test_tool_inventory_rejects_malformed_cases() {
    const auto expect_error = [](std::string_view message, mng::protocol::InventoryError error) {
        const auto parsed = mng::protocol::parse_tools_list_response(
            message, R"("inspect-list")", "srv", {});
        CHECK(!parsed);
        CHECK(parsed.error == error);
    };
    expect_error(
        R"({"jsonrpc":"1.0","id":"inspect-list","result":{"tools":[]}})",
        mng::protocol::InventoryError::unsupported_jsonrpc_version);
    expect_error(
        R"({"jsonrpc":"2.0","id":"other","result":{"tools":[]}})",
        mng::protocol::InventoryError::wrong_response_id);
    expect_error(
        R"({"jsonrpc":"2.0","id":"inspect-list","error":{"code":-1,"message":"x"}})",
        mng::protocol::InventoryError::error_result);
    expect_error(
        R"({"jsonrpc":"2.0","id":"inspect-list","result":{"nextCursor":null}})",
        mng::protocol::InventoryError::missing_tools);
    expect_error(
        R"({"jsonrpc":"2.0","id":"inspect-list","result":{"tools":{}}})",
        mng::protocol::InventoryError::tools_not_array);
    expect_error(
        R"({"jsonrpc":"2.0","id":"inspect-list","result":{"tools":[{"description":"x"}]}})",
        mng::protocol::InventoryError::missing_tool_name);
    expect_error(
        R"({"jsonrpc":"2.0","id":"inspect-list","result":{"tools":[{"name":1}]}})",
        mng::protocol::InventoryError::non_string_tool_name);
    expect_error(
        R"({"jsonrpc":"2.0","id":"inspect-list","result":{"tools":[{"name":"a\"b"}]}})",
        mng::protocol::InventoryError::escaped_tool_name);
    expect_error(
        R"({"jsonrpc":"2.0","id":"inspect-list","result":{"tools":[{"name":"a","name":"b"}]}})",
        mng::protocol::InventoryError::duplicate_member);
    expect_error(
        R"({"jsonrpc":"2.0","id":"inspect-list","result":{"tools":[{"name":"dup"},{"name":"dup"}]}})",
        mng::protocol::InventoryError::duplicate_tool_name);
    expect_error("{not-json", mng::protocol::InventoryError::malformed_json);
}

void test_tool_inventory_enforces_bounds() {
    mng::protocol::InventoryLimits limits;
    limits.max_tools = 1U;
    auto parsed = mng::protocol::parse_tools_list_response(
        R"({"jsonrpc":"2.0","id":"inspect-list","result":{"tools":[{"name":"a"},{"name":"b"}]}})",
        R"("inspect-list")",
        "srv",
        limits);
    CHECK(!parsed);
    CHECK(parsed.error == mng::protocol::InventoryError::excessive_tool_count);

    limits = {};
    limits.max_tool_name_bytes = 2U;
    parsed = mng::protocol::parse_tools_list_response(
        R"({"jsonrpc":"2.0","id":"inspect-list","result":{"tools":[{"name":"abc"}]}})",
        R"("inspect-list")",
        "srv",
        limits);
    CHECK(!parsed);
    CHECK(parsed.error == mng::protocol::InventoryError::oversized_tool_name);

    limits = {};
    limits.max_tool_description_bytes = 3U;
    parsed = mng::protocol::parse_tools_list_response(
        R"({"jsonrpc":"2.0","id":"inspect-list","result":{"tools":[{"name":"a","description":"abcd"}]}})",
        R"("inspect-list")",
        "srv",
        limits);
    CHECK(!parsed);
    CHECK(parsed.error == mng::protocol::InventoryError::oversized_description);

    limits = {};
    limits.max_tool_schema_bytes = 8U;
    parsed = mng::protocol::parse_tools_list_response(
        R"({"jsonrpc":"2.0","id":"inspect-list","result":{"tools":[{"name":"a","inputSchema":{"type":"object","extra":true}}]}})",
        R"("inspect-list")",
        "srv",
        limits);
    CHECK(!parsed);
    CHECK(parsed.error == mng::protocol::InventoryError::oversized_schema);

    limits = {};
    limits.max_nesting_depth = 2U;
    parsed = mng::protocol::parse_tools_list_response(
        R"({"jsonrpc":"2.0","id":"inspect-list","result":{"tools":[{"name":"a","inputSchema":{"a":{"b":1}}}]}})",
        R"("inspect-list")",
        "srv",
        limits);
    CHECK(!parsed);
    CHECK(parsed.error == mng::protocol::InventoryError::excessive_nesting);

    limits = {};
    limits.max_message_bytes = 16U;
    parsed = mng::protocol::parse_tools_list_response(
        R"({"jsonrpc":"2.0","id":"inspect-list","result":{"tools":[]}})",
        R"("inspect-list")",
        "srv",
        limits);
    CHECK(!parsed);
    CHECK(parsed.error == mng::protocol::InventoryError::message_too_large);
}

void test_validate_initialize_response() {
    CHECK(
        mng::protocol::validate_initialize_response(
            R"({"jsonrpc":"2.0","id":"inspect-init","result":{"protocolVersion":"2025-11-25"}})",
            R"("inspect-init")",
            {}) == mng::protocol::InventoryError::none);
    CHECK(
        mng::protocol::validate_initialize_response(
            R"({"jsonrpc":"2.0","id":"inspect-init","error":{"code":-1,"message":"x"}})",
            R"("inspect-init")",
            {}) == mng::protocol::InventoryError::error_result);
    CHECK(
        mng::protocol::validate_initialize_response(
            R"({"jsonrpc":"2.0","id":"other","result":{}})",
            R"("inspect-init")",
            {}) == mng::protocol::InventoryError::wrong_response_id);
}

void test_policy_generator_deny_all_with_no_allow_tools() {
    const auto result = mng::security::generate_policy_from_inventory(
        R"({"inventory_version":1,"server":{"downstream_executable":"x"},)"
        R"("tools":[{"name":"tool.b"},{"name":"tool.a"}]})",
        {},
        {});
    CHECK(result);
    CHECK(result.policy_json ==
          R"({"version":1,"defaults":{"visibility":"deny","invocation":"deny"},"tools":[]})");
}

void test_policy_generator_single_allow_tool() {
    const auto result = mng::security::generate_policy_from_inventory(
        R"({"inventory_version":1,"server":{},"tools":[{"name":"tool.a"},{"name":"tool.b"}]})",
        {"tool.a"},
        {});
    CHECK(result);
    CHECK(result.policy_json ==
          R"({"version":1,"defaults":{"visibility":"deny","invocation":"deny"},)"
          R"("tools":[{"name":"tool.a","visibility":"allow","invocation":"allow"}]})");
}

void test_policy_generator_multiple_allow_tools_sorted_and_order_independent() {
    const std::string inventory =
        R"({"inventory_version":1,"server":{},)"
        R"("tools":[{"name":"tool.c"},{"name":"tool.a"},{"name":"tool.b"}]})";
    const auto forward = mng::security::generate_policy_from_inventory(
        inventory, {"tool.c", "tool.a", "tool.b"}, {});
    const auto reversed = mng::security::generate_policy_from_inventory(
        inventory, {"tool.b", "tool.a", "tool.c"}, {});
    CHECK(forward);
    CHECK(reversed);
    CHECK(forward.policy_json == reversed.policy_json);
    CHECK(forward.policy_json ==
          R"({"version":1,"defaults":{"visibility":"deny","invocation":"deny"},)"
          R"("tools":[{"name":"tool.a","visibility":"allow","invocation":"allow"},)"
          R"({"name":"tool.b","visibility":"allow","invocation":"allow"},)"
          R"({"name":"tool.c","visibility":"allow","invocation":"allow"}]})");
}

void test_policy_generator_inventory_tool_order_independent() {
    const auto order_a = mng::security::generate_policy_from_inventory(
        R"({"inventory_version":1,"server":{},)"
        R"("tools":[{"name":"tool.b"},{"name":"tool.a"}]})",
        {"tool.a", "tool.b"},
        {});
    const auto order_b = mng::security::generate_policy_from_inventory(
        R"({"inventory_version":1,"server":{},)"
        R"("tools":[{"name":"tool.a"},{"name":"tool.b"}]})",
        {"tool.a", "tool.b"},
        {});
    CHECK(order_a);
    CHECK(order_b);
    CHECK(order_a.policy_json == order_b.policy_json);
}

void test_policy_generator_rejects_malformed_and_structural_errors() {
    using mng::security::PolicyGenerateError;
    const mng::security::PolicyGeneratorLimits limits;

    CHECK(mng::security::generate_policy_from_inventory("{not json", {}, limits).error ==
          PolicyGenerateError::malformed_inventory_json);
    CHECK(mng::security::generate_policy_from_inventory(
              R"({"server":{},"tools":[]})", {}, limits)
              .error == PolicyGenerateError::missing_inventory_version);
    CHECK(mng::security::generate_policy_from_inventory(
              R"({"inventory_version":2,"server":{},"tools":[]})", {}, limits)
              .error == PolicyGenerateError::unsupported_inventory_version);
    CHECK(mng::security::generate_policy_from_inventory(
              R"({"inventory_version":1,"inventory_version":1,"server":{},"tools":[]})", {}, limits)
              .error == PolicyGenerateError::duplicate_member);
    CHECK(mng::security::generate_policy_from_inventory(
              R"({"inventory_version":1,"tools":[]})", {}, limits)
              .error == PolicyGenerateError::missing_server);
    CHECK(mng::security::generate_policy_from_inventory(
              R"({"inventory_version":1,"server":"x","tools":[]})", {}, limits)
              .error == PolicyGenerateError::invalid_server);
    CHECK(mng::security::generate_policy_from_inventory(
              R"({"inventory_version":1,"server":{}})", {}, limits)
              .error == PolicyGenerateError::missing_tools);
    CHECK(mng::security::generate_policy_from_inventory(
              R"({"inventory_version":1,"server":{},"tools":{}})", {}, limits)
              .error == PolicyGenerateError::tools_not_array);
    CHECK(mng::security::generate_policy_from_inventory(
              R"({"inventory_version":1,"server":{},"tools":[{"description":"no name"}]})", {}, limits)
              .error == PolicyGenerateError::missing_tool_name);
    CHECK(mng::security::generate_policy_from_inventory(
              R"({"inventory_version":1,"server":{},"tools":[{"name":1}]})", {}, limits)
              .error == PolicyGenerateError::non_string_tool_name);
    CHECK(mng::security::generate_policy_from_inventory(
              R"({"inventory_version":1,"server":{},"tools":[{"name":"esc\"aped"}]})", {}, limits)
              .error == PolicyGenerateError::escaped_tool_name);
    CHECK(mng::security::generate_policy_from_inventory(
              R"({"inventory_version":1,"server":{},"tools":[{"name":""}]})", {}, limits)
              .error == PolicyGenerateError::empty_tool_name);
    CHECK(mng::security::generate_policy_from_inventory(
              R"({"inventory_version":1,"server":{},"tools":[{"name":"a","name":"b"}]})", {}, limits)
              .error == PolicyGenerateError::duplicate_member);
    CHECK(mng::security::generate_policy_from_inventory(
              R"({"inventory_version":1,"server":{},)"
              R"("tools":[{"name":"dup"},{"name":"dup"}]})",
              {},
              limits)
              .error == PolicyGenerateError::duplicate_tool_name);

    // Fields not needed for policy generation are safely ignored.
    const auto ignores_extra_fields = mng::security::generate_policy_from_inventory(
        R"({"inventory_version":1,"server":{"downstream_executable":"x"},)"
        R"("tools":[{"name":"tool.a","description":"d","inputSchema":{"type":"object"},)"
        R"("annotations":{"readOnlyHint":true}}],"extra_field":{"nested":[1,2,3]}})",
        {"tool.a"},
        limits);
    CHECK(ignores_extra_fields);
    CHECK(ignores_extra_fields.policy_json.find("description") == std::string::npos);
    CHECK(ignores_extra_fields.policy_json.find("inputSchema") == std::string::npos);
    CHECK(ignores_extra_fields.policy_json.find("annotations") == std::string::npos);
}

void test_policy_generator_enforces_bounds() {
    using mng::security::PolicyGenerateError;

    const mng::security::PolicyGeneratorLimits tiny_input{16U, 64U, 256U, 256U};
    CHECK(mng::security::generate_policy_from_inventory(
              R"({"inventory_version":1,"server":{},"tools":[]})", {}, tiny_input)
              .error == PolicyGenerateError::inventory_too_large);

    const mng::security::PolicyGeneratorLimits shallow{1024U, 2U, 256U, 256U};
    CHECK(mng::security::generate_policy_from_inventory(
              R"({"inventory_version":1,"server":{"downstream_executable":"x"},)"
              R"("tools":[{"name":"a"}]})",
              {},
              shallow)
              .error == PolicyGenerateError::excessive_nesting);

    const mng::security::PolicyGeneratorLimits few_tools{1024U * 1024U, 64U, 1U, 256U};
    CHECK(mng::security::generate_policy_from_inventory(
              R"({"inventory_version":1,"server":{},)"
              R"("tools":[{"name":"a"},{"name":"b"}]})",
              {},
              few_tools)
              .error == PolicyGenerateError::excessive_tool_count);

    const mng::security::PolicyGeneratorLimits short_name{1024U * 1024U, 64U, 256U, 4U};
    CHECK(mng::security::generate_policy_from_inventory(
              R"({"inventory_version":1,"server":{},"tools":[{"name":"toolong"}]})", {}, short_name)
              .error == PolicyGenerateError::oversized_tool_name);
}

void test_policy_generator_allow_tool_validation() {
    using mng::security::PolicyGenerateError;
    const std::string inventory =
        R"({"inventory_version":1,"server":{},"tools":[{"name":"tool.a"},{"name":"tool.b"}]})";

    const auto unknown =
        mng::security::generate_policy_from_inventory(inventory, {"tool.zzz"}, {});
    CHECK(!unknown);
    CHECK(unknown.error == PolicyGenerateError::unknown_allow_tool);
    CHECK(unknown.offending_tool_name == "tool.zzz");

    const auto duplicate =
        mng::security::generate_policy_from_inventory(inventory, {"tool.a", "tool.a"}, {});
    CHECK(!duplicate);
    CHECK(duplicate.error == PolicyGenerateError::duplicate_allow_tool);
    CHECK(duplicate.offending_tool_name == "tool.a");
}

void test_policy_generator_output_round_trips_through_policy_loader() {
    const std::string inventory =
        R"({"inventory_version":1,"server":{},)"
        R"("tools":[{"name":"allowed.tool"},{"name":"blocked.one"},{"name":"blocked.two"}]})";

    const auto deny_all = mng::security::generate_policy_from_inventory(inventory, {}, {});
    CHECK(deny_all);
    mng::security::PolicyDefinition deny_all_definition;
    const mng::security::PolicyLoader loader;
    CHECK(loader.parse(deny_all.policy_json, deny_all_definition));
    mng::security::PolicyTable deny_all_table;
    CHECK(mng::security::PolicyTable::build(
        std::move(deny_all_definition.rules), deny_all_definition.defaults, deny_all_table));
    CHECK(deny_all_table.visibility_for("allowed.tool") == mng::security::Access::deny);
    CHECK(deny_all_table.invocation_for("allowed.tool") == mng::security::Access::deny);
    CHECK(deny_all_table.visibility_for("blocked.one") == mng::security::Access::deny);

    const auto allow_one =
        mng::security::generate_policy_from_inventory(inventory, {"allowed.tool"}, {});
    CHECK(allow_one);
    mng::security::PolicyDefinition allow_one_definition;
    CHECK(loader.parse(allow_one.policy_json, allow_one_definition));
    mng::security::PolicyTable allow_one_table;
    CHECK(mng::security::PolicyTable::build(
        std::move(allow_one_definition.rules), allow_one_definition.defaults, allow_one_table));
    CHECK(allow_one_table.visibility_for("allowed.tool") == mng::security::Access::allow);
    CHECK(allow_one_table.invocation_for("allowed.tool") == mng::security::Access::allow);
    CHECK(allow_one_table.visibility_for("blocked.one") == mng::security::Access::deny);
    CHECK(allow_one_table.invocation_for("blocked.one") == mng::security::Access::deny);
    CHECK(allow_one_table.visibility_for("blocked.two") == mng::security::Access::deny);
    CHECK(allow_one_table.invocation_for("blocked.two") == mng::security::Access::deny);
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
    test_audit_allowed_denied_ids_and_absent_id();
    test_audit_hidden_tool_and_invalid_call();
    test_audit_json_escaping_and_multiple_jsonl_records();
    test_audit_disabled_and_message_data_not_logged();
    test_audit_write_failure_keeps_enforcement_active_and_reports_once();
    test_audit_oversize_and_pending_capacity_events();
    test_tool_call_filter_enforces_requests_and_notifications();
    test_tool_call_filter_rejects_invalid_params_and_preserves_other_methods();
    test_tools_list_filter_removes_denied_tools_and_preserves_fields();
    test_tools_list_filter_multiple_all_allowed_and_all_denied();
    test_tools_list_filter_reordered_and_unrelated_responses();
    test_tools_list_filter_string_numeric_ids_and_duplicate_members();
    test_tools_list_filter_rejects_malformed_oversized_and_deep_responses();
    test_tools_list_pending_capacity_and_cleanup();
    test_runtime_limits_exact_boundaries_and_untrackable_tools_list();
    test_policy_loader_valid_policy_and_access_values();
    test_policy_loader_allow_and_deny_defaults();
    test_policy_loader_rejects_duplicates_and_malformed_json();
    test_policy_loader_rejects_invalid_required_values();
    test_policy_loader_enforces_size_and_depth_bounds();
    test_cli_deny_overrides_file_policy();
    test_effective_policy_fingerprint_is_canonical_and_sensitive();
    test_session_audit_format_is_bounded_and_safe();
    test_policy_generator_deny_all_with_no_allow_tools();
    test_policy_generator_single_allow_tool();
    test_policy_generator_multiple_allow_tools_sorted_and_order_independent();
    test_policy_generator_inventory_tool_order_independent();
    test_policy_generator_rejects_malformed_and_structural_errors();
    test_policy_generator_enforces_bounds();
    test_policy_generator_allow_tool_validation();
    test_policy_generator_output_round_trips_through_policy_loader();
    test_tool_inventory_valid_and_empty();
    test_tool_inventory_reorders_tools_and_members();
    test_tool_inventory_canonicalizes_nested_schema_and_annotations();
    test_tool_inventory_rejects_malformed_cases();
    test_tool_inventory_enforces_bounds();
    test_validate_initialize_response();

    if (failures != 0) {
        std::cerr << failures << " test check(s) failed\n";
        return 1;
    }

    std::cout << "all focused tests passed\n";
    return 0;
}
