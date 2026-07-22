#include "mcp_native_guard/audit/audit_sink.hpp"
#include "mcp_native_guard/io/line_framer.hpp"
#include "mcp_native_guard/protocol/json_rpc_envelope.hpp"
#include "mcp_native_guard/protocol/tool_call_extractor.hpp"
#include "mcp_native_guard/protocol/tool_call_filter.hpp"
#include "mcp_native_guard/proxy/proxy_core.hpp"
#include "mcp_native_guard/security/policy.hpp"
#include "mcp_native_guard/security/policy_loader.hpp"

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
        std::move(policy), {128U, 16U, 1U, 8U, 8U}, &audit};

    filter.message_too_large(mng::process::MessageDirection::client_to_server, 129U);
    CHECK(filter.inspect(R"({"jsonrpc":"2.0","id":1,"method":"tools/list"})").action ==
          mng::process::ClientMessageAction::forward);
    CHECK(filter.inspect(R"({"jsonrpc":"2.0","id":2,"method":"tools/list"})").action ==
          mng::process::ClientMessageAction::drop);

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
    mng::protocol::ToolCallFilter bounded{std::move(policy), {128U, 4U, 1U, 16U, 16U}};
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
    mng::protocol::ToolCallFilter shallow{std::move(shallow_policy), {1024U, 5U, 4U, 32U, 64U}};
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
    mng::protocol::ToolCallFilter filter{std::move(policy), {1024U, 16U, 1U, 8U, 8U}};
    CHECK(filter.inspect(R"({"jsonrpc":"2.0","id":1,"method":"tools/list"})").action ==
          mng::process::ClientMessageAction::forward);
    CHECK(filter.inspect(R"({"jsonrpc":"2.0","id":2,"method":"tools/list"})").action ==
          mng::process::ClientMessageAction::drop);
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
        std::move(aggregate_policy), {1024U, 16U, 4U, 8U, 2U}};
    CHECK(aggregate.inspect(R"({"jsonrpc":"2.0","id":1,"method":"tools/list"})").action ==
          mng::process::ClientMessageAction::forward);
    CHECK(aggregate.inspect(R"({"jsonrpc":"2.0","id":2,"method":"tools/list"})").action ==
          mng::process::ClientMessageAction::forward);
    CHECK(aggregate.inspect(R"({"jsonrpc":"2.0","id":3,"method":"tools/list"})").action ==
          mng::process::ClientMessageAction::drop);
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
    test_policy_loader_valid_policy_and_access_values();
    test_policy_loader_allow_and_deny_defaults();
    test_policy_loader_rejects_duplicates_and_malformed_json();
    test_policy_loader_rejects_invalid_required_values();
    test_policy_loader_enforces_size_and_depth_bounds();
    test_cli_deny_overrides_file_policy();

    if (failures != 0) {
        std::cerr << failures << " test check(s) failed\n";
        return 1;
    }

    std::cout << "all focused tests passed\n";
    return 0;
}
