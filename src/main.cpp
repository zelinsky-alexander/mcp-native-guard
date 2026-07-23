#include "mcp_native_guard/io/line_framer.hpp"
#if defined(MNG_HAS_LINUX_STDIO_RELAY)
#include "mcp_native_guard/audit/audit_sink.hpp"
#include "mcp_native_guard/process/linux_stdio_relay.hpp"
#include "mcp_native_guard/process/doctor.hpp"
#include "mcp_native_guard/process/inspect.hpp"
#include "mcp_native_guard/protocol/tool_call_filter.hpp"
#include "mcp_native_guard/protocol/runtime_limits.hpp"
#include "mcp_native_guard/security/policy.hpp"
#include "mcp_native_guard/security/policy_loader.hpp"
#include "mcp_native_guard/version.hpp"
#endif

#include <array>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

constexpr std::size_t default_max_message_bytes = 1024U * 1024U;
constexpr std::size_t max_server_label_bytes = 128U;
constexpr std::size_t read_chunk_bytes = 64U * 1024U;

void print_help(std::ostream& output) {
    output << "mcp-native-guard " << mng::version << '\n'
           << "\nUsage:\n"
           << "  mcp-native-guard --help\n"
           << "  mcp-native-guard --version\n"
           << "  mcp-native-guard relay [--discard] [--max-message-bytes N]\n\n"
           << "  mcp-native-guard run [--policy FILE] [--server-label LABEL] [--deny-tool TOOL_NAME ...]\n"
           << "      [--max-message-bytes N] [--max-nesting-depth N]\n"
           << "      [--max-pending-tools-list N] [--audit-file PATH | --audit-stderr] --\n"
           << "      <server> [args...]\n\n"
           << "  mcp-native-guard doctor [run options] [--doctor-timeout SECONDS] -- <server> [args...]\n\n"
           << "  mcp-native-guard inspect [inspect options] -- <server> [args...]\n\n"
           << "relay is an early framing-path harness. It validates bounded newline-delimited\n"
           << "messages and either forwards them to stdout or discards them for measurement.\n"
           << "It is not yet the security proxy MVP.\n\n"
           << "run loads an optional bounded JSON policy before launching one Linux stdio server.\n"
           << "Each --deny-tool rule overrides the file policy to deny invocation and visibility.\n"
           << "Audit JSONL is disabled by default and is never written to MCP stdout.\n"
           << "Runtime limit defaults: max-message-bytes=1048576, max-nesting-depth=64, "
           << "max-pending-tools-list=64.\n\n"
           << "inspect launches one local stdio MCP server, performs initialize and tools/list,\n"
           << "and writes a deterministic tool inventory. It never invokes tools.\n"
           << "Inventory goes to stdout (or --output PATH); diagnostics go to stderr.\n"
           << "Intended future CLI alias: mcpg inspect ...\n";
}


bool parse_bounded_integer(std::string_view text, std::size_t& value) {
    if (text.empty()) {
        return false;
    }
    for (const char c : text) {
        if (c < '0' || c > '9') {
            return false;
        }
    }
    const char* const begin = text.data();
    const char* const end = begin + text.size();
    value = 0;
    const auto result = std::from_chars(begin, end, value);
    return result.ec == std::errc{} && result.ptr == end && value != 0U;
}

void print_run_usage(std::ostream& output) {
    output << "usage: mcp-native-guard run [--policy FILE] [--server-label LABEL] [--deny-tool TOOL_NAME ...] "
              "[--max-message-bytes N] [--max-nesting-depth N] "
              "[--max-pending-tools-list N] [--audit-file PATH | --audit-stderr] -- "
              "<server> [args...]\n";
}

[[nodiscard]] bool valid_server_label(std::string_view label) noexcept {
    if (label.empty() || label.size() > max_server_label_bytes) return false;
    for (const unsigned char byte : label) {
        if (byte < 0x20U || byte == 0x7fU) return false;
    }
    return true;
}

[[nodiscard]] std::string_view executable_basename(std::string_view executable) noexcept {
    const auto slash = executable.find_last_of('/');
    return slash == std::string_view::npos ? executable : executable.substr(slash + 1U);
}

int run_child(int argc, char** argv) {
#if defined(MNG_HAS_LINUX_STDIO_RELAY)
    std::vector<std::string> denied_tools;
    std::string_view policy_path;
    std::string_view audit_file_path;
    std::string_view server_label = "unlabeled";
    bool saw_server_label = false;
    mng::protocol::RuntimeLimits runtime_limits;
    bool audit_stderr = false;
    bool saw_max_message_bytes = false;
    bool saw_max_nesting_depth = false;
    bool saw_max_pending_tools_list = false;
    int separator = -1;
    for (int index = 2; index < argc; ++index) {
        const std::string_view argument{argv[index]};
        if (argument == "--") {
            separator = index;
            break;
        }
        if (argument == "--policy") {
            if (!policy_path.empty() || index + 1 >= argc ||
                std::string_view{argv[index + 1]}.empty() ||
                std::string_view{argv[index + 1]} == "--") {
                print_run_usage(std::cerr);
                return 2;
            }
            policy_path = argv[++index];
            continue;
        }
        if (argument == "--audit-file") {
            if (!audit_file_path.empty() || index + 1 >= argc ||
                std::string_view{argv[index + 1]}.empty() ||
                std::string_view{argv[index + 1]} == "--") {
                print_run_usage(std::cerr);
                return 2;
            }
            audit_file_path = argv[++index];
            continue;
        }
        if (argument == "--server-label") {
            if (saw_server_label || index + 1 >= argc ||
                !valid_server_label(argv[index + 1]) || std::string_view{argv[index + 1]} == "--") {
                print_run_usage(std::cerr);
                return 2;
            }
            saw_server_label = true;
            server_label = argv[++index];
            continue;
        }
        if (argument == "--audit-stderr") {
            if (audit_stderr) {
                print_run_usage(std::cerr);
                return 2;
            }
            audit_stderr = true;
            continue;
        }
        if (argument == "--max-message-bytes") {
            if (saw_max_message_bytes || index + 1 >= argc ||
                !parse_bounded_integer(argv[index + 1], runtime_limits.max_message_bytes)) {
                print_run_usage(std::cerr);
                return 2;
            }
            saw_max_message_bytes = true;
            ++index;
            continue;
        }
        if (argument == "--max-nesting-depth") {
            if (saw_max_nesting_depth || index + 1 >= argc ||
                !parse_bounded_integer(argv[index + 1], runtime_limits.max_nesting_depth)) {
                print_run_usage(std::cerr);
                return 2;
            }
            saw_max_nesting_depth = true;
            ++index;
            continue;
        }
        if (argument == "--max-pending-tools-list") {
            if (saw_max_pending_tools_list || index + 1 >= argc ||
                !parse_bounded_integer(argv[index + 1], runtime_limits.max_pending_tools_list)) {
                print_run_usage(std::cerr);
                return 2;
            }
            saw_max_pending_tools_list = true;
            ++index;
            continue;
        }
        if (argument != "--deny-tool" || index + 1 >= argc ||
            std::string_view{argv[index + 1]}.empty() ||
            std::string_view{argv[index + 1]} == "--") {
            print_run_usage(std::cerr);
            return 2;
        }
        denied_tools.emplace_back(argv[++index]);
    }
    if (separator < 0 || separator + 1 >= argc ||
        (audit_stderr && !audit_file_path.empty())) {
        print_run_usage(std::cerr);
        return 2;
    }

    mng::security::PolicyDefinition definition;
    definition.defaults = {mng::security::Access::allow, mng::security::Access::allow};
    if (!policy_path.empty()) {
        const mng::security::PolicyLoader loader;
        const auto load_status = loader.load_file(policy_path, definition);
        if (!load_status) {
            std::cerr << "policy error: " << load_status.message << " (" << policy_path << ")\n";
            return 2;
        }
    }
    const auto override_status =
        mng::security::apply_deny_overrides(std::move(denied_tools), definition);
    if (!override_status) {
        std::cerr << "policy error: " << override_status.message << '\n';
        return 2;
    }

    mng::security::PolicyTable policy;
    const auto policy_status = mng::security::PolicyTable::build(
        std::move(definition.rules),
        definition.defaults,
        policy);
    if (!policy_status) {
        std::cerr << "policy error: " << policy_status.message << '\n';
        return 2;
    }
    const std::string policy_hash = policy.fingerprint();

    std::ofstream audit_file;
    std::optional<mng::audit::JsonlAuditSink> audit_sink;
    if (!audit_file_path.empty()) {
        audit_file.open(
            std::string{audit_file_path},
            std::ios::out | std::ios::app | std::ios::binary);
        if (!audit_file) {
            std::cerr << "audit error: cannot open audit file (" << audit_file_path << ")\n";
            return 2;
        }
        audit_sink.emplace(audit_file, std::cerr);
    } else if (audit_stderr) {
        audit_sink.emplace(std::cerr, std::cerr);
    }

    mng::protocol::ToolCallFilter filter{
        std::move(policy), {runtime_limits}, audit_sink ? &*audit_sink : nullptr};
    mng::process::RunConfig run_config;
    run_config.runtime = runtime_limits;
    const std::string_view downstream_executable = executable_basename(argv[separator + 1]);
    const mng::audit::SessionIdentity session_identity{
        mng::version, server_label, downstream_executable, policy_hash, runtime_limits};
    class SessionObserver final : public mng::process::RunObserver {
    public:
        SessionObserver(mng::audit::JsonlAuditSink* sink, const mng::audit::SessionIdentity& identity)
            : sink_{sink}, identity_{identity} {}
        void child_started() noexcept override {
            started_ = std::chrono::steady_clock::now();
            if (sink_ != nullptr) sink_->record_session_start(identity_);
        }
        void child_finished(const mng::process::RunResult& result) noexcept override {
            if (sink_ == nullptr) return;
            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - started_).count();
            sink_->record_session_end(identity_, {
                result.child_exit_status, result.proxy_exit_status,
                elapsed < 0 ? 0U : static_cast<std::uint64_t>(elapsed),
                result.clean_shutdown, result.termination_reason});
        }
    private:
        mng::audit::JsonlAuditSink* sink_;
        const mng::audit::SessionIdentity& identity_;
        std::chrono::steady_clock::time_point started_{};
    } observer{audit_sink ? &*audit_sink : nullptr, session_identity};
    return mng::process::run_stdio_child(
        std::span<char* const>{
            argv + separator + 1,
            static_cast<std::size_t>(argc - separator - 1)},
        &filter,
        run_config,
        &observer);
#else
    (void)argc;
    (void)argv;
    std::cerr << "run is supported only on Linux\n";
    return 2;
#endif
}

bool parse_size(std::string_view text, std::size_t& value) {
    return parse_bounded_integer(text, value);
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
        std::cout << mng::version << '\n';
        return 0;
    }
    if (std::string_view{argv[1]} == "relay") {
        return run_relay(argc, argv);
    }
    if (std::string_view{argv[1]} == "run") {
        return run_child(argc, argv);
    }
#if defined(MNG_HAS_LINUX_STDIO_RELAY)
    if (std::string_view{argv[1]} == "doctor") {
        return mng::process::run_doctor(argc, argv);
    }
    if (std::string_view{argv[1]} == "inspect") {
        return mng::process::run_inspect(argc, argv);
    }
#endif

    std::cerr << "unknown command: " << argv[1] << '\n';
    print_help(std::cerr);
    return 2;
}
