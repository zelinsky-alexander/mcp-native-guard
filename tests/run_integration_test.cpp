#include <algorithm>
#include <array>
#include <chrono>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <string_view>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace {

struct FileDescriptor final {
    int value{-1};
    ~FileDescriptor() {
        if (value >= 0) {
            (void)::close(value);
        }
    }
    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;
    FileDescriptor() = default;
    explicit FileDescriptor(int descriptor) noexcept : value{descriptor} {}
    FileDescriptor(FileDescriptor&& other) noexcept : value{other.value} { other.value = -1; }
    FileDescriptor& operator=(FileDescriptor&& other) noexcept {
        if (this != &other) {
            if (value >= 0) {
                (void)::close(value);
            }
            value = other.value;
            other.value = -1;
        }
        return *this;
    }
};

[[nodiscard]] bool make_pipe(FileDescriptor& read_end, FileDescriptor& write_end) {
    std::array<int, 2> descriptors{};
    if (::pipe(descriptors.data()) != 0) {
        return false;
    }
    read_end = FileDescriptor{descriptors[0]};
    write_end = FileDescriptor{descriptors[1]};
    const int read_flags = ::fcntl(read_end.value, F_GETFD);
    const int write_flags = ::fcntl(write_end.value, F_GETFD);
    return read_flags >= 0 && write_flags >= 0 &&
           ::fcntl(read_end.value, F_SETFD, read_flags | FD_CLOEXEC) == 0 &&
           ::fcntl(write_end.value, F_SETFD, write_flags | FD_CLOEXEC) == 0;
}

[[nodiscard]] std::string read_all(FileDescriptor& descriptor) {
    std::string output;
    std::array<char, 4096> buffer{};
    while (true) {
        const auto result = ::read(descriptor.value, buffer.data(), buffer.size());
        if (result > 0) {
            output.append(buffer.data(), static_cast<std::size_t>(result));
            continue;
        }
        if (result == 0) {
            return output;
        }
        if (errno != EINTR) {
            return {};
        }
    }
}

[[nodiscard]] bool write_all(int descriptor, std::string_view input) {
    while (!input.empty()) {
        const auto result = ::write(descriptor, input.data(), input.size());
        if (result > 0) {
            input.remove_prefix(static_cast<std::size_t>(result));
            continue;
        }
        if (result < 0 && errno == EINTR) {
            continue;
        }
        return false;
    }
    return true;
}

struct RunResult final {
    int exit_code{1};
    std::string output;
    std::string error;
};

struct TemporaryFile final {
    std::string path;

    TemporaryFile() = default;
    TemporaryFile(const TemporaryFile&) = delete;
    TemporaryFile& operator=(const TemporaryFile&) = delete;

    ~TemporaryFile() {
        if (!path.empty()) {
            (void)::unlink(path.c_str());
        }
    }

    [[nodiscard]] bool create(std::string_view contents) {
        std::array<char, 64> name{};
        constexpr std::string_view pattern = "/tmp/mng-policy-test-XXXXXX";
        std::copy(pattern.begin(), pattern.end(), name.begin());
        const int descriptor = ::mkstemp(name.data());
        if (descriptor < 0) {
            return false;
        }
        FileDescriptor file{descriptor};
        if (!write_all(file.value, contents)) {
            (void)::unlink(name.data());
            return false;
        }
        path = name.data();
        return true;
    }
};

[[nodiscard]] RunResult run_guard(
    const char* guard_path,
    const char* echo_path,
    std::string_view input,
    bool exit_immediately = false) {
    FileDescriptor parent_input_read;
    FileDescriptor child_input_write;
    FileDescriptor child_output_read;
    FileDescriptor parent_output_write;
    FileDescriptor child_error_read;
    FileDescriptor parent_error_write;
    if (!make_pipe(parent_input_read, child_input_write) ||
        !make_pipe(child_output_read, parent_output_write) ||
        !make_pipe(child_error_read, parent_error_write)) {
        return {};
    }

    const pid_t pid = ::fork();
    if (pid < 0) {
        return {};
    }
    if (pid == 0) {
        (void)::dup2(parent_input_read.value, STDIN_FILENO);
        (void)::dup2(parent_output_write.value, STDOUT_FILENO);
        (void)::dup2(parent_error_write.value, STDERR_FILENO);
        char* arguments[] = {
            const_cast<char*>(guard_path),
            const_cast<char*>("run"),
            const_cast<char*>("--"),
            const_cast<char*>(echo_path),
            const_cast<char*>("--exit-immediately"),
            nullptr,
        };
        if (exit_immediately) {
            ::execv(guard_path, arguments);
        } else {
            arguments[4] = nullptr;
            ::execv(guard_path, arguments);
        }
        _exit(127);
    }

    parent_input_read = {};
    parent_output_write = {};
    parent_error_write = {};
    RunResult result;
    if (!write_all(child_input_write.value, input)) {
        return result;
    }
    child_input_write = {};
    result.output = read_all(child_output_read);
    result.error = read_all(child_error_read);
    int status = 1;
    if (::waitpid(pid, &status, 0) == pid && WIFEXITED(status)) {
        result.exit_code = WEXITSTATUS(status);
    }
    return result;
}

[[nodiscard]] RunResult run_enforcement_guard(
    const char* guard_path,
    const char* server_path,
    std::string_view input,
    bool audit_stderr = false) {
    FileDescriptor parent_input_read;
    FileDescriptor child_input_write;
    FileDescriptor child_output_read;
    FileDescriptor parent_output_write;
    FileDescriptor child_error_read;
    FileDescriptor parent_error_write;
    if (!make_pipe(parent_input_read, child_input_write) ||
        !make_pipe(child_output_read, parent_output_write) ||
        !make_pipe(child_error_read, parent_error_write)) {
        return {};
    }

    const pid_t pid = ::fork();
    if (pid < 0) {
        return {};
    }
    if (pid == 0) {
        (void)::dup2(parent_input_read.value, STDIN_FILENO);
        (void)::dup2(parent_output_write.value, STDOUT_FILENO);
        (void)::dup2(parent_error_write.value, STDERR_FILENO);
        char* arguments[] = {
            const_cast<char*>(guard_path),
            const_cast<char*>("run"),
            const_cast<char*>("--deny-tool"),
            const_cast<char*>("blocked.one"),
            const_cast<char*>("--deny-tool"),
            const_cast<char*>("blocked.two"),
            const_cast<char*>("--audit-stderr"),
            const_cast<char*>("--"),
            const_cast<char*>(server_path),
            nullptr,
        };
        if (!audit_stderr) {
            arguments[6] = arguments[7];
            arguments[7] = arguments[8];
            arguments[8] = nullptr;
        }
        ::execv(guard_path, arguments);
        _exit(127);
    }

    parent_input_read = {};
    parent_output_write = {};
    parent_error_write = {};
    RunResult result;
    if (!write_all(child_input_write.value, input)) {
        return result;
    }
    child_input_write = {};
    result.output = read_all(child_output_read);
    result.error = read_all(child_error_read);
    int status = 1;
    if (::waitpid(pid, &status, 0) == pid && WIFEXITED(status)) {
        result.exit_code = WEXITSTATUS(status);
    }
    return result;
}

[[nodiscard]] RunResult run_policy_guard(
    const char* guard_path,
    const char* server_path,
    const char* policy_path,
    std::string_view input,
    bool add_cli_override) {
    FileDescriptor parent_input_read;
    FileDescriptor child_input_write;
    FileDescriptor child_output_read;
    FileDescriptor parent_output_write;
    FileDescriptor child_error_read;
    FileDescriptor parent_error_write;
    if (!make_pipe(parent_input_read, child_input_write) ||
        !make_pipe(child_output_read, parent_output_write) ||
        !make_pipe(child_error_read, parent_error_write)) {
        return {};
    }

    const pid_t pid = ::fork();
    if (pid < 0) {
        return {};
    }
    if (pid == 0) {
        (void)::dup2(parent_input_read.value, STDIN_FILENO);
        (void)::dup2(parent_output_write.value, STDOUT_FILENO);
        (void)::dup2(parent_error_write.value, STDERR_FILENO);
        char* arguments[] = {
            const_cast<char*>(guard_path),
            const_cast<char*>("run"),
            const_cast<char*>("--policy"),
            const_cast<char*>(policy_path),
            const_cast<char*>("--deny-tool"),
            const_cast<char*>("blocked.two"),
            const_cast<char*>("--"),
            const_cast<char*>(server_path),
            nullptr,
        };
        if (!add_cli_override) {
            arguments[4] = arguments[6];
            arguments[5] = arguments[7];
            arguments[6] = nullptr;
        }
        ::execv(guard_path, arguments);
        _exit(127);
    }

    parent_input_read = {};
    parent_output_write = {};
    parent_error_write = {};
    RunResult result;
    if (!write_all(child_input_write.value, input)) {
        return result;
    }
    child_input_write = {};
    result.output = read_all(child_output_read);
    result.error = read_all(child_error_read);
    int status = 1;
    if (::waitpid(pid, &status, 0) == pid && WIFEXITED(status)) {
        result.exit_code = WEXITSTATUS(status);
    }
    return result;
}

[[nodiscard]] RunResult run_audit_guard(
    const char* guard_path,
    const char* server_path,
    const char* policy_path,
    const char* audit_path,
    std::string_view input,
    bool add_stderr_conflict = false) {
    FileDescriptor parent_input_read;
    FileDescriptor child_input_write;
    FileDescriptor child_output_read;
    FileDescriptor parent_output_write;
    FileDescriptor child_error_read;
    FileDescriptor parent_error_write;
    if (!make_pipe(parent_input_read, child_input_write) ||
        !make_pipe(child_output_read, parent_output_write) ||
        !make_pipe(child_error_read, parent_error_write)) {
        return {};
    }

    const pid_t pid = ::fork();
    if (pid < 0) {
        return {};
    }
    if (pid == 0) {
        (void)::dup2(parent_input_read.value, STDIN_FILENO);
        (void)::dup2(parent_output_write.value, STDOUT_FILENO);
        (void)::dup2(parent_error_write.value, STDERR_FILENO);
        char* arguments[] = {
            const_cast<char*>(guard_path),
            const_cast<char*>("run"),
            const_cast<char*>("--policy"),
            const_cast<char*>(policy_path),
            const_cast<char*>("--deny-tool"),
            const_cast<char*>("blocked.two"),
            const_cast<char*>("--audit-file"),
            const_cast<char*>(audit_path),
            const_cast<char*>("--audit-stderr"),
            const_cast<char*>("--"),
            const_cast<char*>(server_path),
            nullptr,
        };
        if (!add_stderr_conflict) {
            arguments[8] = arguments[9];
            arguments[9] = arguments[10];
            arguments[10] = nullptr;
        }
        ::execv(guard_path, arguments);
        _exit(127);
    }

    parent_input_read = {};
    parent_output_write = {};
    parent_error_write = {};
    RunResult result;
    if (!write_all(child_input_write.value, input)) {
        return result;
    }
    child_input_write = {};
    result.output = read_all(child_output_read);
    result.error = read_all(child_error_read);
    int status = 1;
    if (::waitpid(pid, &status, 0) == pid && WIFEXITED(status)) {
        result.exit_code = WEXITSTATUS(status);
    }
    return result;
}

[[nodiscard]] std::string read_file(std::string_view path) {
    std::ifstream input{std::string{path}, std::ios::binary};
    if (!input) {
        return {};
    }
    return {std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
}

[[nodiscard]] bool check(bool condition, std::string_view description) {
    if (!condition) {
        std::cerr << "check failed: " << description << '\n';
    }
    return condition;
}

[[nodiscard]] bool test_invalid_run_command(const char* guard_path) {
    const pid_t pid = ::fork();
    if (pid < 0) {
        return false;
    }
    if (pid == 0) {
        char* arguments[] = {const_cast<char*>(guard_path), const_cast<char*>("run"), nullptr};
        ::execv(guard_path, arguments);
        _exit(127);
    }
    int status = 1;
    return ::waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 2;
}

[[nodiscard]] bool test_termination(const char* guard_path, const char* echo_path) {
    FileDescriptor parent_input_read;
    FileDescriptor child_input_write;
    FileDescriptor child_output_read;
    FileDescriptor parent_output_write;
    FileDescriptor child_error_read;
    FileDescriptor parent_error_write;
    if (!make_pipe(parent_input_read, child_input_write) ||
        !make_pipe(child_output_read, parent_output_write) ||
        !make_pipe(child_error_read, parent_error_write)) {
        return false;
    }

    const pid_t pid = ::fork();
    if (pid < 0) {
        return false;
    }
    if (pid == 0) {
        (void)::dup2(parent_input_read.value, STDIN_FILENO);
        (void)::dup2(parent_output_write.value, STDOUT_FILENO);
        (void)::dup2(parent_error_write.value, STDERR_FILENO);
        char* arguments[] = {
            const_cast<char*>(guard_path),
            const_cast<char*>("run"),
            const_cast<char*>("--"),
            const_cast<char*>(echo_path),
            const_cast<char*>("--ignore-term"),
            nullptr,
        };
        ::execv(guard_path, arguments);
        _exit(127);
    }

    parent_input_read = {};
    parent_output_write = {};
    parent_error_write = {};
    std::array<char, 64> readiness{};
    if (::read(child_error_read.value, readiness.data(), readiness.size()) <= 0) {
        return false;
    }
    if (::kill(pid, SIGTERM) != 0) {
        return false;
    }
    child_input_write = {};

    int status = 1;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{3};
    while (std::chrono::steady_clock::now() < deadline) {
        if (::waitpid(pid, &status, WNOHANG) == pid) {
            return WIFEXITED(status) && WEXITSTATUS(status) == 128 + SIGTERM;
        }
        ::usleep(10'000U);
    }
    (void)::kill(pid, SIGKILL);
    (void)::waitpid(pid, nullptr, 0);
    return false;
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 4) {
        return 2;
    }

    bool success = true;
    const auto relay = run_guard(
        argv[1], argv[2],
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n"
        "{\"jsonrpc\":\"2.0\",\"method\":\"notice\"}\n");
    success &= check(relay.exit_code == 0, "echo relay exits successfully");
    success &= check(
        relay.output ==
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n"
            "{\"jsonrpc\":\"2.0\",\"method\":\"notice\"}\n",
        "relay preserves JSONL bytes");
    success &= check(relay.output.find("echo-server-stderr") == std::string::npos, "stderr stays off stdout");
    success &= check(relay.error.find("echo-server-stderr") != std::string::npos, "child stderr is separate");

    const auto early_exit = run_guard(argv[1], argv[2], {}, true);
    success &= check(early_exit.exit_code == 0, "early child exit is observed");
    success &= check(early_exit.output.empty(), "early child exit produces no MCP stdout");
    success &= check(test_invalid_run_command(argv[1]), "invalid run command is rejected");
    success &= check(test_termination(argv[1], argv[2]), "termination escalates without hanging");

    const auto enforcement = run_enforcement_guard(
        argv[1],
        argv[3],
        "{\"jsonrpc\":\"2.0\",\"id\":\"list-1\",\"method\":\"tools/list\"}\n"
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"allowed.tool\"}}\n"
        "{\"jsonrpc\":\"2.0\",\"id\":\"deny-2\",\"method\":\"tools/call\",\"params\":{\"name\":\"blocked.one\"}}\n"
        "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"blocked.two\"}}\n"
        "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"initialize\",\"params\":{}}\n");
    success &= check(enforcement.exit_code == 0, "enforcing proxy and child exit cleanly");
    success &= check(
        enforcement.output.find(
            R"({"jsonrpc":"2.0","id":"list-1","result":{"tools":[{"name":"allowed.tool","description":"allowed test tool","inputSchema":{"type":"object","properties":{"value":{"type":"string"}}}}],"nextCursor":null}})") !=
            std::string::npos,
        "tools/list reaches child and denied tools are hidden");
    success &= check(
        enforcement.output.find("denied test tool") == std::string::npos &&
            enforcement.output.find("second denied test tool") == std::string::npos,
        "client does not see denied tool definitions");
    success &= check(
        enforcement.output.find(R"({"jsonrpc":"2.0","id":1,"result":{"tool":"allowed.tool"}})") !=
            std::string::npos,
        "allowed tool call reaches downstream server");
    success &= check(
        enforcement.output.find(
            R"({"jsonrpc":"2.0","id":"deny-2","error":{"code":-32001,"message":"Tool call denied by policy"}})") !=
            std::string::npos,
        "denied request receives policy error with original id");
    success &= check(
        enforcement.output.find(R"("tool":"blocked.one")") == std::string::npos &&
            enforcement.output.find(R"("tool":"blocked.two")") == std::string::npos,
        "denied calls do not reach downstream server");
    success &= check(
        enforcement.output.find(
            R"({"jsonrpc":"2.0","id":3,"result":{"protocolVersion":"2025-11-25")") !=
            std::string::npos,
        "ordinary MCP traffic passes through");

    const auto stderr_audit = run_enforcement_guard(
        argv[1],
        argv[3],
        "{\"jsonrpc\":\"2.0\",\"id\":12,\"method\":\"tools/call\",\"params\":{\"name\":\"allowed.tool\"}}\n",
        true);
    success &= check(stderr_audit.exit_code == 0, "stderr-audited proxy exits cleanly");
    success &= check(
        stderr_audit.error.find(
            R"("event":"tools/call","decision":"allow","reason":"policy_allowed","tool":"allowed.tool","request_id":12)") !=
            std::string::npos,
        "--audit-stderr emits structured JSONL records");
    success &= check(
        stderr_audit.output.find(R"("event":"tools/call")") == std::string::npos &&
            stderr_audit.output.find(
                R"({"jsonrpc":"2.0","id":12,"result":{"tool":"allowed.tool"}})") !=
                std::string::npos,
        "stderr audit does not contaminate MCP stdout");

    TemporaryFile valid_policy;
    success &= check(valid_policy.create(
        R"({"version":1,"defaults":{"visibility":"allow","invocation":"allow"},"tools":[{"name":"blocked.one","visibility":"deny","invocation":"deny"}]})"),
        "temporary valid policy is created");
    if (!valid_policy.path.empty()) {
        const auto policy_enforcement = run_policy_guard(
            argv[1],
            argv[3],
            valid_policy.path.c_str(),
            "{\"jsonrpc\":\"2.0\",\"id\":\"policy-list\",\"method\":\"tools/list\"}\n"
            "{\"jsonrpc\":\"2.0\",\"id\":21,\"method\":\"tools/call\",\"params\":{\"name\":\"blocked.one\"}}\n"
            "{\"jsonrpc\":\"2.0\",\"id\":22,\"method\":\"tools/call\",\"params\":{\"name\":\"allowed.tool\"}}\n",
            true);
        success &= check(policy_enforcement.exit_code == 0, "file-policy proxy exits cleanly");
        success &= check(
            policy_enforcement.output.find(R"("name":"allowed.tool")") != std::string::npos &&
                policy_enforcement.output.find("denied test tool") == std::string::npos &&
                policy_enforcement.output.find("second denied test tool") == std::string::npos,
            "file and CLI policies filter tools/list visibility");
        success &= check(
            policy_enforcement.output.find(
                R"({"jsonrpc":"2.0","id":21,"error":{"code":-32001,"message":"Tool call denied by policy"}})") !=
                std::string::npos,
            "file policy blocks denied tools/call");
        success &= check(
            policy_enforcement.output.find(
                R"({"jsonrpc":"2.0","id":22,"result":{"tool":"allowed.tool"}})") !=
                std::string::npos,
            "file policy leaves allowed tool visible and callable");

        TemporaryFile audit_file;
        success &= check(audit_file.create({}), "temporary audit file is created");
        if (!audit_file.path.empty()) {
            const auto audited = run_audit_guard(
                argv[1],
                argv[3],
                valid_policy.path.c_str(),
                audit_file.path.c_str(),
                "{\"jsonrpc\":\"2.0\",\"id\":\"audit-list\",\"method\":\"tools/list\"}\n"
                "{\"jsonrpc\":\"2.0\",\"id\":31,\"method\":\"tools/call\",\"params\":{\"name\":\"blocked.one\",\"arguments\":{\"secret\":\"do-not-log\"}}}\n"
                "{\"jsonrpc\":\"2.0\",\"id\":32,\"method\":\"tools/call\",\"params\":{\"name\":\"allowed.tool\",\"arguments\":{\"value\":\"safe-to-server\"}}}\n");
            success &= check(audited.exit_code == 0, "audited proxy and child exit cleanly");
            success &= check(
                audited.output.find(R"("name":"allowed.tool")") != std::string::npos &&
                    audited.output.find("denied test tool") == std::string::npos,
                "tools/list filtering still works with file audit");
            success &= check(
                audited.output.find(
                    R"({"jsonrpc":"2.0","id":31,"error":{"code":-32001,"message":"Tool call denied by policy"}})") !=
                    std::string::npos,
                "denied call remains blocked with file audit");
            success &= check(
                audited.output.find(
                    R"({"jsonrpc":"2.0","id":32,"result":{"tool":"allowed.tool"}})") !=
                    std::string::npos,
                "allowed call succeeds with file audit");
            success &= check(
                audited.output.find(R"("timestamp":)") == std::string::npos &&
                    audited.output.find(R"("event":"tools/call")") == std::string::npos,
                "MCP stdout remains protocol-only");

            const std::string audit = read_file(audit_file.path);
            success &= check(
                audit.find(
                    R"("event":"tools/list_tool_removed","decision":"deny","reason":"policy_denied","tool":"blocked.one","request_id":"audit-list")") !=
                    std::string::npos,
                "audit records hidden tools");
            success &= check(
                audit.find(
                    R"("event":"tools/call","decision":"deny","reason":"policy_denied","tool":"blocked.one","request_id":31)") !=
                    std::string::npos,
                "audit records denied calls");
            success &= check(
                audit.find(
                    R"("event":"tools/call","decision":"allow","reason":"policy_allowed","tool":"allowed.tool","request_id":32)") !=
                    std::string::npos,
                "audit records allowed calls");
            success &= check(
                audit.find("do-not-log") == std::string::npos &&
                    audit.find("safe-to-server") == std::string::npos &&
                    audit.find("arguments") == std::string::npos &&
                    audit.find("jsonrpc") == std::string::npos,
                "audit excludes arguments and full request bodies");

            const auto conflict = run_audit_guard(
                argv[1],
                argv[2],
                valid_policy.path.c_str(),
                audit_file.path.c_str(),
                {},
                true);
            success &= check(conflict.exit_code == 2, "conflicting audit options are rejected");
            success &= check(
                conflict.error.find("echo-server-stderr") == std::string::npos,
                "audit option conflict prevents downstream child launch");
        }

        const std::string invalid_audit_path = valid_policy.path + "/audit.jsonl";
        const auto audit_open_failure = run_audit_guard(
            argv[1],
            argv[2],
            valid_policy.path.c_str(),
            invalid_audit_path.c_str(),
            {});
        success &= check(audit_open_failure.exit_code != 0, "audit open failure returns nonzero");
        success &= check(
            audit_open_failure.error.find("audit error: cannot open audit file") !=
                std::string::npos,
            "audit open failure reports a clear startup error");
        success &= check(
            audit_open_failure.error.find("echo-server-stderr") == std::string::npos,
            "audit open failure prevents downstream child launch");
    }

    TemporaryFile invalid_policy;
    success &= check(invalid_policy.create(R"({"version":2})"), "temporary invalid policy is created");
    if (!invalid_policy.path.empty()) {
        const auto invalid = run_policy_guard(
            argv[1], argv[2], invalid_policy.path.c_str(), {}, false);
        success &= check(invalid.exit_code != 0, "invalid policy returns nonzero");
        success &= check(invalid.error.find("policy error:") != std::string::npos,
                         "invalid policy reports a clear stderr error");
        success &= check(invalid.error.find("echo-server-stderr") == std::string::npos,
                         "invalid policy prevents downstream child launch");
    }

    return success ? 0 : 1;
}
