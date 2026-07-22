#include <array>
#include <chrono>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <iostream>
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
    std::string_view input) {
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
            const_cast<char*>("--"),
            const_cast<char*>(server_path),
            nullptr,
        };
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

    return success ? 0 : 1;
}
