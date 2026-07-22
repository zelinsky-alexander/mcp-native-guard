#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <string_view>
#include <poll.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace {
struct Fd {
    int value{-1};
    ~Fd() { if (value >= 0) (void)::close(value); }
    Fd() = default;
    explicit Fd(int fd) : value{fd} {}
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    Fd(Fd&& other) noexcept : value{other.value} { other.value = -1; }
    Fd& operator=(Fd&& other) noexcept {
        if (this != &other) { if (value >= 0) (void)::close(value); value = other.value; other.value = -1; }
        return *this;
    }
};

bool pipe_pair(Fd& read_end, Fd& write_end) {
    std::array<int, 2> values{};
    if (::pipe(values.data()) != 0) return false;
    read_end = Fd{values[0]}; write_end = Fd{values[1]};
    const int read_flags = ::fcntl(read_end.value, F_GETFD);
    const int write_flags = ::fcntl(write_end.value, F_GETFD);
    return read_flags >= 0 && write_flags >= 0 &&
        ::fcntl(read_end.value, F_SETFD, read_flags | FD_CLOEXEC) == 0 &&
        ::fcntl(write_end.value, F_SETFD, write_flags | FD_CLOEXEC) == 0;
}

bool write_all(int fd, std::string_view input) {
    while (!input.empty()) {
        const auto count = ::write(fd, input.data(), input.size());
        if (count > 0) input.remove_prefix(static_cast<std::size_t>(count));
        else if (count < 0 && errno == EINTR) continue;
        else return false;
    }
    return true;
}

std::string read_all(int fd) {
    std::string output; std::array<char, 4096> bytes{};
    while (true) {
        const auto count = ::read(fd, bytes.data(), bytes.size());
        if (count > 0) output.append(bytes.data(), static_cast<std::size_t>(count));
        else if (count < 0 && errno == EINTR) continue;
        else return output;
    }
}

struct TempFile {
    std::string path;
    TempFile() {
        std::array<char, 64> pattern{};
        constexpr std::string_view value = "/tmp/mng-session-health-XXXXXX";
        std::copy(value.begin(), value.end(), pattern.begin());
        const int fd = ::mkstemp(pattern.data());
        if (fd >= 0) { (void)::close(fd); path = pattern.data(); }
    }
    ~TempFile() { if (!path.empty()) (void)::unlink(path.c_str()); }
    bool set(std::string_view value) const {
        std::ofstream stream{path, std::ios::binary | std::ios::trunc};
        stream << value; return static_cast<bool>(stream);
    }
    std::string get() const {
        std::ifstream stream{path, std::ios::binary};
        return {std::istreambuf_iterator<char>{stream}, std::istreambuf_iterator<char>{}};
    }
};

struct Result { int status{-1}; bool timed_out{false}; std::string output; std::string error; };

Result execute(const std::vector<std::string>& command, std::string_view input, bool close_input, int timeout_seconds) {
    Fd in_read, in_write, out_read, out_write, err_read, err_write;
    if (!pipe_pair(in_read, in_write) || !pipe_pair(out_read, out_write) || !pipe_pair(err_read, err_write)) return {};
    const pid_t pid = ::fork();
    if (pid == 0) {
        (void)::dup2(in_read.value, STDIN_FILENO); (void)::dup2(out_write.value, STDOUT_FILENO);
        (void)::dup2(err_write.value, STDERR_FILENO);
        (void)::setenv("MNG_FIXTURE_SECRET", "SECRET_ENVIRONMENT_VALUE", 1);
        std::vector<char*> arguments;
        for (const auto& value : command) arguments.push_back(const_cast<char*>(value.c_str()));
        arguments.push_back(nullptr); ::execv(arguments[0], arguments.data()); _exit(127);
    }
    in_read = {}; out_write = {}; err_write = {};
    Result result;
    if (pid < 0) return result;
    (void)write_all(in_write.value, input);
    if (close_input) in_write = {};
    int wait_status = 0;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{timeout_seconds};
    while (std::chrono::steady_clock::now() < deadline) {
        const pid_t waited = ::waitpid(pid, &wait_status, WNOHANG);
        if (waited == pid) break;
        if (waited < 0 && errno != EINTR) break;
        (void)::poll(nullptr, 0, 10);
    }
    if (::waitpid(pid, &wait_status, WNOHANG) == 0) {
        result.timed_out = true; (void)::kill(pid, SIGKILL); (void)::waitpid(pid, &wait_status, 0);
    }
    in_write = {};
    result.output = read_all(out_read.value); result.error = read_all(err_read.value);
    if (WIFEXITED(wait_status)) result.status = WEXITSTATUS(wait_status);
    else if (WIFSIGNALED(wait_status)) result.status = 128 + WTERMSIG(wait_status);
    return result;
}

std::size_t occurrences(std::string_view text, std::string_view needle) {
    std::size_t count = 0, offset = 0;
    while ((offset = text.find(needle, offset)) != std::string_view::npos) { ++count; offset += needle.size(); }
    return count;
}

bool check(bool condition, std::string_view description) {
    if (!condition) std::cerr << "check failed: " << description << '\n';
    return condition;
}

bool process_gone(pid_t pid) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{2};
    while (std::chrono::steady_clock::now() < deadline) {
        if (::kill(pid, 0) != 0 && errno == ESRCH) return true;
        (void)::poll(nullptr, 0, 10);
    }
    (void)::kill(pid, SIGKILL); // fixture cleanup if the assertion exposes a leak
    return false;
}

Result run_session(const char* guard, const char* echo, const TempFile& audit,
                   const TempFile& policy, const std::vector<std::string>& child_args,
                   std::string_view input, bool close_input = true) {
    std::vector<std::string> command{guard, "run", "--server-label", "fixture-label", "--policy",
        policy.path, "--audit-file", audit.path, "--", echo};
    command.insert(command.end(), child_args.begin(), child_args.end());
    return execute(command, input, close_input, 5);
}

bool test_sessions(const char* guard, const char* echo) {
    bool ok = true;
    TempFile policy;
    ok &= check(policy.set(R"({"version":1,"defaults":{"visibility":"allow","invocation":"allow"},"tools":[{"name":"SECRET_POLICY_CONTENT","visibility":"deny","invocation":"deny"}]})"), "policy fixture created");
    TempFile audit;
    const auto clean = run_session(guard, echo, audit, policy,
        {"--fixture-argument", "SECRET_DOWNSTREAM_ARGUMENT"},
        R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"allowed.tool","arguments":{"secret":"SECRET_TOOL_ARGUMENT"}}})" "\n");
    const std::string clean_audit = audit.get();
    ok &= check(clean.status == 0 && !clean.timed_out, "stdin-close session exits cleanly");
    ok &= check(occurrences(clean_audit, R"("event":"session_start")") == 1, "one session_start emitted");
    ok &= check(occurrences(clean_audit, R"("event":"session_end")") == 1, "one session_end emitted");
    ok &= check(clean_audit.find(R"("clean_shutdown":true)") != std::string::npos, "stdin close is clean");
    ok &= check(clean_audit.find(R"("duration_ms":)") != std::string::npos, "duration is present");
    ok &= check(clean.output.find("session_start") == std::string::npos && clean.output.find("session_end") == std::string::npos,
                "session audit never reaches protocol stdout");
    ok &= check(clean_audit.find(echo) == std::string::npos &&
                clean_audit.find("SECRET_DOWNSTREAM_ARGUMENT") == std::string::npos &&
                clean_audit.find("SECRET_POLICY_CONTENT") == std::string::npos &&
                clean_audit.find("SECRET_TOOL_ARGUMENT") == std::string::npos &&
                clean_audit.find("SECRET_ENVIRONMENT_VALUE") == std::string::npos,
                "session audit excludes command, arguments, policy, tool arguments, and environment");

    TempFile missing_audit;
    const auto missing = run_session(guard, "/definitely/missing/mng-server", missing_audit, policy, {}, {});
    ok &= check(missing.status != 0, "missing executable returns nonzero");
    ok &= check(missing_audit.get().find("session_start") == std::string::npos &&
                missing_audit.get().find("session_end") == std::string::npos,
                "launch failure emits no session events");

    TempFile nonzero_audit;
    const auto nonzero = run_session(guard, echo, nonzero_audit, policy, {"--exit-code", "7"}, {}, false);
    const std::string nonzero_records = nonzero_audit.get();
    ok &= check(nonzero.status == 7 && !nonzero.timed_out, "child-first nonzero exit is deterministic");
    ok &= check(occurrences(nonzero_records, R"("event":"session_start")") == 1 &&
                occurrences(nonzero_records, R"("event":"session_end")") == 1,
                "child-first exit has matching session events");
    ok &= check(nonzero_records.find(R"("child_exit_status":7)") != std::string::npos &&
                nonzero_records.find(R"("proxy_exit_status":7)") != std::string::npos &&
                nonzero_records.find(R"("termination_reason":"child_nonzero_exit")") != std::string::npos &&
                nonzero_records.find(R"("clean_shutdown":false)") != std::string::npos,
                "nonzero child status and reason are accurate");
    return ok;
}

Result run_doctor(const char* guard, const char* server, std::string_view mode, const TempFile* pid_file = nullptr) {
    std::vector<std::string> command{guard, "doctor", "--doctor-timeout", "1", "--", server};
    if (!mode.empty()) { command.push_back("--mode"); command.emplace_back(mode); }
    if (pid_file != nullptr) { command.push_back("--pid-file"); command.push_back(pid_file->path); }
    return execute(command, {}, true, 5);
}

bool test_doctor(const char* guard, const char* server) {
    bool ok = true;
    TempFile timeout_pid;
    const auto timeout = run_doctor(guard, server, "initialize-timeout", &timeout_pid);
    pid_t fixture_pid = -1; { std::ifstream stream{timeout_pid.path}; stream >> fixture_pid; }
    ok &= check(timeout.status != 0 && !timeout.timed_out, "doctor initialize timeout returns promptly");
    ok &= check(timeout.output.find("FAIL initialize") != std::string::npos &&
                timeout.output.find("doctor result: unhealthy") != std::string::npos,
                "doctor timeout prints concise failure");
    ok &= check(fixture_pid > 0 && process_gone(fixture_pid), "doctor timeout terminates and reaps fixture");

    TempFile malformed_pid_file;
    const auto malformed_init = run_doctor(guard, server, "malformed-initialize", &malformed_pid_file);
    pid_t malformed_pid = -1; { std::ifstream stream{malformed_pid_file.path}; stream >> malformed_pid; }
    ok &= check(malformed_init.status != 0 && !malformed_init.timed_out &&
                malformed_init.output.find("FAIL initialize") != std::string::npos,
                "malformed initialize response fails cleanly");
    ok &= check(malformed_pid > 0 && process_gone(malformed_pid),
                "malformed initialize failure terminates and reaps fixture");
    const auto list_error = run_doctor(guard, server, "tools-list-error");
    ok &= check(list_error.status != 0 && list_error.output.find("FAIL tools/list") != std::string::npos,
                "tools/list error fails named check");
    const auto list_missing = run_doctor(guard, server, "tools-list-missing");
    ok &= check(list_missing.status != 0 && list_missing.output.find("FAIL tools/list") != std::string::npos,
                "missing result.tools fails");
    const auto list_not_array = run_doctor(guard, server, "tools-list-not-array");
    ok &= check(list_not_array.status != 0 && list_not_array.output.find("FAIL tools/list") != std::string::npos,
                "non-array result.tools fails");
    const auto missing = run_doctor(guard, "/definitely/missing/mng-server", "");
    ok &= check(missing.status != 0 && missing.output.find("doctor result: healthy") == std::string::npos,
                "doctor missing executable is not healthy");
    const auto healthy = run_doctor(guard, server, "healthy");
    ok &= check(healthy.status == 0 && healthy.output.find("PASS initialize") != std::string::npos &&
                healthy.output.find("PASS tools/list") != std::string::npos &&
                healthy.output.find("PASS clean shutdown") != std::string::npos &&
                healthy.output.find("doctor result: healthy") != std::string::npos,
                "healthy doctor prints expected PASS lines");
    return ok;
}
} // namespace

int main(int argc, char** argv) {
    if (argc != 4) return 2;
    const bool ok = test_sessions(argv[1], argv[2]) && test_doctor(argv[1], argv[3]);
    return ok ? 0 : 1;
}
