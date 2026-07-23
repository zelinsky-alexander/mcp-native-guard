#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <iterator>
#include <poll.h>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace {

struct Fd {
    int value{-1};
    ~Fd() {
        if (value >= 0) {
            (void)::close(value);
        }
    }
    Fd() = default;
    explicit Fd(int fd) : value{fd} {}
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    Fd(Fd&& other) noexcept : value{other.value} { other.value = -1; }
    Fd& operator=(Fd&& other) noexcept {
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

bool pipe_pair(Fd& read_end, Fd& write_end) {
    std::array<int, 2> values{};
    if (::pipe(values.data()) != 0) {
        return false;
    }
    read_end = Fd{values[0]};
    write_end = Fd{values[1]};
    const int read_flags = ::fcntl(read_end.value, F_GETFD);
    const int write_flags = ::fcntl(write_end.value, F_GETFD);
    return read_flags >= 0 && write_flags >= 0 &&
           ::fcntl(read_end.value, F_SETFD, read_flags | FD_CLOEXEC) == 0 &&
           ::fcntl(write_end.value, F_SETFD, write_flags | FD_CLOEXEC) == 0;
}

std::string read_all(int fd) {
    std::string output;
    std::array<char, 4096> bytes{};
    while (true) {
        const auto count = ::read(fd, bytes.data(), bytes.size());
        if (count > 0) {
            output.append(bytes.data(), static_cast<std::size_t>(count));
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            return output;
        }
    }
}

bool write_all(int fd, std::string_view input) {
    while (!input.empty()) {
        const auto count = ::write(fd, input.data(), input.size());
        if (count > 0) {
            input.remove_prefix(static_cast<std::size_t>(count));
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            return false;
        }
    }
    return true;
}

struct Result final {
    int status{-1};
    bool timed_out{false};
    std::string output;
    std::string error;
};

// Runs a command with no stdin, bounded by timeout_seconds. Used for
// `policy create` and `inspect` invocations, which never read stdin.
Result execute(const std::vector<std::string>& command, int timeout_seconds) {
    Fd out_read;
    Fd out_write;
    Fd err_read;
    Fd err_write;
    if (!pipe_pair(out_read, out_write) || !pipe_pair(err_read, err_write)) {
        return {};
    }
    const pid_t pid = ::fork();
    if (pid == 0) {
        const Fd dev_null{::open("/dev/null", O_RDONLY)};
        if (dev_null.value >= 0) {
            (void)::dup2(dev_null.value, STDIN_FILENO);
        }
        (void)::dup2(out_write.value, STDOUT_FILENO);
        (void)::dup2(err_write.value, STDERR_FILENO);
        std::vector<char*> arguments;
        for (const auto& value : command) {
            arguments.push_back(const_cast<char*>(value.c_str()));
        }
        arguments.push_back(nullptr);
        ::execv(arguments[0], arguments.data());
        _exit(127);
    }
    out_write = {};
    err_write = {};
    Result result;
    if (pid < 0) {
        return result;
    }
    int wait_status = 0;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{timeout_seconds};
    while (std::chrono::steady_clock::now() < deadline) {
        const pid_t waited = ::waitpid(pid, &wait_status, WNOHANG);
        if (waited == pid) {
            break;
        }
        if (waited < 0 && errno != EINTR) {
            break;
        }
        (void)::poll(nullptr, 0, 10);
    }
    if (::waitpid(pid, &wait_status, WNOHANG) == 0) {
        result.timed_out = true;
        (void)::kill(pid, SIGKILL);
        (void)::waitpid(pid, &wait_status, 0);
    }
    result.output = read_all(out_read.value);
    result.error = read_all(err_read.value);
    if (WIFEXITED(wait_status)) {
        result.status = WEXITSTATUS(wait_status);
    } else if (WIFSIGNALED(wait_status)) {
        result.status = 128 + WTERMSIG(wait_status);
    }
    return result;
}

// Runs a command, writing stdin_data completely before reading output. Used
// for `run`/`doctor` invocations against the fixture MCP server, mirroring
// the existing pattern in run_integration_test.cpp.
Result run_with_stdin(const std::vector<std::string>& command, std::string_view stdin_data) {
    Fd in_read;
    Fd in_write;
    Fd out_read;
    Fd out_write;
    Fd err_read;
    Fd err_write;
    if (!pipe_pair(in_read, in_write) || !pipe_pair(out_read, out_write) ||
        !pipe_pair(err_read, err_write)) {
        return {};
    }
    const pid_t pid = ::fork();
    if (pid == 0) {
        (void)::dup2(in_read.value, STDIN_FILENO);
        (void)::dup2(out_write.value, STDOUT_FILENO);
        (void)::dup2(err_write.value, STDERR_FILENO);
        std::vector<char*> arguments;
        for (const auto& value : command) {
            arguments.push_back(const_cast<char*>(value.c_str()));
        }
        arguments.push_back(nullptr);
        ::execv(arguments[0], arguments.data());
        _exit(127);
    }
    in_read = {};
    out_write = {};
    err_write = {};
    Result result;
    if (pid < 0) {
        return result;
    }
    if (!write_all(in_write.value, stdin_data)) {
        (void)::waitpid(pid, nullptr, 0);
        return result;
    }
    in_write = {};
    result.output = read_all(out_read.value);
    result.error = read_all(err_read.value);
    int status = 1;
    if (::waitpid(pid, &status, 0) == pid && WIFEXITED(status)) {
        result.status = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        result.status = 128 + WTERMSIG(status);
    }
    return result;
}

struct TempFile {
    std::string path;
    TempFile() {
        std::array<char, 64> pattern{};
        constexpr std::string_view value = "/tmp/mng-policy-create-XXXXXX";
        std::copy(value.begin(), value.end(), pattern.begin());
        const int fd = ::mkstemp(pattern.data());
        if (fd >= 0) {
            (void)::close(fd);
            path = pattern.data();
        }
    }
    ~TempFile() {
        if (!path.empty()) {
            (void)::unlink(path.c_str());
        }
    }
    [[nodiscard]] bool set(std::string_view value) const {
        std::ofstream stream{path, std::ios::binary | std::ios::trunc};
        stream << value;
        return static_cast<bool>(stream);
    }
    [[nodiscard]] std::string get() const {
        std::ifstream stream{path, std::ios::binary};
        return {std::istreambuf_iterator<char>{stream}, std::istreambuf_iterator<char>{}};
    }
    [[nodiscard]] std::string directory() const {
        const auto slash = path.find_last_of('/');
        return slash == std::string::npos ? std::string{"."} : path.substr(0, slash);
    }
};

bool check(bool condition, std::string_view description) {
    if (!condition) {
        std::cerr << "check failed: " << description << '\n';
    }
    return condition;
}

bool directory_has_mng_policy_temp(const std::string& directory) {
    DIR* dir = ::opendir(directory.c_str());
    if (dir == nullptr) {
        return false;
    }
    bool found = false;
    while (const dirent* entry = ::readdir(dir)) {
        const std::string_view name{entry->d_name};
        if (name.rfind(".mng-policy-", 0) == 0) {
            found = true;
            break;
        }
    }
    (void)::closedir(dir);
    return found;
}

std::string strip_trailing_newline(std::string value) {
    while (!value.empty() && (value.back() == '\n' || value.back() == '\r')) {
        value.pop_back();
    }
    return value;
}

bool test_cli_argument_errors(const std::string& guard) {
    bool ok = true;

    const auto missing_from = execute({guard, "policy", "create"}, 5);
    ok &= check(
        missing_from.status == 2 && missing_from.output.empty(), "missing --from fails with no stdout");

    const auto no_create = execute({guard, "policy"}, 5);
    ok &= check(no_create.status == 2, "policy without create fails");

    TempFile inventory;
    ok &= check(
        inventory.set(R"({"inventory_version":1,"server":{},"tools":[{"name":"a"}]})"),
        "seed minimal inventory");

    const auto duplicate_from =
        execute({guard, "policy", "create", "--from", inventory.path, "--from", inventory.path}, 5);
    ok &= check(duplicate_from.status == 2, "duplicate --from fails");

    const auto duplicate_output = execute(
        {guard, "policy", "create", "--from", inventory.path, "--output", "/tmp/x", "--output",
         "/tmp/y"},
        5);
    ok &= check(duplicate_output.status == 2, "duplicate --output fails");

    const auto unknown_flag =
        execute({guard, "policy", "create", "--from", inventory.path, "--nope"}, 5);
    ok &= check(unknown_flag.status == 2, "unknown flag fails");

    const auto missing_allow_value =
        execute({guard, "policy", "create", "--from", inventory.path, "--allow-tool"}, 5);
    ok &= check(missing_allow_value.status == 2, "--allow-tool without value fails");

    const auto no_inventory_file =
        execute({guard, "policy", "create", "--from", "/tmp/mng-policy-does-not-exist.json"}, 5);
    ok &= check(
        no_inventory_file.status == 2 && no_inventory_file.output.empty(),
        "missing inventory file fails with no stdout");

    return ok;
}

bool test_generation_semantics(const std::string& guard) {
    bool ok = true;

    TempFile inventory_order_a;
    ok &= check(
        inventory_order_a.set(
            R"({"inventory_version":1,"server":{"downstream_executable":"x"},)"
            R"("tools":[{"name":"blocked.two"},{"name":"allowed.tool"},{"name":"blocked.one"}]})"),
        "seed inventory order a");
    TempFile inventory_order_b;
    ok &= check(
        inventory_order_b.set(
            R"({"inventory_version":1,"server":{"downstream_executable":"x"},)"
            R"("tools":[{"name":"allowed.tool"},{"name":"blocked.one"},{"name":"blocked.two"}]})"),
        "seed inventory order b");

    const auto deny_all = execute({guard, "policy", "create", "--from", inventory_order_a.path}, 5);
    ok &= check(deny_all.status == 0, "deny-all generation succeeds");
    ok &= check(
        strip_trailing_newline(deny_all.output) ==
            R"({"version":1,"defaults":{"visibility":"deny","invocation":"deny"},"tools":[]})",
        "deny-all output matches exact expected shape");
    ok &= check(
        deny_all.error.find("policy create result: success") != std::string::npos,
        "success status appears on stderr");
    ok &= check(
        deny_all.output.find("FAIL") == std::string::npos && deny_all.error.find("{") == std::string::npos,
        "stdout/stderr stay separated");

    const auto one_allow = execute(
        {guard, "policy", "create", "--from", inventory_order_a.path, "--allow-tool", "allowed.tool"},
        5);
    ok &= check(one_allow.status == 0, "single allow-tool generation succeeds");
    ok &= check(
        strip_trailing_newline(one_allow.output) ==
            R"({"version":1,"defaults":{"visibility":"deny","invocation":"deny"},)"
            R"("tools":[{"name":"allowed.tool","visibility":"allow","invocation":"allow"}]})",
        "single allow-tool output matches exact expected shape");

    const auto multi_order_1 = execute(
        {guard, "policy", "create", "--from", inventory_order_a.path, "--allow-tool", "blocked.two",
         "--allow-tool", "allowed.tool"},
        5);
    const auto multi_order_2 = execute(
        {guard, "policy", "create", "--from", inventory_order_a.path, "--allow-tool", "allowed.tool",
         "--allow-tool", "blocked.two"},
        5);
    ok &= check(
        multi_order_1.status == 0 && multi_order_2.status == 0, "multi allow-tool generation succeeds");
    ok &= check(
        multi_order_1.output == multi_order_2.output,
        "reordered --allow-tool arguments produce byte-identical output");
    ok &= check(
        strip_trailing_newline(multi_order_1.output).find(
            R"("tools":[{"name":"allowed.tool","visibility":"allow","invocation":"allow"},)"
            R"({"name":"blocked.two","visibility":"allow","invocation":"allow"}])") != std::string::npos,
        "multi allow-tool rules sorted by bytewise name");

    const auto reordered_inventory = execute(
        {guard, "policy", "create", "--from", inventory_order_b.path, "--allow-tool", "blocked.two",
         "--allow-tool", "allowed.tool"},
        5);
    ok &= check(
        reordered_inventory.status == 0 && reordered_inventory.output == multi_order_1.output,
        "reordered inventory tools produce byte-identical output");

    const auto unknown_allow = execute(
        {guard, "policy", "create", "--from", inventory_order_a.path, "--allow-tool", "not.a.tool"}, 5);
    ok &= check(
        unknown_allow.status == 2 && unknown_allow.output.empty(),
        "unknown --allow-tool fails with no stdout");
    ok &= check(
        unknown_allow.error.find("unknown_allow_tool") != std::string::npos,
        "unknown --allow-tool reports specific error");

    const auto duplicate_allow = execute(
        {guard, "policy", "create", "--from", inventory_order_a.path, "--allow-tool", "allowed.tool",
         "--allow-tool", "allowed.tool"},
        5);
    ok &= check(
        duplicate_allow.status == 2 && duplicate_allow.output.empty(),
        "duplicate --allow-tool fails with no stdout");
    ok &= check(
        duplicate_allow.error.find("duplicate_allow_tool") != std::string::npos,
        "duplicate --allow-tool reports specific error");

    TempFile bad_inventory;
    ok &= check(bad_inventory.set("{not json"), "seed malformed inventory");
    const auto malformed = execute({guard, "policy", "create", "--from", bad_inventory.path}, 5);
    ok &= check(
        malformed.status == 2 && malformed.output.empty(), "malformed inventory JSON fails");
    ok &= check(
        malformed.error.find("malformed_inventory_json") != std::string::npos,
        "malformed inventory JSON reports specific error");

    return ok;
}

bool test_atomic_output(const std::string& guard) {
    bool ok = true;

    TempFile inventory;
    ok &= check(
        inventory.set(R"({"inventory_version":1,"server":{},"tools":[{"name":"allowed.tool"}]})"),
        "seed inventory for atomic output test");

    TempFile output_file;
    ok &= check(output_file.set("OLD_POLICY"), "seed old output contents");
    const auto success = execute(
        {guard, "policy", "create", "--from", inventory.path, "--allow-tool", "allowed.tool", "--output",
         output_file.path},
        5);
    ok &= check(success.status == 0 && success.output.empty(), "output-file mode keeps stdout empty");
    ok &= check(
        output_file.get().find(R"("name":"allowed.tool")") != std::string::npos &&
            output_file.get().find("OLD_POLICY") == std::string::npos,
        "successful output replaces destination");
    ok &= check(!directory_has_mng_policy_temp(output_file.directory()), "no temp file after success");

    std::array<char, 64> readonly_pattern{};
    constexpr std::string_view readonly_value = "/tmp/mng-policy-ro-XXXXXX";
    std::copy(readonly_value.begin(), readonly_value.end(), readonly_pattern.begin());
    const char* readonly_dir = ::mkdtemp(readonly_pattern.data());
    ok &= check(readonly_dir != nullptr, "readonly dir created");
    if (readonly_dir != nullptr) {
        const std::string readonly_dest = std::string{readonly_dir} + "/policy.json";
        {
            std::ofstream stream{readonly_dest, std::ios::binary | std::ios::trunc};
            stream << "KEEP_WRITE_FAIL";
        }
        ok &= check(::chmod(readonly_dir, 0555) == 0, "directory made read-only");
        const auto write_fail = execute(
            {guard, "policy", "create", "--from", inventory.path, "--output", readonly_dest}, 5);
        ok &= check(write_fail.status != 0, "write failure returns nonzero");
        {
            std::ifstream stream{readonly_dest, std::ios::binary};
            const std::string content{
                std::istreambuf_iterator<char>{stream}, std::istreambuf_iterator<char>{}};
            ok &= check(content == "KEEP_WRITE_FAIL", "write failure preserves destination");
        }
        ok &= check(!directory_has_mng_policy_temp(readonly_dir), "no temp file after write failure");
        (void)::chmod(readonly_dir, 0755);
        (void)::unlink(readonly_dest.c_str());
        (void)::rmdir(readonly_dir);
    }

    return ok;
}

std::string find_response_line(const std::string& output, std::string_view id) {
    const std::string needle = "\"id\":\"" + std::string{id} + "\"";
    const auto position = output.find(needle);
    if (position == std::string::npos) {
        return {};
    }
    const auto line_begin_search = output.rfind('\n', position);
    const std::size_t line_begin = line_begin_search == std::string::npos ? 0U : line_begin_search + 1U;
    const auto line_end = output.find('\n', position);
    return output.substr(line_begin, (line_end == std::string::npos ? output.size() : line_end) - line_begin);
}

bool response_is_denied(const std::string& output, std::string_view id) {
    const std::string line = find_response_line(output, id);
    return !line.empty() && line.find("-32001") != std::string::npos &&
           line.find("Tool call denied by policy") != std::string::npos;
}

bool response_has_result(const std::string& output, std::string_view id) {
    const std::string line = find_response_line(output, id);
    return !line.empty() && line.find("\"result\"") != std::string::npos;
}

std::string requests_for_all_tools() {
    return
        R"({"jsonrpc":"2.0","id":"init-1","method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"mng-policy-create-test","version":"0.1.0"}}})"
        "\n"
        R"({"jsonrpc":"2.0","method":"notifications/initialized","params":{}})"
        "\n"
        R"({"jsonrpc":"2.0","id":"list-1","method":"tools/list","params":{}})"
        "\n"
        R"({"jsonrpc":"2.0","id":"call-allowed","method":"tools/call","params":{"name":"allowed.tool"}})"
        "\n"
        R"({"jsonrpc":"2.0","id":"call-blocked-one","method":"tools/call","params":{"name":"blocked.one"}})"
        "\n"
        R"({"jsonrpc":"2.0","id":"call-blocked-two","method":"tools/call","params":{"name":"blocked.two"}})"
        "\n";
}

bool test_end_to_end_enforcement(const std::string& guard, const std::string& server) {
    bool ok = true;

    const auto inspected = execute({guard, "inspect", "--", server}, 8);
    ok &= check(
        inspected.status == 0 &&
            inspected.output.find(R"("inventory_version":1)") != std::string::npos,
        "inspect fixture server succeeds and produces an inventory");

    TempFile inventory;
    ok &= check(inventory.set(inspected.output), "save inspect output as inventory file");

    TempFile deny_all_policy;
    const auto deny_all_generated = execute(
        {guard, "policy", "create", "--from", inventory.path, "--output", deny_all_policy.path}, 5);
    ok &= check(deny_all_generated.status == 0, "deny-all policy generation from real inventory succeeds");

    const auto deny_all_run = run_with_stdin(
        {guard, "run", "--policy", deny_all_policy.path, "--", server}, requests_for_all_tools());
    ok &= check(deny_all_run.status == 0, "guard exits cleanly under deny-all policy");
    ok &= check(
        find_response_line(deny_all_run.output, "list-1").find(R"("tools":[])") != std::string::npos,
        "deny-all policy hides every fixture tool from tools/list");
    ok &= check(
        response_is_denied(deny_all_run.output, "call-allowed") &&
            response_is_denied(deny_all_run.output, "call-blocked-one") &&
            response_is_denied(deny_all_run.output, "call-blocked-two"),
        "deny-all policy denies tools/call for every fixture tool");

    TempFile allow_one_policy;
    const auto allow_one_generated = execute(
        {guard, "policy", "create", "--from", inventory.path, "--allow-tool", "allowed.tool", "--output",
         allow_one_policy.path},
        5);
    ok &= check(
        allow_one_generated.status == 0, "single allow-tool policy generation from real inventory succeeds");

    const auto allow_one_run = run_with_stdin(
        {guard, "run", "--policy", allow_one_policy.path, "--", server}, requests_for_all_tools());
    ok &= check(allow_one_run.status == 0, "guard exits cleanly under single allow-tool policy");
    ok &= check(
        allow_one_run.output.find(R"("name":"allowed.tool")") != std::string::npos &&
            allow_one_run.output.find(R"("name":"blocked.one")") == std::string::npos &&
            allow_one_run.output.find(R"("name":"blocked.two")") == std::string::npos,
        "allowlist policy exposes only the selected fixture tool");
    ok &= check(
        response_has_result(allow_one_run.output, "call-allowed"),
        "allowed tool remains callable");
    ok &= check(
        response_is_denied(allow_one_run.output, "call-blocked-one") &&
            response_is_denied(allow_one_run.output, "call-blocked-two"),
        "unapproved tools remain denied at tools/call under the allowlist policy");

    const auto doctor_check =
        execute({guard, "doctor", "--policy", allow_one_policy.path, "--", server}, 8);
    ok &= check(
        doctor_check.status == 0 &&
            doctor_check.output.find("doctor result: healthy") != std::string::npos,
        "doctor loads the generated allowlist policy successfully");

    return ok;
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "usage: policy_create_integration_test <guard> <test-server>\n";
        return 2;
    }
    const std::string guard = argv[1];
    const std::string server = argv[2];

    bool ok = true;
    ok &= test_cli_argument_errors(guard);
    ok &= test_generation_semantics(guard);
    ok &= test_atomic_output(guard);
    ok &= test_end_to_end_enforcement(guard, server);
    return ok ? 0 : 1;
}
