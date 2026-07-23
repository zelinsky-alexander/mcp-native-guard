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

struct TempFile {
    std::string path;
    TempFile() {
        std::array<char, 64> pattern{};
        constexpr std::string_view value = "/tmp/mng-inspect-XXXXXX";
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

struct Result {
    int status{-1};
    bool timed_out{false};
    std::string output;
    std::string error;
};

Result execute(const std::vector<std::string>& command, int timeout_seconds) {
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
    in_write = {};
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

bool check(bool condition, std::string_view description) {
    if (!condition) {
        std::cerr << "check failed: " << description << '\n';
    }
    return condition;
}

bool process_gone(pid_t pid) {
    if (pid <= 0) {
        return false;
    }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{2};
    while (std::chrono::steady_clock::now() < deadline) {
        if (::kill(pid, 0) != 0 && errno == ESRCH) {
            return true;
        }
        (void)::poll(nullptr, 0, 10);
    }
    (void)::kill(pid, SIGKILL);
    return false;
}

bool directory_has_mng_temp(const std::string& directory) {
    DIR* dir = ::opendir(directory.c_str());
    if (dir == nullptr) {
        return false;
    }
    bool found = false;
    while (const dirent* entry = ::readdir(dir)) {
        const std::string_view name{entry->d_name};
        if (name.rfind(".mng-inspect-", 0) == 0) {
            found = true;
            break;
        }
    }
    (void)::closedir(dir);
    return found;
}

Result run_inspect(
    const char* guard,
    const char* server,
    std::string_view mode,
    const std::vector<std::string>& extra_options = {},
    const std::vector<std::string>& server_extra = {}) {
    std::vector<std::string> command{guard, "inspect"};
    command.insert(command.end(), extra_options.begin(), extra_options.end());
    command.push_back("--");
    command.push_back(server);
    if (!mode.empty()) {
        command.push_back("--mode");
        command.emplace_back(mode);
    }
    command.insert(command.end(), server_extra.begin(), server_extra.end());
    return execute(command, 8);
}

bool test_inspect(const char* guard, const char* server) {
    bool ok = true;

    const auto healthy = run_inspect(guard, server, "healthy");
    ok &= check(healthy.status == 0 && !healthy.timed_out, "healthy inspect succeeds");
    ok &= check(
        healthy.output.find(R"("inventory_version":1)") != std::string::npos &&
            healthy.output.find(R"("name":"allowed.tool")") != std::string::npos &&
            healthy.output.find(R"("name":"blocked.one")") != std::string::npos &&
            healthy.output.find(R"("name":"blocked.two")") != std::string::npos,
        "healthy inventory contains sorted tools");
    ok &= check(
        healthy.output.find("inspect result") == std::string::npos &&
            healthy.output.find("FAIL") == std::string::npos,
        "diagnostics never appear in inventory stdout");
    ok &= check(
        healthy.error.find("inspect result: success") != std::string::npos &&
            healthy.error.find("shutdown:") != std::string::npos,
        "success diagnostics go to stderr");
    ok &= check(
        healthy.output.find("tools/call") == std::string::npos, "inventory does not mention tools/call");

    const auto reordered = run_inspect(guard, server, "tools-list-reordered");
    const auto members = run_inspect(guard, server, "tools-list-member-reordered");
    const auto schema_reordered = run_inspect(guard, server, "tools-list-schema-reordered");
    const auto schema_ws = run_inspect(guard, server, "tools-list-schema-whitespace");
    ok &= check(reordered.status == 0 && members.status == 0, "reorder fixture modes succeed");
    ok &= check(schema_reordered.status == 0 && schema_ws.status == 0, "schema reorder fixtures succeed");
    ok &= check(healthy.output == reordered.output, "reordered tools produce identical inventory");
    ok &= check(healthy.output == members.output, "reordered members produce identical inventory");
    ok &= check(
        healthy.output == schema_reordered.output,
        "reordered nested schema produces identical inventory");
    ok &= check(
        healthy.output == schema_ws.output,
        "whitespace-different nested schema produces identical inventory");
    ok &= check(
        healthy.output.find(
            R"("inputSchema":{"properties":{"value":{"type":"string"}},"type":"object"})") !=
            std::string::npos,
        "healthy inventory emits canonical nested schema");

    const auto annotations_a = run_inspect(guard, server, "tools-list-annotations-reordered");
    const auto annotations_b = run_inspect(guard, server, "tools-list-annotations-alt-order");
    ok &= check(annotations_a.status == 0 && annotations_b.status == 0, "annotations fixtures succeed");
    ok &= check(
        annotations_a.output == annotations_b.output,
        "reordered nested annotations produce identical inventory");
    ok &= check(
        annotations_a.output.find(R"("annotations":{"openWorldHint":false,"readOnlyHint":true})") !=
            std::string::npos,
        "annotations are emitted in canonical key order");

    const auto array_order = run_inspect(guard, server, "tools-list-schema-array-order");
    ok &= check(
        array_order.status == 0 &&
            array_order.output.find(R"("required":["b","a"])") != std::string::npos,
        "array element order is preserved");

    const auto empty = run_inspect(guard, server, "tools-list-empty");
    ok &= check(
        empty.status == 0 && empty.output.find(R"("tools":[])") != std::string::npos,
        "empty tools array is valid");

    TempFile method_log;
    const auto logged = run_inspect(
        guard, server, "healthy", {}, {"--method-log", method_log.path});
    ok &= check(logged.status == 0, "method-log inspect succeeds");
    const std::string methods = method_log.get();
    ok &= check(
        methods.find("initialize") != std::string::npos &&
            methods.find("notifications/initialized") != std::string::npos &&
            methods.find("tools/list") != std::string::npos,
        "fixture saw initialize, initialized, tools/list");
    ok &= check(methods.find("tools/call") == std::string::npos, "fixture never saw tools/call");

    TempFile output_file;
    ok &= check(output_file.set("OLD_INVENTORY"), "seed output file");
    const auto to_file = run_inspect(
        guard, server, "healthy", {"--output", output_file.path});
    ok &= check(to_file.status == 0 && to_file.output.empty(), "output file keeps stdout empty");
    ok &= check(
        output_file.get().find(R"("inventory_version":1)") != std::string::npos &&
            output_file.get().find("OLD_INVENTORY") == std::string::npos,
        "successful output replaces destination");
    ok &= check(!directory_has_mng_temp(output_file.directory()), "no temp file after success");

    TempFile preserved;
    ok &= check(preserved.set("KEEP_ME"), "seed preserved output");
    const auto fail_preserves = run_inspect(
        guard, server, "malformed-initialize", {"--timeout", "1", "--output", preserved.path});
    ok &= check(fail_preserves.status != 0, "failed inspect with --output fails");
    ok &= check(preserved.get() == "KEEP_ME", "inspection failure preserves destination");
    ok &= check(!directory_has_mng_temp(preserved.directory()), "no temp file after inspect failure");

    std::array<char, 64> readonly_pattern{};
    constexpr std::string_view readonly_value = "/tmp/mng-inspect-ro-XXXXXX";
    std::copy(readonly_value.begin(), readonly_value.end(), readonly_pattern.begin());
    const char* readonly_dir = ::mkdtemp(readonly_pattern.data());
    ok &= check(readonly_dir != nullptr, "readonly dir created");
    if (readonly_dir != nullptr) {
        const std::string readonly_dest = std::string{readonly_dir} + "/out.json";
        {
            std::ofstream stream{readonly_dest, std::ios::binary | std::ios::trunc};
            stream << "KEEP_WRITE_FAIL";
        }
        ok &= check(::chmod(readonly_dir, 0555) == 0, "directory made read-only");
        const auto write_fail = run_inspect(guard, server, "healthy", {"--output", readonly_dest});
        ok &= check(write_fail.status != 0, "write failure returns nonzero");
        {
            std::ifstream stream{readonly_dest, std::ios::binary};
            const std::string content{
                std::istreambuf_iterator<char>{stream}, std::istreambuf_iterator<char>{}};
            ok &= check(content == "KEEP_WRITE_FAIL", "write failure preserves destination");
        }
        ok &= check(!directory_has_mng_temp(readonly_dir), "no temp file after write failure");
        (void)::chmod(readonly_dir, 0755);
        (void)::unlink(readonly_dest.c_str());
        (void)::rmdir(readonly_dir);
    }

    const auto expect_fail = [&](std::string_view mode, std::string_view stage_fragment) {
        const auto result = run_inspect(guard, server, mode, {"--timeout", "1"});
        ok &= check(result.status != 0 && !result.timed_out, std::string{mode} + " fails");
        ok &= check(
            result.error.find("FAIL") != std::string::npos &&
                result.error.find("inspect result: failure") != std::string::npos,
            std::string{mode} + " prints failure diagnostics");
        ok &= check(
            result.output.find(R"("inventory_version")") == std::string::npos,
            std::string{mode} + " emits no inventory");
        if (!stage_fragment.empty()) {
            ok &= check(
                result.error.find(stage_fragment) != std::string::npos,
                std::string{mode} + " mentions expected stage");
        }
    };

    expect_fail("malformed-initialize", "malformed_json");
    expect_fail("wrong-jsonrpc", "unsupported_jsonrpc_version");
    expect_fail("wrong-init-id", "wrong_response_id");
    expect_fail("missing-init-result", "error_result");
    expect_fail("tools-list-error", "error_result");
    expect_fail("tools-list-missing", "missing_tools");
    expect_fail("tools-list-not-array", "tools_not_array");
    expect_fail("tools-list-missing-name", "missing_tool_name");
    expect_fail("tools-list-non-string-name", "non_string_tool_name");
    expect_fail("tools-list-escaped-name", "escaped_tool_name");
    expect_fail("tools-list-duplicate-name-member", "duplicate_member");
    expect_fail("tools-list-duplicate-names", "duplicate_tool_name");
    expect_fail("tools-list-schema-dup-member", "duplicate_member");
    expect_fail("tools-list-annotations-dup-member", "duplicate_member");
    expect_fail("wrong-list-id", "wrong_response_id");
    expect_fail("unsolicited-before-init", "unsolicited");
    expect_fail("unsolicited-before-list", "unsolicited");
    expect_fail("initialize-timeout", "timeout");
    expect_fail("tools-list-timeout", "timeout");
    expect_fail("exit-early", "exited");

    const auto oversized = run_inspect(
        guard, server, "oversized-message", {"--timeout", "1", "--max-message-bytes", "512"});
    ok &= check(oversized.status != 0, "oversized message fails");
    ok &= check(
        oversized.error.find("oversized") != std::string::npos ||
            oversized.error.find("message_too_large") != std::string::npos ||
            oversized.error.find("oversized_tool_name") != std::string::npos,
        "oversized message reports a size failure");

    const auto nesting = run_inspect(
        guard, server, "healthy", {"--timeout", "1", "--max-nesting-depth", "2"});
    ok &= check(nesting.status != 0, "excessive nesting fails");

    const auto too_few_tools =
        run_inspect(guard, server, "healthy", {"--timeout", "1", "--max-tools", "1"});
    ok &= check(
        too_few_tools.status != 0 &&
            too_few_tools.error.find("excessive_tool_count") != std::string::npos,
        "excessive tool count fails");

    const auto short_name =
        run_inspect(guard, server, "healthy", {"--timeout", "1", "--max-tool-name-bytes", "4"});
    ok &= check(
        short_name.status != 0 &&
            short_name.error.find("oversized_tool_name") != std::string::npos,
        "oversized tool name fails");

    const auto short_description = run_inspect(
        guard, server, "healthy", {"--timeout", "1", "--max-tool-description-bytes", "4"});
    ok &= check(
        short_description.status != 0 &&
            short_description.error.find("oversized_description") != std::string::npos,
        "oversized description fails");

    const auto short_schema =
        run_inspect(guard, server, "healthy", {"--timeout", "1", "--max-tool-schema-bytes", "8"});
    ok &= check(
        short_schema.status != 0 &&
            short_schema.error.find("oversized_schema") != std::string::npos,
        "oversized schema fails");

    const auto hang = run_inspect(
        guard, server, "hang-after-list", {"--timeout", "2", "--shutdown-timeout-ms", "200"});
    ok &= check(hang.status == 0 && !hang.timed_out, "hang-after-list still succeeds inspection");
    ok &= check(
        hang.error.find("shutdown: forced") != std::string::npos,
        "hang-after-list reports forced shutdown");
    ok &= check(
        hang.output.find(R"("inventory_version":1)") != std::string::npos,
        "hang-after-list still emits inventory");

    TempFile child_pid_file;
    TempFile grandchild_pid_file;
    const auto grandchild = run_inspect(
        guard,
        server,
        "hang-with-grandchild",
        {"--timeout", "2", "--shutdown-timeout-ms", "200"},
        {"--pid-file", child_pid_file.path, "--grandchild-pid-file", grandchild_pid_file.path});
    ok &= check(grandchild.status == 0 && !grandchild.timed_out, "hang-with-grandchild succeeds");
    ok &= check(
        grandchild.error.find("shutdown: forced") != std::string::npos,
        "hang-with-grandchild forced shutdown");
    pid_t child_pid = -1;
    pid_t gchild_pid = -1;
    {
        std::ifstream child_stream{child_pid_file.path};
        child_stream >> child_pid;
        std::ifstream gchild_stream{grandchild_pid_file.path};
        gchild_stream >> gchild_pid;
    }
    ok &= check(child_pid > 0 && gchild_pid > 0, "child and grandchild pids recorded");
    ok &= check(process_gone(child_pid), "direct child terminated by process group kill");
    ok &= check(process_gone(gchild_pid), "grandchild terminated by process group kill");

    const auto flooded = run_inspect(guard, server, "stderr-flood", {"--timeout", "3"});
    ok &= check(flooded.status == 0 && !flooded.timed_out, "stderr flood does not block inspect");
    ok &= check(
        flooded.output.find(R"("inventory_version":1)") != std::string::npos &&
            flooded.output.find("EEEE") == std::string::npos,
        "stderr flood does not contaminate inventory stdout");
    ok &= check(
        flooded.error.find("inspect result: success") != std::string::npos,
        "guard diagnostics still appear on parent stderr");

    const auto policy_rejected =
        run_inspect(guard, server, "healthy", {"--policy", "/tmp/nope.json"});
    ok &= check(policy_rejected.status == 2, "policy option rejected by inspect CLI");

    return ok;
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "usage: inspect_integration_test <guard> <test-server>\n";
        return 2;
    }
    return test_inspect(argv[1], argv[2]) ? 0 : 1;
}
