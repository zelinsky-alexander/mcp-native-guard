#include "mcp_native_guard/process/inspect.hpp"

#include "mcp_native_guard/protocol/json_rpc_envelope.hpp"
#include "mcp_native_guard/protocol/tool_inventory.hpp"

#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <poll.h>
#include <spawn.h>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

extern char** environ;

namespace mng::process {
namespace {

constexpr std::string_view initialize_request =
    R"({"jsonrpc":"2.0","id":"inspect-init","method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"mcp-native-guard-inspect","version":"0.1.0"}}})"
    "\n";
constexpr std::string_view initialized_notification =
    R"({"jsonrpc":"2.0","method":"notifications/initialized","params":{}})"
    "\n";
constexpr std::string_view tools_list_request =
    R"({"jsonrpc":"2.0","id":"inspect-list","method":"tools/list","params":{}})"
    "\n";
constexpr std::string_view initialize_id_json = R"("inspect-init")";
constexpr std::string_view tools_list_id_json = R"("inspect-list")";

struct InspectLimits final {
    protocol::InventoryLimits inventory{};
    unsigned timeout_seconds{5U};
    unsigned shutdown_timeout_ms{2000U};
};

class FileDescriptor final {
public:
    FileDescriptor() = default;
    explicit FileDescriptor(int descriptor) noexcept : descriptor_{descriptor} {}
    ~FileDescriptor() { reset(); }

    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;

    FileDescriptor(FileDescriptor&& other) noexcept
        : descriptor_{std::exchange(other.descriptor_, -1)} {}
    FileDescriptor& operator=(FileDescriptor&& other) noexcept {
        if (this != &other) {
            reset();
            descriptor_ = std::exchange(other.descriptor_, -1);
        }
        return *this;
    }

    [[nodiscard]] int get() const noexcept { return descriptor_; }
    [[nodiscard]] explicit operator bool() const noexcept { return descriptor_ >= 0; }

    void reset() noexcept {
        if (descriptor_ >= 0) {
            (void)::close(descriptor_);
            descriptor_ = -1;
        }
    }

    int release() noexcept { return std::exchange(descriptor_, -1); }

private:
    int descriptor_{-1};
};

[[nodiscard]] bool write_all(int fd, std::string_view bytes) {
    while (!bytes.empty()) {
        const auto count = ::write(fd, bytes.data(), bytes.size());
        if (count > 0) {
            bytes.remove_prefix(static_cast<std::size_t>(count));
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool parse_unsigned_decimal(std::string_view text, unsigned& value) {
    if (text.empty()) {
        return false;
    }
    for (const char character : text) {
        if (character < '0' || character > '9') {
            return false;
        }
    }
    unsigned parsed = 0;
    const auto result = std::from_chars(text.data(), text.data() + text.size(), parsed);
    if (result.ec != std::errc{} || result.ptr != text.data() + text.size() || parsed == 0U) {
        return false;
    }
    value = parsed;
    return true;
}

[[nodiscard]] bool parse_size_decimal(std::string_view text, std::size_t& value) {
    if (text.empty()) {
        return false;
    }
    for (const char character : text) {
        if (character < '0' || character > '9') {
            return false;
        }
    }
    std::size_t parsed = 0;
    const auto result = std::from_chars(text.data(), text.data() + text.size(), parsed);
    if (result.ec != std::errc{} || result.ptr != text.data() + text.size() || parsed == 0U) {
        return false;
    }
    value = parsed;
    return true;
}

[[nodiscard]] std::string_view executable_basename(std::string_view executable) noexcept {
    const auto slash = executable.find_last_of('/');
    return slash == std::string_view::npos ? executable : executable.substr(slash + 1U);
}

void print_inspect_usage(std::ostream& output) {
    output << "usage: mcp-native-guard inspect "
              "[--timeout SECONDS] [--shutdown-timeout-ms N] "
              "[--max-message-bytes N] [--max-nesting-depth N] "
              "[--max-tools N] [--max-tool-name-bytes N] "
              "[--max-tool-description-bytes N] [--max-tool-schema-bytes N] "
              "[--output PATH] -- <server> [args...]\n";
}

void terminate_process_group(pid_t pgid, unsigned shutdown_timeout_ms) noexcept {
    if (pgid <= 0) {
        return;
    }
    const pid_t waited = ::waitpid(-pgid, nullptr, WNOHANG);
    if (waited > 0 || (waited < 0 && errno == ECHILD)) {
        return;
    }
    (void)::kill(-pgid, SIGTERM);
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds{shutdown_timeout_ms};
    while (std::chrono::steady_clock::now() < deadline) {
        const pid_t result = ::waitpid(-pgid, nullptr, WNOHANG);
        if (result > 0) {
            // Keep reaping members of the group until none remain.
            continue;
        }
        if (result < 0 && errno == ECHILD) {
            return;
        }
        if (result < 0 && errno != EINTR) {
            break;
        }
        (void)::poll(nullptr, 0, 10);
    }
    (void)::kill(-pgid, SIGKILL);
    while (true) {
        const pid_t result = ::waitpid(-pgid, nullptr, 0);
        if (result < 0 && errno == ECHILD) {
            return;
        }
        if (result < 0 && errno != EINTR) {
            return;
        }
    }
}

struct SpawnedChild final {
    pid_t pid{-1};
    pid_t pgid{-1};
    FileDescriptor stdin_write{};
    FileDescriptor stdout_read{};
};

[[nodiscard]] bool spawn_inspect_child(
    char* const* argv,
    SpawnedChild& child) noexcept {
    FileDescriptor child_stdin_read;
    FileDescriptor parent_stdin_write;
    FileDescriptor parent_stdout_read;
    FileDescriptor child_stdout_write;
    FileDescriptor child_stderr_null;

    std::array<int, 2> input_pipe{};
    std::array<int, 2> output_pipe{};
    if (::pipe2(input_pipe.data(), O_CLOEXEC) != 0 ||
        ::pipe2(output_pipe.data(), O_CLOEXEC) != 0) {
        return false;
    }
    child_stdin_read = FileDescriptor{input_pipe[0]};
    parent_stdin_write = FileDescriptor{input_pipe[1]};
    parent_stdout_read = FileDescriptor{output_pipe[0]};
    child_stdout_write = FileDescriptor{output_pipe[1]};
    child_stderr_null = FileDescriptor{::open("/dev/null", O_WRONLY | O_CLOEXEC)};
    if (!child_stderr_null) {
        return false;
    }

    posix_spawn_file_actions_t actions;
    if (::posix_spawn_file_actions_init(&actions) != 0) {
        return false;
    }
    posix_spawnattr_t attributes;
    if (::posix_spawnattr_init(&attributes) != 0) {
        (void)::posix_spawn_file_actions_destroy(&actions);
        return false;
    }

    sigset_t child_defaults;
    short flags = static_cast<short>(POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETPGROUP);
    const bool attributes_ready =
        ::sigemptyset(&child_defaults) == 0 && ::sigaddset(&child_defaults, SIGINT) == 0 &&
        ::sigaddset(&child_defaults, SIGTERM) == 0 && ::sigaddset(&child_defaults, SIGPIPE) == 0 &&
        ::posix_spawnattr_setsigdefault(&attributes, &child_defaults) == 0 &&
        ::posix_spawnattr_setpgroup(&attributes, 0) == 0 &&
        ::posix_spawnattr_setflags(&attributes, flags) == 0;
    if (!attributes_ready) {
        (void)::posix_spawnattr_destroy(&attributes);
        (void)::posix_spawn_file_actions_destroy(&actions);
        return false;
    }

    const bool actions_ready =
        ::posix_spawn_file_actions_adddup2(
            &actions, child_stdin_read.get(), STDIN_FILENO) == 0 &&
        ::posix_spawn_file_actions_adddup2(
            &actions, child_stdout_write.get(), STDOUT_FILENO) == 0 &&
        ::posix_spawn_file_actions_adddup2(
            &actions, child_stderr_null.get(), STDERR_FILENO) == 0 &&
        ::posix_spawn_file_actions_addclose(&actions, child_stdin_read.get()) == 0 &&
        ::posix_spawn_file_actions_addclose(&actions, parent_stdin_write.get()) == 0 &&
        ::posix_spawn_file_actions_addclose(&actions, parent_stdout_read.get()) == 0 &&
        ::posix_spawn_file_actions_addclose(&actions, child_stdout_write.get()) == 0 &&
        ::posix_spawn_file_actions_addclose(&actions, child_stderr_null.get()) == 0;
    if (!actions_ready) {
        (void)::posix_spawnattr_destroy(&attributes);
        (void)::posix_spawn_file_actions_destroy(&actions);
        return false;
    }

    pid_t pid = -1;
    const int spawn_error =
        ::posix_spawnp(&pid, argv[0], &actions, &attributes, argv, environ);
    (void)::posix_spawnattr_destroy(&attributes);
    (void)::posix_spawn_file_actions_destroy(&actions);
    if (spawn_error != 0) {
        errno = spawn_error;
        return false;
    }

    child.pid = pid;
    child.pgid = pid;
    child.stdin_write = std::move(parent_stdin_write);
    child.stdout_read = std::move(parent_stdout_read);
    return true;
}

enum class ReceiveStatus : unsigned char {
    ok,
    timeout,
    child_exited,
    oversized,
    unsolicited,
    wrong_id,
    malformed,
    unsupported_jsonrpc,
    io_error,
};

[[nodiscard]] ReceiveStatus receive_expected_response(
    int fd,
    pid_t pid,
    std::string_view expected_id_json,
    std::size_t max_message_bytes,
    std::size_t max_nesting_depth,
    std::chrono::steady_clock::time_point deadline,
    std::string& response) {
    protocol::JsonRpcEnvelopeClassifier classifier{
        protocol::RuntimeLimits{max_message_bytes, max_nesting_depth, 64U}};
    std::string pending;
    pending.reserve(4096U);

    while (std::chrono::steady_clock::now() < deadline) {
        int status = 0;
        const pid_t waited = ::waitpid(pid, &status, WNOHANG);
        if (waited == pid) {
            return ReceiveStatus::child_exited;
        }

        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                                   deadline - std::chrono::steady_clock::now())
                                   .count();
        pollfd descriptor{fd, POLLIN, 0};
        const int ready =
            ::poll(&descriptor, 1, static_cast<int>(remaining > 100 ? 100 : remaining));
        if (ready < 0 && errno == EINTR) {
            continue;
        }
        if (ready == 0) {
            continue;
        }
        if (ready < 0) {
            return ReceiveStatus::io_error;
        }

        std::array<char, 4096> buffer{};
        const auto count = ::read(fd, buffer.data(), buffer.size());
        if (count == 0) {
            return ReceiveStatus::child_exited;
        }
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            return ReceiveStatus::io_error;
        }

        pending.append(buffer.data(), static_cast<std::size_t>(count));
        if (pending.size() > max_message_bytes + 1U) {
            return ReceiveStatus::oversized;
        }

        std::size_t newline = 0;
        while ((newline = pending.find('\n')) != std::string::npos) {
            std::string line = pending.substr(0, newline);
            pending.erase(0, newline + 1U);
            if (line.size() > max_message_bytes) {
                return ReceiveStatus::oversized;
            }
            const auto envelope = classifier.classify(line);
            if (!envelope) {
                if (envelope.error == protocol::ClassificationError::unsupported_jsonrpc_version) {
                    return ReceiveStatus::unsupported_jsonrpc;
                }
                if (envelope.error == protocol::ClassificationError::message_too_large) {
                    return ReceiveStatus::oversized;
                }
                return ReceiveStatus::malformed;
            }
            if (envelope.kind != protocol::EnvelopeKind::response) {
                return ReceiveStatus::unsolicited;
            }
            if (envelope.id_json != expected_id_json) {
                return ReceiveStatus::wrong_id;
            }
            response = std::move(line);
            return ReceiveStatus::ok;
        }
    }
    return ReceiveStatus::timeout;
}

[[nodiscard]] bool write_inventory_atomic(
    std::string_view destination,
    std::string_view inventory_json) {
    if (destination.empty() || destination == "." || destination == ".." ||
        destination.back() == '/') {
        std::cerr << "FAIL invalid inventory output path\n";
        return false;
    }

    struct stat destination_stat {};
    if (::lstat(std::string{destination}.c_str(), &destination_stat) == 0) {
        if (S_ISDIR(destination_stat.st_mode) || S_ISLNK(destination_stat.st_mode)) {
            std::cerr << "FAIL inventory output path is not a regular file\n";
            return false;
        }
    } else if (errno != ENOENT) {
        std::cerr << "FAIL inventory output path unusable\n";
        return false;
    }

    std::string directory;
    const auto slash = destination.find_last_of('/');
    if (slash == std::string_view::npos) {
        directory = ".";
    } else if (slash == 0U) {
        directory = "/";
    } else {
        directory.assign(destination.data(), slash);
    }

    struct stat directory_stat {};
    if (::stat(directory.c_str(), &directory_stat) != 0 || !S_ISDIR(directory_stat.st_mode)) {
        std::cerr << "FAIL inventory output directory unusable\n";
        return false;
    }

    std::string pattern = directory;
    if (pattern.back() != '/') {
        pattern.push_back('/');
    }
    pattern.append(".mng-inspect-XXXXXX");
    std::vector<char> template_path{pattern.begin(), pattern.end()};
    template_path.push_back('\0');
    const int fd = ::mkstemp(template_path.data());
    if (fd < 0) {
        std::cerr << "FAIL inventory temporary file create\n";
        return false;
    }
    const std::string temporary{template_path.data()};
    (void)::fchmod(fd, S_IRUSR | S_IWUSR);

    const auto fail_temp = [&](std::string_view stage) {
        std::cerr << "FAIL " << stage << '\n';
        (void)::close(fd);
        (void)::unlink(temporary.c_str());
        return false;
    };

    std::string payload;
    payload.reserve(inventory_json.size() + 1U);
    payload.assign(inventory_json);
    payload.push_back('\n');
    std::string_view remaining{payload};
    while (!remaining.empty()) {
        const auto count = ::write(fd, remaining.data(), remaining.size());
        if (count > 0) {
            remaining.remove_prefix(static_cast<std::size_t>(count));
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            return fail_temp("inventory temporary file write");
        }
    }
    if (::fsync(fd) != 0) {
        return fail_temp("inventory temporary file sync");
    }
    if (::close(fd) != 0) {
        (void)::unlink(temporary.c_str());
        std::cerr << "FAIL inventory temporary file close\n";
        return false;
    }
    if (::rename(temporary.c_str(), std::string{destination}.c_str()) != 0) {
        (void)::unlink(temporary.c_str());
        std::cerr << "FAIL inventory output rename\n";
        return false;
    }
    return true;
}

[[nodiscard]] bool wait_for_clean_shutdown(
    pid_t pid,
    pid_t pgid,
    unsigned shutdown_timeout_ms) noexcept {
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds{shutdown_timeout_ms};
    while (std::chrono::steady_clock::now() < deadline) {
        int status = 0;
        const pid_t waited = ::waitpid(pid, &status, WNOHANG);
        if (waited == pid) {
            return WIFEXITED(status);
        }
        if (waited < 0 && errno == ECHILD) {
            return true;
        }
        (void)::poll(nullptr, 0, 10);
    }
    terminate_process_group(pgid, shutdown_timeout_ms);
    return false;
}

} // namespace

int run_inspect(int argc, char** argv) noexcept {
    InspectLimits limits;
    std::string_view output_path;
    bool saw_timeout = false;
    bool saw_shutdown = false;
    bool saw_max_message = false;
    bool saw_max_nesting = false;
    bool saw_max_tools = false;
    bool saw_max_name = false;
    bool saw_max_description = false;
    bool saw_max_schema = false;
    bool saw_output = false;
    int separator = -1;

    for (int index = 2; index < argc; ++index) {
        const std::string_view argument{argv[index]};
        if (argument == "--") {
            separator = index;
            break;
        }
        if (argument == "--policy" || argument == "--deny-tool" || argument == "--server-label" ||
            argument == "--audit-file" || argument == "--audit-stderr") {
            std::cerr << "inspect does not accept policy or audit options\n";
            print_inspect_usage(std::cerr);
            return 2;
        }
        auto require_value = [&](bool& seen, auto parser, auto& destination) -> bool {
            if (seen || index + 1 >= argc) {
                return false;
            }
            const std::string_view value{argv[index + 1]};
            if (value == "--" || !parser(value, destination)) {
                return false;
            }
            seen = true;
            ++index;
            return true;
        };

        if (argument == "--timeout") {
            if (!require_value(saw_timeout, parse_unsigned_decimal, limits.timeout_seconds) ||
                limits.timeout_seconds > 300U) {
                std::cerr << "invalid --timeout\n";
                print_inspect_usage(std::cerr);
                return 2;
            }
        } else if (argument == "--shutdown-timeout-ms") {
            if (!require_value(
                    saw_shutdown, parse_unsigned_decimal, limits.shutdown_timeout_ms)) {
                std::cerr << "invalid --shutdown-timeout-ms\n";
                print_inspect_usage(std::cerr);
                return 2;
            }
        } else if (argument == "--max-message-bytes") {
            if (!require_value(
                    saw_max_message, parse_size_decimal, limits.inventory.max_message_bytes)) {
                std::cerr << "invalid --max-message-bytes\n";
                print_inspect_usage(std::cerr);
                return 2;
            }
        } else if (argument == "--max-nesting-depth") {
            if (!require_value(
                    saw_max_nesting, parse_size_decimal, limits.inventory.max_nesting_depth)) {
                std::cerr << "invalid --max-nesting-depth\n";
                print_inspect_usage(std::cerr);
                return 2;
            }
        } else if (argument == "--max-tools") {
            if (!require_value(saw_max_tools, parse_size_decimal, limits.inventory.max_tools)) {
                std::cerr << "invalid --max-tools\n";
                print_inspect_usage(std::cerr);
                return 2;
            }
        } else if (argument == "--max-tool-name-bytes") {
            if (!require_value(
                    saw_max_name, parse_size_decimal, limits.inventory.max_tool_name_bytes)) {
                std::cerr << "invalid --max-tool-name-bytes\n";
                print_inspect_usage(std::cerr);
                return 2;
            }
        } else if (argument == "--max-tool-description-bytes") {
            if (!require_value(
                    saw_max_description,
                    parse_size_decimal,
                    limits.inventory.max_tool_description_bytes)) {
                std::cerr << "invalid --max-tool-description-bytes\n";
                print_inspect_usage(std::cerr);
                return 2;
            }
        } else if (argument == "--max-tool-schema-bytes") {
            if (!require_value(
                    saw_max_schema, parse_size_decimal, limits.inventory.max_tool_schema_bytes)) {
                std::cerr << "invalid --max-tool-schema-bytes\n";
                print_inspect_usage(std::cerr);
                return 2;
            }
        } else if (argument == "--output") {
            if (saw_output || index + 1 >= argc || std::string_view{argv[index + 1]} == "--") {
                std::cerr << "invalid --output\n";
                print_inspect_usage(std::cerr);
                return 2;
            }
            saw_output = true;
            output_path = argv[++index];
            if (output_path.empty()) {
                std::cerr << "invalid --output\n";
                print_inspect_usage(std::cerr);
                return 2;
            }
        } else {
            std::cerr << "unknown inspect option: " << argument << '\n';
            print_inspect_usage(std::cerr);
            return 2;
        }
    }

    if (separator < 0 || separator + 1 >= argc) {
        std::cerr << "missing server command after --\n";
        print_inspect_usage(std::cerr);
        return 2;
    }

    std::vector<char*> command;
    command.reserve(static_cast<std::size_t>(argc - separator));
    for (int index = separator + 1; index < argc; ++index) {
        command.push_back(argv[index]);
    }
    command.push_back(nullptr);

    const std::string_view downstream = executable_basename(command.front());
    SpawnedChild child;
    if (!spawn_inspect_child(command.data(), child)) {
        std::cerr << "FAIL downstream process start\n";
        std::cerr << "inspect result: failure\n";
        return 4;
    }

    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds{limits.timeout_seconds};

    const auto fail = [&](std::string_view stage) {
        std::cerr << "FAIL " << stage << '\n';
        std::cerr << "inspect result: failure\n";
        child.stdin_write.reset();
        child.stdout_read.reset();
        terminate_process_group(child.pgid, limits.shutdown_timeout_ms);
        return 1;
    };

    if (!write_all(child.stdin_write.get(), initialize_request)) {
        return fail("initialize write");
    }

    std::string response;
    const ReceiveStatus init_status = receive_expected_response(
        child.stdout_read.get(),
        child.pid,
        initialize_id_json,
        limits.inventory.max_message_bytes,
        limits.inventory.max_nesting_depth,
        deadline,
        response);
    if (init_status == ReceiveStatus::timeout) {
        return fail("initialize timeout");
    }
    if (init_status == ReceiveStatus::child_exited) {
        return fail("child exited early");
    }
    if (init_status == ReceiveStatus::oversized) {
        return fail("oversized message");
    }
    if (init_status == ReceiveStatus::unsolicited) {
        return fail("unsolicited message");
    }
    if (init_status == ReceiveStatus::wrong_id) {
        return fail("wrong_response_id");
    }
    if (init_status == ReceiveStatus::malformed) {
        return fail("malformed_json");
    }
    if (init_status == ReceiveStatus::unsupported_jsonrpc) {
        return fail("unsupported_jsonrpc_version");
    }
    if (init_status != ReceiveStatus::ok) {
        return fail("initialize receive");
    }

    const auto init_error =
        protocol::validate_initialize_response(response, initialize_id_json, limits.inventory);
    if (init_error != protocol::InventoryError::none) {
        return fail(protocol::inventory_error_name(init_error));
    }

    if (!write_all(child.stdin_write.get(), initialized_notification) ||
        !write_all(child.stdin_write.get(), tools_list_request)) {
        return fail("tools/list write");
    }

    const ReceiveStatus list_status = receive_expected_response(
        child.stdout_read.get(),
        child.pid,
        tools_list_id_json,
        limits.inventory.max_message_bytes,
        limits.inventory.max_nesting_depth,
        deadline,
        response);
    if (list_status == ReceiveStatus::timeout) {
        return fail("tools/list timeout");
    }
    if (list_status == ReceiveStatus::child_exited) {
        return fail("child exited early");
    }
    if (list_status == ReceiveStatus::oversized) {
        return fail("oversized message");
    }
    if (list_status == ReceiveStatus::unsolicited) {
        return fail("unsolicited message");
    }
    if (list_status == ReceiveStatus::wrong_id) {
        return fail("wrong_response_id");
    }
    if (list_status == ReceiveStatus::malformed) {
        return fail("malformed_json");
    }
    if (list_status == ReceiveStatus::unsupported_jsonrpc) {
        return fail("unsupported_jsonrpc_version");
    }
    if (list_status != ReceiveStatus::ok) {
        return fail("tools/list receive");
    }

    const auto parsed = protocol::parse_tools_list_response(
        response, tools_list_id_json, downstream, limits.inventory);
    if (!parsed) {
        return fail(protocol::inventory_error_name(parsed.error));
    }

    std::string inventory_json;
    if (!protocol::emit_inventory_json(
            parsed.inventory, inventory_json, limits.inventory.max_message_bytes)) {
        return fail("inventory emit");
    }

    child.stdin_write.reset();
    const bool clean_shutdown =
        wait_for_clean_shutdown(child.pid, child.pgid, limits.shutdown_timeout_ms);
    child.stdout_read.reset();

    if (output_path.empty()) {
        std::cout << inventory_json << '\n';
        if (!std::cout) {
            std::cerr << "FAIL inventory stdout write\n";
            std::cerr << "inspect result: failure\n";
            return 1;
        }
    } else if (!write_inventory_atomic(output_path, inventory_json)) {
        std::cerr << "inspect result: failure\n";
        return 1;
    }

    std::cerr << "inspect result: success\n";
    std::cerr << "shutdown: " << (clean_shutdown ? "clean" : "forced") << '\n';
    return 0;
}

} // namespace mng::process
