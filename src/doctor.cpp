#include "mcp_native_guard/process/doctor.hpp"

#include "mcp_native_guard/protocol/json_rpc_envelope.hpp"

#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <poll.h>
#include <string>
#include <string_view>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace mng::process {
namespace {
constexpr std::size_t max_doctor_message_bytes = 1024U * 1024U;

bool write_all(int fd, std::string_view bytes) {
    while (!bytes.empty()) {
        const auto count = ::write(fd, bytes.data(), bytes.size());
        if (count > 0) bytes.remove_prefix(static_cast<std::size_t>(count));
        else if (count < 0 && errno == EINTR) continue;
        else return false;
    }
    return true;
}

void close_fd(int& fd) { if (fd >= 0) { (void)::close(fd); fd = -1; } }

void terminate_and_reap(pid_t pid) noexcept {
    if (pid <= 0) return;
    const pid_t initial = ::waitpid(pid, nullptr, WNOHANG);
    if (initial == pid || (initial < 0 && errno == ECHILD)) return;
    (void)::kill(pid, SIGTERM);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{2};
    while (std::chrono::steady_clock::now() < deadline) {
        const pid_t result = ::waitpid(pid, nullptr, WNOHANG);
        if (result == pid || (result < 0 && errno == ECHILD)) return;
        if (result < 0 && errno != EINTR) break;
        (void)::poll(nullptr, 0, 10);
    }
    (void)::kill(pid, SIGKILL);
    while (::waitpid(pid, nullptr, 0) < 0 && errno == EINTR) {}
}

bool receive_response(
    int fd, pid_t pid, std::string_view expected_id,
    std::chrono::steady_clock::time_point deadline, std::string& response) {
    protocol::JsonRpcEnvelopeClassifier classifier;
    std::string pending;
    pending.reserve(4096U);
    while (std::chrono::steady_clock::now() < deadline) {
        int status = 0;
        if (::waitpid(pid, &status, WNOHANG) == pid) return false;
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now()).count();
        pollfd descriptor{fd, POLLIN, 0};
        const int ready = ::poll(&descriptor, 1, static_cast<int>(remaining > 100 ? 100 : remaining));
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0) continue;
        std::array<char, 4096> buffer{};
        const auto count = ::read(fd, buffer.data(), buffer.size());
        if (count <= 0) return false;
        pending.append(buffer.data(), static_cast<std::size_t>(count));
        if (pending.size() > max_doctor_message_bytes) return false;
        std::size_t newline = 0;
        while ((newline = pending.find('\n')) != std::string::npos) {
            std::string line = pending.substr(0, newline);
            pending.erase(0, newline + 1U);
            const auto envelope = classifier.classify(line);
            if (envelope && envelope.kind == protocol::EnvelopeKind::response &&
                envelope.id_json == expected_id) {
                response = std::move(line);
                return true;
            }
        }
    }
    return false;
}
} // namespace

int run_doctor(int argc, char** argv) noexcept {
    unsigned timeout_seconds = 5U;
    std::vector<std::string_view> denied_tools;
    std::vector<char*> run_arguments;
    run_arguments.reserve(static_cast<std::size_t>(argc) + 1U);
    run_arguments.push_back(argv[0]);
    run_arguments.push_back(const_cast<char*>("run"));
    bool separator = false;
    for (int index = 2; index < argc; ++index) {
        const std::string_view arg{argv[index]};
        if (!separator && arg == "--doctor-timeout") {
            if (index + 1 >= argc) { std::cerr << "FAIL CLI arguments\n"; return 2; }
            const std::string_view value{argv[++index]};
            const auto parsed = std::from_chars(value.data(), value.data() + value.size(), timeout_seconds);
            if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() ||
                timeout_seconds == 0U || timeout_seconds > 300U) {
                std::cerr << "FAIL CLI arguments\n"; return 2;
            }
            continue;
        }
        if (!separator && arg == "--deny-tool" && index + 1 < argc) {
            denied_tools.emplace_back(argv[index + 1]);
        }
        if (arg == "--") separator = true;
        run_arguments.push_back(argv[index]);
    }
    if (!separator || run_arguments.back() == nullptr || std::string_view{run_arguments.back()} == "--") {
        std::cerr << "FAIL CLI arguments\n"; return 2;
    }
    run_arguments.push_back(nullptr);

    std::array<int, 2> input{}, output{}, error{};
    if (::pipe2(input.data(), O_CLOEXEC) != 0 || ::pipe2(output.data(), O_CLOEXEC) != 0 ||
        ::pipe2(error.data(), O_CLOEXEC) != 0) {
        std::cerr << "FAIL local pipe setup\n"; return 4;
    }
    const pid_t pid = ::fork();
    if (pid == 0) {
        (void)::dup2(input[0], STDIN_FILENO);
        (void)::dup2(output[1], STDOUT_FILENO);
        (void)::dup2(error[1], STDERR_FILENO);
        ::execv(argv[0], run_arguments.data());
        _exit(127);
    }
    close_fd(input[0]); close_fd(output[1]); close_fd(error[1]);
    if (pid < 0) { std::cerr << "FAIL downstream process start\n"; return 4; }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{timeout_seconds};
    const auto fail = [&](std::string_view stage) {
        std::cout << "FAIL " << stage << '\n' << "doctor result: unhealthy\n";
        close_fd(input[1]); terminate_and_reap(pid);
        close_fd(output[0]); close_fd(error[0]);
        return 1;
    };
    // A successful launch also proves CLI, policy, effective-table, fingerprint, and audit setup.
    std::string response;
    const std::string initialize = R"({"jsonrpc":"2.0","id":"doctor-init","method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"mcp-native-guard-doctor","version":"0.1.0"}}})" "\n";
    if (!write_all(input[1], initialize) ||
        !receive_response(output[0], pid, R"("doctor-init")", deadline, response) ||
        response.find(R"("result":)") == std::string::npos) {
        return fail("initialize");
    }
    std::cout << "PASS CLI arguments\nPASS policy loaded and effective table built\n"
                 "PASS effective policy fingerprint computed\nPASS audit destination writable\n"
                 "PASS downstream process started\nPASS initialize\n";
    if (!write_all(input[1], R"({"jsonrpc":"2.0","method":"notifications/initialized","params":{}})" "\n") ||
        !write_all(input[1], R"({"jsonrpc":"2.0","id":"doctor-list","method":"tools/list","params":{}})" "\n")) {
        return fail("notifications/initialized");
    }
    std::cout << "PASS notifications/initialized\n";
    if (!receive_response(output[0], pid, R"("doctor-list")", deadline, response) ||
        response.find(R"("tools":[)") == std::string::npos) {
        return fail("tools/list");
    }
    for (const std::string_view denied : denied_tools) {
        std::string needle = R"("name":")";
        for (const char character : denied) {
            if (character == '"' || character == '\\') needle.push_back('\\');
            needle.push_back(character);
        }
        needle.push_back('"');
        if (response.find(needle) != std::string::npos) return fail("denied tools hidden");
    }
    std::cout << "PASS tools/list\nPASS tools/list returned tools array\nPASS denied tools hidden by guard policy\n";
    close_fd(input[1]);
    int status = 0;
    while (std::chrono::steady_clock::now() < deadline) {
        if (::waitpid(pid, &status, WNOHANG) == pid) {
            close_fd(output[0]); close_fd(error[0]);
            if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                std::cout << "PASS clean shutdown\ndoctor result: healthy\n"; return 0;
            }
            return fail("clean shutdown");
        }
        (void)::poll(nullptr, 0, 10);
    }
    return fail("clean shutdown");
}
} // namespace mng::process
