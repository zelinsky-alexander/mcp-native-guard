#include "mcp_native_guard/process/linux_stdio_relay.hpp"

#include "mcp_native_guard/io/line_framer.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <climits>
#include <csignal>
#include <cstddef>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <poll.h>
#include <spawn.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

extern char** environ;

namespace mng::process {
namespace {

constexpr int poll_timeout_milliseconds = 50;
constexpr auto termination_grace_period = std::chrono::seconds{1};
constexpr std::size_t read_chunk_bytes = 64U * 1024U;

volatile std::sig_atomic_t termination_signal = 0;

extern "C" void record_termination(int signal_number) {
    termination_signal = signal_number;
}

class FileDescriptor final {
public:
    FileDescriptor() = default;
    explicit FileDescriptor(int descriptor) noexcept : descriptor_{descriptor} {}
    ~FileDescriptor() { reset(); }

    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;

    FileDescriptor(FileDescriptor&& other) noexcept : descriptor_{std::exchange(other.descriptor_, -1)} {}
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

private:
    int descriptor_{-1};
};

class SignalScope final {
public:
    SignalScope() noexcept {
        struct sigaction termination_action {};
        termination_action.sa_handler = record_termination;
        (void)::sigemptyset(&termination_action.sa_mask);
        termination_action.sa_flags = 0;
        int_installed_ = ::sigaction(SIGINT, &termination_action, &previous_int_) == 0;
        term_installed_ = ::sigaction(SIGTERM, &termination_action, &previous_term_) == 0;

        struct sigaction pipe_action {};
        pipe_action.sa_handler = SIG_IGN;
        (void)::sigemptyset(&pipe_action.sa_mask);
        pipe_action.sa_flags = 0;
        pipe_installed_ = ::sigaction(SIGPIPE, &pipe_action, &previous_pipe_) == 0;
        valid_ = int_installed_ && term_installed_ && pipe_installed_;
    }

    ~SignalScope() {
        if (int_installed_) {
            (void)::sigaction(SIGINT, &previous_int_, nullptr);
        }
        if (term_installed_) {
            (void)::sigaction(SIGTERM, &previous_term_, nullptr);
        }
        if (pipe_installed_) {
            (void)::sigaction(SIGPIPE, &previous_pipe_, nullptr);
        }
    }

    [[nodiscard]] bool valid() const noexcept { return valid_; }

private:
    struct sigaction previous_int_ {};
    struct sigaction previous_term_ {};
    struct sigaction previous_pipe_ {};
    bool int_installed_{false};
    bool term_installed_{false};
    bool pipe_installed_{false};
    bool valid_{false};
};

class HandlerConnectionScope final {
public:
    explicit HandlerConnectionScope(ClientMessageHandler* handler) noexcept : handler_{handler} {}
    ~HandlerConnectionScope() {
        if (handler_ != nullptr) {
            handler_->connection_closed();
        }
    }

private:
    ClientMessageHandler* handler_;
};

[[nodiscard]] bool set_close_on_exec(int descriptor) noexcept {
    const int flags = ::fcntl(descriptor, F_GETFD);
    return flags >= 0 && ::fcntl(descriptor, F_SETFD, flags | FD_CLOEXEC) == 0;
}

[[nodiscard]] bool set_nonblocking(int descriptor) noexcept {
    const int flags = ::fcntl(descriptor, F_GETFL);
    return flags >= 0 && ::fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0;
}

[[nodiscard]] bool set_pipe_capacity(int descriptor, std::size_t requested) noexcept {
    if (requested == 0U || requested > static_cast<std::size_t>(INT_MAX)) {
        errno = EINVAL;
        return false;
    }
    const int configured = ::fcntl(descriptor, F_SETPIPE_SZ, static_cast<int>(requested));
    return configured > 0 && configured <= static_cast<int>(requested);
}

[[nodiscard]] bool create_pipe(FileDescriptor& read_end, FileDescriptor& write_end, std::size_t capacity) noexcept {
    std::array<int, 2> descriptors{};
    if (::pipe(descriptors.data()) != 0) {
        return false;
    }
    read_end = FileDescriptor{descriptors[0]};
    write_end = FileDescriptor{descriptors[1]};
    return set_close_on_exec(read_end.get()) && set_close_on_exec(write_end.get()) &&
           set_pipe_capacity(read_end.get(), capacity);
}

struct ChildProcess final {
    pid_t pid{-1};
    FileDescriptor stdin_write;
    FileDescriptor stdout_read;
};

class ChildReaper final {
public:
    explicit ChildReaper(pid_t pid) noexcept : pid_{pid} {}
    ~ChildReaper() {
        if (reaped_ || pid_ <= 0) {
            return;
        }
        (void)::kill(pid_, SIGKILL);
        while (::waitpid(pid_, nullptr, 0) < 0 && errno == EINTR) {
        }
    }

    void mark_reaped() noexcept { reaped_ = true; }

private:
    pid_t pid_;
    bool reaped_{false};
};

[[nodiscard]] bool spawn_child(
    std::span<char* const> command,
    std::size_t pipe_capacity,
    ChildProcess& child) noexcept {
    FileDescriptor child_stdin_read;
    FileDescriptor parent_stdin_write;
    FileDescriptor parent_stdout_read;
    FileDescriptor child_stdout_write;
    if (!create_pipe(child_stdin_read, parent_stdin_write, pipe_capacity) ||
        !create_pipe(parent_stdout_read, child_stdout_write, pipe_capacity)) {
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
    const bool attributes_ready =
        ::sigemptyset(&child_defaults) == 0 && ::sigaddset(&child_defaults, SIGINT) == 0 &&
        ::sigaddset(&child_defaults, SIGTERM) == 0 && ::sigaddset(&child_defaults, SIGPIPE) == 0 &&
        ::posix_spawnattr_setsigdefault(&attributes, &child_defaults) == 0 &&
        ::posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETSIGDEF) == 0;
    if (!attributes_ready) {
        (void)::posix_spawnattr_destroy(&attributes);
        (void)::posix_spawn_file_actions_destroy(&actions);
        errno = EINVAL;
        return false;
    }

    const bool actions_ready =
        ::posix_spawn_file_actions_adddup2(&actions, child_stdin_read.get(), STDIN_FILENO) == 0 &&
        ::posix_spawn_file_actions_adddup2(&actions, child_stdout_write.get(), STDOUT_FILENO) == 0 &&
        ::posix_spawn_file_actions_addclose(&actions, child_stdin_read.get()) == 0 &&
        ::posix_spawn_file_actions_addclose(&actions, parent_stdin_write.get()) == 0 &&
        ::posix_spawn_file_actions_addclose(&actions, parent_stdout_read.get()) == 0 &&
        ::posix_spawn_file_actions_addclose(&actions, child_stdout_write.get()) == 0;
    if (!actions_ready) {
        (void)::posix_spawnattr_destroy(&attributes);
        (void)::posix_spawn_file_actions_destroy(&actions);
        errno = EINVAL;
        return false;
    }

    pid_t pid = -1;
    const int spawn_error = ::posix_spawnp(
        &pid,
        command.front(),
        &actions,
        &attributes,
        command.data(),
        environ);
    (void)::posix_spawnattr_destroy(&attributes);
    (void)::posix_spawn_file_actions_destroy(&actions);
    if (spawn_error != 0) {
        errno = spawn_error;
        return false;
    }

    child = {pid, std::move(parent_stdin_write), std::move(parent_stdout_read)};
    return true;
}

enum class WriteStatus : unsigned char { data, retry, broken_pipe, error };

[[nodiscard]] WriteStatus flush_to(
    int destination,
    std::vector<char>& buffer,
    std::size_t& begin) noexcept {
    if (begin == buffer.size()) {
        buffer.clear();
        begin = 0;
        return WriteStatus::data;
    }
    const auto result = ::write(destination, buffer.data() + begin, buffer.size() - begin);
    if (result > 0) {
        begin += static_cast<std::size_t>(result);
        if (begin == buffer.size()) {
            buffer.clear();
            begin = 0;
        }
        return WriteStatus::data;
    }
    if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
        return WriteStatus::retry;
    }
    if (result < 0 && errno == EPIPE) {
        return WriteStatus::broken_pipe;
    }
    return WriteStatus::error;
}

[[nodiscard]] bool append_bytes(std::vector<char>& output, std::string_view value) {
    if (value.size() > output.capacity() - output.size()) {
        return false;
    }
    output.insert(output.end(), value.begin(), value.end());
    return true;
}

[[nodiscard]] bool append_message(std::vector<char>& output, std::string_view message) {
    return append_bytes(output, message) && append_bytes(output, "\n");
}

[[nodiscard]] bool append_json_rpc_error(
    std::vector<char>& output,
    const ClientMessageDecision& decision) {
    std::array<char, 16> code_buffer{};
    const auto code = std::to_chars(
        code_buffer.data(), code_buffer.data() + code_buffer.size(), decision.error_code);
    if (code.ec != std::errc{}) {
        return false;
    }

    return append_bytes(output, R"({"jsonrpc":"2.0","id":)") &&
           append_bytes(output, decision.id_json) &&
           append_bytes(output, R"(,"error":{"code":)") &&
           append_bytes(
               output,
               std::string_view{code_buffer.data(), static_cast<std::size_t>(code.ptr - code_buffer.data())}) &&
           append_bytes(output, R"(,"message":")") &&
           append_bytes(output, decision.error_message) && append_bytes(output, "\"}}\n");
}

[[nodiscard]] int exit_code_from_status(int status) noexcept {
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);
    }
    return 1;
}

} // namespace

int run_stdio_child(
    std::span<char* const> command,
    ClientMessageHandler* client_message_handler,
    RunConfig config) noexcept {
    constexpr std::size_t response_expansion_bytes = 4U * read_chunk_bytes + 512U;
    if (command.empty() || command.front() == nullptr || config.relay_buffer_bytes == 0U ||
        config.max_message_bytes == 0U ||
        config.max_message_bytes > static_cast<std::size_t>(-1) - response_expansion_bytes) {
        std::cerr << "invalid run configuration\n";
        return 2;
    }

    termination_signal = 0;
    HandlerConnectionScope handler_scope{client_message_handler};
    SignalScope signals;
    if (!signals.valid()) {
        std::cerr << "failed to install signal handlers\n";
        return 4;
    }

    ChildProcess child;
    if (!spawn_child(command, config.pipe_capacity_bytes, child)) {
        std::cerr << "failed to launch downstream process: " << std::strerror(errno) << '\n';
        return 4;
    }
    ChildReaper reaper{child.pid};
    if (!set_nonblocking(STDIN_FILENO) || !set_nonblocking(STDOUT_FILENO) ||
        !set_nonblocking(child.stdin_write.get()) || !set_nonblocking(child.stdout_read.get())) {
        std::cerr << "failed to configure nonblocking relay: " << std::strerror(errno) << '\n';
        return 4;
    }

    std::vector<char> to_child;
    std::vector<char> to_client;
    try {
        const std::size_t client_queue_bytes = config.max_message_bytes + read_chunk_bytes + 1U;
        const std::size_t server_queue_bytes = config.max_message_bytes + response_expansion_bytes;
        to_child.reserve(std::max(config.relay_buffer_bytes, client_queue_bytes));
        to_client.reserve(std::max(config.relay_buffer_bytes, server_queue_bytes));
    } catch (...) {
        std::cerr << "failed to allocate relay buffers\n";
        return 4;
    }
    std::size_t child_begin = 0;
    std::size_t client_begin = 0;
    io::LineFramer client_framer{{config.max_message_bytes, 4096U, false}};
    io::LineFramer server_framer{{config.max_message_bytes, 4096U, false}};
    bool input_eof = false;
    bool output_eof = false;
    bool child_reaped = false;
    int child_status = 1;
    bool sent_termination = false;
    bool sent_kill = false;
    std::chrono::steady_clock::time_point termination_started{};

    while (!child_reaped || child.stdout_read || !to_client.empty()) {
        if (!child_reaped) {
            const pid_t wait_result = ::waitpid(child.pid, &child_status, WNOHANG);
            if (wait_result == child.pid) {
                child_reaped = true;
                reaper.mark_reaped();
                child.stdin_write.reset();
                to_child.clear();
                child_begin = 0;
            } else if (wait_result < 0 && errno != EINTR) {
                std::cerr << "failed to observe downstream process: " << std::strerror(errno) << '\n';
                return 4;
            }
        }

        if (termination_signal != 0 && !sent_termination && !child_reaped) {
            (void)::kill(child.pid, SIGTERM);
            child.stdin_write.reset();
            to_child.clear();
            child_begin = 0;
            sent_termination = true;
            termination_started = std::chrono::steady_clock::now();
        }
        if (sent_termination && !sent_kill && !child_reaped &&
            std::chrono::steady_clock::now() - termination_started >= termination_grace_period) {
            (void)::kill(child.pid, SIGKILL);
            sent_kill = true;
        }

        if (input_eof && to_child.empty()) {
            child.stdin_write.reset();
        }
        if (output_eof && to_client.empty() && child_reaped) {
            break;
        }

        std::array<pollfd, 4> poll_descriptors{};
        nfds_t descriptor_count = 0;
        if (!input_eof && child.stdin_write && to_child.empty() && to_client.empty()) {
            poll_descriptors[descriptor_count++] = {STDIN_FILENO, POLLIN, 0};
        }
        if (child.stdout_read && to_client.empty()) {
            poll_descriptors[descriptor_count++] = {child.stdout_read.get(), POLLIN, 0};
        }
        if (child.stdin_write && !to_child.empty()) {
            poll_descriptors[descriptor_count++] = {child.stdin_write.get(), POLLOUT, 0};
        }
        if (!to_client.empty()) {
            poll_descriptors[descriptor_count++] = {STDOUT_FILENO, POLLOUT, 0};
        }

        const int poll_result = ::poll(poll_descriptors.data(), descriptor_count, poll_timeout_milliseconds);
        if (poll_result < 0) {
            if (errno == EINTR) {
                continue;
            }
            std::cerr << "relay poll failed: " << std::strerror(errno) << '\n';
            return 4;
        }
        if (poll_result == 0) {
            continue;
        }

        for (nfds_t index = 0; index < descriptor_count; ++index) {
            const auto descriptor = poll_descriptors[index];
            if (descriptor.revents == 0) {
                continue;
            }
            if (descriptor.fd == STDIN_FILENO && (descriptor.revents & (POLLIN | POLLHUP)) != 0) {
                std::array<char, read_chunk_bytes> input{};
                const auto read_result = ::read(STDIN_FILENO, input.data(), input.size());
                if (read_result > 0) {
                    bool queue_overflow = false;
                    const auto frame_status = client_framer.feed(
                        std::span<const char>{input.data(), static_cast<std::size_t>(read_result)},
                        [&](std::string_view message) {
                            const ClientMessageDecision decision = client_message_handler == nullptr
                                ? ClientMessageDecision{}
                                : client_message_handler->inspect(message);
                            if (decision.action == ClientMessageAction::forward) {
                                queue_overflow = !append_message(to_child, message) || queue_overflow;
                            } else if (decision.action == ClientMessageAction::respond_with_error) {
                                queue_overflow = !append_json_rpc_error(to_client, decision) || queue_overflow;
                            }
                        });
                    if (!frame_status) {
                        std::cerr << "client framing error: " << frame_status.message << '\n';
                        return 3;
                    }
                    if (queue_overflow) {
                        std::cerr << "bounded relay queue exceeded\n";
                        return 4;
                    }
                } else if (read_result == 0) {
                    const auto finish_status = client_framer.finish();
                    if (!finish_status) {
                        std::cerr << "client framing error: " << finish_status.message << '\n';
                        return 3;
                    }
                    input_eof = true;
                } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                    std::cerr << "stdin read failed: " << std::strerror(errno) << '\n';
                    return 4;
                }
            } else if (child.stdout_read && descriptor.fd == child.stdout_read.get() &&
                       (descriptor.revents & (POLLIN | POLLHUP)) != 0) {
                std::array<char, read_chunk_bytes> output{};
                const auto read_result = ::read(child.stdout_read.get(), output.data(), output.size());
                if (read_result > 0) {
                    bool queue_overflow = false;
                    const auto frame_status = server_framer.feed(
                        std::span<const char>{output.data(), static_cast<std::size_t>(read_result)},
                        [&](std::string_view message) {
                            const ServerMessageDecision decision = client_message_handler == nullptr
                                ? ServerMessageDecision{}
                                : client_message_handler->inspect_server(message);
                            if (decision.action == ServerMessageAction::forward) {
                                queue_overflow = !append_message(to_client, message) || queue_overflow;
                            } else if (decision.action == ServerMessageAction::replace) {
                                queue_overflow =
                                    !append_message(to_client, decision.replacement) || queue_overflow;
                            }
                        });
                    if (!frame_status) {
                        std::cerr << "server framing error: " << frame_status.message << '\n';
                        return 3;
                    }
                    if (queue_overflow) {
                        std::cerr << "bounded relay queue exceeded\n";
                        return 4;
                    }
                } else if (read_result == 0) {
                    const auto finish_status = server_framer.finish();
                    if (!finish_status) {
                        std::cerr << "server framing error: " << finish_status.message << '\n';
                        return 3;
                    }
                    child.stdout_read.reset();
                    output_eof = true;
                } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                    std::cerr << "downstream stdout read failed: " << std::strerror(errno) << '\n';
                    return 4;
                }
            } else if (child.stdin_write && descriptor.fd == child.stdin_write.get() &&
                       (descriptor.revents & (POLLOUT | POLLERR | POLLHUP)) != 0) {
                const auto write_status = flush_to(child.stdin_write.get(), to_child, child_begin);
                if (write_status == WriteStatus::broken_pipe) {
                    child.stdin_write.reset();
                    input_eof = true;
                    to_child.clear();
                    child_begin = 0;
                } else if (write_status == WriteStatus::error) {
                    std::cerr << "downstream stdin write failed: " << std::strerror(errno) << '\n';
                    return 4;
                }
            } else if (descriptor.fd == STDOUT_FILENO &&
                       (descriptor.revents & (POLLOUT | POLLERR | POLLHUP)) != 0) {
                const auto write_status = flush_to(STDOUT_FILENO, to_client, client_begin);
                if (write_status == WriteStatus::broken_pipe || write_status == WriteStatus::error) {
                    std::cerr << "stdout write failed: " << std::strerror(errno) << '\n';
                    if (!child_reaped) {
                        (void)::kill(child.pid, SIGTERM);
                    }
                    return 4;
                }
            }
        }
    }

    if (!child_reaped) {
        while (::waitpid(child.pid, &child_status, 0) < 0) {
            if (errno != EINTR) {
                std::cerr << "failed to wait for downstream process: " << std::strerror(errno) << '\n';
                return 4;
            }
        }
        reaper.mark_reaped();
    }
    return termination_signal != 0 ? 128 + termination_signal : exit_code_from_status(child_status);
}

} // namespace mng::process
