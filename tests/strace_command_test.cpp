#include "mcp_native_guard/process/strace_command.hpp"

#include <iostream>
#include <string_view>

namespace {

bool check(bool result, const char* message) {
    if (!result) {
        std::cerr << "strace command test failure: " << message << '\n';
    }
    return result;
}

} // namespace

int main() {
    using mng::process::make_strace_command;
    using mng::process::valid_strace_output_path;

    bool passed = true;
    passed &= check(valid_strace_output_path("/tmp/trace.log"), "normal path");
    passed &= check(!valid_strace_output_path(""), "empty path");
    passed &= check(!valid_strace_output_path("-"), "stdout path");
    passed &= check(!valid_strace_output_path("/tmp/a\n.log"), "control character");

    char server[] = "/bin/server";
    char option[] = "--server-argument";
    char* argv[] = {server, option};
    const auto original = make_strace_command(argv, 2U, nullptr);
    passed &= check(original.size() == 3U && original[0] == argv[0] &&
                        original[1] == argv[1] && original[2] == nullptr,
                    "untraced command unchanged");

    const auto traced = make_strace_command(argv, 2U, "/tmp/trace.log");
    passed &= check(traced.size() == 13U, "trace argv size");
    passed &= check(std::string_view{traced[0]} == "strace", "strace executable");
    passed &= check(std::string_view{traced[1]} == "-f", "descendants followed");
    passed &= check(std::string_view{traced[6]} == "trace=%file,%process,%network",
                    "trace filter");
    passed &= check(std::string_view{traced[8]} == "/tmp/trace.log", "trace destination");
    passed &= check(std::string_view{traced[9]} == "--", "argument separator");
    passed &= check(traced[10] == argv[0] && traced[11] == argv[1] &&
                        traced[12] == nullptr,
                    "server argv preserved");
    return passed ? 0 : 1;
}
