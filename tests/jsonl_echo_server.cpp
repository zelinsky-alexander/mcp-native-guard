#include <charconv>
#include <csignal>
#include <iostream>
#include <string>
#include <string_view>

int main(int argc, char** argv) {
    const bool exit_immediately = argc == 2 && std::string_view{argv[1]} == "--exit-immediately";
    const bool ignore_termination = argc == 2 && std::string_view{argv[1]} == "--ignore-term";
    std::cerr << "echo-server-stderr\n";
    if (exit_immediately) {
        return 0;
    }
    if (argc == 3 && std::string_view{argv[1]} == "--exit-code") {
        int status = 1;
        const std::string_view text{argv[2]};
        const auto parsed = std::from_chars(text.data(), text.data() + text.size(), status);
        return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size() ? status : 125;
    }
    if (ignore_termination) {
        (void)::signal(SIGTERM, SIG_IGN);
        while (true) {
            (void)::pause();
        }
    }

    std::string line;
    while (std::getline(std::cin, line)) {
        std::cout << line << '\n' << std::flush;
    }
    return std::cin.bad() ? 1 : 0;
}
#include <unistd.h>
