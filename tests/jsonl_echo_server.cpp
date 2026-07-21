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
