#include "mcp_native_guard/process/strace_command.hpp"

#include <array>

namespace mng::process {

bool valid_strace_output_path(std::string_view path) noexcept {
    if (path.empty() || path == "-" || path.size() > 4096U) {
        return false;
    }
    for (const unsigned char character : path) {
        if (character < 0x20U || character == 0x7fU) {
            return false;
        }
    }
    return true;
}

std::vector<char*> make_strace_command(
    char* const* argv, std::size_t argument_count, const char* output_path) {
    std::vector<char*> result;
    constexpr std::array<const char*, 8> strace_flags{
        "strace", "-f", "-qq", "-s", "256", "-e",
        "trace=%file,%process,%network", "-o"
    };
    const std::size_t prefix_count = output_path == nullptr ? 0U : strace_flags.size() + 2U;
    result.reserve(prefix_count + argument_count + 1U);
    if (output_path != nullptr) {
        for (const char* flag : strace_flags) {
            result.push_back(const_cast<char*>(flag));
        }
        result.push_back(const_cast<char*>(output_path));
        result.push_back(const_cast<char*>("--"));
    }
    for (std::size_t index = 0; index < argument_count; ++index) {
        result.push_back(argv[index]);
    }
    result.push_back(nullptr);
    return result;
}

} // namespace mng::process
