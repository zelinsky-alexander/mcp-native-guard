#pragma once

#include <cstddef>
#include <string_view>
#include <vector>

namespace mng::process {

// The path is supplied by the local operator, never an MCP client.
[[nodiscard]] bool valid_strace_output_path(std::string_view path) noexcept;

// Returns a null-terminated argv for posix_spawnp. The original argv and
// output_path must outlive the returned vector and the subsequent spawn call.
// When output_path is null, the original command is preserved.
[[nodiscard]] std::vector<char*> make_strace_command(
    char* const* argv, std::size_t argument_count, const char* output_path);

} // namespace mng::process
