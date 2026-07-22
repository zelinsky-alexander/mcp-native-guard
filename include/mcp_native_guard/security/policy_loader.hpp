#pragma once

#include "mcp_native_guard/security/policy.hpp"

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

namespace mng::security {

enum class PolicyLoadError : std::uint8_t {
    none = 0,
    io_error,
    file_too_large,
    malformed_json,
    excessive_nesting,
    unsupported_version,
    duplicate_member,
    missing_defaults,
    invalid_access,
    tools_not_array,
    invalid_tool,
    escaped_tool_name,
    duplicate_tool_name,
    allocation_failure,
};

struct PolicyLoadResult final {
    PolicyLoadError error{PolicyLoadError::none};
    std::string_view message{};

    [[nodiscard]] constexpr explicit operator bool() const noexcept {
        return error == PolicyLoadError::none;
    }
};

struct PolicyDefinition final {
    PolicyDefaults defaults{};
    std::vector<ToolRule> rules;
};

class PolicyLoader final {
public:
    struct Config final {
        std::size_t max_file_bytes{256U * 1024U};
        std::size_t max_nesting_depth{16U};
    };

    PolicyLoader();
    explicit PolicyLoader(Config config) noexcept;

    [[nodiscard]] PolicyLoadResult load_file(
        std::string_view path,
        PolicyDefinition& output) const;
    [[nodiscard]] PolicyLoadResult parse(
        std::string_view json,
        PolicyDefinition& output) const;

private:
    Config config_;
};

[[nodiscard]] PolicyLoadResult apply_deny_overrides(
    std::vector<std::string> denied_tools,
    PolicyDefinition& policy);

} // namespace mng::security
