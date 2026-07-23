#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace mng::security {

// Bounds applied while reading a version-1 inspect inventory document during
// policy generation. These are independent of the runtime InventoryLimits used
// by inspect itself, since policy generation never retains descriptions,
// schemas, or annotations and therefore does not need size limits for them.
struct PolicyGeneratorLimits final {
    std::size_t max_inventory_bytes{1024U * 1024U};
    std::size_t max_nesting_depth{64U};
    std::size_t max_tools{256U};
    std::size_t max_tool_name_bytes{256U};
};

enum class PolicyGenerateError : std::uint8_t {
    none = 0,
    inventory_too_large,
    excessive_nesting,
    malformed_inventory_json,
    missing_inventory_version,
    unsupported_inventory_version,
    duplicate_member,
    missing_server,
    invalid_server,
    missing_tools,
    tools_not_array,
    missing_tool_name,
    non_string_tool_name,
    escaped_tool_name,
    empty_tool_name,
    oversized_tool_name,
    duplicate_tool_name,
    excessive_tool_count,
    duplicate_allow_tool,
    unknown_allow_tool,
    allocation_failure,
};

struct PolicyGenerateResult final {
    PolicyGenerateError error{PolicyGenerateError::none};
    // Populated only when error == unknown_allow_tool or duplicate_allow_tool.
    std::string offending_tool_name{};
    // Populated only on success: compact deterministic version-1 policy JSON.
    std::string policy_json{};

    [[nodiscard]] constexpr explicit operator bool() const noexcept {
        return error == PolicyGenerateError::none;
    }
};

// Generates a deterministic version-1 default-deny policy document from a
// version-1 inspect inventory document (the on-disk inventory shape: top-level
// inventory_version/server/tools; distinct from the live tools/list wire
// response). Every name in allow_tool_names must appear in the inventory
// exactly once among the arguments and must exist in the inventory; each
// becomes one explicit visibility=allow/invocation=allow rule. Defaults are
// always visibility=deny/invocation=deny. Output is compact JSON with fixed
// member order, and tool rules sorted by exact UTF-8 bytewise name -
// independent of inventory tool order or argument order.
//
// This function performs no I/O, launches no process, and never classifies
// tool safety: it only encodes the caller's explicit allow list.
[[nodiscard]] PolicyGenerateResult generate_policy_from_inventory(
    std::string_view inventory_json,
    const std::vector<std::string_view>& allow_tool_names,
    const PolicyGeneratorLimits& limits);

[[nodiscard]] const char* policy_generate_error_name(PolicyGenerateError error) noexcept;

} // namespace mng::security
