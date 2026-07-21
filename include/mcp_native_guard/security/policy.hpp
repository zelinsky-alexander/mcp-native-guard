#pragma once

#include "mcp_native_guard/core/status.hpp"

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace mng::security {

enum class Access : unsigned char { deny = 0, allow = 1 };

struct ToolRule final {
    std::string name;
    Access visible{Access::deny};
    Access callable{Access::deny};
};

struct PolicyDefaults final {
    Access visible{Access::deny};
    Access callable{Access::deny};
};

// Immutable after construction. Sorted storage keeps lookup allocation-free and avoids
// attacker-controlled hash-table collision behaviour.
class PolicyTable final {
public:
    PolicyTable() = default;

    [[nodiscard]] static Status build(
        std::vector<ToolRule> rules,
        PolicyDefaults defaults,
        PolicyTable& output);

    [[nodiscard]] Access visibility_for(std::string_view tool_name) const noexcept;
    [[nodiscard]] Access invocation_for(std::string_view tool_name) const noexcept;
    [[nodiscard]] std::size_t rule_count() const noexcept { return rules_.size(); }

private:
    [[nodiscard]] const ToolRule* find(std::string_view tool_name) const noexcept;

    std::vector<ToolRule> rules_;
    PolicyDefaults defaults_{};
};

} // namespace mng::security
