#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace mng::protocol {

struct InventoryLimits final {
    std::size_t max_message_bytes{1024U * 1024U};
    std::size_t max_nesting_depth{64U};
    std::size_t max_tools{256U};
    std::size_t max_tool_name_bytes{256U};
    std::size_t max_tool_description_bytes{8192U};
    std::size_t max_tool_schema_bytes{65536U};
};

enum class InventoryError : std::uint8_t {
    none = 0,
    message_too_large,
    malformed_json,
    invalid_envelope,
    unsupported_jsonrpc_version,
    duplicate_member,
    wrong_response_id,
    missing_result,
    error_result,
    missing_tools,
    tools_not_array,
    missing_tool_name,
    non_string_tool_name,
    escaped_tool_name,
    empty_tool_name,
    oversized_tool_name,
    oversized_description,
    oversized_schema,
    duplicate_tool_name,
    excessive_tool_count,
    excessive_nesting,
};

struct ToolInventoryEntry final {
    std::string name{};
    // Optional JSON string literal including quotes. Empty means absent.
    std::string description_json{};
    // Optional compact canonical JSON for inputSchema / annotations. Empty means absent.
    std::string input_schema_json{};
    std::string annotations_json{};
};

struct ToolInventory final {
    static constexpr int version = 1;
    std::string downstream_executable{};
    std::vector<ToolInventoryEntry> tools{};
};

struct InventoryParseResult final {
    InventoryError error{InventoryError::none};
    ToolInventory inventory{};

    [[nodiscard]] constexpr explicit operator bool() const noexcept {
        return error == InventoryError::none;
    }
};

// Validates a JSON-RPC initialize response: matching id, result present, not an error.
[[nodiscard]] InventoryError validate_initialize_response(
    std::string_view message,
    std::string_view expected_id_json,
    const InventoryLimits& limits) noexcept;

// Parses and validates a tools/list JSON-RPC response into a sorted inventory.
[[nodiscard]] InventoryParseResult parse_tools_list_response(
    std::string_view message,
    std::string_view expected_id_json,
    std::string_view downstream_executable,
    const InventoryLimits& limits);

// Emits compact deterministic inventory JSON. Returns false if the output would exceed
// max_output_bytes.
[[nodiscard]] bool emit_inventory_json(
    const ToolInventory& inventory,
    std::string& output,
    std::size_t max_output_bytes);

[[nodiscard]] const char* inventory_error_name(InventoryError error) noexcept;

} // namespace mng::protocol
