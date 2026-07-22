#pragma once

#include <cstdint>
#include <string_view>

namespace mng::process {

enum class ClientMessageAction : std::uint8_t { forward = 0, drop, respond_with_error };

struct ClientMessageDecision final {
    ClientMessageAction action{ClientMessageAction::forward};
    std::string_view id_json{};
    int error_code{};
    std::string_view error_message{};
};

// Protocol filtering is supplied by a higher layer. The transport invokes this
// only for one complete client-to-server JSONL message at a time.
class ClientMessageHandler {
public:
    virtual ~ClientMessageHandler() = default;
    [[nodiscard]] virtual ClientMessageDecision inspect(std::string_view message) noexcept = 0;
};

} // namespace mng::process
