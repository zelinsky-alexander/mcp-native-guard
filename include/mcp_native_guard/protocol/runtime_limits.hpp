#pragma once

#include <cstddef>

namespace mng::protocol {

struct RuntimeLimits final {
    std::size_t max_message_bytes{1024U * 1024U};
    std::size_t max_nesting_depth{64U};
    std::size_t max_pending_tools_list{64U};
};

} // namespace mng::protocol
