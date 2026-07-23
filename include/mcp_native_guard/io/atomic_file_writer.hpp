#pragma once

#include <cstdint>
#include <string_view>

namespace mng::io {

enum class AtomicWriteError : std::uint8_t {
    none = 0,
    invalid_destination,
    destination_unusable,
    directory_unusable,
    temporary_file_create,
    temporary_file_write,
    temporary_file_sync,
    temporary_file_close,
    rename_failed,
};

struct AtomicWriteResult final {
    AtomicWriteError error{AtomicWriteError::none};

    [[nodiscard]] constexpr explicit operator bool() const noexcept {
        return error == AtomicWriteError::none;
    }
};

// Atomically replaces `destination` with `contents`. Creates a temporary file
// in the destination's own directory (named ".<temp_file_prefix>-XXXXXX"),
// writes the complete contents, flushes and closes it, then renames it over
// the destination. On any failure the destination is left untouched (or
// absent, if it did not already exist) and the temporary file is removed.
// `destination` must not be empty, ".", "..", or end in '/'; it must not
// currently be a directory or a symbolic link.
[[nodiscard]] AtomicWriteResult write_file_atomic(
    std::string_view destination,
    std::string_view contents,
    std::string_view temp_file_prefix);

[[nodiscard]] const char* atomic_write_error_name(AtomicWriteError error) noexcept;

} // namespace mng::io
