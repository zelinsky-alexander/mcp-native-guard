#include "mcp_native_guard/io/atomic_file_writer.hpp"

#include <cerrno>
#include <string>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

namespace mng::io {
namespace {

[[nodiscard]] AtomicWriteResult fail(AtomicWriteError error) noexcept {
    return AtomicWriteResult{error};
}

} // namespace

AtomicWriteResult write_file_atomic(
    std::string_view destination,
    std::string_view contents,
    std::string_view temp_file_prefix) {
    if (destination.empty() || destination == "." || destination == ".." ||
        destination.back() == '/') {
        return fail(AtomicWriteError::invalid_destination);
    }

    struct stat destination_stat {};
    if (::lstat(std::string{destination}.c_str(), &destination_stat) == 0) {
        if (S_ISDIR(destination_stat.st_mode) || S_ISLNK(destination_stat.st_mode)) {
            return fail(AtomicWriteError::destination_unusable);
        }
    } else if (errno != ENOENT) {
        return fail(AtomicWriteError::destination_unusable);
    }

    std::string directory;
    const auto slash = destination.find_last_of('/');
    if (slash == std::string_view::npos) {
        directory = ".";
    } else if (slash == 0U) {
        directory = "/";
    } else {
        directory.assign(destination.data(), slash);
    }

    struct stat directory_stat {};
    if (::stat(directory.c_str(), &directory_stat) != 0 || !S_ISDIR(directory_stat.st_mode)) {
        return fail(AtomicWriteError::directory_unusable);
    }

    std::string pattern = directory;
    if (pattern.back() != '/') {
        pattern.push_back('/');
    }
    pattern.push_back('.');
    pattern.append(temp_file_prefix);
    pattern.append("-XXXXXX");
    std::vector<char> template_path{pattern.begin(), pattern.end()};
    template_path.push_back('\0');
    const int fd = ::mkstemp(template_path.data());
    if (fd < 0) {
        return fail(AtomicWriteError::temporary_file_create);
    }
    const std::string temporary{template_path.data()};
    (void)::fchmod(fd, S_IRUSR | S_IWUSR);

    const auto fail_temp = [&](AtomicWriteError error) {
        (void)::close(fd);
        (void)::unlink(temporary.c_str());
        return fail(error);
    };

    std::string_view remaining{contents};
    while (!remaining.empty()) {
        const auto count = ::write(fd, remaining.data(), remaining.size());
        if (count > 0) {
            remaining.remove_prefix(static_cast<std::size_t>(count));
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            return fail_temp(AtomicWriteError::temporary_file_write);
        }
    }
    if (::fsync(fd) != 0) {
        return fail_temp(AtomicWriteError::temporary_file_sync);
    }
    if (::close(fd) != 0) {
        (void)::unlink(temporary.c_str());
        return fail(AtomicWriteError::temporary_file_close);
    }
    if (::rename(temporary.c_str(), std::string{destination}.c_str()) != 0) {
        (void)::unlink(temporary.c_str());
        return fail(AtomicWriteError::rename_failed);
    }
    return {};
}

const char* atomic_write_error_name(AtomicWriteError error) noexcept {
    switch (error) {
    case AtomicWriteError::none:
        return "none";
    case AtomicWriteError::invalid_destination:
        return "invalid output destination";
    case AtomicWriteError::destination_unusable:
        return "output destination is not a regular file";
    case AtomicWriteError::directory_unusable:
        return "output directory unusable";
    case AtomicWriteError::temporary_file_create:
        return "temporary output file create";
    case AtomicWriteError::temporary_file_write:
        return "temporary output file write";
    case AtomicWriteError::temporary_file_sync:
        return "temporary output file sync";
    case AtomicWriteError::temporary_file_close:
        return "temporary output file close";
    case AtomicWriteError::rename_failed:
        return "output rename";
    }
    return "unknown";
}

} // namespace mng::io
