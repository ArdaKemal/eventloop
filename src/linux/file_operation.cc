#include "file_operation.h"
#include "eventloop/file_io.h"

#include <cerrno>
#include <fcntl.h>
#include <unistd.h>

namespace eventloop {

auto detail::perform_file_operation(detail::file_io_operation& operation) noexcept
    -> int
{
    using detail::file_opcode;
    if (operation.cancelled.load(std::memory_order_acquire)) {
        return -ECANCELED;
    }
    for (;;) {
        ssize_t result = -1;
        switch (operation.opcode) {
        case file_opcode::openat:
            result = ::openat(operation.descriptor, operation.path,
                              operation.flags, operation.mode);
            break;
        case file_opcode::read_at:
            result = ::pread(operation.descriptor, operation.buffer,
                             operation.length,
                             static_cast<off_t>(operation.offset));
            break;
        case file_opcode::write_at:
            result = ::pwrite(operation.descriptor, operation.buffer,
                              operation.length,
                              static_cast<off_t>(operation.offset));
            break;
        }
        if (result >= 0) return static_cast<int>(result);
        if (errno != EINTR) return -errno;
        if (operation.cancelled.load(std::memory_order_acquire)) {
            return -ECANCELED;
        }
    }
}

} // namespace eventloop
