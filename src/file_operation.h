#pragma once

namespace eventloop::detail {

struct file_io_operation;

[[nodiscard]] auto perform_file_operation(file_io_operation& operation) noexcept
    -> int;

} // namespace eventloop::detail
