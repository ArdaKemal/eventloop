#include "eventloop/task.h"

using namespace eventloop;

namespace {
auto immediate(event_loop&, bool& ran) -> task<void>
{
    ran = true;
    co_return;
}
} // namespace

auto main() -> int
{
    event_loop loop;
    bool ran = false;
    auto operation = immediate(loop, ran);
    const auto result = loop.spawn(std::move(operation));
    return result == task_spawn_result::accepted && ran &&
                   loop.coroutine_statistics().live == 0 ? 0 : 1;
}
