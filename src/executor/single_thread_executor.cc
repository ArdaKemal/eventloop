#include "eventloop/executor.h"

#include <memory>

namespace eventloop {

namespace {

class single_thread_executor final : public executor {
public:
    auto execute(execution_task&& task) noexcept -> bool override
    {
        if (!task) return false;
        task();
        return true;
    }
};

} // namespace

auto make_single_thread_executor() -> std::unique_ptr<executor>
{
    return std::make_unique<single_thread_executor>();
}

} // namespace eventloop
