#pragma once

#include <functional>
#include <memory>
#include <type_traits>
#include <utility>

namespace eventloop::detail {

#ifdef __cpp_lib_move_only_function

template<typename Signature>
using move_only_function = std::move_only_function<Signature>;

#else

// libc++ (including Apple's) lacks std::move_only_function. This covers the
// subset public callbacks use: empty construction, construction from a
// move-only callable, move, explicit bool, and a non-const call.
template<typename Signature>
class move_only_function;

template<typename Result, typename... Args>
class move_only_function<Result(Args...)> {
public:
    move_only_function() noexcept = default;
    move_only_function(std::nullptr_t) noexcept {}

    template<typename Function>
        requires(!std::same_as<std::remove_cvref_t<Function>, move_only_function> &&
                 std::is_invocable_r_v<Result, std::decay_t<Function>&, Args...>)
    move_only_function(Function&& function)
        : callable_(std::make_unique<model<std::decay_t<Function>>>(
              std::forward<Function>(function)))
    {
    }

    move_only_function(move_only_function&&) noexcept = default;
    auto operator=(move_only_function&&) noexcept -> move_only_function& = default;

    explicit operator bool() const noexcept { return callable_ != nullptr; }

    auto operator()(Args... args) -> Result
    {
        return callable_->invoke(std::forward<Args>(args)...);
    }

private:
    struct concept_base {
        virtual ~concept_base() = default;
        virtual auto invoke(Args... args) -> Result = 0;
    };

    template<typename Function>
    struct model final : concept_base {
        explicit model(Function function) : function_(std::move(function)) {}
        auto invoke(Args... args) -> Result override
        {
            return std::invoke_r<Result>(function_, std::forward<Args>(args)...);
        }
        Function function_;
    };

    std::unique_ptr<concept_base> callable_;
};

#endif

} // namespace eventloop::detail
