#include "eventloop/executor.h"
#include "eventloop/event_loop.h"
#include "eventloop/task.h"
#include "eventloop/udp_socket.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <bit>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <memory>
#include <new>
#include <span>
#include <string_view>
#include <utility>

#ifdef _MSC_VER
#include <intrin.h>
#include <malloc.h>
#endif

namespace {
std::atomic<std::size_t> allocation_count {0};
std::atomic<bool> count_allocations {false};

auto record_allocation() noexcept -> void
{
    if (count_allocations.load(std::memory_order_relaxed))
        allocation_count.fetch_add(1, std::memory_order_relaxed);
}

auto allocate(std::size_t size) -> void*
{
    record_allocation();
    if (auto* memory = std::malloc(size == 0 ? 1 : size)) return memory;
    throw std::bad_alloc {};
}

auto allocate_aligned(std::size_t size, std::size_t alignment) -> void*
{
    record_allocation();
#ifdef _MSC_VER
    auto* memory = _aligned_malloc(size == 0 ? 1 : size, alignment);
#else
    const auto rounded = ((size == 0 ? 1 : size) + alignment - 1) / alignment * alignment;
    auto* memory = std::aligned_alloc(alignment, rounded);
#endif
    if (memory != nullptr) return memory;
    throw std::bad_alloc {};
}

auto free_aligned(void* memory) noexcept -> void
{
#ifdef _MSC_VER
    _aligned_free(memory);
#else
    std::free(memory);
#endif
}
} // namespace

auto operator new(std::size_t size) -> void* { return allocate(size); }
auto operator new[](std::size_t size) -> void* { return allocate(size); }
auto operator new(std::size_t size, std::align_val_t alignment) -> void*
{ return allocate_aligned(size, static_cast<std::size_t>(alignment)); }
auto operator new[](std::size_t size, std::align_val_t alignment) -> void*
{ return allocate_aligned(size, static_cast<std::size_t>(alignment)); }
auto operator delete(void* memory) noexcept -> void { std::free(memory); }
auto operator delete[](void* memory) noexcept -> void { std::free(memory); }
auto operator delete(void* memory, std::size_t) noexcept -> void { std::free(memory); }
auto operator delete[](void* memory, std::size_t) noexcept -> void { std::free(memory); }
auto operator delete(void* memory, std::align_val_t) noexcept -> void { free_aligned(memory); }
auto operator delete[](void* memory, std::align_val_t) noexcept -> void { free_aligned(memory); }
auto operator delete(void* memory, std::size_t, std::align_val_t) noexcept -> void
{ free_aligned(memory); }
auto operator delete[](void* memory, std::size_t, std::align_val_t) noexcept -> void
{ free_aligned(memory); }

namespace {
using namespace eventloop;
using clock_type = std::chrono::steady_clock;

// Materialize the object and let its address escape without executing extra
// workload. Both builds use exactly the same barrier. No private headers.
template<typename T>
auto escape(T& value) noexcept -> void
{
#if defined(__GNUC__) || defined(__clang__)
    asm volatile("" : : "g"(&value) : "memory");
#elif defined(_MSC_VER)
    static const void* volatile escaped;
    escaped = &value;
    _ReadWriteBarrier();
#else
    static const void* volatile escaped;
    escaped = &value;
    std::atomic_signal_fence(std::memory_order_seq_cst);
#endif
}

struct workload {
    std::array<std::uint64_t, 64> words {};
    std::uint64_t checksum {0x123456789abcdef0ULL};
    std::size_t calls {0};

    workload()
    {
        for (std::size_t index = 0; index < words.size(); ++index)
            words[index] = (index + 1) * 0x9e3779b97f4a7c15ULL;
    }
};

auto update(workload& state, std::span<std::uint64_t> words,
            std::uint64_t salt) noexcept -> void
{
    const auto index = static_cast<std::size_t>(state.checksum & 63U);
    state.checksum = std::rotl(state.checksum ^ words[index], 13) + salt;
    words[index] += state.checksum;
    ++state.calls;
}

auto make_callable(workload& state)
{
    return [&state, words = std::span(state.words),
            salt = std::uint64_t {0xd1b54a32d192ed03ULL}]() noexcept {
        update(state, words, salt);
    };
}

struct lifetime_counts {
    std::size_t moves {0};
    std::size_t destructors {0};
    std::size_t releases {0};
};

struct tracked_callable {
    workload* state;
    lifetime_counts* counts;
    std::span<std::uint64_t> words;
    std::uint64_t salt {0xd1b54a32d192ed03ULL};

    tracked_callable(workload& input, lifetime_counts& lifetime) noexcept
        : state(&input), counts(&lifetime), words(input.words) {}
    tracked_callable(const tracked_callable&) = delete;
    tracked_callable(tracked_callable&& other) noexcept
        : state(std::exchange(other.state, nullptr)), counts(other.counts),
          words(other.words), salt(other.salt)
    { ++counts->moves; }
    ~tracked_callable() noexcept
    {
        ++counts->destructors;
        if (state != nullptr) ++counts->releases;
    }
    auto operator()() noexcept -> void { update(*state, words, salt); }
};

struct borrowed_deleter {
    lifetime_counts* counts;
    auto operator()(workload*) const noexcept -> void { ++counts->releases; }
};

struct result {
    std::uint64_t checksum;
    bool valid;
};

template<typename Function>
auto measure(std::string_view name, std::size_t iterations, Function&& function) -> bool
{
    // Warm the same path with fresh local state before timing it.
    if (!function(10'000).valid) return false;
    allocation_count.store(0, std::memory_order_relaxed);
    count_allocations.store(true, std::memory_order_relaxed);
    const auto started = clock_type::now();
    const auto measured = function(iterations);
    const auto ended = clock_type::now();
    count_allocations.store(false, std::memory_order_relaxed);
    const auto allocations = allocation_count.load(std::memory_order_relaxed);
    const auto nanoseconds = std::chrono::duration<double, std::nano>(ended - started).count();
    std::cout << name << ',' << iterations << ',' << std::fixed << std::setprecision(3)
              << nanoseconds / static_cast<double>(iterations) << ',' << allocations
              << ',' << measured.checksum << ',' << (measured.valid ? "ok" : "FAIL") << '\n';
    return measured.valid && allocations == 0;
}

auto expected_checksum(std::size_t count) -> std::uint64_t
{
    workload reference;
    auto callable = make_callable(reference);
    for (std::size_t index = 0; index < count; ++index) callable();
    return reference.checksum;
}

template<typename Invoke>
auto invocation(std::size_t count, std::uint64_t expected, Invoke&& invoke) -> result
{
    workload state;
    invoke(state, count);
    return {state.checksum, state.calls == count && state.checksum == expected};
}

auto run_executor_cases(std::size_t count, std::string_view filter) -> bool
{
    auto executor_owner = make_single_thread_executor();
    executor& executor_ref = *executor_owner;
    const auto expected = expected_checksum(count);
    const auto warm_expected = expected_checksum(10'000);
    bool ok = true;
    bool matched = false;
    const auto run = [&](std::string_view name, auto&& function) {
        if (filter.empty() || filter == name) {
            matched = true;
            ok &= measure(name, count, function);
        }
    };
    const auto invoke = [&](std::size_t iterations, auto&& function) {
        return invocation(iterations, iterations == count ? expected : warm_expected, function);
    };

    run("direct_callable", [&](std::size_t iterations) {
        return invoke(iterations, [](workload& state, std::size_t n) {
            auto callable = make_callable(state);
            for (std::size_t index = 0; index < n; ++index) {
                escape(callable);
                callable();
            }
        });
    });
    run("task_construct_destroy", [](std::size_t iterations) -> result {
        workload state;
        for (std::size_t index = 0; index < iterations; ++index) {
            execution_task current(make_callable(state));
            escape(current);
        }
        return {iterations, state.calls == 0};
    });
    run("task_construct_destroy_nontrivial", [](std::size_t iterations) -> result {
        workload state;
        lifetime_counts counts;
        for (std::size_t index = 0; index < iterations; ++index) {
            execution_task current(tracked_callable(state, counts));
            escape(current);
        }
        return {counts.destructors, counts.moves == iterations &&
            counts.destructors == 2 * iterations && counts.releases == iterations};
    });
    run("task_move_trivial", [](std::size_t iterations) -> result {
        workload state;
        for (std::size_t index = 0; index < iterations; ++index) {
            execution_task source(make_callable(state));
            escape(source);
            execution_task destination(std::move(source));
            escape(destination);
        }
        return {iterations, state.calls == 0};
    });
    run("task_move_nontrivial", [](std::size_t iterations) -> result {
        workload state;
        lifetime_counts counts;
        for (std::size_t index = 0; index < iterations; ++index) {
            execution_task source(tracked_callable(state, counts));
            escape(source);
            execution_task destination(std::move(source));
            escape(destination);
        }
        return {counts.destructors, counts.moves == 2 * iterations &&
            counts.destructors == 3 * iterations && counts.releases == iterations};
    });
    run("task_move_only", [](std::size_t iterations) -> result {
        workload state;
        lifetime_counts counts;
        for (std::size_t index = 0; index < iterations; ++index) {
            // Stack storage is borrowed; the custom deleter records retirement.
            // Ownership moves are real, and there is no payload allocation.
            std::unique_ptr<workload, borrowed_deleter> owner(&state, {&counts});
            execution_task source([held = std::move(owner), words = std::span(state.words),
                                   salt = std::uint64_t {0xd1b54a32d192ed03ULL}]() noexcept {
                update(*held, words, salt);
            });
            escape(source);
            execution_task destination(std::move(source));
            escape(destination);
        }
        return {counts.releases, counts.releases == iterations && state.calls == 0};
    });
    run("task_invoke_reused", [&](std::size_t iterations) {
        return invoke(iterations, [](workload& state, std::size_t n) {
            execution_task current(make_callable(state));
            escape(current);
            for (std::size_t index = 0; index < n; ++index) current();
        });
    });
    run("executor_invoke_reused", [&](std::size_t iterations) {
        return invoke(iterations, [&](workload& state, std::size_t n) {
            execution_task current(make_callable(state));
            escape(current);
            for (std::size_t index = 0; index < n; ++index)
                if (!executor_ref.execute(std::move(current))) std::terminate();
        });
    });
    run("task_construct_invoke", [&](std::size_t iterations) {
        return invoke(iterations, [](workload& state, std::size_t n) {
            for (std::size_t index = 0; index < n; ++index) {
                execution_task current(make_callable(state));
                escape(current);
                current();
            }
        });
    });
    run("executor_construct_invoke", [&](std::size_t iterations) {
        return invoke(iterations, [&](workload& state, std::size_t n) {
            for (std::size_t index = 0; index < n; ++index) {
                execution_task current(make_callable(state));
                escape(current);
                if (!executor_ref.execute(std::move(current))) std::terminate();
            }
        });
    });
    return ok && matched;
}

struct measurement {
    clock_type::time_point started;
    measurement()
    {
        allocation_count.store(0, std::memory_order_relaxed);
        count_allocations.store(true, std::memory_order_relaxed);
        started = clock_type::now();
    }
    ~measurement() { count_allocations.store(false, std::memory_order_relaxed); }
    auto finish(std::string_view name, std::size_t operations,
                std::uint64_t checksum, bool valid, bool require_zero = true) -> bool
    {
        const auto ended = clock_type::now();
        count_allocations.store(false, std::memory_order_relaxed);
        const auto allocations = allocation_count.load(std::memory_order_relaxed);
        valid &= !require_zero || allocations == 0;
        const auto ns = std::chrono::duration<double, std::nano>(ended - started).count();
        std::cout << name << ',' << operations << ',' << std::fixed << std::setprecision(3)
                  << ns / static_cast<double>(operations) << ',' << allocations << ','
                  << checksum << ',' << (valid ? "ok" : "FAIL") << '\n';
        return valid;
    }
};

struct post_chain {
    event_loop& loop;
    std::size_t target;
    std::size_t completed {0};
    auto run() noexcept -> void
    {
        if (++completed == target) loop.stop();
        else if (!loop.post(execution_task([this]() noexcept { run(); }))) std::terminate();
    }
};

auto post_workload(std::size_t count) -> bool
{
    measurement setup;
    event_loop_options options;
    options.worker_count = 0;
    event_loop loop(options);
    post_chain chain {loop, count};
    if (!loop.post(execution_task([&chain]() noexcept { chain.run(); }))) return false;
    (void)setup.finish("loop_post_setup", 1, 0, true, false);
    measurement steady;
    const auto status = loop.run();
    return steady.finish("loop_post", count, chain.completed,
        status == event_loop_result::stopped && chain.completed == count);
}

struct loop_state {
    event_loop& loop;
    std::size_t roots;
    std::size_t completed {0};
    std::size_t operations {0};
    bool valid {true};
    auto finish() noexcept -> void { if (++completed == roots) loop.stop(); }
    auto fail() -> void
    {
        valid = false;
        loop.shutdown(event_loop::clock::duration::zero());
    }
};

auto timer_root(event_loop& loop, std::size_t count, loop_state& state) -> task<void>
{
    for (std::size_t index = 0; index < count; ++index) {
        if (co_await sleep_for(loop, std::chrono::microseconds(50)) != timer_wait_result::expired) {
            state.valid = false;
            break;
        }
        ++state.operations;
    }
    state.finish();
}

auto timer_workload(std::size_t count) -> bool
{
    measurement setup;
    event_loop_options options;
    options.worker_count = 0;
    options.coroutine_frame_capacities.fill(64);
    options.coroutine_frame_initial_capacities = options.coroutine_frame_capacities;
    event_loop loop(options);
    const auto roots = std::min(count, std::size_t {32});
    loop_state state {loop, roots};
    for (std::size_t index = 0; index < roots; ++index) {
        const auto per_root = count / roots + (index < count % roots ? 1U : 0U);
        if (loop.spawn(timer_root(loop, per_root, state)) != task_spawn_result::accepted)
            std::terminate();
    }
    (void)setup.finish("loop_timer_setup", 1, roots, true, false);
    measurement steady;
    const auto status = loop.run();
    return steady.finish("loop_timer", count, state.operations,
        status == event_loop_result::stopped && state.valid && state.operations == count &&
        state.completed == roots && loop.coroutine_statistics().live == 0);
}

using message = std::array<std::byte, 64>;
auto udp_server(event_loop&, udp_socket& socket, std::size_t count,
                loop_state& state) -> task<void>
{
    message buffer {};
    for (std::size_t index = 0; index < count; ++index) {
        const auto received = co_await socket.async_receive_from(buffer);
        if (!received || received->size != buffer.size()) { state.fail(); co_return; }
        const auto sent = co_await socket.async_send_to(buffer, received->source);
        if (!sent || *sent != buffer.size()) { state.fail(); co_return; }
    }
    state.finish();
}

auto udp_client(event_loop&, udp_socket& socket, ip_endpoint destination,
                std::size_t count, loop_state& state) -> task<void>
{
    message sent {};
    message received {};
    for (std::size_t index = 0; index < sent.size(); ++index)
        sent[index] = static_cast<std::byte>((index * 17U) & 0xffU);
    for (std::size_t index = 0; index < count; ++index) {
        sent[0] = static_cast<std::byte>(index & 0xffU);
        const auto size = co_await socket.async_send_to(sent, destination);
        if (!size || *size != sent.size()) { state.fail(); co_return; }
        const auto reply = co_await socket.async_receive_from(received);
        if (!reply || reply->size != received.size() || received != sent) {
            state.fail();
            co_return;
        }
        ++state.operations;
    }
    state.finish();
}

auto udp_workload(std::size_t count) -> bool
{
    measurement setup;
    event_loop_options options;
    options.worker_count = 0;
    event_loop loop(options);
    auto server_owner = std::make_unique<udp_socket>(loop, ip_endpoint::loopback_v4());
    auto client_owner = std::make_unique<udp_socket>(loop, ip_endpoint::loopback_v4());
    auto* server = server_owner.get();
    auto* client = client_owner.get();
    const auto destination = server->local_endpoint();
    loop.add(std::move(server_owner));
    loop.add(std::move(client_owner));
    loop_state state {loop, 2};
    if (loop.spawn(udp_server(loop, *server, count, state)) != task_spawn_result::accepted ||
        loop.spawn(udp_client(loop, *client, destination, count, state)) != task_spawn_result::accepted)
        std::terminate();
    (void)setup.finish("loop_udp_setup", 1, 2, true, false);
    measurement steady;
    const auto status = loop.run();
    return steady.finish("loop_udp", count, state.operations,
        status == event_loop_result::stopped && state.valid && state.operations == count &&
        state.completed == 2 && loop.coroutine_statistics().live == 0);
}

auto run_loop_cases(std::size_t count, std::string_view filter) -> bool
{
    bool ok = true;
    if (filter == "loop" || filter == "loop_post") ok &= post_workload(count);
    if (filter == "loop" || filter == "loop_timer") ok &= timer_workload(count);
    if (filter == "loop" || filter == "loop_udp") ok &= udp_workload(count);
    return ok;
}
} // namespace

auto main(int argc, char** argv) -> int try
{
    std::size_t iterations = 5'000'000;
    if (argc > 1) {
        const std::string_view argument(argv[1]);
        const auto parsed = std::from_chars(argument.data(), argument.data() + argument.size(), iterations);
        if (parsed.ec != std::errc {} || parsed.ptr != argument.data() + argument.size() ||
            iterations == 0 || iterations > 1'000'000'000) {
            std::cerr << "iterations must be in [1, 1000000000]\n";
            return 1;
        }
    }
    std::cout << "case,operations,ns_per_op,allocations,checksum,status\n";
    const auto filter = argc > 2 ? std::string_view(argv[2]) : std::string_view {};
    if (filter == "loop" || filter == "loop_post" || filter == "loop_timer" || filter == "loop_udp")
        return run_loop_cases(iterations, filter) ? 0 : 1;
    if (run_executor_cases(iterations, filter)) return 0;
    std::cerr << "unknown case or failed workload\n";
    return 1;
} catch (const std::exception& error) {
    std::cerr << "benchmark failed: " << error.what() << '\n';
    return 1;
}
