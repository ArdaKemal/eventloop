#include "eventloop/channel.h"
#include "eventloop/task.h"
#include "eventloop/task_composition.h"

#include <array>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <optional>
#include <string_view>
#include <system_error>
#include <thread>

using namespace eventloop;
using namespace std::chrono_literals;

namespace {

auto check(bool condition, std::string_view message) -> void
{
    if (condition) return;
    std::cerr << "channel: " << message << '\n';
    std::exit(1);
}

template<typename T>
auto is(const std::expected<T, std::error_code>& result, std::errc error) -> bool
{
    return !result && result.error() == std::make_error_code(error);
}

auto run(event_loop& loop) -> void
{
    while (loop.run() == event_loop_result::interrupted) {}
}

auto watchdog(event_loop& loop) -> task<void>
{
    if (co_await sleep_for(loop, 5s) == timer_wait_result::expired)
        check(false, "test did not finish");
}

auto run_case(task<void> (*test)(event_loop&), std::string_view name) -> void
{
    event_loop loop;
    task_handle<void> driver;
    task_handle<void> timeout;
    check(loop.spawn(watchdog(loop), timeout) == task_spawn_result::accepted, "spawn watchdog");
    check(loop.spawn(test(loop), driver) == task_spawn_result::accepted, name);
    run(loop);
    check(driver.done(), "test retired");
    check(driver.take_result() == task_result::success, "test result");
    loop.shutdown(0s);
    run(loop);
}

auto buffered(event_loop& loop) -> task<void>
{
    std::array<std::optional<std::unique_ptr<int>>, 3> storage;
    {
        channel<std::unique_ptr<int>> messages(loop, storage);
        check(messages.capacity() == 3 && messages.size() == 0, "explicit capacity");
        check(is(messages.try_receive(), std::errc::resource_unavailable_try_again), "empty");
        auto first = std::make_unique<int>(1);
        check(messages.try_send(std::move(first)).has_value() && !first, "send moves on success");
        check(messages.try_send(std::make_unique<int>(2)).has_value(), "second send");
        check(messages.try_send(std::make_unique<int>(3)).has_value(), "third send");
        auto fourth = std::make_unique<int>(4);
        check(is(messages.try_send(std::move(fourth)), std::errc::resource_unavailable_try_again), "full");
        check(fourth && *fourth == 4, "failed send preserves value");
        check(**messages.try_receive() == 1, "FIFO first");
        check(messages.try_send(std::move(fourth)).has_value(), "wrap ring");
        for (int value = 2; value <= 4; ++value) {
            auto received = co_await messages.async_receive();
            check(received && **received == value, "FIFO wrapped receive");
        }
        check((co_await messages.async_send(std::make_unique<int>(5))).has_value(), "immediate async send");
        messages.close();
        messages.close();
        auto unsent = std::make_unique<int>(6);
        check(is(messages.try_send(std::move(unsent)), std::errc::broken_pipe) && unsent, "closed preserves value");
        check(**messages.try_receive() == 5, "close drains buffer");
        check(is(co_await messages.async_receive(), std::errc::broken_pipe), "drained close");
        check(is(co_await messages.async_send(std::move(unsent)), std::errc::broken_pipe), "closed async send");
    }
    for (const auto& slot : storage) check(!slot, "storage returned empty");
    loop.stop();
}

auto send(event_loop&, channel<int>& messages, int value,
          std::expected<void, std::error_code>& result) -> task<void>
{
    result = co_await messages.async_send(value);
}

auto receive(event_loop&, channel<int>& messages,
             std::expected<int, std::error_code>& result) -> task<void>
{
    result = co_await messages.async_receive();
}

auto fifo_senders(event_loop& loop) -> task<void>
{
    std::array<std::optional<int>, 1> storage;
    channel<int> messages(loop, storage);
    check(messages.try_send(1).has_value(), "fill channel");
    task_handle<void> a, b;
    std::expected<void, std::error_code> a_result, b_result;
    check(loop.spawn(send(loop, messages, 2, a_result), a) == task_spawn_result::accepted, "spawn first sender");
    check(loop.spawn(send(loop, messages, 3, b_result), b) == task_spawn_result::accepted, "spawn second sender");
    check(!a.done() && !b.done(), "full suspends senders");
    check(*messages.try_receive() == 1, "receive oldest buffered value");
    check(!a.done(), "sender resumption deferred");
    check(is(messages.try_send(4), std::errc::resource_unavailable_try_again), "no sender barging");
    check(*messages.try_receive() == 2, "admit oldest sender");
    check(*messages.try_receive() == 3, "admit second sender");
    check(co_await a == task_result::success && a_result.has_value(), "first sender completes");
    check(co_await b == task_result::success && b_result.has_value(), "second sender completes");
    loop.stop();
}

auto fifo_receivers(event_loop& loop) -> task<void>
{
    std::array<std::optional<int>, 1> storage;
    channel<int> messages(loop, storage);
    task_handle<void> a, b;
    std::expected<int, std::error_code> a_result, b_result;
    check(loop.spawn(receive(loop, messages, a_result), a) == task_spawn_result::accepted, "spawn first receiver");
    check(loop.spawn(receive(loop, messages, b_result), b) == task_spawn_result::accepted, "spawn second receiver");
    check(messages.try_send(1).has_value(), "handoff first");
    check(messages.try_send(2).has_value(), "handoff second");
    check(!a.done() && !b.done() && messages.size() == 0, "handoff bypasses buffer and defers resumption");
    check(messages.try_send(3).has_value() && messages.size() == 1, "buffer after waiting receivers");
    check(co_await a == task_result::success && a_result == 1, "first receiver");
    check(co_await b == task_result::success && b_result == 2, "second receiver");
    check(*messages.try_receive() == 3, "new arrival stays behind handoffs");
    loop.stop();
}

auto cancel_senders(event_loop& loop) -> task<void>
{
    std::array<std::optional<int>, 1> storage;
    channel<int> messages(loop, storage);
    check(messages.try_send(0).has_value(), "fill for cancellation");
    std::array<task_handle<void>, 5> waiting;
    std::array<std::expected<void, std::error_code>, 5> results;
    for (std::size_t index = 0; index < waiting.size(); ++index)
        check(loop.spawn(send(loop, messages, static_cast<int>(index + 1), results[index]), waiting[index])
                  == task_spawn_result::accepted, "spawn cancellable sender");
    for (auto index : {2u, 0u, 4u}) {
        check(waiting[index].cancel(), "cancel middle/head/tail sender");
        check(!waiting[index].done(), "cancellation resumption deferred");
    }
    for (int value : {0, 2, 4}) check(*messages.try_receive() == value, "cancelled sends do not transfer");
    check(messages.size() == 0, "cancelled sends do not reserve capacity");
    for (std::size_t index = 0; index < waiting.size(); ++index) {
        check(co_await waiting[index] == task_result::success, "sender retires");
        if (index % 2 == 0) check(is(results[index], std::errc::operation_canceled), "cancel result");
        else check(results[index].has_value(), "surviving sender");
    }
    check((co_await messages.async_send(6)).has_value(), "send after cancellations");
    check(*(co_await messages.async_receive()) == 6, "receive after cancellations");
    loop.stop();
}

auto cancel_receivers(event_loop& loop) -> task<void>
{
    std::array<std::optional<int>, 1> storage;
    channel<int> messages(loop, storage);
    std::array<task_handle<void>, 5> waiting;
    std::array<std::expected<int, std::error_code>, 5> results;
    for (std::size_t index = 0; index < waiting.size(); ++index)
        check(loop.spawn(receive(loop, messages, results[index]), waiting[index])
                  == task_spawn_result::accepted, "spawn cancellable receiver");
    for (auto index : {2u, 0u, 4u}) {
        check(waiting[index].cancel(), "cancel middle/head/tail receiver");
        check(!waiting[index].done(), "receiver cancellation deferred");
    }
    check(messages.try_send(2).has_value() && messages.try_send(4).has_value(), "surviving receivers get values");
    for (std::size_t index = 0; index < waiting.size(); ++index) {
        check(co_await waiting[index] == task_result::success, "receiver retires");
        if (index % 2 == 0) check(is(results[index], std::errc::operation_canceled), "cancelled receive");
        else check(results[index] == static_cast<int>(index + 1), "receiver order after cancellation");
    }
    check(messages.try_send(6).has_value(), "send after empty waiter queue");
    check(*messages.try_receive() == 6, "cancelled receivers consumed nothing");
    loop.stop();
}

auto close_senders(event_loop& loop) -> task<void>
{
    std::array<std::optional<int>, 1> storage;
    channel<int> messages(loop, storage);
    check(messages.try_send(1).has_value(), "fill before close");
    task_handle<void> a, b;
    std::expected<void, std::error_code> a_result, b_result;
    check(loop.spawn(send(loop, messages, 2, a_result), a) == task_spawn_result::accepted, "close sender a");
    check(loop.spawn(send(loop, messages, 3, b_result), b) == task_spawn_result::accepted, "close sender b");
    messages.close();
    check(!a.done() && !b.done(), "close resumption deferred");
    check(a.cancel(), "cancel after close is queued");
    check(*(co_await messages.async_receive()) == 1, "close preserves buffered value");
    check(is(messages.try_receive(), std::errc::broken_pipe), "pending sends not admitted after close");
    check(co_await a == task_result::success && is(a_result, std::errc::broken_pipe), "close wins before cancellation");
    check(co_await b == task_result::success && is(b_result, std::errc::broken_pipe), "all senders closed");
    loop.stop();
}

auto close_receivers(event_loop& loop) -> task<void>
{
    std::array<std::optional<int>, 1> storage;
    channel<int> messages(loop, storage);
    task_handle<void> a, b;
    std::expected<int, std::error_code> a_result, b_result;
    check(loop.spawn(receive(loop, messages, a_result), a) == task_spawn_result::accepted, "close receiver a");
    check(loop.spawn(receive(loop, messages, b_result), b) == task_spawn_result::accepted, "close receiver b");
    check(a.cancel(), "cancel before close");
    messages.close();
    messages.close();
    check(!a.done() && !b.done(), "closing receivers deferred");
    check(co_await a == task_result::success && is(a_result, std::errc::operation_canceled), "cancellation wins before close");
    check(co_await b == task_result::success && is(b_result, std::errc::broken_pipe), "receiver closed");
    loop.stop();
}

auto committed_transfer(event_loop& loop) -> task<void>
{
    std::array<std::optional<int>, 1> storage;
    channel<int> messages(loop, storage);
    task_handle<void> receiver;
    std::expected<int, std::error_code> received;
    check(loop.spawn(receive(loop, messages, received), receiver) == task_spawn_result::accepted, "committed receiver");
    check(messages.try_send(1).has_value(), "commit handoff");
    check(receiver.cancel(), "cancel committed receiver");
    messages.close();
    check(co_await receiver == task_result::success && received == 1, "handoff survives cancellation and close");

    std::array<std::optional<int>, 1> other_storage;
    channel<int> other(loop, other_storage);
    task_handle<void> sender;
    std::expected<void, std::error_code> sent;
    check(other.try_send(2).has_value(), "fill for committed sender");
    check(loop.spawn(send(loop, other, 3, sent), sender) == task_spawn_result::accepted, "committed sender");
    check(*other.try_receive() == 2, "commit sender into freed slot");
    check(sender.cancel(), "cancel committed sender");
    other.close();
    check(*other.try_receive() == 3, "committed send remains buffered");
    check(co_await sender == task_result::success && sent.has_value(), "send survives cancellation and close");
    loop.stop();
}

auto already_cancelled_send(event_loop& loop, channel<int>& messages,
                           std::expected<void, std::error_code>& result) -> task<void>
{
    (void)co_await sleep_for(loop, 1h);
    result = co_await messages.async_send(9);
}

auto already_cancelled_receive(event_loop& loop, channel<int>& messages,
                              std::expected<int, std::error_code>& result) -> task<void>
{
    (void)co_await sleep_for(loop, 1h);
    result = co_await messages.async_receive();
}

auto cancellation_before_ready(event_loop& loop) -> task<void>
{
    std::array<std::optional<int>, 1> storage;
    channel<int> messages(loop, storage);
    task_handle<void> sender, receiver;
    std::expected<void, std::error_code> sent;
    std::expected<int, std::error_code> received;
    check(loop.spawn(already_cancelled_send(loop, messages, sent), sender) == task_spawn_result::accepted, "cancel before send");
    check(sender.cancel() && sender.done(), "timer cancellation resumes sender");
    check(is(sent, std::errc::operation_canceled) && messages.size() == 0, "cancelled send cannot use free slot");
    check(messages.try_send(1).has_value(), "ready receive");
    check(loop.spawn(already_cancelled_receive(loop, messages, received), receiver) == task_spawn_result::accepted, "cancel before receive");
    check(receiver.cancel() && receiver.done(), "timer cancellation resumes receiver");
    check(is(received, std::errc::operation_canceled) && messages.size() == 1, "cancelled receive cannot take ready value");
    check(*messages.try_receive() == 1, "ready value preserved");
    messages.close();
    task_handle<void> closed_sender, closed_receiver;
    std::expected<void, std::error_code> closed_send_result;
    std::expected<int, std::error_code> closed_receive_result;
    check(loop.spawn(already_cancelled_send(loop, messages, closed_send_result), closed_sender)
              == task_spawn_result::accepted, "cancel before closed send");
    check(closed_sender.cancel() && closed_sender.done(), "cancelled closed sender retires");
    check(is(closed_send_result, std::errc::operation_canceled), "cancellation checked before closed send");
    check(loop.spawn(already_cancelled_receive(loop, messages, closed_receive_result), closed_receiver)
              == task_spawn_result::accepted, "cancel before closed receive");
    check(closed_receiver.cancel() && closed_receiver.done(), "cancelled closed receiver retires");
    check(is(closed_receive_result, std::errc::operation_canceled), "cancellation checked before closed receive");
    loop.stop();
    co_return;
}

auto shutdown_waiters(event_loop& loop) -> task<void>
{
    std::array<std::optional<int>, 1> send_storage, receive_storage;
    channel<int> outgoing(loop, send_storage), incoming(loop, receive_storage);
    check(outgoing.try_send(1).has_value(), "fill before shutdown");
    task_handle<void> sender, receiver;
    std::expected<void, std::error_code> sent;
    std::expected<int, std::error_code> received;
    check(loop.spawn(send(loop, outgoing, 2, sent), sender) == task_spawn_result::accepted, "shutdown sender");
    check(loop.spawn(receive(loop, incoming, received), receiver) == task_spawn_result::accepted, "shutdown receiver");
    loop.shutdown(0s);
    check(co_await sender == task_result::success && is(sent, std::errc::operation_canceled), "shutdown cancels send");
    check(co_await receiver == task_result::success && is(received, std::errc::operation_canceled), "shutdown cancels receive");
    check(*outgoing.try_receive() == 1, "shutdown does not consume buffered value");
}

auto invalid_storage(event_loop& loop) -> task<void>
{
    try {
        channel<int> empty(loop, {});
        check(false, "empty storage must be rejected");
    } catch (const std::invalid_argument&) {}
    std::array<std::optional<int>, 1> storage {1};
    try {
        channel<int> occupied(loop, storage);
        check(false, "occupied storage must be rejected");
    } catch (const std::invalid_argument&) {}
    check(storage[0] == 1, "invalid construction leaves storage intact");
    storage[0].reset();
    {
        channel<int> messages(loop, storage);
        check(messages.try_send(2).has_value(), "buffer value before destruction");
    }
    check(!storage[0], "destruction releases buffered value");
    {
        channel<int> reused(loop, storage);
        check(reused.try_send(3).has_value(), "returned storage reusable");
    }
    loop.stop();
    co_return;
}

// Deliberately has no default/copy constructor or move assignment.
struct move_only {
    move_only(int value, int& live) noexcept : value(value), live(&live) { ++live; }
    move_only(move_only&& other) noexcept
        : value(other.value), live(std::exchange(other.live, nullptr)) {}
    ~move_only() { if (live != nullptr) --*live; }
    int value;
    int* live;
};

auto owning_sender(event_loop&, channel<move_only>& messages, int value, int& live,
                   std::expected<void, std::error_code>& result) -> task<void>
{
    result = co_await messages.async_send(move_only(value, live));
}

auto owning_receiver(event_loop&, channel<move_only>& messages, int& value) -> task<void>
{
    auto received = co_await messages.async_receive();
    check(received.has_value(), "move-only receive");
    value = received->value;
}

auto value_lifetimes(event_loop& loop) -> task<void>
{
    int live = 0;
    std::array<std::optional<move_only>, 1> storage;
    {
        channel<move_only> messages(loop, storage);
        check(messages.try_send(move_only(1, live)).has_value() && live == 1, "buffer owns value");
        task_handle<void> cancelled, closed;
        std::expected<void, std::error_code> cancelled_result, closed_result;
        check(loop.spawn(owning_sender(loop, messages, 2, live, cancelled_result), cancelled)
                  == task_spawn_result::accepted, "owning cancelled sender");
        check(live == 2, "pending sender owns extra value");
        check(cancelled.cancel() && live == 2, "cancel retains value through retirement");
        check(co_await cancelled == task_result::success && live == 1, "cancel releases owned argument");
        check(is(cancelled_result, std::errc::operation_canceled), "owning cancel result");
        check(loop.spawn(owning_sender(loop, messages, 3, live, closed_result), closed)
                  == task_spawn_result::accepted, "owning closed sender");
        messages.close();
        check(live == 2, "close retains pending value through retirement");
        check(co_await closed == task_result::success && live == 1, "close releases owned argument");
        check(is(closed_result, std::errc::broken_pipe), "owning close result");
    }
    check(live == 0 && !storage[0], "destruction releases undrained message");
    {
        channel<move_only> messages(loop, storage);
        {
            auto unused = messages.async_send(move_only(4, live));
            check(live == 1 && messages.size() == 0, "unawaited send owns argument without sending");
            (void)unused;
        }
        check(live == 0, "unawaited send releases argument");
        task_handle<void> receiver;
        int value = 0;
        check(loop.spawn(owning_receiver(loop, messages, value), receiver)
                  == task_spawn_result::accepted, "owning receiver");
        check(messages.try_send(move_only(5, live)).has_value() && live == 1, "queued receiver owns message");
        messages.close();
        check(receiver.cancel(), "cancel owning committed receiver");
        check(co_await receiver == task_result::success && value == 5 && live == 0, "handoff releases exactly once");
    }
    loop.stop();
}

inline constexpr int producers = 5;
inline constexpr int per_producer = 100;

auto producer(event_loop&, channel<int>& messages, int id) -> task<void>
{
    for (int index = 0; index < per_producer; ++index)
        check((co_await messages.async_send(id * per_producer + index)).has_value(), "pipeline send");
}

auto consumer(event_loop&, channel<int>& messages,
              std::array<int, producers * per_producer>& seen) -> task<void>
{
    for (;;) {
        auto value = co_await messages.async_receive();
        if (!value) {
            check(is(value, std::errc::broken_pipe), "pipeline ends with close");
            co_return;
        }
        check(*value >= 0 && *value < static_cast<int>(seen.size()), "pipeline value range");
        ++seen[static_cast<std::size_t>(*value)];
    }
}

auto pipeline(event_loop& loop) -> task<void>
{
    std::array<std::optional<int>, 7> storage;
    channel<int> messages(loop, storage);
    std::array<int, producers * per_producer> seen {};
    std::array<task_handle<void>, 3> readers;
    std::array<task_handle<void>, producers> writers;
    for (auto& reader : readers)
        check(loop.spawn(consumer(loop, messages, seen), reader) == task_spawn_result::accepted, "spawn pipeline consumer");
    for (int id = 0; id < producers; ++id)
        check(loop.spawn(producer(loop, messages, id), writers[static_cast<std::size_t>(id)])
                  == task_spawn_result::accepted, "spawn pipeline producer");
    for (auto& writer : writers) check(co_await writer == task_result::success, "producer retires");
    messages.close();
    for (auto& reader : readers) check(co_await reader == task_result::success, "consumer retires");
    for (int count : seen) check(count == 1, "every message delivered exactly once");
    check(messages.size() == 0, "pipeline drained");
    loop.stop();
}

auto immediate(event_loop&) -> task<int>
{
    co_return 7;
}

auto composition_cancellation(event_loop& loop) -> task<void>
{
    std::array<std::optional<int>, 1> storage;
    channel<int> messages(loop, storage);
    std::expected<int, std::error_code> received;
    auto read_race = co_await race(receive(loop, messages, received), immediate(loop));
    check(read_race && read_race->index == 1, "immediate branch wins receive race");
    check(is(received, std::errc::operation_canceled), "race retires cancelled receiver");
    check(messages.try_send(1).has_value(), "race leaves channel reusable");
    std::expected<void, std::error_code> sent;
    auto write_race = co_await race(send(loop, messages, 2, sent), immediate(loop));
    check(write_race && write_race->index == 1, "immediate branch wins send race");
    check(is(sent, std::errc::operation_canceled), "race retires cancelled sender");
    check(messages.try_receive() == 1 && messages.size() == 0, "race preserves original buffered value");
    loop.stop();
}

auto wrong_loop_send(event_loop& loop, channel<int>& messages) -> task<void>
{
    (void)loop;
    (void)co_await messages.async_send(1);
    std::_Exit(1);
}

auto wrong_loop_receive(event_loop& loop, channel<int>& messages) -> task<void>
{
    (void)loop;
    (void)co_await messages.async_receive();
    std::_Exit(1);
}

// The deliberate misuse must reach terminate(), rather than crash or succeed.
[[noreturn]] auto programming_error(std::string_view mode) -> void
{
    std::set_terminate([] { std::_Exit(0); });
    event_loop loop;
    std::array<std::optional<int>, 1> storage;
    if (mode == "wrong_loop_send" || mode == "wrong_loop_receive") {
        channel<int> messages(loop, storage);
        event_loop other;
        if (mode == "wrong_loop_send") {
            (void)other.spawn(wrong_loop_send(other, messages));
        } else {
            check(messages.try_send(1).has_value(), "ready wrong-loop receive");
            (void)other.spawn(wrong_loop_receive(other, messages));
        }
    } else if (mode == "wrong_thread") {
        channel<int> messages(loop, storage);
        std::thread worker([&] {
            messages.close();
            std::_Exit(1);
        });
        worker.join();
    } else if (mode == "destroy_pending" || mode == "destroy_queued") {
        task_handle<void> waiting;
        std::expected<int, std::error_code> result;
        {
            channel<int> messages(loop, storage);
            check(loop.spawn(receive(loop, messages, result), waiting) == task_spawn_result::accepted, "lifetime receiver");
            if (mode == "destroy_queued") check(messages.try_send(1).has_value(), "queue before destruction");
        }
    }
    std::_Exit(1);
}

} // namespace

auto main(int argc, char** argv) -> int
{
    if (argc == 2) programming_error(argv[1]);
    struct test_case {
        task<void> (*test)(event_loop&);
        std::string_view name;
    };
    const test_case cases[] {
        {&buffered, "buffered"},
        {&fifo_senders, "fifo_senders"},
        {&fifo_receivers, "fifo_receivers"},
        {&cancel_senders, "cancel_senders"},
        {&cancel_receivers, "cancel_receivers"},
        {&close_senders, "close_senders"},
        {&close_receivers, "close_receivers"},
        {&committed_transfer, "committed_transfer"},
        {&cancellation_before_ready, "cancellation_before_ready"},
        {&shutdown_waiters, "shutdown_waiters"},
        {&invalid_storage, "invalid_storage"},
        {&value_lifetimes, "value_lifetimes"},
        {&pipeline, "pipeline"},
        {&composition_cancellation, "composition_cancellation"},
    };
    for (const auto& item : cases) run_case(item.test, item.name);
}
