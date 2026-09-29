#include "windows/iocp_loop.h"

#include <array>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <thread>

namespace {
auto check(bool condition, const char* message) -> void
{
    if (!condition) throw std::runtime_error(message);
}
} // namespace

auto main() -> int
{
    try {
        using namespace std::chrono_literals;
        eventloop::iocp_loop loop;
        std::array<eventloop::ready_event, 8> events {};

        std::jthread producer([&] {
            std::this_thread::sleep_for(10ms);
            loop.wake();
        });
        const auto wake = loop.poll(events);
        check(wake.wake_requested && wake.event_count == 0,
              "cross-thread wake packet missing");

        loop.arm_timer(1ms);
        const auto timer = loop.poll(events);
        check(timer.timer_requested, "IOCP deadline missing");
        loop.arm_timer(std::nullopt);

        const SOCKET socket = ::WSASocketW(AF_INET, SOCK_DGRAM, IPPROTO_UDP,
                                           nullptr, 0, WSA_FLAG_OVERLAPPED);
        check(socket != INVALID_SOCKET, "WSASocket failed");
        sockaddr_in local {};
        local.sin_family = AF_INET;
        local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        check(::bind(socket, reinterpret_cast<sockaddr*>(&local),
                     sizeof(local)) == 0, "UDP bind failed");
        loop.add_descriptor(static_cast<eventloop::native_socket>(socket));

        eventloop::detail::socket_operation operation;
        std::array<char, 16> buffer {};
        WSABUF wsabuf {static_cast<ULONG>(buffer.size()), buffer.data()};
        sockaddr_storage peer {};
        int peer_length = sizeof(peer);
        DWORD bytes = 0;
        DWORD flags = 0;
        const int start = ::WSARecvFrom(
            socket, &wsabuf, 1, &bytes, &flags,
            reinterpret_cast<sockaddr*>(&peer), &peer_length,
            &operation.overlapped, nullptr);
        check(start == 0 || ::WSAGetLastError() == WSA_IO_PENDING,
              "overlapped WSARecvFrom failed to start");
        check(::CancelIoEx(reinterpret_cast<HANDLE>(socket),
                           &operation.overlapped) != 0,
              "CancelIoEx failed");
        loop.arm_timer(5s);
        const auto completion = loop.poll(events);
        check(completion.event_count == 1, "cancel completion missing");
        check(events[0].operation == &operation, "wrong OVERLAPPED packet");
        check(events[0].error == ERROR_OPERATION_ABORTED,
              "canceled operation did not report ERROR_OPERATION_ABORTED");
        ::closesocket(socket);

        loop.request_stop();
        const auto stop = loop.poll(events);
        check(stop.stop_requested, "stop packet missing");
        std::cout << "IOCP wake, timer, overlapped cancellation, and stop passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
