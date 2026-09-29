#include "eventloop/unique_fd.h"
#include "windows/iocp_loop.h"

#include <array>
#include <iostream>
#include <stdexcept>
#include <system_error>

namespace {
using namespace eventloop;

auto check(bool condition, const char* message) -> void
{
    if (!condition) throw std::runtime_error(message);
}

[[nodiscard]] auto make_datagram() -> unique_fd
{
    const SOCKET socket = ::WSASocketW(AF_INET, SOCK_DGRAM, IPPROTO_UDP,
                                       nullptr, 0, WSA_FLAG_OVERLAPPED);
    if (socket == INVALID_SOCKET)
        throw std::system_error(::WSAGetLastError(), std::system_category(),
                                "WSASocketW");
    return unique_fd(static_cast<native_socket>(socket));
}

auto test_queued_completion_cancel() -> void
{
    iocp_loop loop;
    auto receiver = make_datagram();
    sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    check(::bind(static_cast<SOCKET>(receiver.get()),
                 reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0,
          "bind failed");
    int address_length = sizeof(address);
    check(::getsockname(static_cast<SOCKET>(receiver.get()),
                        reinterpret_cast<sockaddr*>(&address),
                        &address_length) == 0, "getsockname failed");
    auto sender = make_datagram();
    loop.add_descriptor(sender.get());

    detail::socket_operation operation;
    char payload = 'x';
    WSABUF buffer {1, &payload};
    DWORD bytes = 0;
    const int status = ::WSASendTo(
        static_cast<SOCKET>(sender.get()), &buffer, 1, nullptr, 0,
        reinterpret_cast<const sockaddr*>(&address), sizeof(address),
        &operation.overlapped, nullptr);
    check(status == 0 || ::WSAGetLastError() == WSA_IO_PENDING,
          "overlapped send did not start");
    DWORD flags = 0;
    check(::WSAGetOverlappedResult(static_cast<SOCKET>(sender.get()),
                                   &operation.overlapped, &bytes, TRUE,
                                   &flags) != 0, "overlapped send failed");
    check(bytes == 1, "overlapped send byte count was wrong");

    // Kernel I/O is complete, but its IOCP packet remains queued.
    check(::CancelIoEx(reinterpret_cast<HANDLE>(sender.get()),
                       &operation.overlapped) == 0,
          "CancelIoEx unexpectedly canceled completed I/O");
    check(::GetLastError() == ERROR_NOT_FOUND,
          "completed I/O did not report ERROR_NOT_FOUND");
    std::array<ready_event, 1> events {};
    const auto completion = loop.poll(events, true);
    check(completion.event_count == 1 && events[0].operation == &operation &&
              events[0].bytes == 1 && events[0].error == 0,
          "queued completion was lost after CancelIoEx");
}
} // namespace

auto main() -> int
{
    try {
        test_queued_completion_cancel();
        std::cout << "IOCP queued completion survived CancelIoEx\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
