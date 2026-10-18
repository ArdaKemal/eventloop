cmake_minimum_required(VERSION 3.20)
project(event_loop VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(CTest)

find_package(Threads REQUIRED)
find_package(OpenSSL 3.5 REQUIRED COMPONENTS Crypto SSL)
set(EVENTLOOP_CONFIG_NEEDS_OPENSSL ON)

# TLS, WebSocket, and HTTP/2 are optional only on Windows; QUIC always needs OpenSSL.
if(WIN32)
    option(EVENTLOOP_WINDOWS_TLS "Build Windows TLS/WebSocket support" ON)
    set(EVENTLOOP_TLS ${EVENTLOOP_WINDOWS_TLS})
else()
    set(EVENTLOOP_TLS ON)
endif()
option(EVENTLOOP_HTTP3_INTEROP_TESTS
    "Enable optional outbound HTTP/3 v1/v2 tests using aioquic 1.3.0" OFF)
option(EVENTLOOP_WEBSOCKET_INTEROP_TESTS
    "Enable Python websockets interoperability test" OFF)

# --- Library -----------------------------------------------------------------

add_library(eventloop
    src/event_loop.cc
    src/executor/multi_thread_executor.cc
    src/executor/single_thread_executor.cc
    src/http/directory_listing.cc
    src/http/mime_types.cc
    src/http/open_file_cache.cc
    src/http/parser.cc
    src/http/resource.cc
    src/http/routing.cc
    src/http/server.cc
    src/http/session.cc
    src/http3/client.cc
    src/http3/qpack.cc
    src/http3/server.cc
    src/quic/connection_core.cc
    src/quic/key_update.cc
    src/quic/packet_protection.cc
    src/quic/protected_packet.cc
    src/quic/quic_endpoint.cc
    src/quic/retry_packet.cc
    src/quic/retry_token.cc
    src/quic/tls_provider.cc
    src/quic/udp_endpoint.cc
    src/quic/worker_group.cc
    src/tcp_acceptor.cc
    src/tcp_stream.cc
    src/udp_socket.cc
    src/util/arg_parser.cc
)
if(EVENTLOOP_TLS)
    target_sources(eventloop PRIVATE
        src/http2/client.cc
        src/http2/connection.cc
        src/http2/hpack.cc
        src/http2/session.cc
        src/tls_stream.cc
        src/ws/web_socket.cpp
    )
endif()
if(WIN32)
    target_sources(eventloop PRIVATE
        src/windows/file_operation.cc
        src/windows/http_file_operations.cc
        src/windows/iocp_loop.cc
        src/windows/socket_operations.cc
    )
    target_compile_definitions(eventloop PRIVATE NOMINMAX)
    target_link_libraries(eventloop PUBLIC ws2_32 mswsock PRIVATE crypt32)
    if(EVENTLOOP_TLS)
        target_compile_definitions(eventloop PUBLIC EVENTLOOP_WINDOWS_TLS=1)
    endif()
    if(BUILD_SHARED_LIBS)
        target_compile_definitions(eventloop PRIVATE EVENTLOOP_WINDOWS_SHARED=1)
    endif()
else()
    target_sources(eventloop PRIVATE
        src/linux/file_operation.cc
        src/linux/http_file_operations.cc
        src/unix_socket.cc
    )
    if(APPLE OR CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
        target_sources(eventloop PRIVATE src/macos/kqueue_loop.cc src/macos/socket_operations.cc)
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_sources(eventloop PRIVATE src/linux/epoll_loop.cc src/linux/socket_operations.cc)
    else()
        message(FATAL_ERROR "eventloop supports FreeBSD, Linux, macOS, and Windows")
    endif()
endif()
add_library(eventloop::eventloop ALIAS eventloop)
target_include_directories(eventloop
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_features(eventloop PUBLIC cxx_std_23)
target_link_libraries(eventloop PUBLIC Threads::Threads PRIVATE OpenSSL::SSL OpenSSL::Crypto)

function(eventloop_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
    endif()
endfunction()
eventloop_warnings(eventloop)

# --- Install -----------------------------------------------------------------

set(eventloop_package_dir "${CMAKE_INSTALL_LIBDIR}/cmake/eventloop")
install(TARGETS eventloop EXPORT eventloopTargets
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
)
set(eventloop_excluded_headers)
if(NOT EVENTLOOP_TLS)
    list(APPEND eventloop_excluded_headers
        PATTERN "tls_context.h" EXCLUDE
        PATTERN "tls_stream.h" EXCLUDE
        PATTERN "http2" EXCLUDE
        PATTERN "ws" EXCLUDE
    )
endif()
install(DIRECTORY include/eventloop/
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/eventloop"
    ${eventloop_excluded_headers}
)
install(EXPORT eventloopTargets
    FILE eventloopTargets.cmake
    NAMESPACE eventloop::
    DESTINATION "${eventloop_package_dir}"
)
configure_package_config_file(
    cmake/eventloopConfig.cmake.in
    "${CMAKE_CURRENT_BINARY_DIR}/eventloopConfig.cmake"
    INSTALL_DESTINATION "${eventloop_package_dir}"
)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/eventloopConfigVersion.cmake"
    VERSION "${PROJECT_VERSION}"
    COMPATIBILITY SameMajorVersion
)
install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/eventloopConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/eventloopConfigVersion.cmake"
    DESTINATION "${eventloop_package_dir}"
)

# --- Examples, fixtures, and benchmarks --------------------------------------

function(eventloop_executable name)
    add_executable(${name} ${ARGN})
    target_link_libraries(${name} PRIVATE eventloop::eventloop)
    eventloop_warnings(${name})
    # GCC diagnoses the standard coroutine allocation/deallocation pair as
    # mismatched when allocation receives coroutine function arguments.
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(${name} PRIVATE -Wno-mismatched-new-delete)
    endif()
endfunction()

eventloop_executable(tcp_echo examples/basics/tcp_echo.cc)
eventloop_executable(routing_server examples/basics/routing_server.cc)
eventloop_executable(quic_echo_server examples/basics/quic_echo_server.cc)
if(NOT WIN32)
    eventloop_executable(unix_echo examples/basics/unix_echo.cc)
endif()
if(EVENTLOOP_TLS)
    eventloop_executable(tls_echo examples/basics/tls_echo.cc)
    eventloop_executable(websocket_echo_server examples/basics/websocket_echo_server.cc)
    target_link_libraries(websocket_echo_server PRIVATE OpenSSL::Crypto)
    eventloop_executable(websocket_routing_server examples/basics/websocket_routing_server.cc)
    eventloop_executable(websocket_client examples/basics/websocket_client.cc
        examples/client_support/url.cc examples/client_support/resolve.cc)
    target_include_directories(websocket_client PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/examples)
    target_link_libraries(websocket_client PRIVATE OpenSSL::Crypto)
    eventloop_executable(http_server tests/fixtures/http_server.cc)
endif()
eventloop_executable(http3_client tests/fixtures/http3_client.cc
    examples/client_support/url.cc examples/client_support/resolve.cc)
target_include_directories(http3_client PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/examples)
eventloop_executable(http3_file_server tests/fixtures/http3_file_server.cc)

foreach(benchmark coroutine_socket_benchmark event_loop_benchmark executor_benchmark
                  file_io_benchmark http_benchmark_server)
    eventloop_executable(${benchmark} benchmark/${benchmark}.cc)
endforeach()
if(NOT WIN32)
    eventloop_executable(routing_benchmark_server benchmark/routing_benchmark_server.cc)
endif()

# --- Tests -------------------------------------------------------------------

# eventloop_test(<name> <sources>... [PRIVATE] [LINK <libraries>...] [TIMEOUT <seconds>])
# builds <name>_test and registers it as test <name>. PRIVATE adds src/ to the
# include path for tests of internal headers.
function(eventloop_test name)
    cmake_parse_arguments(PARSE_ARGV 1 test "PRIVATE" "TIMEOUT" "LINK")
    eventloop_executable(${name}_test ${test_UNPARSED_ARGUMENTS})
    target_link_libraries(${name}_test PRIVATE ${test_LINK})
    if(test_PRIVATE)
        target_include_directories(${name}_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    endif()
    add_test(NAME ${name} COMMAND ${name}_test)
    if(test_TIMEOUT)
        set_tests_properties(${name} PROPERTIES TIMEOUT ${test_TIMEOUT})
    endif()
endfunction()

if(BUILD_TESTING)
    eventloop_test(http_api tests/http_api.cc LINK OpenSSL::Crypto TIMEOUT 10)
    eventloop_test(socket_api tests/socket_api.cc LINK OpenSSL::Crypto TIMEOUT 10)
    if(EVENTLOOP_TLS)
        target_compile_definitions(socket_api_test PRIVATE EVENTLOOP_TEST_TLS=1)
    endif()
    eventloop_test(event_loop tests/event_loop.cc)
    eventloop_test(executor tests/executor.cc PRIVATE TIMEOUT 30)
    eventloop_test(task tests/task.cc)
    if(WIN32 AND BUILD_SHARED_LIBS)
        target_compile_definitions(task_test PRIVATE EVENTLOOP_TEST_SHARED_LIBRARY=1)
    endif()
    eventloop_test(task_composition tests/task_composition.cc)
    eventloop_test(task_handle tests/task_handle.cc)
    eventloop_test(file_io tests/file_io.cc TIMEOUT 10)
    eventloop_test(coroutine_tcp tests/tcp_coroutine.cc TIMEOUT 10)
    eventloop_test(coroutine_udp tests/udp_coroutine.cc TIMEOUT 10)

    foreach(name ack_ranges congestion_control connection_id_registry connection_lifecycle
                 crypto_buffer crypto_send_buffer datagram_queue ecn_state endpoint_router
                 flow_control frame_encoder frame_policy frames local_connection_id_registry
                 loss_detection packet_header packet_protection path_recovery_state
                 path_validation protected_packet received_packet_ranges recovery_orchestration
                 recovery_timer sent_packet_history stateless_reset stream_receive
                 stream_registry stream_send_buffer stream_state transport_parameter_validation
                 transport_parameters varint version_negotiation)
        eventloop_test(quic_${name} tests/quic_${name}.cc PRIVATE)
    endforeach()
    foreach(name grease_quic_bit key_update packet_protection_context retry_packet retry_token
                 udp_endpoint)
        eventloop_test(quic_${name} tests/quic_${name}.cc PRIVATE LINK OpenSSL::Crypto)
    endforeach()
    foreach(name connection connection_core packet_scheduler tls)
        eventloop_test(quic_${name} tests/quic_${name}.cc PRIVATE
            LINK OpenSSL::SSL OpenSSL::Crypto)
    endforeach()
    eventloop_test(quic_public_api tests/quic_public_api.cc PRIVATE
        LINK OpenSSL::SSL OpenSSL::Crypto TIMEOUT 20)
    eventloop_test(quic_connection_driver tests/quic_connection_driver.cc PRIVATE
        LINK OpenSSL::SSL OpenSSL::Crypto TIMEOUT 15)
    eventloop_test(quic_driver_failure tests/quic_driver_failure.cc
        LINK OpenSSL::SSL OpenSSL::Crypto TIMEOUT 15)

    eventloop_test(http3_frames tests/http3_frames.cc PRIVATE)
    eventloop_test(http3_request_stream tests/http3_request_stream.cc PRIVATE)
    eventloop_test(http3_qpack tests/http3_qpack.cc src/http3/qpack.cc PRIVATE)
    eventloop_test(http3_peer_streams tests/http3_peer_streams.cc src/http3/qpack.cc PRIVATE)
    eventloop_test(http3_server_errors tests/http3_server_errors.cc src/http3/qpack.cc PRIVATE
        LINK OpenSSL::SSL OpenSSL::Crypto TIMEOUT 20)
    eventloop_test(http3_server_peer_close tests/http3_server_peer_close.cc
        LINK OpenSSL::SSL OpenSSL::Crypto TIMEOUT 20)

    if(EVENTLOOP_TLS)
        eventloop_test(web_socket tests/web_socket.cc)
        eventloop_test(http2_hpack tests/http2_hpack.cc PRIVATE)
        eventloop_test(http2_priority tests/http2_priority.cc PRIVATE)
    endif()

    if(WIN32)
        eventloop_test(windows_iocp tests/windows_iocp.cc PRIVATE TIMEOUT 10)
        if(BUILD_SHARED_LIBS)
            target_compile_definitions(windows_iocp_test PRIVATE EVENTLOOP_WINDOWS_SHARED=1)
        endif()
        eventloop_test(windows_socket_operations tests/windows_socket_operations.cc TIMEOUT 10)
        eventloop_test(windows_iocp_lifecycle tests/windows_iocp_lifecycle.cc PRIVATE TIMEOUT 10)
        # Tests load OpenSSL's DLLs from its installation.
        get_property(eventloop_tests DIRECTORY PROPERTY TESTS)
        set_tests_properties(${eventloop_tests} PROPERTIES
            ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${OPENSSL_ROOT_DIR}/bin")
    else()
        find_program(OPENSSL_EXECUTABLE openssl REQUIRED)
        find_program(CURL_EXECUTABLE curl REQUIRED)

        eventloop_test(arg_parser tests/arg_parser.cc)
        eventloop_test(coroutine_unix tests/unix_socket.cc TIMEOUT 10)
        eventloop_test(wakeup tests/wakeup.cc TIMEOUT 15)
        add_test(NAME wakeup_wrong_loop COMMAND wakeup_test wrong_loop)
        set_tests_properties(wakeup_wrong_loop PROPERTIES TIMEOUT 15)
        eventloop_test(tls_openssl tests/tls_openssl.cc LINK OpenSSL::SSL OpenSSL::Crypto TIMEOUT 10)
        eventloop_executable(tls_loopback_test tests/tls_loopback.cc)
        target_link_libraries(tls_loopback_test PRIVATE OpenSSL::SSL)
        add_test(NAME tls_loopback
            COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_tls_loopback.sh
                         $<TARGET_FILE:tls_loopback_test>)
        set_tests_properties(tls_loopback PROPERTIES TIMEOUT 10)

        eventloop_test(http tests/http_test.cc PRIVATE)
        eventloop_test(http_routing tests/http_routing.cc LINK OpenSSL::Crypto TIMEOUT 15)
        eventloop_test(http_routing_allocations tests/http_routing_allocations.cc TIMEOUT 15)
        eventloop_test(http_connection_lifetime tests/http_connection_lifetime.cc
            LINK OpenSSL::Crypto TIMEOUT 15)
        eventloop_test(http_server_connections tests/http_server_connections.cc
            LINK OpenSSL::Crypto TIMEOUT 30)
        eventloop_test(http_websocket tests/http_websocket.cc src/http3/qpack.cc PRIVATE
            LINK OpenSSL::Crypto TIMEOUT 20)
        eventloop_test(http2_hardening tests/http2_hardening.cc PRIVATE)
        eventloop_test(http2_routing tests/http2_routing.cc PRIVATE LINK OpenSSL::Crypto TIMEOUT 30)
        eventloop_test(http2_routing_allocations tests/http2_routing_allocations.cc PRIVATE
            LINK OpenSSL::Crypto TIMEOUT 30)
        eventloop_test(http2_client_validation tests/http2_client_validation.cc
            LINK OpenSSL::Crypto TIMEOUT 30)
        eventloop_test(http3_client tests/http3_client.cc LINK OpenSSL::Crypto TIMEOUT 30)
        eventloop_test(http3_routing tests/http3_routing.cc src/http3/qpack.cc PRIVATE
            LINK OpenSSL::SSL OpenSSL::Crypto TIMEOUT 20)
        eventloop_test(http3_routing_allocations tests/http3_routing_allocations.cc
            src/http3/qpack.cc PRIVATE LINK OpenSSL::SSL OpenSSL::Crypto TIMEOUT 20)
        if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
            eventloop_test(interest_churn tests/interest_churn.cc LINK OpenSSL::Crypto TIMEOUT 10)
            eventloop_test(http2_file_send tests/http2_file_send.cc PRIVATE)
            eventloop_test(http_file_batching tests/http_file_batching.cc PRIVATE
                LINK OpenSSL::SSL OpenSSL::Crypto TIMEOUT 60)
            eventloop_test(http_open_file_cache tests/http_open_file_cache.cc PRIVATE)
            add_test(NAME http_open_file_cache_openat2_unavailable
                COMMAND http_open_file_cache_test ENOSYS)
            add_test(NAME http_open_file_cache_openat2_blocked
                COMMAND http_open_file_cache_test EPERM)
        endif()

        # Server and client binaries driven by shell or Python scripts.
        add_test(NAME http_server
            COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_http_server.sh
                         $<TARGET_FILE:http_server> ${OPENSSL_EXECUTABLE} ${CURL_EXECUTABLE})
        set_tests_properties(http_server PROPERTIES TIMEOUT 15)
        add_test(NAME http2_server
            COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_http2_server.sh
                         $<TARGET_FILE:http_server> ${OPENSSL_EXECUTABLE} ${CURL_EXECUTABLE})
        set_tests_properties(http2_server PROPERTIES TIMEOUT 30)
        add_test(NAME http3_server
            COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_http3_server.sh
                         $<TARGET_FILE:http3_file_server> ${OPENSSL_EXECUTABLE}
                         ${CURL_EXECUTABLE} $<TARGET_FILE:http3_client>)
        set_tests_properties(http3_server PROPERTIES TIMEOUT 30)

        # h2spec is not vendored; point H2SPEC_EXECUTABLE at it to run the suite.
        find_program(H2SPEC_EXECUTABLE h2spec)
        if(H2SPEC_EXECUTABLE)
            add_test(NAME http2_h2spec
                COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_h2spec.sh
                             $<TARGET_FILE:http_server> ${OPENSSL_EXECUTABLE} ${H2SPEC_EXECUTABLE})
            set_tests_properties(http2_h2spec PROPERTIES TIMEOUT 120)
        endif()

        find_package(Python3 QUIET COMPONENTS Interpreter)
        if(Python3_Interpreter_FOUND)
            add_test(NAME http2_file_transfer
                COMMAND "${Python3_EXECUTABLE}"
                    "${CMAKE_CURRENT_SOURCE_DIR}/tests/run_http2_file_transfer.py"
                    $<TARGET_FILE:http_server> ${OPENSSL_EXECUTABLE})
            set_tests_properties(http2_file_transfer PROPERTIES TIMEOUT 20)
            execute_process(COMMAND "${Python3_EXECUTABLE}" -c
                "import h2, wsproto, aioquic; assert aioquic.__version__ == '1.3.0'"
                RESULT_VARIABLE http_websocket_interop_available
                OUTPUT_QUIET ERROR_QUIET)
            if(http_websocket_interop_available EQUAL 0)
                add_test(NAME http_websocket_interop
                    COMMAND "${Python3_EXECUTABLE}"
                        "${CMAKE_CURRENT_SOURCE_DIR}/tests/run_http_websocket_interop.py"
                        $<TARGET_FILE:websocket_routing_server> ${OPENSSL_EXECUTABLE})
                set_tests_properties(http_websocket_interop PROPERTIES TIMEOUT 50)
            endif()
        endif()
        if(EVENTLOOP_WEBSOCKET_INTEROP_TESTS)
            find_package(Python3 REQUIRED COMPONENTS Interpreter)
            execute_process(COMMAND "${Python3_EXECUTABLE}" -c "import websockets"
                RESULT_VARIABLE websocket_python_result)
            if(NOT websocket_python_result EQUAL 0)
                message(FATAL_ERROR "WebSocket interop test requires Python websockets")
            endif()
            add_test(NAME websocket_server_interop
                COMMAND "${Python3_EXECUTABLE}"
                    "${CMAKE_CURRENT_SOURCE_DIR}/tests/run_websocket_server.py"
                    $<TARGET_FILE:websocket_echo_server>)
            set_tests_properties(websocket_server_interop PROPERTIES TIMEOUT 20)
        endif()
    endif()

    if(EVENTLOOP_HTTP3_INTEROP_TESTS)
        find_package(Python3 REQUIRED COMPONENTS Interpreter)
        execute_process(
            COMMAND "${Python3_EXECUTABLE}" -c
                "import aioquic; assert aioquic.__version__ == '1.3.0', 'aioquic 1.3.0 required'"
            RESULT_VARIABLE aioquic_import_result
            ERROR_VARIABLE aioquic_import_error)
        if(NOT aioquic_import_result EQUAL 0)
            message(FATAL_ERROR
                "HTTP/3 interop tests require aioquic==1.3.0 in Python3_EXECUTABLE: ${aioquic_import_error}")
        endif()
        foreach(version v1 v2)
            add_test(NAME http3_outbound_${version}
                COMMAND "${Python3_EXECUTABLE}"
                    "${CMAKE_CURRENT_SOURCE_DIR}/tests/run_http3_outbound.py"
                    --client $<TARGET_FILE:http3_client> --version ${version})
            set_tests_properties(http3_outbound_${version} PROPERTIES
                TIMEOUT 60 LABELS "http3;interop")
        endforeach()
    endif()
endif()
