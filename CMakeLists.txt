cmake_minimum_required(VERSION 3.20)
project(event_loop VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

if(WIN32)
    include(CTest)
    find_package(Threads REQUIRED)
    option(EVENTLOOP_WINDOWS_TLS "Build Windows TLS/WebSocket support" ON)
    set(EVENTLOOP_CONFIG_NEEDS_BOTAN ${EVENTLOOP_WINDOWS_TLS})
    if(EVENTLOOP_WINDOWS_TLS)
        find_package(Botan 3 REQUIRED)
    endif()
    add_library(eventloop
        src/event_loop.cc
        src/executor/single_thread_executor.cc
        src/executor/multi_thread_executor.cc
        src/tcp_acceptor.cc
        src/tcp_stream.cc
        src/udp_socket.cc
        src/util/arg_parser.cc
        src/http/request.cc
        src/http/mime_types.cc
        src/http/resource.cc
        src/http/directory_listing.cc
        src/http/session.cc
        src/http/server.cc
        src/windows/iocp_loop.cc
        src/windows/http_file_operations.cc
        src/windows/socket_operations.cc
    )
    if(EVENTLOOP_WINDOWS_TLS)
        target_sources(eventloop PRIVATE src/tls_stream.cc src/ws/web_socket.cpp)
        target_link_libraries(eventloop PUBLIC botan::botan)
        target_compile_definitions(eventloop PUBLIC EVENTLOOP_WINDOWS_TLS=1)
    endif()
    add_library(eventloop::eventloop ALIAS eventloop)
    target_include_directories(eventloop PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    )
    target_include_directories(eventloop PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_compile_features(eventloop PUBLIC cxx_std_23)
    target_compile_definitions(eventloop PRIVATE NOMINMAX)
    target_link_libraries(eventloop PUBLIC ws2_32 mswsock Threads::Threads)
    if(BUILD_SHARED_LIBS)
        target_compile_definitions(eventloop PRIVATE EVENTLOOP_WINDOWS_SHARED=1)
    endif()
    if(MSVC)
        target_compile_options(eventloop PRIVATE /W4)
    endif()
    if(BUILD_TESTING)
        add_executable(http_api_test tests/http_api.cc)
        target_link_libraries(http_api_test PRIVATE eventloop::eventloop)
        add_test(NAME http_api COMMAND http_api_test)
        set_tests_properties(http_api PROPERTIES TIMEOUT 10)
        if(EVENTLOOP_WINDOWS_TLS)
            set_tests_properties(http_api PROPERTIES ENVIRONMENT_MODIFICATION
                "PATH=path_list_prepend:$<TARGET_FILE_DIR:botan::botan>")
        endif()

        add_executable(coroutine_smoke_test tests/coroutine_smoke.cc)
        target_link_libraries(coroutine_smoke_test PRIVATE eventloop::eventloop)
        add_test(NAME coroutine_smoke COMMAND coroutine_smoke_test)

        add_executable(socket_api_test tests/socket_api.cc)
        target_link_libraries(socket_api_test PRIVATE eventloop::eventloop)
        if(EVENTLOOP_WINDOWS_TLS)
            target_compile_definitions(socket_api_test PRIVATE EVENTLOOP_TEST_TLS=1)
        endif()
        add_test(NAME socket_api COMMAND socket_api_test)
        set_tests_properties(socket_api PROPERTIES TIMEOUT 10)
        if(EVENTLOOP_WINDOWS_TLS)
            set_tests_properties(socket_api PROPERTIES ENVIRONMENT_MODIFICATION
                "PATH=path_list_prepend:$<TARGET_FILE_DIR:botan::botan>")
        endif()

        add_executable(windows_iocp_test tests/windows_iocp.cc)
        target_include_directories(windows_iocp_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(windows_iocp_test PRIVATE eventloop)
        if(BUILD_SHARED_LIBS)
            target_compile_definitions(windows_iocp_test PRIVATE
                EVENTLOOP_WINDOWS_SHARED=1)
        endif()
        add_test(NAME windows_iocp COMMAND windows_iocp_test)
        set_tests_properties(windows_iocp PROPERTIES TIMEOUT 10)

        add_executable(windows_socket_operations_test
            tests/windows_socket_operations.cc)
        target_link_libraries(windows_socket_operations_test PRIVATE eventloop)
        add_test(NAME windows_socket_operations
                 COMMAND windows_socket_operations_test)
        set_tests_properties(windows_socket_operations PROPERTIES TIMEOUT 10)

        add_executable(windows_iocp_lifecycle_test
            tests/windows_iocp_lifecycle.cc)
        target_include_directories(windows_iocp_lifecycle_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(windows_iocp_lifecycle_test PRIVATE eventloop)
        add_test(NAME windows_iocp_lifecycle
                 COMMAND windows_iocp_lifecycle_test)
        set_tests_properties(windows_iocp_lifecycle PROPERTIES TIMEOUT 10)
        if(EVENTLOOP_WINDOWS_TLS)
            add_executable(web_socket_test tests/web_socket.cc)
            target_link_libraries(web_socket_test PRIVATE eventloop::eventloop)
            add_test(NAME web_socket COMMAND web_socket_test)
        endif()
    endif()

    if(EVENTLOOP_WINDOWS_TLS)
        add_executable(http_server examples/http_server.cc)
        target_link_libraries(http_server PRIVATE eventloop::eventloop)
    endif()

    add_executable(executor_benchmark benchmark/executor_benchmark.cc)
    target_link_libraries(executor_benchmark PRIVATE eventloop::eventloop)
    add_executable(event_loop_benchmark benchmark/event_loop_benchmark.cc)
    target_link_libraries(event_loop_benchmark PRIVATE eventloop::eventloop)
    add_executable(coroutine_socket_benchmark
        benchmark/coroutine_socket_benchmark.cc)
    target_link_libraries(coroutine_socket_benchmark PRIVATE eventloop::eventloop)
    if(MSVC)
        target_compile_options(executor_benchmark PRIVATE /W4)
        target_compile_options(event_loop_benchmark PRIVATE /W4)
        target_compile_options(coroutine_socket_benchmark PRIVATE /W4)
    endif()

    set(eventloop_package_dir "${CMAKE_INSTALL_LIBDIR}/cmake/eventloop")
    install(TARGETS eventloop EXPORT eventloopTargets
        ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
    )
    set(eventloop_windows_excluded_headers
        PATTERN "file_io.h" EXCLUDE
    )
    if(NOT EVENTLOOP_WINDOWS_TLS)
        list(APPEND eventloop_windows_excluded_headers
            PATTERN "tls_context.h" EXCLUDE
            PATTERN "tls_stream.h" EXCLUDE
            PATTERN "ws" EXCLUDE
        )
    endif()
    install(DIRECTORY include/eventloop/
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/eventloop"
        ${eventloop_windows_excluded_headers}
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
    return()
endif()

set(EVENTLOOP_CONFIG_NEEDS_BOTAN ON)
find_package(Botan 3 REQUIRED)
find_package(Threads REQUIRED)
include(CTest)

add_library(eventloop
    include/eventloop/event_loop.h
    include/eventloop/executor.h
    include/eventloop/file_io.h
    include/eventloop/http/mime_types.h
    include/eventloop/http/request.h
    include/eventloop/http/server.h
    include/eventloop/http/session.h
    include/eventloop/ip_endpoint.h
    include/eventloop/tcp_acceptor.h
    include/eventloop/tcp_stream.h
    include/eventloop/task.h
    include/eventloop/task_composition.h
    include/eventloop/tls_context.h
    include/eventloop/tls_stream.h
    include/eventloop/unique_fd.h
    include/eventloop/udp_socket.h
    include/eventloop/util/arg_parser.h
    include/eventloop/ws/web_socket.h
    src/linux/epoll_loop.cc
    src/linux/http_file_operations.cc
    src/linux/socket_operations.cc
    src/event_loop.cc
    src/executor/single_thread_executor.cc
    src/executor/multi_thread_executor.cc
    src/http/directory_listing.cc
    src/http/mime_types.cc
    src/http/request.cc
    src/http/resource.h
    src/http/resource.cc
    src/http/server.cc
    src/http/session.cc
    src/http2/connection.h
    src/http2/connection.cc
    src/http2/hpack.h
    src/http2/hpack.cc
    src/http2/session.h
    src/http2/session.cc
    src/tcp_acceptor.cc
    src/tcp_stream.cc
    src/tls_stream.cc
    src/util/arg_parser.cc
    src/udp_socket.cc
    src/ws/web_socket.cpp
)

add_library(eventloop::eventloop ALIAS eventloop)

target_include_directories(eventloop
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
target_include_directories(eventloop PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_features(eventloop PUBLIC cxx_std_23)
target_link_libraries(eventloop PUBLIC botan::botan Threads::Threads)
target_compile_options(eventloop PRIVATE -Wall -Wextra -Wpedantic -Wconversion)

set(eventloop_package_dir "${CMAKE_INSTALL_LIBDIR}/cmake/eventloop")

install(TARGETS eventloop EXPORT eventloopTargets
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
)
install(DIRECTORY include/eventloop DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")
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

add_executable(tcp_echo examples/tcp_echo.cc)
target_link_libraries(tcp_echo PRIVATE eventloop::eventloop)
target_compile_options(tcp_echo PRIVATE -Wall -Wextra -Wpedantic -Wconversion)

add_executable(tls_echo examples/tls_echo.cc)
target_link_libraries(tls_echo PRIVATE eventloop::eventloop)
target_compile_options(tls_echo PRIVATE -Wall -Wextra -Wpedantic -Wconversion)

add_executable(http_server examples/http_server.cc)
target_link_libraries(http_server PRIVATE eventloop::eventloop)
target_compile_options(http_server PRIVATE -Wall -Wextra -Wpedantic -Wconversion)

add_executable(http_client
    examples/http_client.cc
    examples/http_client_url.cc
    examples/http_client_resolve.cc
)
target_link_libraries(http_client PRIVATE eventloop::eventloop)
target_compile_options(http_client PRIVATE -Wall -Wextra -Wpedantic -Wconversion)

add_executable(http_benchmark_server examples/http_benchmark_server.cc)
target_link_libraries(http_benchmark_server PRIVATE eventloop::eventloop)
target_compile_options(http_benchmark_server PRIVATE -Wall -Wextra -Wpedantic -Wconversion)

add_executable(executor_benchmark benchmark/executor_benchmark.cc)
target_link_libraries(executor_benchmark PRIVATE eventloop::eventloop)
target_compile_options(executor_benchmark PRIVATE -Wall -Wextra -Wpedantic -Wconversion)

add_executable(event_loop_benchmark benchmark/event_loop_benchmark.cc)
target_link_libraries(event_loop_benchmark PRIVATE eventloop::eventloop)
target_compile_options(event_loop_benchmark PRIVATE -Wall -Wextra -Wpedantic -Wconversion)

add_executable(file_io_benchmark benchmark/file_io_benchmark.cc)
target_link_libraries(file_io_benchmark PRIVATE eventloop::eventloop)
target_compile_options(file_io_benchmark PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(file_io_benchmark PRIVATE -Wno-mismatched-new-delete)
endif()

add_executable(coroutine_socket_benchmark benchmark/coroutine_socket_benchmark.cc)
target_link_libraries(coroutine_socket_benchmark PRIVATE eventloop::eventloop)
target_compile_options(coroutine_socket_benchmark PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(coroutine_socket_benchmark PRIVATE -Wno-mismatched-new-delete)
endif()

if(BUILD_TESTING)
    add_executable(http_api_test tests/http_api.cc)
    target_link_libraries(http_api_test PRIVATE eventloop::eventloop)
    target_compile_options(http_api_test PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME http_api COMMAND http_api_test)
    set_tests_properties(http_api PROPERTIES TIMEOUT 10)

    add_executable(coroutine_smoke_test tests/coroutine_smoke.cc)
    target_link_libraries(coroutine_smoke_test PRIVATE eventloop::eventloop)
    target_compile_options(coroutine_smoke_test PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME coroutine_smoke COMMAND coroutine_smoke_test)

    add_executable(socket_api_test tests/socket_api.cc)
    target_link_libraries(socket_api_test PRIVATE eventloop::eventloop)
    target_compile_definitions(socket_api_test PRIVATE EVENTLOOP_TEST_TLS=1)
    target_compile_options(socket_api_test PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME socket_api COMMAND socket_api_test)
    set_tests_properties(socket_api PROPERTIES TIMEOUT 10)

    find_program(OPENSSL_EXECUTABLE openssl REQUIRED)
    find_program(CURL_EXECUTABLE curl REQUIRED)
    add_executable(tls_loopback_test tests/tls_loopback.cc)
    target_link_libraries(tls_loopback_test PRIVATE eventloop::eventloop)
    target_compile_options(tls_loopback_test PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
    add_test(
        NAME tls_loopback
        COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_tls_loopback.sh
                     $<TARGET_FILE:tls_loopback_test>
    )
    set_tests_properties(tls_loopback PROPERTIES TIMEOUT 10)

    add_executable(event_loop_test tests/event_loop.cc)
    target_link_libraries(event_loop_test PRIVATE eventloop::eventloop)
    target_compile_options(event_loop_test PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_link_options(event_loop_test PRIVATE -Wl,--wrap=timerfd_settime)
        target_compile_definitions(event_loop_test PRIVATE EVENTLOOP_TEST_WRAP_TIMERFD=1)
    endif()
    add_test(NAME event_loop COMMAND event_loop_test)

    add_executable(http_test tests/http_test.cc)
    target_link_libraries(http_test PRIVATE eventloop::eventloop)
    target_compile_options(http_test PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME http COMMAND http_test)

    add_executable(http2_hpack_test tests/http2_hpack.cc)
    target_include_directories(http2_hpack_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(http2_hpack_test PRIVATE eventloop::eventloop)
    target_compile_options(http2_hpack_test PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME http2_hpack COMMAND http2_hpack_test)

    add_executable(executor_test tests/executor.cc)
    target_include_directories(executor_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(executor_test PRIVATE eventloop::eventloop)
    target_compile_options(executor_test PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME executor COMMAND executor_test)
    set_tests_properties(executor PROPERTIES TIMEOUT 30)

    add_executable(web_socket_test tests/web_socket.cc)
    target_link_libraries(web_socket_test PRIVATE eventloop::eventloop)
    target_compile_options(web_socket_test PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME web_socket COMMAND web_socket_test)

    add_executable(task_test tests/task.cc)
    target_link_libraries(task_test PRIVATE eventloop::eventloop)
    target_compile_options(task_test PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        # GCC diagnoses the standard coroutine allocation/deallocation pair as
        # mismatched when allocation receives coroutine function arguments.
        target_compile_options(task_test PRIVATE -Wno-mismatched-new-delete)
    endif()
    add_test(NAME task COMMAND task_test)

    add_executable(task_composition_test tests/task_composition.cc)
    target_link_libraries(task_composition_test PRIVATE eventloop::eventloop)
    target_compile_options(task_composition_test PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(task_composition_test PRIVATE -Wno-mismatched-new-delete)
    endif()
    add_test(NAME task_composition COMMAND task_composition_test)

    add_executable(task_handle_test tests/task_handle.cc)
    target_link_libraries(task_handle_test PRIVATE eventloop::eventloop)
    target_compile_options(task_handle_test PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(task_handle_test PRIVATE -Wno-mismatched-new-delete)
    endif()
    add_test(NAME task_handle COMMAND task_handle_test)

    add_executable(file_io_test tests/file_io.cc)
    target_link_libraries(file_io_test PRIVATE eventloop::eventloop)
    target_compile_options(file_io_test PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(file_io_test PRIVATE -Wno-mismatched-new-delete)
    endif()
    add_test(NAME file_io COMMAND file_io_test)
    set_tests_properties(file_io PROPERTIES TIMEOUT 10)

    add_executable(coroutine_tcp_test tests/tcp_coroutine.cc)
    target_link_libraries(coroutine_tcp_test PRIVATE eventloop::eventloop)
    target_compile_options(coroutine_tcp_test PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(coroutine_tcp_test PRIVATE -Wno-mismatched-new-delete)
    endif()
    add_test(NAME coroutine_tcp COMMAND coroutine_tcp_test)
    set_tests_properties(coroutine_tcp PROPERTIES TIMEOUT 10)

    add_executable(coroutine_udp_test tests/udp_coroutine.cc)
    target_link_libraries(coroutine_udp_test PRIVATE eventloop::eventloop)
    target_compile_options(coroutine_udp_test PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(coroutine_udp_test PRIVATE -Wno-mismatched-new-delete)
    endif()
    add_test(NAME coroutine_udp COMMAND coroutine_udp_test)
    set_tests_properties(coroutine_udp PROPERTIES TIMEOUT 10)

    add_test(
        NAME http_server
        COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_http_server.sh
                     $<TARGET_FILE:http_server>
                     ${OPENSSL_EXECUTABLE}
                     ${CURL_EXECUTABLE}
    )
    set_tests_properties(http_server PROPERTIES TIMEOUT 15)
endif()
