cmake_minimum_required(VERSION 3.20)
project(event_loop LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(Botan 3 REQUIRED)
include(CTest)

add_library(eventloop
    include/eventloop/byte_stream.h
    include/eventloop/event_loop.h
    include/eventloop/http/mime_types.h
    include/eventloop/http/request.h
    include/eventloop/http/server.h
    include/eventloop/http/session.h
    include/eventloop/tcp_acceptor.h
    include/eventloop/tcp_stream.h
    include/eventloop/tls_acceptor.h
    include/eventloop/tls_context.h
    include/eventloop/tls_stream.h
    include/eventloop/util/arg_parser.h
    src/linux/epoll_loop.cc
    src/event_loop.cc
    src/http/directory_listing.cc
    src/http/mime_types.cc
    src/http/request.cc
    src/http/server.cc
    src/http/session.cc
    src/tcp_acceptor.cc
    src/tcp_stream.cc
    src/tls_acceptor.cc
    src/tls_stream.cc
    src/util/arg_parser.cc
)

add_library(eventloop::eventloop ALIAS eventloop)

target_include_directories(eventloop
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_compile_features(eventloop PUBLIC cxx_std_23)
target_link_libraries(eventloop PUBLIC botan::botan)
target_compile_options(eventloop PRIVATE -Wall -Wextra -Wpedantic -Wconversion)

add_executable(tcp_echo examples/tcp_echo.cc)
target_link_libraries(tcp_echo PRIVATE eventloop::eventloop)
target_compile_options(tcp_echo PRIVATE -Wall -Wextra -Wpedantic -Wconversion)

add_executable(tls_echo examples/tls_echo.cc)
target_link_libraries(tls_echo PRIVATE eventloop::eventloop)
target_compile_options(tls_echo PRIVATE -Wall -Wextra -Wpedantic -Wconversion)

add_executable(http_server examples/http_server.cc)
target_link_libraries(http_server PRIVATE eventloop::eventloop)
target_compile_options(http_server PRIVATE -Wall -Wextra -Wpedantic -Wconversion)

add_executable(http_benchmark_server examples/http_benchmark_server.cc)
target_link_libraries(http_benchmark_server PRIVATE eventloop::eventloop)
target_compile_options(http_benchmark_server PRIVATE -Wall -Wextra -Wpedantic -Wconversion)

if(BUILD_TESTING)
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

    add_executable(http_test tests/http_test.cc)
    target_link_libraries(http_test PRIVATE eventloop::eventloop)
    target_compile_options(http_test PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME http COMMAND http_test)

    add_test(
        NAME http_server
        COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_http_server.sh
                     $<TARGET_FILE:http_server>
                     ${OPENSSL_EXECUTABLE}
                     ${CURL_EXECUTABLE}
    )
    set_tests_properties(http_server PROPERTIES TIMEOUT 15)
endif()
