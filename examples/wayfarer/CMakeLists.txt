cmake_minimum_required(VERSION 3.20)
project(wayfarer LANGUAGES CXX)

set(EVENTLOOP_SOURCE_DIR "${CMAKE_CURRENT_LIST_DIR}/../.." CACHE PATH
    "eventloop source checkout used by the standalone wayfarer build")
add_subdirectory("${EVENTLOOP_SOURCE_DIR}" "${CMAKE_CURRENT_BINARY_DIR}/eventloop-root")

add_executable(wayfarer main.cc http3.cc
    ../http_client_url.cc ../http_client_resolve.cc)
target_include_directories(wayfarer PRIVATE ..)
target_compile_features(wayfarer PRIVATE cxx_std_23)
target_link_libraries(wayfarer PRIVATE eventloop::eventloop)
if(MSVC)
    target_compile_options(wayfarer PRIVATE /W4)
else()
    target_compile_options(wayfarer PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
endif()

# Wayfarer W3 acceptance checks use an independent aioquic HTTP/3 peer. They
# are opt-in because aioquic is an optional Python dependency.
#
#   cmake -S examples/wayfarer -B /tmp/wayfarer-build \
#     -DWAYFARER_HTTP3_TESTS=ON -DBUILD_TESTING=OFF \
#     -DPython3_EXECUTABLE=/path/to/aioquic-venv/bin/python
#   cmake --build /tmp/wayfarer-build --target wayfarer
#   ctest --test-dir /tmp/wayfarer-build -R wayfarer_http3_w3 --output-on-failure
option(WAYFARER_HTTP3_TESTS
    "Enable Wayfarer W3 HTTP/3 acceptance checks (requires aioquic 1.3.0)" OFF)
if(WAYFARER_HTTP3_TESTS)
    enable_testing()
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    execute_process(
        COMMAND "${Python3_EXECUTABLE}" -c
            "import aioquic; assert aioquic.__version__ == '1.3.0', 'aioquic 1.3.0 required'"
        RESULT_VARIABLE aioquic_import_result
        ERROR_VARIABLE aioquic_import_error)
    if(NOT aioquic_import_result EQUAL 0)
        message(FATAL_ERROR
            "Wayfarer W3 tests require aioquic==1.3.0 in Python3_EXECUTABLE: ${aioquic_import_error}")
    endif()
    add_test(NAME wayfarer_http3_w3
        COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/run_w3_aioquic.py"
            --wayfarer $<TARGET_FILE:wayfarer> --version both)
    set_tests_properties(wayfarer_http3_w3 PROPERTIES
        TIMEOUT 300 LABELS "wayfarer;http3;interop")
endif()
