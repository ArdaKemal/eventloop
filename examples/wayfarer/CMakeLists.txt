cmake_minimum_required(VERSION 3.20)
project(wayfarer LANGUAGES CXX)

set(EVENTLOOP_SOURCE_DIR "${CMAKE_CURRENT_LIST_DIR}/../.." CACHE PATH
    "eventloop source checkout used by the standalone wayfarer build")
add_subdirectory("${EVENTLOOP_SOURCE_DIR}" "${CMAKE_CURRENT_BINARY_DIR}/eventloop-root")

add_executable(wayfarer main.cc
    ../common/http_client_url.cc ../common/http_client_resolve.cc)
target_include_directories(wayfarer PRIVATE ../common)
target_compile_features(wayfarer PRIVATE cxx_std_23)
target_link_libraries(wayfarer PRIVATE eventloop::eventloop)
if(MSVC)
    target_compile_options(wayfarer PRIVATE /W4)
else()
    target_compile_options(wayfarer PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
endif()

# Wayfarer acceptance checks use an independent aioquic HTTP/3 peer and an h2
# HTTP/2 peer. They are opt-in because those are optional Python dependencies.
#
#   cmake -S examples/wayfarer -B /tmp/wayfarer-build \
#     -DWAYFARER_HTTP3_TESTS=ON -DBUILD_TESTING=OFF \
#     -DPython3_EXECUTABLE=/path/to/aioquic-venv/bin/python
#   cmake --build /tmp/wayfarer-build --target wayfarer
#   ctest --test-dir /tmp/wayfarer-build --output-on-failure
option(WAYFARER_HTTP3_TESTS
    "Enable Wayfarer HTTP/3 and W4 CLI acceptance checks (requires aioquic 1.3.0, h2)" OFF)
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
            "Wayfarer HTTP/3 tests require aioquic==1.3.0 in Python3_EXECUTABLE: ${aioquic_import_error}")
    endif()
    add_test(NAME wayfarer_http3_w3
        COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/run_w3_aioquic.py"
            --wayfarer $<TARGET_FILE:wayfarer> --version both)
    set_tests_properties(wayfarer_http3_w3 PROPERTIES
        TIMEOUT 300 LABELS "wayfarer;http3;interop")

    execute_process(
        COMMAND "${Python3_EXECUTABLE}" -c "import h2"
        RESULT_VARIABLE h2_import_result
        ERROR_VARIABLE h2_import_error)
    if(h2_import_result EQUAL 0)
        add_test(NAME wayfarer_w4_cli
            COMMAND "${Python3_EXECUTABLE}"
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/run_w4.py"
                --wayfarer $<TARGET_FILE:wayfarer> --version all)
        set_tests_properties(wayfarer_w4_cli PROPERTIES
            TIMEOUT 300 LABELS "wayfarer;http3;interop")
    else()
        message(STATUS
            "h2 unavailable; skipping wayfarer_w4_cli HTTP/2 checks: ${h2_import_error}")
    endif()
endif()
