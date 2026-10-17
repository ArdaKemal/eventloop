cmake_minimum_required(VERSION 3.20)
project(skirmish LANGUAGES CXX)

set(EVENTLOOP_SOURCE_DIR "${CMAKE_CURRENT_LIST_DIR}/../.." CACHE PATH
    "eventloop source checkout; set to empty to use an installed package")
if(EVENTLOOP_SOURCE_DIR)
    add_subdirectory("${EVENTLOOP_SOURCE_DIR}"
        "${CMAKE_CURRENT_BINARY_DIR}/eventloop" EXCLUDE_FROM_ALL)
else()
    find_package(eventloop CONFIG REQUIRED)
endif()
find_package(OpenSSL 3.5 REQUIRED)

add_executable(skirmish main.cc server.cc world.cc)
target_link_libraries(skirmish PRIVATE eventloop::eventloop OpenSSL::Crypto)
target_compile_features(skirmish PRIVATE cxx_std_23)
target_compile_definitions(skirmish PRIVATE
    SKIRMISH_WEB_ROOT="${CMAKE_CURRENT_SOURCE_DIR}/web")

add_executable(skirmish_world_test world.cc world_test.cc)
target_compile_features(skirmish_world_test PRIVATE cxx_std_23)

if(NOT MSVC)
    target_compile_options(skirmish PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(skirmish_world_test PRIVATE -Wall -Wextra -Wpedantic)
endif()

enable_testing()
add_test(NAME skirmish_world_test COMMAND skirmish_world_test)

option(SKIRMISH_INTEROP_TESTS "Enable the draft-07 smoke test using aioquic 1.3.0" OFF)
if(SKIRMISH_INTEROP_TESTS)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    execute_process(COMMAND "${Python3_EXECUTABLE}" -c
        "import aioquic; assert aioquic.__version__ == '1.3.0', 'aioquic 1.3.0 required'"
        RESULT_VARIABLE aioquic_import_result ERROR_VARIABLE aioquic_import_error)
    if(NOT aioquic_import_result EQUAL 0)
        message(FATAL_ERROR "Skirmish interop requires aioquic==1.3.0: ${aioquic_import_error}")
    endif()
    add_test(NAME skirmish_webtransport
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/smoke_test.py"
            --server $<TARGET_FILE:skirmish>)
    set_tests_properties(skirmish_webtransport PROPERTIES TIMEOUT 40 LABELS "http3;interop")
endif()
