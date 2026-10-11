cmake_minimum_required(VERSION 3.20)
project(stonegate LANGUAGES CXX)

set(EVENTLOOP_SOURCE_DIR "${CMAKE_CURRENT_LIST_DIR}/../.." CACHE PATH
    "eventloop source checkout; set to empty to use an installed package")
if(EVENTLOOP_SOURCE_DIR)
    add_subdirectory("${EVENTLOOP_SOURCE_DIR}"
        "${CMAKE_CURRENT_BINARY_DIR}/eventloop" EXCLUDE_FROM_ALL)
else()
    find_package(eventloop CONFIG REQUIRED)
endif()

add_executable(stonegate stonegate.cc configuration.cc)
target_link_libraries(stonegate PRIVATE eventloop::eventloop)
target_compile_features(stonegate PRIVATE cxx_std_23)

if(MSVC)
    target_compile_options(stonegate PRIVATE /W4)
else()
    target_compile_options(stonegate PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(stonegate PRIVATE -Wno-mismatched-new-delete)
    endif()
endif()

include(CTest)
if(BUILD_TESTING)
    find_package(Python3 QUIET COMPONENTS Interpreter)
    # The lifecycle harness sends POSIX SIGINT to the child process.
    if(Python3_Interpreter_FOUND AND NOT WIN32)
        add_test(NAME stonegate_configuration
            COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/configuration_test.py"
                $<TARGET_FILE:stonegate>)
        set_tests_properties(stonegate_configuration PROPERTIES TIMEOUT 45)
    endif()
endif()
