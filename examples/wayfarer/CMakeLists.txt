cmake_minimum_required(VERSION 3.20)
project(wayfarer LANGUAGES CXX)

set(EVENTLOOP_SOURCE_DIR "${CMAKE_CURRENT_LIST_DIR}/../.." CACHE PATH
    "eventloop source checkout used by the standalone wayfarer build")
add_subdirectory("${EVENTLOOP_SOURCE_DIR}" "${CMAKE_CURRENT_BINARY_DIR}/eventloop-root")

add_executable(wayfarer main.cc http3.cc
    ../common/http_client_url.cc ../common/http_client_resolve.cc)
target_include_directories(wayfarer PRIVATE ../common)
target_compile_features(wayfarer PRIVATE cxx_std_23)
target_link_libraries(wayfarer PRIVATE eventloop::eventloop)
if(MSVC)
    target_compile_options(wayfarer PRIVATE /W4)
else()
    target_compile_options(wayfarer PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
endif()
