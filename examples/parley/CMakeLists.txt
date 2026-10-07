cmake_minimum_required(VERSION 3.20)
project(parley LANGUAGES CXX)

set(EVENTLOOP_SOURCE_DIR "${CMAKE_CURRENT_LIST_DIR}/../.." CACHE PATH
    "eventloop source checkout; set to empty to use an installed package")
if(EVENTLOOP_SOURCE_DIR)
    add_subdirectory("${EVENTLOOP_SOURCE_DIR}"
        "${CMAKE_CURRENT_BINARY_DIR}/eventloop" EXCLUDE_FROM_ALL)
else()
    find_package(eventloop CONFIG REQUIRED)
endif()
find_package(OpenSSL 3.5 REQUIRED)

add_executable(parley main.cc api.cc hub.cc store.cc json.cc)
target_link_libraries(parley PRIVATE eventloop::eventloop OpenSSL::Crypto)
target_compile_features(parley PRIVATE cxx_std_23)
target_compile_definitions(parley PRIVATE
    PARLEY_WEB_ROOT="${CMAKE_CURRENT_SOURCE_DIR}/web")
if(NOT MSVC)
    target_compile_options(parley PRIVATE -Wall -Wextra -Wpedantic)
endif()
