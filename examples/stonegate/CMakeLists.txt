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

add_executable(stonegate stonegate.cc)
target_link_libraries(stonegate PRIVATE eventloop::eventloop)
target_compile_features(stonegate PRIVATE cxx_std_23)
