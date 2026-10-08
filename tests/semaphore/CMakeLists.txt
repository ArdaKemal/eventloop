cmake_minimum_required(VERSION 3.20)
project(eventloop_semaphore_tests LANGUAGES CXX)

include(CTest)
find_package(eventloop CONFIG REQUIRED)

foreach(name semaphore semaphore_allocations)
    add_executable(${name}_test ../${name}.cc)
    target_link_libraries(${name}_test PRIVATE eventloop::eventloop)
    if(MSVC)
        target_compile_options(${name}_test PRIVATE /W4)
    else()
        target_compile_options(${name}_test PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
    endif()
endforeach()
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    # The allocation counter implements global new/delete with malloc/free.
    target_compile_options(semaphore_allocations_test PRIVATE -Wno-mismatched-new-delete)
endif()
add_test(NAME semaphore COMMAND semaphore_test)
add_test(NAME semaphore_allocations COMMAND semaphore_allocations_test)
set_tests_properties(semaphore semaphore_allocations PROPERTIES TIMEOUT 15)

foreach(mode wrong_loop wrong_thread_acquire wrong_thread_release wrong_thread_move
             wrong_thread_self_move destroy_held destroy_reserved destroy_cancelled reuse_awaiter)
    add_test(NAME semaphore_${mode} COMMAND semaphore_test ${mode})
    set_tests_properties(semaphore_${mode} PROPERTIES TIMEOUT 15)
endforeach()
