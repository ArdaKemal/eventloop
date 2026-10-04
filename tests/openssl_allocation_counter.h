#pragma once

// Counts OpenSSL's own heap allocations through CRYPTO_set_mem_functions.
// OpenSSL calls malloc directly, so a replaced operator new does not see
// them. Install before anything else uses OpenSSL.
#include <openssl/crypto.h>

#include <atomic>
#include <cstddef>
#include <cstdlib>

namespace eventloop::test {

inline std::atomic<std::size_t> openssl_allocations {0};

inline auto openssl_counting_malloc(std::size_t size, const char*, int) -> void*
{
    openssl_allocations.fetch_add(1, std::memory_order_relaxed);
    return std::malloc(size);
}

inline auto openssl_counting_realloc(void* pointer, std::size_t size, const char*, int) -> void*
{
    // A reallocation can move the block, so it counts as an allocation.
    if (size != 0) openssl_allocations.fetch_add(1, std::memory_order_relaxed);
    return std::realloc(pointer, size);
}

inline auto openssl_counting_free(void* pointer, const char*, int) -> void
{
    std::free(pointer);
}

[[nodiscard]] inline auto install_openssl_allocation_counter() -> bool
{
    return CRYPTO_set_mem_functions(openssl_counting_malloc, openssl_counting_realloc,
                                    openssl_counting_free) == 1;
}

} // namespace eventloop::test
