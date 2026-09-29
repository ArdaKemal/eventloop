#pragma once

#ifdef _WIN32
#include <cstdint>
namespace eventloop { using native_socket = std::uintptr_t; }
#else
namespace eventloop { using native_socket = int; }
#endif
