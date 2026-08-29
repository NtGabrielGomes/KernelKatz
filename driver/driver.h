#pragma once

#include <windows.h>
#include <cstdint>

namespace nx {

inline constexpr DWORD IOCTL_MAP = 0x80202080;

struct MapReq {
    LARGE_INTEGER s0;
    LARGE_INTEGER pa;
    PVOID sh;
    PVOID va;
};

bool load_driver();
bool open_driver();
void close_driver();
HANDLE driver_handle();

bool pr8(std::uint64_t pa, std::uint64_t* v);
bool pw8(std::uint64_t pa, std::uint64_t v);
bool prn(std::uint64_t pa, void* buf, std::uint32_t len);
bool pwn(std::uint64_t pa, const void* buf, std::uint32_t len);
void enable_priv();

}
