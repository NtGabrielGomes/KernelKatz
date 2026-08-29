#pragma once
#include <windows.h>
#include <cstdint>
#include <initializer_list>

namespace dm {

class Engine {
public:

    bool init() noexcept;

    bool init_precomputed(uint64_t ntos_base, uint64_t trampoline_pa) noexcept;

    uint64_t ntos_base()     const noexcept { return m_ntos_base; }
    uint64_t trampoline_pa() const noexcept { return m_tramp_pa; }

    bool kernel_call(const char* func, std::initializer_list<uint64_t> args,
                     uint64_t* out_rax) noexcept;

    HANDLE open_process(uint32_t pid) noexcept;

    uint64_t get_cr3(uint32_t pid) noexcept;

    uint64_t get_peb(uint32_t pid) noexcept;

private:
    bool     locate_trampoline() noexcept;
    bool     verify_trampoline(uint64_t func_pa) noexcept;
    uint64_t export_va(const char* func) noexcept;

    static uint32_t export_rva(const char* func,
                               uint8_t* ref_bytes, uint32_t ref_len) noexcept;

    using TrampFn = uint64_t (*)(uint64_t, uint64_t, uint64_t, uint64_t,
                                 uint64_t, uint64_t, uint64_t, uint64_t,
                                 uint64_t, uint64_t);
    TrampFn  m_tramp_fn  = nullptr;
    uint64_t m_tramp_pa  = 0;
    uint64_t m_ntos_base = 0;
};

}
