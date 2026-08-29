#include "syscall.h"
#include "log.h"

#include <windows.h>
#include <winternl.h>
#include <vector>
#include <cstring>

namespace nx {
namespace {

using NtOpenSection_t = NTSTATUS(NTAPI*)(
    PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);

using NtMapViewOfSection_t = NTSTATUS(NTAPI*)(
    HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress,
    ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType,
    ULONG Win32Protect);

constexpr DWORD ViewShare = 1;

HMODULE g_fresh_ntdll = nullptr;

uint8_t* g_stub_page   = nullptr;
size_t   g_stub_offset = 0;
constexpr size_t kStubSize = 12;

uint32_t g_ssn_OpenProcess            = 0;
uint32_t g_ssn_CreateProcessEx        = 0;
uint32_t g_ssn_QuerySystemInformation = 0;
uint32_t g_ssn_DuplicateObject        = 0;
uint32_t g_ssn_Close                  = 0;
uint32_t g_ssn_QueryVirtualMemory     = 0;
uint32_t g_ssn_ReadVirtualMemory      = 0;

PVOID g_fp_OpenProcess            = nullptr;
PVOID g_fp_CreateProcessEx        = nullptr;
PVOID g_fp_QuerySystemInformation = nullptr;
PVOID g_fp_DuplicateObject        = nullptr;
PVOID g_fp_Close                  = nullptr;
PVOID g_fp_QueryVirtualMemory     = nullptr;
PVOID g_fp_ReadVirtualMemory      = nullptr;

static void* find_export(void* base, const char* name) noexcept {
    auto* dos = static_cast<IMAGE_DOS_HEADER*>(base);
    if (!base || dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(
        static_cast<uint8_t*>(base) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress || !dir.Size) return nullptr;

    auto* ed  = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
        static_cast<uint8_t*>(base) + dir.VirtualAddress);
    auto* names = reinterpret_cast<uint32_t*>(
        static_cast<uint8_t*>(base) + ed->AddressOfNames);
    auto* ords  = reinterpret_cast<uint16_t*>(
        static_cast<uint8_t*>(base) + ed->AddressOfNameOrdinals);
    auto* funcs = reinterpret_cast<uint32_t*>(
        static_cast<uint8_t*>(base) + ed->AddressOfFunctions);

    for (DWORD i = 0; i < ed->NumberOfNames; i++) {
        auto* n = reinterpret_cast<char*>(static_cast<uint8_t*>(base) + names[i]);
        if (n && strcmp(n, name) == 0)
            return static_cast<uint8_t*>(base) + funcs[ords[i]];
    }
    return nullptr;
}

HMODULE map_fresh_ntdll() noexcept {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-function-type"
    auto NtOpenSection = reinterpret_cast<NtOpenSection_t>(
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenSection"));
    auto NtMapViewOfSection = reinterpret_cast<NtMapViewOfSection_t>(
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtMapViewOfSection"));
#pragma GCC diagnostic pop
    if (!NtOpenSection || !NtMapViewOfSection) return nullptr;

    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"\\KnownDlls\\ntdll.dll");

    OBJECT_ATTRIBUTES attr;
    InitializeObjectAttributes(&attr, &name, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

    HANDLE section = nullptr;
    NTSTATUS st = NtOpenSection(
        &section, SECTION_MAP_READ | SECTION_MAP_EXECUTE, &attr);
    if (!NT_SUCCESS(st)) {
        log_err("syscall: NtOpenSection(KnownDlls\\ntdll) failed: 0x{:08X}",
                static_cast<uint32_t>(st));
        return nullptr;
    }

    PVOID base = nullptr;
    SIZE_T view_size = 0;
    st = NtMapViewOfSection(section, GetCurrentProcess(), &base, 0, 0, nullptr,
                            &view_size, ViewShare, 0, PAGE_EXECUTE_READ);
    NtClose(section);

    if (!NT_SUCCESS(st)) {
        log_err("syscall: NtMapViewOfSection failed: 0x{:08X}",
                static_cast<uint32_t>(st));
        return nullptr;
    }

    return static_cast<HMODULE>(base);
}

struct SyscallEntry {
    const char* name;
    uint32_t*   ssn_out;
    PVOID*      fp_out;
};

bool load_syscalls() noexcept {
    if (!g_fresh_ntdll) return false;

    SyscallEntry entries[] = {
        {"NtOpenProcess",            &g_ssn_OpenProcess,            &g_fp_OpenProcess},
        {"NtCreateProcessEx",        &g_ssn_CreateProcessEx,        &g_fp_CreateProcessEx},
        {"NtQuerySystemInformation", &g_ssn_QuerySystemInformation, &g_fp_QuerySystemInformation},
        {"NtDuplicateObject",        &g_ssn_DuplicateObject,        &g_fp_DuplicateObject},
        {"NtClose",                  &g_ssn_Close,                  &g_fp_Close},
        {"NtQueryVirtualMemory",     &g_ssn_QueryVirtualMemory,     &g_fp_QueryVirtualMemory},
        {"NtReadVirtualMemory",      &g_ssn_ReadVirtualMemory,      &g_fp_ReadVirtualMemory},
    };

    int ok = 0;
    for (auto& e : entries) {
        auto* fn = static_cast<const uint8_t*>(find_export(g_fresh_ntdll, e.name));
        if (!fn) {
            log_err("syscall: {} not found in fresh ntdll exports", e.name);
            continue;
        }
        *e.fp_out = const_cast<uint8_t*>(fn);

        if (fn[0] == 0x4C && fn[1] == 0x8B && fn[2] == 0xD1 && fn[3] == 0xB8) {
            memcpy(e.ssn_out, fn + 4, 4);
            ok++;
        } else {
            log_inf("syscall: {} has unexpected prologue: {:02X} {:02X} {:02X} {:02X}",
                    e.name, fn[0], fn[1], fn[2], fn[3]);
        }
    }

    return ok >= 3;
}

}

bool init_syscalls() noexcept {

    g_fresh_ntdll = map_fresh_ntdll();
    if (!g_fresh_ntdll) {
        log_inf("syscall: fresh ntdll mapping failed - using original ntdll");
        return false;
    }
    log_ok("syscall: fresh ntdll mapped at 0x{:X}",
           reinterpret_cast<uint64_t>(g_fresh_ntdll));

    if (!load_syscalls()) {
        log_err("syscall: export parse failed");
        return false;
    }

    g_stub_page = static_cast<uint8_t*>(
        VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (g_stub_page)
        log_ok("syscall: stub page at 0x{:X}", reinterpret_cast<uint64_t>(g_stub_page));

    log_inf("syscall: NtOpenProcess={} NtCreateProcessEx={} NtQuerySystemInformation={}",
            g_ssn_OpenProcess, g_ssn_CreateProcessEx, g_ssn_QuerySystemInformation);

    return true;
}

SyscallFn get_stub(uint32_t syscall_number) noexcept {
    if (!g_stub_page || g_stub_offset + kStubSize > 4096) return nullptr;

    uint8_t* slot = g_stub_page + g_stub_offset;
    g_stub_offset += kStubSize;

    slot[0] = 0x4C; slot[1] = 0x8B; slot[2] = 0xD1;

    slot[3] = 0xB8;
    memcpy(slot + 4, &syscall_number, 4);

    slot[8]  = 0x0F; slot[9]  = 0x05;

    slot[10] = 0xC3; slot[11] = 0x90;

    return reinterpret_cast<SyscallFn>(slot);
}

uint32_t extract_syscall_number(const char* func_name) noexcept {
    if (!g_fresh_ntdll) return 0;
    auto* fn = static_cast<const uint8_t*>(find_export(g_fresh_ntdll, func_name));
    if (!fn) return 0;
    if (fn[0] != 0x4C || fn[1] != 0x8B || fn[2] != 0xD1 || fn[3] != 0xB8)
        return 0;
    uint32_t num = 0;
    memcpy(&num, fn + 4, 4);
    return num;
}

template<typename Fn>
static Fn resolve_syscall(uint32_t ssn, PVOID fallback) noexcept {

    if (fallback) return reinterpret_cast<Fn>(fallback);

    if (ssn && g_stub_page) {
        auto stub = get_stub(ssn);
        if (stub) return reinterpret_cast<Fn>(stub);
    }
    return nullptr;
}

NTSTATUS NtOpenProcess_syscall(
    PHANDLE h, ACCESS_MASK a, POBJECT_ATTRIBUTES oa, PCLIENT_ID cid) noexcept
{
    using Fn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
    return resolve_syscall<Fn>(g_ssn_OpenProcess, g_fp_OpenProcess)
        (h, a, oa, cid);
}

NTSTATUS NtCreateProcessEx_syscall(
    PHANDLE h, ACCESS_MASK a, PVOID oa, HANDLE p, ULONG f,
    HANDLE s, HANDLE d, HANDLE t, ULONG j) noexcept
{
    using Fn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, ULONG,
                                HANDLE, HANDLE, HANDLE, ULONG);
    return resolve_syscall<Fn>(g_ssn_CreateProcessEx, g_fp_CreateProcessEx)
        (h, a, oa, p, f, s, d, t, j);
}

NTSTATUS NtQuerySystemInformation_syscall(
    SYSTEM_INFORMATION_CLASS c, PVOID p, ULONG l, PULONG r) noexcept
{
    using Fn = NTSTATUS(NTAPI*)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
    return resolve_syscall<Fn>(g_ssn_QuerySystemInformation, g_fp_QuerySystemInformation)
        (c, p, l, r);
}

NTSTATUS NtDuplicateObject_syscall(
    HANDLE sp, HANDLE sh, HANDLE tp, PHANDLE th,
    ACCESS_MASK a, ULONG attr, ULONG opt) noexcept
{
    using Fn = NTSTATUS(NTAPI*)(HANDLE, HANDLE, HANDLE, PHANDLE,
                                ACCESS_MASK, ULONG, ULONG);
    return resolve_syscall<Fn>(g_ssn_DuplicateObject, g_fp_DuplicateObject)
        (sp, sh, tp, th, a, attr, opt);
}

NTSTATUS NtClose_syscall(HANDLE h) noexcept {
    using Fn = NTSTATUS(NTAPI*)(HANDLE);
    return resolve_syscall<Fn>(g_ssn_Close, g_fp_Close)(h);
}

NTSTATUS NtQueryVirtualMemory_syscall(
    HANDLE h, uint64_t base, uint32_t cls, MBI* mbi, size_t len, size_t* ret) noexcept
{
    using Fn = NTSTATUS(NTAPI*)(HANDLE, uint64_t, uint32_t, MBI*, size_t, size_t*);
    return resolve_syscall<Fn>(g_ssn_QueryVirtualMemory, g_fp_QueryVirtualMemory)
        (h, base, cls, mbi, len, ret);
}

NTSTATUS NtReadVirtualMemory_syscall(
    HANDLE h, uint64_t base, void* buf, size_t size, size_t* read) noexcept
{
    using Fn = NTSTATUS(NTAPI*)(HANDLE, uint64_t, void*, size_t, size_t*);
    return resolve_syscall<Fn>(g_ssn_ReadVirtualMemory, g_fp_ReadVirtualMemory)
        (h, base, buf, size, read);
}

void* fresh_export(const char* func_name) noexcept {
    if (!g_fresh_ntdll) return nullptr;
    return find_export(g_fresh_ntdll, func_name);
}

}
