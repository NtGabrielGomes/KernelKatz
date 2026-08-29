#pragma once
#include <windows.h>
#include <winternl.h>
#include <cstdint>

namespace nx {

using SyscallFn = NTSTATUS(NTAPI*)();

bool init_syscalls() noexcept;

SyscallFn get_stub(uint32_t syscall_number) noexcept;

uint32_t extract_syscall_number(const char* func_name) noexcept;

NTSTATUS NtOpenProcess_syscall(
    PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) noexcept;

NTSTATUS NtCreateProcessEx_syscall(
    PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes, HANDLE ParentProcess, ULONG Flags,
    HANDLE SectionHandle, HANDLE DebugPort, HANDLE TokenHandle,
    ULONG JobMemberLevel) noexcept;

NTSTATUS NtQuerySystemInformation_syscall(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation, ULONG SystemInformationLength,
    PULONG ReturnLength) noexcept;

NTSTATUS NtDuplicateObject_syscall(
    HANDLE SourceProcessHandle, HANDLE SourceHandle,
    HANDLE TargetProcessHandle, PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options) noexcept;

NTSTATUS NtClose_syscall(HANDLE Handle) noexcept;

struct MBI {
    uint64_t base_address;
    uint64_t allocation_base;
    uint32_t allocation_protect;
    uint32_t _pad1;
    uint64_t region_size;
    uint32_t state;
    uint32_t protect;
    uint32_t type;
    uint32_t _pad2;
};

NTSTATUS NtQueryVirtualMemory_syscall(
    HANDLE ProcessHandle, uint64_t BaseAddress, uint32_t MemoryInformationClass,
    MBI* MemoryInformation, size_t MemoryInformationLength,
    size_t* ReturnLength) noexcept;

NTSTATUS NtReadVirtualMemory_syscall(
    HANDLE ProcessHandle, uint64_t BaseAddress, void* Buffer,
    size_t BufferSize, size_t* NumberOfBytesRead) noexcept;

void* fresh_export(const char* func_name) noexcept;

}
