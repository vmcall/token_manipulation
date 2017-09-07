#include "stdafx.h"
#include "ntdll.hpp"

fnNtOpenProcessToken ntdll::NtOpenProcessToken = nullptr;
fnNtDuplicateToken ntdll::NtDuplicateToken = nullptr;
fnRtlAllocateAndInitializeSid ntdll::RtlAllocateAndInitializeSid = nullptr;
fnNtSetInformationToken ntdll::NtSetInformationToken = nullptr;
fnRtlLengthSid ntdll::RtlLengthSid = nullptr;
fnNtFilterToken ntdll::NtFilterToken = nullptr;
fnNtSetInformationThread ntdll::NtSetInformationThread = nullptr;

void ntdll::initialise_functions()
{
	auto module_handle = GetModuleHandle(L"ntdll.dll");
	ntdll::NtOpenProcessToken = reinterpret_cast<fnNtOpenProcessToken>(GetProcAddress(module_handle, "NtOpenProcessToken"));
	ntdll::NtDuplicateToken = reinterpret_cast<fnNtDuplicateToken>(GetProcAddress(module_handle, "NtDuplicateToken"));
	ntdll::RtlAllocateAndInitializeSid = reinterpret_cast<fnRtlAllocateAndInitializeSid>(GetProcAddress(module_handle, "RtlAllocateAndInitializeSid"));
	ntdll::NtSetInformationToken = reinterpret_cast<fnNtSetInformationToken>(GetProcAddress(module_handle, "NtSetInformationToken"));
	ntdll::RtlLengthSid = reinterpret_cast<fnRtlLengthSid>(GetProcAddress(module_handle, "RtlLengthSid"));
	ntdll::NtFilterToken = reinterpret_cast<fnNtFilterToken>(GetProcAddress(module_handle, "NtFilterToken"));
	ntdll::NtSetInformationThread = reinterpret_cast<fnNtSetInformationThread>(GetProcAddress(module_handle, "NtSetInformationThread"));
}
