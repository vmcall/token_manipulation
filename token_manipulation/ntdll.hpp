#pragma once
#include "stdafx.h"

#define CurrentThread ((HANDLE)(LONG_PTR)-2)

typedef NTSTATUS (NTAPI* fnNtOpenProcessToken)(
	HANDLE ProcessHandle,
	ACCESS_MASK DesiredAccess,
	PHANDLE TokenHandle);

typedef NTSTATUS (NTAPI* fnNtDuplicateToken)(
	HANDLE ExistingTokenHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	BOOLEAN EffectiveOnly,
	TOKEN_TYPE TokenType,
	PHANDLE NewTokenHandle
 );

typedef NTSTATUS (NTAPI* fnRtlAllocateAndInitializeSid)(
	IN PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
	IN UCHAR SubAuthorityCount,
	IN ULONG SubAuthority0,
	IN ULONG SubAuthority1,
	IN ULONG SubAuthority2,
	IN ULONG SubAuthority3,
	IN ULONG SubAuthority4,
	IN ULONG SubAuthority5,
	IN ULONG SubAuthority6,
	IN ULONG SubAuthority7,
	OUT PSID *Sid
);

typedef NTSTATUS (NTAPI* fnNtSetInformationToken)(
	_In_ HANDLE TokenHandle,
	_In_ TOKEN_INFORMATION_CLASS TokenInformationClass,
	_In_ PVOID TokenInformation,
	_In_ ULONG TokenInformationLength
);

typedef NTSTATUS (NTAPI* fnNtFilterToken)(
	_In_ HANDLE ExistingTokenHandle,
	_In_ ULONG Flags,
	_In_opt_ PTOKEN_GROUPS SidsToDisable,
	_In_opt_ PTOKEN_PRIVILEGES PrivilegesToDelete,
	_In_opt_ PTOKEN_GROUPS RestrictedSids,
	_Out_ PHANDLE NewTokenHandle
);

typedef ULONG (NTAPI* fnRtlLengthSid)(
	PSID Sid
);

typedef NTSTATUS (NTAPI* fnNtClose)(
	_In_ HANDLE Handle
);


typedef NTSTATUS (NTAPI* fnNtSetInformationThread)(
	_In_       HANDLE ThreadHandle,
	_In_       THREADINFOCLASS ThreadInformationClass,
	_In_       PVOID ThreadInformation,
	_In_       ULONG ThreadInformationLength
);



namespace ntdll
{
	void initialise_functions();

	extern fnNtOpenProcessToken NtOpenProcessToken;
	extern fnNtDuplicateToken NtDuplicateToken;
	extern fnRtlAllocateAndInitializeSid RtlAllocateAndInitializeSid;
	extern fnNtSetInformationToken NtSetInformationToken;
	extern fnRtlLengthSid RtlLengthSid;
	extern fnNtFilterToken NtFilterToken;
	extern fnNtSetInformationThread NtSetInformationThread;
}