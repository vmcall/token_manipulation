#pragma once
#include "safe_handle.hpp"

namespace token_manipulation
{
	bool run();
	bool find_elevated_process(safe_handle& process_handle);
	bool open_process_token(safe_handle& process_handle, ACCESS_MASK desired_access, safe_handle& token_handle);
	bool duplicate_token(safe_handle& token_handle, ACCESS_MASK desired_access, _TOKEN_TYPE token_type, safe_handle& duplicated_token);
	bool create_restricted_token(safe_handle& token_handle, safe_handle& restricted_token);
	bool is_process_admin(HANDLE process_handle);
	bool lower_token_il(safe_handle& token_handle);
	bool launch_auto_elevating_app(safe_handle& process_handle);
	bool impersonate_user(safe_handle& token_handle);
	bool revert_impersonation();
	bool launch_payload();
}