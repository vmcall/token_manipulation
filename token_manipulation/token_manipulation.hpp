#pragma once

namespace token_manipulation
{
	bool run();
	HANDLE find_elevated_process();
	HANDLE duplicate_token(HANDLE token_handle, ACCESS_MASK desired_access, _TOKEN_TYPE token_type);
	HANDLE create_restricted_token(HANDLE token_handle);
	bool is_process_admin(HANDLE process_handle);
	bool lower_token_il(HANDLE token_handle);
	bool launch_auto_elevating_app(HANDLE* process_handle);
	bool impersonate_user(HANDLE token_handle);
	bool revert_impersonation();
	bool launch_payload();
}