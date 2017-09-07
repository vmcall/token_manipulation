#include "stdafx.h"
#include "safe_handle.hpp"

safe_handle::~safe_handle()
{
	if (m_handle)
		CloseHandle(m_handle);
}

void safe_handle::set_handle(HANDLE handle)
{
	m_handle = handle;
}

HANDLE safe_handle::get_handle()
{
	return m_handle;
}
