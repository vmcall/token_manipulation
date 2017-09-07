#pragma once
#include "stdafx.h"

class safe_handle
{
public:
	safe_handle() : m_handle(nullptr) {}
	safe_handle(HANDLE handle) : m_handle (handle) {}
	~safe_handle();
	HANDLE get_handle();
	void set_handle(HANDLE);

private:
	HANDLE m_handle;
};