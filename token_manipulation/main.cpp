// token_manipulation.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "token_manipulation.hpp"
#include "ntdll.hpp"

int main()
{
	ntdll::initialise_functions();
	token_manipulation::run();

	std::cin.get();

    return 0;
}

