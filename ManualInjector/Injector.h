#pragma once
#include <stdio.h>
#include <Windows.h>
#include <tchar.h>
#include <cstdio>
#include <tlhelp32.h>
#include <iostream>
#include <fstream>

class Injector
{

public:
	int Inject(wchar_t* filename, wchar_t* process);
	~Injector();
	void PrintInjectedMethod();

private:
	HANDLE hProcess;
	HANDLE hThread;
	PVOID buffer, image, mem;
};

