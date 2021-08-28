#include <stdio.h>
#include <Windows.h>
#include <tchar.h>
#include "Injector.h"





int wmain(int argc, wchar_t* argv[]) {
	Injector injector;

	if (argc < 3)
	{
		printf("\nUsage: ManualInject [DLL name] [WINDOW NAME]\n");
		return -1;
	}

	printf("Opening file %ls for proc %ls", argv[1], argv[2]);;
	return injector.Inject(argv[1], argv[2]);;
}