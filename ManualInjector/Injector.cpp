#include "Injector.h"


typedef HMODULE(WINAPI* pLoadLibraryA)(LPCSTR);
typedef FARPROC(WINAPI* pGetProcAddress)(HMODULE, LPCSTR);

typedef BOOL(WINAPI* PDLL_MAIN)(HMODULE, DWORD, PVOID);

typedef struct _MANUAL_INJECT
{
    PVOID ImageBase;
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_BASE_RELOCATION BaseRelocation;
    PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;
    pLoadLibraryA fnLoadLibraryA;
    pGetProcAddress fnGetProcAddress;
} MANUAL_INJECT, *PMANUAL_INJECT;

static DWORD WINAPI __stdcall LoadDll(PVOID p)
{
    PMANUAL_INJECT ManualInject = (PMANUAL_INJECT)p;
    DWORD delta = (DWORD)((LPBYTE)ManualInject->ImageBase - ManualInject->NtHeaders->OptionalHeader.ImageBase);
    PIMAGE_BASE_RELOCATION pIBR = ManualInject->BaseRelocation;

    // Relocate the image
    while (pIBR->VirtualAddress)
    {
        if (pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
        {
            DWORD count = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            PWORD list = (PWORD)(pIBR + 1);

            for (int i = 0; i < count; i++)
            {
                if (list[i])
                {
                    PDWORD ptr = (PDWORD)((LPBYTE)ManualInject->ImageBase + (pIBR->VirtualAddress + (list[i] & 0xFFF)));
                    *ptr += delta;
                }
            }
        }

        pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);
    }

    PIMAGE_IMPORT_DESCRIPTOR pIID = ManualInject->ImportDirectory;

    // Resolve DLL imports

    while (pIID->Characteristics)
    {
        PIMAGE_THUNK_DATA OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)ManualInject->ImageBase + pIID->OriginalFirstThunk);
        PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)ManualInject->ImageBase + pIID->FirstThunk);

        HMODULE hModule = ManualInject->fnLoadLibraryA((LPCSTR)ManualInject->ImageBase + pIID->Name);

        if (!hModule)
        {
            return FALSE;
        }

        while (OrigFirstThunk->u1.AddressOfData)
        {
            if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
            {
                // Import by ordinal

                DWORD Function = (DWORD)ManualInject->fnGetProcAddress(hModule, (LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));

                if (!Function)
                {
                    return FALSE;
                }

                FirstThunk->u1.Function = Function;
            }

            else
            {
                // Import by name

                PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)ManualInject->ImageBase + OrigFirstThunk->u1.AddressOfData);
                DWORD Function = (DWORD)ManualInject->fnGetProcAddress(hModule, (LPCSTR)pIBN->Name);

                if (!Function)
                {
                    return FALSE;
                }

                FirstThunk->u1.Function = Function;
            }

            OrigFirstThunk++;
            FirstThunk++;
        }

        pIID++;
    }

    if (ManualInject->NtHeaders->OptionalHeader.AddressOfEntryPoint)
    {
        PDLL_MAIN EntryPoint = (PDLL_MAIN)((LPBYTE)ManualInject->ImageBase + ManualInject->NtHeaders->OptionalHeader.AddressOfEntryPoint);
        return EntryPoint((HMODULE)ManualInject->ImageBase, DLL_PROCESS_ATTACH, NULL); // Call the entry point
    }

    return TRUE;
}

DWORD WINAPI LoadDllEnd()
{
    return 0;
}

void AdjustPrivileges() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;

    if (OpenProcessToken((HANDLE)-1, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        tp.Privileges[0].Luid.LowPart = 20;
        tp.Privileges[0].Luid.HighPart = 0;

        AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
        CloseHandle(hToken);
    }
}

PVOID OpenDLLFile(wchar_t* file_name) {
    printf("Opening the DLL.\n");
    HANDLE hFile = CreateFile(file_name, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL); // Open the DLL

    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("\nError: Unable to open the DLL (%d)\n", GetLastError());
        return 0;
    }

    DWORD FileSize = GetFileSize(hFile, NULL);
    PVOID buffer = VirtualAlloc(NULL, FileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    printf("Starting reading dll\n");

    if (!buffer)
    {
        printf("\nError: Unable to allocate memory for DLL data (%d)\n", GetLastError());

        CloseHandle(hFile);
        return 0;
    }

    // Read the DLL
    DWORD read;
    if (!ReadFile(hFile, buffer, FileSize, &read, NULL))
    {
        printf("\nError: Unable to read the DLL (%d)\n", GetLastError());

        CloseHandle(hFile);

        return 0;
    }

    CloseHandle(hFile);

    printf("DLL file is opened\n");

    return buffer;
}

bool IsHeaderCorrent(PVOID buffer) {
    printf("Start checking the file\n");
    PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)buffer;
    printf("Created pIDH\n");

    if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("\nError: Invalid executable image.\n");
        return 0;
    }

    printf("DOS Signature is correct\n");

    PIMAGE_NT_HEADERS pINH = (PIMAGE_NT_HEADERS)((LPBYTE)buffer + pIDH->e_lfanew);

    if (pINH->Signature != IMAGE_NT_SIGNATURE)
    {
        printf("\nError: Invalid PE header.\n");

        return 0;
    }

    if (!(pINH->FileHeader.Characteristics & IMAGE_FILE_DLL))
    {
        printf("\nError: The image is not DLL.\n");
        return 0;
    }
    
    return 1;
}

DWORD FindProcessId(const wchar_t* processName)
{
    PROCESSENTRY32 processInfo;
    processInfo.dwSize = sizeof(processInfo);

    HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (processesSnapshot == INVALID_HANDLE_VALUE) {
        printf("Invalid handle value");
        return 0;
    }

    Process32First(processesSnapshot, &processInfo);

    do
    {
        //printf("%ls\n", processInfo.szExeFile);
        if (wcscmp(processName, processInfo.szExeFile) == 0)
        {
            printf("Find process with name %ls\n", processInfo.szExeFile);
            CloseHandle(processesSnapshot);
            return processInfo.th32ProcessID;
        }
    } while (Process32Next(processesSnapshot, &processInfo));

    CloseHandle(processesSnapshot);
    printf("Cannot find the required proces %ls\n", processName);
    return 0;
}

void PrintMemReg(PVOID start, size_t size) {
    std::ofstream binfile;
    char* mem = new char[size];
    binfile.open("out.bin");
    printf("Printing mem region start: %#x; size: %#x", start, size);
    printf("File is open: %d", binfile.is_open());
    memcpy(mem, start, size);
    for (int i = 0; i < size; ++i) {
        binfile << mem[i];
    }
    binfile.flush();
    binfile.close();
 
    delete[] mem;
}

void Injector::PrintInjectedMethod() {
    PrintMemReg(LoadDll, (DWORD)LoadDllEnd - (DWORD)LoadDll);
}

int Injector::Inject(wchar_t* filename, wchar_t* process) 
{
    printf("inject function start %#x\n", LoadDll);

    AdjustPrivileges();

    buffer = OpenDLLFile(filename);

    if (!IsHeaderCorrent(buffer)) 
    {
        printf("Header is incorrect");
        return -1;
    }

    printf("Openning the process\n");

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, FindProcessId(process));

    if (!hProcess)
    {
        printf("Error: Unable to open target process (%d)\n", GetLastError());
        return -1;
    }

    PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)buffer;
    PIMAGE_NT_HEADERS pINH = (PIMAGE_NT_HEADERS)((LPBYTE)buffer + pIDH->e_lfanew);

    printf("Allocating memory for the DLL.\n");
    image = VirtualAllocEx(hProcess, NULL, pINH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); // Allocate memory for the DLL

    if (!image)
    {
        printf("Error: Unable to allocate memory for the DLL (%d)\n", GetLastError());
        return -1;
    }

    printf("Copying headers into target process.\n");

    if (!WriteProcessMemory(hProcess, image, buffer, pINH->OptionalHeader.SizeOfHeaders, NULL))
    {
        printf("\nError: Unable to copy headers to target process (%d)\n", GetLastError());
        return -1;
    }

    PIMAGE_SECTION_HEADER pISH = (PIMAGE_SECTION_HEADER)(pINH + 1);

    // Copy the DLL to target process

    printf("Copying sections to target process.\n");

    for (int i = 0; i < pINH->FileHeader.NumberOfSections; i++)
    {
        if (!WriteProcessMemory(hProcess, (PVOID)((LPBYTE)image + pISH[i].VirtualAddress), (PVOID)((LPBYTE)buffer + pISH[i].PointerToRawData), pISH[i].SizeOfRawData, NULL)) 
        {
            printf("Error: Cannot write DLL to process (%d)", GetLastError());
            return -1;
        }
    }

    printf("Allocating memory for the loader code.\n");
    mem = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); // Allocate memory for the loader code

    if (!mem)
    {
        printf("\nError: Unable to allocate memory for the loader code (%d)\n", GetLastError());

        VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
        CloseHandle(hProcess);

        VirtualFree(buffer, 0, MEM_RELEASE);
        return -1;
    }

    printf("Loader code allocated at %#x\n", mem);
    
    MANUAL_INJECT ManualInject;
    memset(&ManualInject,0,sizeof(MANUAL_INJECT));
    printf("Image base located at %#x\n", image);
    ManualInject.ImageBase = image;
    ManualInject.NtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)image + pIDH->e_lfanew);
    ManualInject.BaseRelocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)image + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    ManualInject.ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)image + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    ManualInject.fnLoadLibraryA = LoadLibraryA;
    ManualInject.fnGetProcAddress = GetProcAddress;
    printf("Writing loader code to target process.\n");
    printf("Inject param size %#x\n", sizeof(MANUAL_INJECT));
    printf("Inject func start addr %#x\n", (PVOID)((PMANUAL_INJECT)mem + 1));
    
    WriteProcessMemory(hProcess, mem, &ManualInject, sizeof(MANUAL_INJECT), NULL); // Write the loader information to target process
    WriteProcessMemory(hProcess, (PVOID)((PMANUAL_INJECT)mem + 1), LoadDll, (DWORD)LoadDllEnd - (DWORD)LoadDll, NULL); // Write the loader code to target process

    printf("Executing loader code at %#x.\n", (LPTHREAD_START_ROUTINE)((PMANUAL_INJECT)mem + 1));
    hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((PMANUAL_INJECT)mem + 1), mem, 0, NULL); // Create a remote thread to execute the loader code

    if (!hThread)
    {
        printf("\nError: Unable to execute loader code (%d)\n", GetLastError());
        return -1;
    }
    WaitForSingleObject(hThread, INFINITE);
    DWORD ExitCode = 0;
    GetExitCodeThread(hThread, &ExitCode);

    if (!ExitCode)
    {
        printf("Wait error %d", ExitCode);
        return -1;
    }

    printf("\nDLL injected at %#x\n", image);

    if (pINH->OptionalHeader.AddressOfEntryPoint)
    {
        printf("\nDLL entry point: %#x\n", (PVOID)((LPBYTE)image + pINH->OptionalHeader.AddressOfEntryPoint));
    }

    return 0;
}

Injector::~Injector() {
    VirtualFreeEx(hProcess, mem, 0, MEM_RELEASE);
    //VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);

    CloseHandle(hThread);
    CloseHandle(hProcess);

    VirtualFree(buffer, 0, MEM_RELEASE);
}
