// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "ProcessTools.h"


HMODULE myModule{};

DWORD WINAPI ShutdownThread(_In_ LPVOID unused)
{
    Sleep(100);
    FreeLibraryAndExitThread(myModule, 0);
}

DWORD WINAPI MainThread(_In_ LPVOID unused) 
{
    // Disable hard coded bone limit

    // There is a check (probably an assertion) that does not allow armatures with 
    // over 1140 total bones (including bones found on ped components) to load.
    DWORD64 address = PatternScan("RDR2.exe", "49 8B 4E 50 81 B9 08 01");

    BYTE data[]{ 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 
        0x90, 0x90, 0x90 };

    WriteToProcessMemory(address, data, sizeof(data));

    CreateThread(NULL, 0, ShutdownThread, NULL, 0, NULL);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    myModule = hModule;
    HANDLE thread = NULL;
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);
            thread = CreateThread(NULL, 0, MainThread, NULL, 0, NULL);

            if (thread == NULL)
            {
                return FALSE;
            }

            CloseHandle(thread);
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}

