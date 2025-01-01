#include <windows.h>
#include <shellapi.h>
#include "pch.h"
#include <string>
#include <iostream>
#include "detours.h"

#pragma comment(lib,"detours.lib")



extern "C" __declspec(dllexport)
LRESULT WINAPI CALLBACK Hooker(int code, WPARAM wParam, LPARAM lParam)
{
    return CallNextHookEx(NULL, code, wParam, lParam);
}

HHOOK g_HookProc;

extern "C" __declspec(dllexport)
void EnableGlobalHook()
{
    g_HookProc = SetWindowsHookEx(WH_CBT, Hooker, GetModuleHandle(L"ProtAPIHooker.dll"), 0);
}

extern "C" __declspec(dllexport)
void DisableGlobalHook(int password)
{
    if (password != 436375628) return;
    UnhookWindowsHookEx(g_HookProc);
}

BOOL IsApp(LPCSTR lpName) {
    char modName[MAX_PATH];
    GetModuleFileNameA(NULL, modName, MAX_PATH);
    char* p = strrchr(modName, '\\');

    return !strcmp(p + 1, lpName);
}


// 原始CreateProcess函数指针
typedef BOOL(WINAPI* Real_CreateProcess)(
    LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
    LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID,
    LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

Real_CreateProcess RealCreateProcess = nullptr;

// Hooked CreateProcess function
BOOL WINAPI HookedCreateProcess(
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{
    // Call ProtEndPointProtection.exe with the command line of the process to be created.

    LPWSTR substr = const_cast<LPWSTR>(L"nnd.exe");
    LPWSTR result = wcsstr(lpCommandLine , substr);

    if (result != nullptr)
    {
        return RealCreateProcess(lpApplicationName, lpCommandLine, lpProcessAttributes,
            lpThreadAttributes, bInheritHandles, dwCreationFlags,
            lpEnvironment, lpCurrentDirectory, lpStartupInfo,
            lpProcessInformation);
    }
    
    std::wstring checkCmdLine = L"nnd.exe ";
    
    
    checkCmdLine += lpCommandLine;
    

    SHELLEXECUTEINFO shexInfo = { sizeof(shexInfo) };
    shexInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
    //shexInfo.fMask = 0;
    shexInfo.lpFile = L"nnd.exe";
    shexInfo.lpParameters = checkCmdLine.c_str() + wcslen(L"nnd.exe ");
    //shexInfo.nShow = SW_HIDE;

    if (!ShellExecuteEx(&shexInfo)) {
        MessageBox(NULL, L"Create EndPoint Failed", L"", 0);
        return RealCreateProcess(lpApplicationName, lpCommandLine, lpProcessAttributes,
            lpThreadAttributes, bInheritHandles, dwCreationFlags,
            lpEnvironment, lpCurrentDirectory, lpStartupInfo,
            lpProcessInformation);
    }

    WaitForSingleObject(shexInfo.hProcess, INFINITE);
    DWORD exitCode = 0;
    if (GetExitCodeProcess(shexInfo.hProcess, &exitCode)) {
        CloseHandle(shexInfo.hProcess);

        if (exitCode == 1) {
            //std::wcout << L"Process creation denied by ProtEndPointProtection.exe." << std::endl;
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE; // 阻止进程创建
        }
    }

    // Allow process creation
    return RealCreateProcess(lpApplicationName, lpCommandLine, lpProcessAttributes,
        lpThreadAttributes, bInheritHandles, dwCreationFlags,
        lpEnvironment, lpCurrentDirectory, lpStartupInfo,
        lpProcessInformation);
}

// Initialization function to install the hook
extern "C" __declspec(dllexport)
void InitializeHook()
{
    // Get the address of the original CreateProcessW function
    HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");
    RealCreateProcess = (Real_CreateProcess)GetProcAddress(hKernel32, "CreateProcessW");
    
    // Install the hook
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)RealCreateProcess, HookedCreateProcess);
    LONG error = DetourTransactionCommit();

    if (error != NO_ERROR) {
        MessageBox(NULL, L"无法启动防护。", L"ProtEndPointProtectionService", MB_ICONERROR);
        //std::wcerr << L"Failed to install hook: " << error << std::endl;
    }
}

// Entry point for DLL or application
BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD ul_reason_for_call,
    LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        //DisableThreadLibraryCalls(hModule);
        InitializeHook(); // Install hooks when the DLL is loaded
        break;
    case DLL_PROCESS_DETACH:
        // Remove hooks if necessary
        break;
    }
    return TRUE;
}