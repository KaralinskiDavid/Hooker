#include <iostream>
#include <Windows.h>

STARTUPINFO processStartupInfo;
PROCESS_INFORMATION processInfo;

int main()
{
    std::wstring invokableProcessPath = L"..\\InjectionLibrary\\Debug\\InvokableApplication.exe";
    std::wstring injectionLibPath = L"..\\InjectionLibrary\\Debug\\InjectionLibrary.dll";
    CreateProcess(invokableProcessPath.c_str(), NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &processStartupInfo, &processInfo);
    void* loadLibraryW = GetProcAddress(GetModuleHandle(L"Kernel32"), "LoadLibraryW");
    LPVOID lpvMemory = VirtualAllocEx(processInfo.hProcess, NULL, injectionLibPath.size() * sizeof(wchar_t) + 1, MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(processInfo.hProcess, lpvMemory, injectionLibPath.c_str(), injectionLibPath.size() * sizeof(wchar_t) + 1, NULL);
    HANDLE hRemoteThread = CreateRemoteThread(processInfo.hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)loadLibraryW, lpvMemory, NULL, NULL);
    WaitForSingleObject(hRemoteThread, INFINITE);
    CloseHandle(hRemoteThread);

    ResumeThread(processInfo.hThread);
    WaitForSingleObject(processInfo.hProcess, INFINITE);

    VirtualFreeEx(processInfo.hProcess, lpvMemory, 0, MEM_RELEASE);
    CloseHandle(processInfo.hProcess);
    CloseHandle(processInfo.hThread);

    std::cout << "Invoking process\n";
}