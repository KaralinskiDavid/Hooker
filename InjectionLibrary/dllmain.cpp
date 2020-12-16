// dllmain.cpp : Определяет точку входа для приложения DLL.
#include "pch.h"
#include <string>
#include <sstream>
#include "Detours/src/detours.h"

HANDLE hStdOut;

VOID DisplayMessage(std::wstring message)
{
    WriteConsole(hStdOut, message.c_str(), message.size(), NULL, NULL);
}

std::wstring getKeyPath(HKEY key)
{
    std::wstring keyPath;
    if (key)
    {
        HMODULE hLib = LoadLibrary(L"ntdll.dll");
        if (hLib != NULL) {
            typedef DWORD(__stdcall* NtQueryKeyType) (HANDLE  KeyHandle, int KeyInformationClass, PVOID  KeyInformation, ULONG  Length, PULONG  ResultLength);
            NtQueryKeyType ntQueryKeyAddress = reinterpret_cast<NtQueryKeyType>(::GetProcAddress(hLib, "NtQueryKey"));
            if (ntQueryKeyAddress) {
                DWORD size = 0;
                DWORD result = 0;
                result = ntQueryKeyAddress(key, 3, 0, 0, &size);
                if (result == ((LONG)0xC0000023L))
                {
                    size = size + 2;
                    wchar_t* buffer = new (std::nothrow) wchar_t[size / sizeof(wchar_t)];
                    if (buffer != NULL)
                    {
                        result = ntQueryKeyAddress(key, 3, buffer, size, &size);
                        if (result == ((LONG)0x00000000L))
                        {
                            buffer[size / sizeof(wchar_t)] = L'\0';
                            keyPath = std::wstring(buffer + 2);
                        }

                        delete[] buffer;
                    }
                }
            }
            FreeLibrary(hLib);
        }
    }
    return keyPath;
}

HANDLE(WINAPI* real_CreateFile) (LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) = CreateFile;
BOOL(WINAPI* real_ReadFile) (HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) = ReadFile;
BOOL(WINAPI* real_WriteFile) (HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) = WriteFile;
BOOL(WINAPI* real_DeleteFile) (LPCWSTR lpFileName) = DeleteFile;

LSTATUS(WINAPI* real_RegCreateKey) (HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult) = RegCreateKey;
LSTATUS(WINAPI* real_RegOpenKey) (HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult) = RegOpenKey;
LSTATUS(WINAPI* real_RegCloseKey) (HKEY hKey) = RegCloseKey;
LSTATUS(WINAPI* real_RegDeleteKey) (HKEY hKey, LPCWSTR lpSubKey) = RegDeleteKey;
LSTATUS(WINAPI* real_RegGetValue) (HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValue, DWORD dwFlags, LPDWORD pdwType, PVOID pvData, LPDWORD pcbData) = RegGetValue;
LSTATUS(WINAPI* real_RegSetValue) (HKEY hKey, LPCWSTR lpSubKey, DWORD dwType, LPCWSTR lpData, DWORD cbData) = RegSetValue;

HANDLE WINAPI HookCreateFile(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    DisplayMessage(L"Create file: " + (std::wstring)lpFileName + L"\n");
    return real_CreateFile(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}
BOOL WINAPI HookReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) {
    std::wostringstream wss;
    wss << "Read from file " << hFile << " " << nNumberOfBytesToRead << " bytes\n";
    DisplayMessage(wss.str());
    return real_ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}
BOOL WINAPI HookWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped)
{
    std::wostringstream wss;
    wss << "Write to file " << hFile << " " << nNumberOfBytesToWrite << " bytes\n";
    DisplayMessage(wss.str());
    return real_WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}
BOOL WINAPI HookDeleteFile(LPCWSTR lpFileName)
{
    DisplayMessage(L"Delete file: " + (std::wstring)lpFileName + L"\n");
    return real_DeleteFile(lpFileName);
}

LSTATUS WINAPI HookRegCreateKey(HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult)
{
    DisplayMessage(L"Create key " + (std::wstring)lpSubKey + L"\n");
    return real_RegCreateKey(hKey, lpSubKey, phkResult);
}
LSTATUS WINAPI HookRegOpenKey(HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult)
{
    DisplayMessage(L"Open key " + (std::wstring)lpSubKey + L"\n");
    return real_RegOpenKey(hKey, lpSubKey, phkResult);
}
LSTATUS WINAPI HookRegCloseKey(HKEY hKey)
{
    DisplayMessage(L"Close key " + getKeyPath(hKey) + L"\n");
    return real_RegCloseKey(hKey);
}
LSTATUS WINAPI HookRegDeleteKey(HKEY hKey, LPCWSTR lpSubKey)
{
    DisplayMessage(L"Delete key " + (std::wstring)lpSubKey + L"\n");
    return real_RegDeleteKey(hKey, lpSubKey);
}
LSTATUS WINAPI HookRegGetValue(HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValue, DWORD dwFlags, LPDWORD pdwType, PVOID pvData, LPDWORD pcbData)
{
    DisplayMessage(L"Get value from key " + (std::wstring)lpSubKey + L"\n");
    return real_RegGetValue(hKey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData);
}
LSTATUS WINAPI HookRegSetValue(HKEY hKey, LPCWSTR lpSubKey, DWORD dwType, LPCWSTR lpData, DWORD cbData)
{
    DisplayMessage(L"Set value " + (std::wstring)lpData + L" to key " + (std::wstring)lpSubKey + L"\n");
    return real_RegSetValue(hKey, lpSubKey, dwType, lpData, cbData);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);

        DisableThreadLibraryCalls(hModule);
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        DetourAttach(&(PVOID&)real_CreateFile, HookCreateFile);
        DetourAttach(&(PVOID&)real_DeleteFile, HookDeleteFile);
        DetourAttach(&(PVOID&)real_WriteFile, HookWriteFile);
        DetourAttach(&(PVOID&)real_ReadFile, HookReadFile);

        DetourAttach(&(PVOID&)real_RegCreateKey, HookRegCreateKey);
        DetourAttach(&(PVOID&)real_RegOpenKey, HookRegOpenKey);
        DetourAttach(&(PVOID&)real_RegCloseKey, HookRegCloseKey);
        DetourAttach(&(PVOID&)real_RegDeleteKey, HookRegDeleteKey);
        DetourAttach(&(PVOID&)real_RegSetValue, HookRegSetValue);
        DetourAttach(&(PVOID&)real_RegGetValue, HookRegGetValue);

        DetourTransactionCommit();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        DetourDetach(&(PVOID&)real_CreateFile, HookCreateFile);
        DetourDetach(&(PVOID&)real_DeleteFile, HookDeleteFile);
        DetourDetach(&(PVOID&)real_WriteFile, HookWriteFile);
        DetourDetach(&(PVOID&)real_ReadFile, HookReadFile);

        DetourDetach(&(PVOID&)real_RegCreateKey, HookRegCreateKey);
        DetourDetach(&(PVOID&)real_RegOpenKey, HookRegOpenKey);
        DetourDetach(&(PVOID&)real_RegCloseKey, HookRegCloseKey);
        DetourDetach(&(PVOID&)real_RegDeleteKey, HookRegDeleteKey);
        DetourDetach(&(PVOID&)real_RegSetValue, HookRegSetValue);
        DetourDetach(&(PVOID&)real_RegGetValue, HookRegGetValue);

        DetourTransactionCommit();
        CloseHandle(hStdOut);
        break;
    }
    return TRUE;
}

