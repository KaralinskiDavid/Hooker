#include <iostream>
#include <Windows.h>

int main()
{
    HANDLE hFile = CreateFile(L"B:\\test.txt", GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    std::string testData = "Test data";
    WriteFile(hFile, testData.c_str(), testData.size(), NULL, NULL);
    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
    char buf[40];
    DWORD bufSize = sizeof(buf);
    ZeroMemory(&buf, sizeof(buf));
    ReadFile(hFile, buf, 31, NULL, NULL);
    CloseHandle(hFile);
    DeleteFile(L"B:\\test.txt");

    HKEY hKeyOpened;
    RegOpenKey(HKEY_CURRENT_USER, L"Software\\Microsoft", &hKeyOpened);
    RegCloseKey(hKeyOpened);

    HKEY hKeyCrated;
    RegCreateKey(HKEY_CURRENT_USER, L"Software\\Test", &hKeyCrated);
    LPCWSTR lpTestData = L"Test data";
    RegSetValue(HKEY_CURRENT_USER, L"Software\\Test", REG_SZ, lpTestData, sizeof(wchar_t) * (wcslen(lpTestData) + 1));

    ZeroMemory(&buf, sizeof(buf));
    RegGetValue(HKEY_CURRENT_USER, L"Software\\Test", NULL, RRF_RT_ANY, NULL, buf, &bufSize);
    RegCloseKey(hKeyCrated);
    RegDeleteKey(HKEY_CURRENT_USER, L"Software\\Test");

    std::cout << "Invokable application\n";
}
