/*------------------------------------------------------------------------------------------------*/

#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>

/*------------------------------------------------------------------------------------------------*/

const char* dll_path = "C:\\Windows\\System32\\asus_always_keybd_light.dll";
int wait_asus_process();
bool enable_debug_priveleges();

/*------------------------------------------------------------------------------------------------*/

int main()
{
    int asus_process_id = wait_asus_process();
    if (!asus_process_id)
    {
        MessageBox(NULL, L"keybd_light", L"find process failed.", NULL);
        return NULL;
    }
    enable_debug_priveleges(); // for access the asus service

    auto handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, static_cast<DWORD>(asus_process_id));
    if (!handle)
    {
        MessageBox(NULL, L"keybd_light", L"open process failed.", NULL);
        return NULL;
    }

    void* path_buffer = VirtualAllocEx(handle, nullptr, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!path_buffer)
    {
        MessageBox(NULL, L"keybd_light", L"allocation failed.", NULL);
        return NULL;
    }

    if (!WriteProcessMemory(handle, path_buffer, dll_path, strlen(dll_path) + 1, nullptr))
    {
        MessageBox(NULL, L"keybd_light", L"write failed.", NULL);
        return NULL;
    }

    HANDLE thread = CreateRemoteThread(handle, NULL, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(&LoadLibraryA), path_buffer, NULL, NULL);
    if (!thread)
    {
        MessageBox(NULL, L"keybd_light", L"execute thread failed.", NULL);
        return NULL;
    }

    CloseHandle(thread);
    CloseHandle(handle);

    return NULL;
}

/*------------------------------------------------------------------------------------------------*/

int wait_asus_process()
{
    auto get_process = [](const wchar_t* process_name) -> int
        {
            HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snapshot == INVALID_HANDLE_VALUE) 
            {
                return NULL;
            }

            PROCESSENTRY32 entry = { }; entry.dwSize = sizeof(entry);
            if (!Process32First(snapshot, &entry))
            {
                CloseHandle(snapshot);
                return NULL;
            }

            do
            {
                if (wcscmp(entry.szExeFile, process_name) == 0) 
                {
                    CloseHandle(snapshot);
                    return entry.th32ProcessID;
                }
            } while (Process32Next(snapshot, &entry));

            CloseHandle(snapshot);
            return NULL;
        };

    while (true)
    {
        auto result = get_process(L"AsusOptimization.exe");
        if (result)
        {
            return result;
        }
        Sleep(1000);
    }
    return NULL;
}

bool enable_debug_priveleges()
{
    HANDLE token = { };
    TOKEN_PRIVILEGES new_priveleges = { };

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token))
    {
        return false;
    }
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &new_priveleges.Privileges[0].Luid))
    {
        CloseHandle(token);
        return false;
    }

    new_priveleges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    new_priveleges.PrivilegeCount = 1;

    if (!AdjustTokenPrivileges(token, FALSE, &new_priveleges, 0, NULL, NULL))
    {
        CloseHandle(token);
        return false;
    }

    CloseHandle(token);
    return true;
}

/*------------------------------------------------------------------------------------------------*/