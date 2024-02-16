/*------------------------------------------------------------------------------------------------*/

#include <stdio.h>
#include <Windows.h>

#define MIN_HOOK_IMPLEMENTATION
#include "MinHook.h"

/*------------------------------------------------------------------------------------------------*/

PBYTE scan_memory(PBYTE base_address, PCHAR signature, PCHAR mask);
void print_debug(const char* fmt, ...);

/*------------------------------------------------------------------------------------------------*/

UINT64(*original_send_lightning)(UINT64, UINT64, UINT64, UINT64) = { };
static UINT64 naked_send_lightning(UINT64 a1, UINT64 a2, UINT64 a3, UINT64 a4)
{
	print_debug("[ info ] intercepted %llX %llX %llX %llX.\n", a1, a2, a3, a4);
	if (a2 == 1 && a3 == 1 && a4 == 1) // enable lightning after windows waked up
	{
		return original_send_lightning(a1, a2, a3, a4);
	}
	if (a3 == 1 && a4 > 0x1000) // manual change lightning
	{
		return original_send_lightning(a1, a2, a3, a4);
	}

	print_debug("[ info ] fxcked %llX %llX %llX %llX.\n", a1, a2, a3, a4);
	return NULL;
}

/*------------------------------------------------------------------------------------------------*/

static void main_thread()
{
    auto main_module = reinterpret_cast<PBYTE>(GetModuleHandle(L"AsusOptimization.exe"));
    if (!main_module)
    {
		print_debug("[ error ] no main_module.\n");
        return;
    }

	auto send_lightning = scan_memory(main_module, const_cast<PCHAR>("\x33\xFF\x45\x8B\xF0"), const_cast<PCHAR>("xxxxx"));
	if (!send_lightning)
	{
		print_debug("[ error ] no send_lightning.\n");
		return;
	}
	send_lightning -= 0x21;

	MH_Initialize();
	MH_CreateHook(send_lightning, &naked_send_lightning, reinterpret_cast<void**>(&original_send_lightning));
	MH_EnableHook(send_lightning);

	print_debug("[ info ] hooked.\n");
}

/*------------------------------------------------------------------------------------------------*/

int __stdcall DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        auto thread = CreateThread(NULL, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(main_thread), nullptr, NULL, NULL);
        if (thread)
        {
            CloseHandle(thread);
        }
        else
        {
			print_debug("[ error ] thread creation failed.");
        }
    }
    return TRUE;
}

/*-----------------------------------------------------------------------------------------------*/

PBYTE scan_memory(PBYTE base_address, PCHAR signature, PCHAR mask)
{
	auto _compare = [](PCHAR data, PCHAR sig, PCHAR mask) -> bool
		{
			for (; *mask; mask += 1, data += 1, sig += 1)
			{
				if (*mask == 'x' && *data != *sig)
				{
					return false;
				}
			}
			return true;
		};

	SIZE_T mask_size = strlen(mask);
	PBYTE result = { };

	PIMAGE_NT_HEADERS headers = reinterpret_cast<PIMAGE_NT_HEADERS>(base_address + reinterpret_cast<PIMAGE_DOS_HEADER>(base_address)->e_lfanew);
	PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);

	for (DWORD section_it = NULL; section_it < headers->FileHeader.NumberOfSections && !result; ++section_it)
	{
		PIMAGE_SECTION_HEADER section = &sections[section_it];

		PCHAR virtualaddress = reinterpret_cast<PCHAR>(base_address + section->VirtualAddress);
		DWORD virtualsize = static_cast<DWORD>(section->Misc.VirtualSize - mask_size);

		for (ULONG i = NULL; i <= virtualsize; ++i)
		{
			if (_compare(&virtualaddress[i], signature, mask))
			{
				result = reinterpret_cast<PBYTE>(&virtualaddress[i]);
				break;
			}
		}
	}
	return result;
}

void print_debug(const char* fmt, ...)
{
	char buffer[0x256] = { };

	va_list ap = { }; va_start(ap, fmt);
	vsprintf_s(buffer, fmt, ap);
	va_end(ap);

	return OutputDebugStringA(buffer);
}

/*------------------------------------------------------------------------------------------------*/