#include "ProcessTools.h"
#include "pch.h"

MODULEINFO GetModuleInfo(const char* szModule)
{
	MODULEINFO moduleInfo{};
	HMODULE hModule = GetModuleHandle(szModule);

	if (hModule == NULL) 
	{
		return moduleInfo;
	}

	HANDLE process = GetCurrentProcess();

	GetModuleInformation(process, hModule, &moduleInfo, sizeof(MODULEINFO));

	CloseHandle(process);
	CloseHandle(hModule);

	return moduleInfo;
}

void WriteToProcessMemory(uintptr_t address, BYTE* data, int dataLength) 
{
	DWORD oldProtect{};

	VirtualProtect(reinterpret_cast<void*>(address), dataLength, PAGE_EXECUTE_READWRITE, &oldProtect);

	memcpy(reinterpret_cast<void*>(address), data, dataLength);

	VirtualProtect(reinterpret_cast<void*>(address), dataLength, oldProtect, &oldProtect);
}

DWORD64 PatternScan(const char* module, const char* signature)
{
	static auto pattern_to_byte = [](const char* pattern)
		{
			auto bytes = std::vector<char>{};
			auto start = const_cast<char*>(pattern);
			auto end = const_cast<char*>(pattern) + strlen(pattern);

			for (auto current = start; current < end; ++current)
			{
				if (*current == '?')
				{
					++current;
					if (*current == '?')
						++current;
					bytes.push_back('\?');
				}
				else
				{
					bytes.push_back(strtoul(current, &current, 16));
				}
			}
			return bytes;
		};

	MODULEINFO mInfo = GetModuleInfo(module);
	DWORD64 base = (DWORD64)mInfo.lpBaseOfDll;
	DWORD64 sizeOfImage = (DWORD64)mInfo.SizeOfImage;
	auto patternBytes = pattern_to_byte(signature);

	DWORD64 patternLength = patternBytes.size();
	auto data = patternBytes.data();

	for (DWORD64 i = 0; i < sizeOfImage - patternLength; i++)
	{
		bool found = true;
		for (DWORD64 j = 0; j < patternLength; j++)
		{
			char a = '\?';
			char b = *(char*)(base + i + j);
			found &= data[j] == a || data[j] == b;
		}
		if (found)
		{
			return base + i;
		}
	}
	return NULL;
}