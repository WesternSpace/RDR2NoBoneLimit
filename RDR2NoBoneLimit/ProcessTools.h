#pragma once

void WriteToProcessMemory(uintptr_t address, BYTE* data, int dataLength);

DWORD64 PatternScan(const char* module, const char* signature);