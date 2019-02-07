#pragma once
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>

uintptr_t GetProcessId(const char *);
MODULEINFO GetModuleInfoEx(uintptr_t, const char *, HANDLE);
bool CreateSignature(MODULEINFO, uintptr_t, unsigned int, HANDLE , BYTE *);
void SignatureDefaultFormatString(const BYTE *, unsigned int, char *);
void decToHexa(int, char *);