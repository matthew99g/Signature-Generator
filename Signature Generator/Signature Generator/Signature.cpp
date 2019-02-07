#define _CRT_SECURE_NO_WARNINGS

#include "Signature.h"

uintptr_t GetProcessId(const char *szProcessName) {
	uintptr_t uProcId = NULL;
	PROCESSENTRY32 pEntry = { sizeof(pEntry) };
	HANDLE hProcList;

	do {
		hProcList = CreateToolhelp32Snapshot(PROCESS_ALL_ACCESS, 0);
		if (hProcList == INVALID_HANDLE_VALUE)
			return uProcId;

		if (Process32First(hProcList, &pEntry)) {

			do {

				if (!strcmp(pEntry.szExeFile, szProcessName)) {
					uProcId = (uintptr_t)pEntry.th32ProcessID;
					break;
				}

			} while (Process32Next(hProcList, &pEntry));

		}

	} while (!uProcId);

	return uProcId;
}

MODULEINFO GetModuleInfoEx(uintptr_t uProcId, const char *szModuleName, HANDLE hProc) {
	MODULEENTRY32 mEntry = { sizeof(mEntry) };
	MODULEINFO modInfo = { 0 };
	HANDLE hProcList;

	do {
		hProcList = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, uProcId);
		if (hProcList == INVALID_HANDLE_VALUE)
			return modInfo;

		if (Module32First(hProcList, &mEntry)) {

			do {

				if (!strcmp(mEntry.szModule, szModuleName)) {
					GetModuleInformation(hProc, mEntry.hModule, &modInfo, sizeof(modInfo));
					break;
				}

			} while (Module32Next(hProcList, &mEntry));

		}

	} while (!modInfo.lpBaseOfDll);

	return modInfo;
}

bool CreateSignature(MODULEINFO modInfo, uintptr_t uStartAddress,
	unsigned int iSizeOfScan, HANDLE hProc, BYTE *szPtr) {
	// Declare Base and Size of Memory
	uintptr_t uMemoryBase;
	uintptr_t uMemorySize;

	// Declare Offset Variable
	unsigned int iOffset;

	// Define Memory Base and Size
	uMemoryBase = (uintptr_t)modInfo.lpBaseOfDll;
	uMemorySize = (uintptr_t)modInfo.SizeOfImage;

	// Define Offset: Offset = Starting addres - Base of Memory
	iOffset = uStartAddress - uMemoryBase;

	// Clear Memory Protection Scheme
	DWORD dwOld = NULL;
	VirtualProtectEx(hProc, (LPVOID)(uMemoryBase + iOffset), iSizeOfScan,
		PAGE_EXECUTE_READWRITE, &dwOld);

	// Read Memory into a char *
	unsigned int iBytesRead = 0;
	ReadProcessMemory(hProc, (LPCVOID)(uMemoryBase + iOffset), szPtr, iSizeOfScan,
		(SIZE_T *)(&iBytesRead));

	// Write old Memory Permission Scheme
	VirtualProtectEx(hProc, (LPVOID)(uMemoryBase + iOffset), iSizeOfScan,
		dwOld, NULL);

	if (iBytesRead < iSizeOfScan)
		return false;

	return true;
}

// function to convert decimal to hexadecimal 
void decToHexa(int n, char *szBuffer)
{
	int saveNum = n;
	char hexaDeciNum[100];

	// counter for hexadecimal number array 
	int i = 0;
	while (n != 0)
	{
		// temporary variable to store remainder 
		int temp = 0;

		// storing remainder in temp variable. 
		temp = n % 16;

		// check if temp < 10 
		if (temp < 10) {
			hexaDeciNum[i] = temp + 48;
			i++;
		}
		else {
			hexaDeciNum[i] = temp + 55;
			i++;
		}
		n = n / 16;
	}

	if (saveNum < 16)
		hexaDeciNum[1] = '0';

	for (int i = 0; i < 2; i++)
		szBuffer[i] = hexaDeciNum[i];

}

void SignatureDefaultFormatString(const BYTE *szSignatureData, unsigned int iMemoryLength,
	char *szSignature) {
	char szBuffer[5];
	int y = 0;

	for (int index = 0; index < iMemoryLength; index++) {
		char temp[3];
		decToHexa((int)szSignatureData[index + y], temp);

		szBuffer[0] = '\\';
		szBuffer[1] = 'x';
		szBuffer[2] = temp[1];
		szBuffer[3] = temp[0];

		int x = 0;
		for (int i = 4 * index;
			i < 4 * index + 4; i++) {
			szSignature[i] = szBuffer[x];
			x++;
		}

		if (szBuffer[2] == 'E' && szBuffer[3] == '8') {
			index++;

			for (int i = 4 * index;
				i < 4 * index + 4; i++) {
				szSignature[i] = '?';
			}
			y += 3;
		}
	}

	szSignature[4 * iMemoryLength - (y * 4)] = 0;
}
