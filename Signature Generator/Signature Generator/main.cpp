// 32 Bit Signature Generator
// Matthew Geiger

#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <Psapi.h>
#include <stdio.h>
#include <stdlib.h>

#include "Signature.h"

const char szAppName[] = "ac_client.exe";

int main(const int argc, const char *argv[]) {
	unsigned int iSignatureLength;
	unsigned int iStartAddress;

	uintptr_t uProcessId = GetProcessId(szAppName);
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, uProcessId);
	MODULEINFO modInfo = GetModuleInfoEx(uProcessId, szAppName, hProc);

	printf("Enter Signature Length: ");
	scanf("%d", &iSignatureLength);
	getchar();

	printf("Enter Start Address 0x");
	scanf("%x", &iStartAddress);
	getchar();

	if (iSignatureLength > 4096) {
		fprintf(stderr, "Signature Length is too large!\n");
		getchar();
		ExitProcess(EXIT_FAILURE);
	}

	BYTE *szSignature = new BYTE[iSignatureLength];

	if (!CreateSignature(modInfo, (uintptr_t)iStartAddress, iSignatureLength,
		hProc, szSignature)) {
		fprintf(stderr, "Failed to Generate Signature!\n");
		getchar();
		ExitProcess(EXIT_FAILURE);
	}

	char *szSignatureString = new char[iSignatureLength * 6];

	SignatureDefaultFormatString((const BYTE *)szSignature, iSignatureLength, szSignatureString);


	printf("\nGenerated Signature: %s\n", szSignatureString);

#ifdef _DEBUG
	printf("\nProcess ID: %d\n", uProcessId);
	printf("Base of module: 0x%X\n", modInfo.lpBaseOfDll);
	printf("Signature Length: %d\n", iSignatureLength);
	printf("Start Address: 0x%X\n", iStartAddress);
	printf("First Instruction Hex: 0x%x\n", szSignature[0]);
#endif // _DEBUG


	delete szSignature;
	delete szSignatureString;

	getchar();
	return EXIT_SUCCESS;
}