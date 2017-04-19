// Dll.cpp : Defines the entry point for the DLL application.
//

#include "stdafx.h"
#include "info.h"
#pragma comment(linker, "/MERGE:.data=.text")
#pragma comment(linker, "/MERGE:.rdata=.text")
#pragma comment(linker, "/section:.text,RWE") 
#pragma comment(linker,"/ENTRY:MyMain")


#include "aplib.h"
#pragma comment(lib, "aplib.lib")
#pragma comment(lib, "msvcrt.lib")
#pragma comment(lib,"kernel32.lib")
//用来支持tls
_declspec (thread) LPCTSTR g_strTLS = L"Stub TLS DATA";
void WINAPI TlsCallBack(PVOID dwDllHandle, DWORD dwReason, PVOID pReserved)
{
	if (pReserved)
		g_strTLS = L"Nothing";
}
#pragma data_seg(".CRT$XLB")
PIMAGE_TLS_CALLBACK pTlsCallBack[] = { TlsCallBack,NULL };
#pragma data_seg()

DWORD GetKernel32Base()
{
	DWORD dwKernel32Addr = 0;
	/*
	__asm
	{
		push eax
		mov eax, dword ptr fs : [0x30] // eax = PEB的地址
		mov eax, [eax + 0x0C]          // eax = 指向PEB_LDR_DATA结构的指针
		mov eax, [eax + 0x1C]          // eax = 模块初始化链表的头指针InInitializationOrderModuleList
		mov eax, [eax]               // eax = 列表中的第二个条目
		mov eax, [eax + 0x08]          // eax = 获取到的Kernel32.dll基址（Win7下获取的是KernelBase.dll的基址）
		mov dwKernel32Addr, eax
		pop eax
	}
	*/

	_asm
	{
		pushad
		xor ecx, ecx
		mov eax, fs:[0x30]
		mov eax, [eax + 0xc]
		mov esi, [eax + 0x1c]
		next_module :
		mov eax, [esi + 0x8]
		mov edi, [esi + 0x20]
		mov esi, [esi]
		cmp[edi + 12 * 2], cx
		jnz next_module
		mov dwKernel32Addr, eax
		popad
	}

	return dwKernel32Addr;
}

DWORD GetGPAFunAddr()
{
	DWORD dwAddrBase = GetKernel32Base();

	// 1. 获取DOS头、NT头
	PIMAGE_DOS_HEADER pDos_Header;
	PIMAGE_NT_HEADERS pNt_Header;
	pDos_Header = (PIMAGE_DOS_HEADER)dwAddrBase;
	pNt_Header = (PIMAGE_NT_HEADERS)(dwAddrBase + pDos_Header->e_lfanew);

	// 2. 获取导出表项
	PIMAGE_DATA_DIRECTORY   pDataDir;
	PIMAGE_EXPORT_DIRECTORY pExport;
	pDataDir = pNt_Header->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXPORT;
	pExport = (PIMAGE_EXPORT_DIRECTORY)(dwAddrBase + pDataDir->VirtualAddress);
	
	// 3. 获取导出表详细信息
	PDWORD pAddrOfFun = (PDWORD)(pExport->AddressOfFunctions + dwAddrBase);
	PDWORD pAddrOfNames = (PDWORD)(pExport->AddressOfNames + dwAddrBase);
	PWORD  pAddrOfOrdinals = (PWORD)(pExport->AddressOfNameOrdinals + dwAddrBase);

	// 4. 处理以函数名查找函数地址的请求，循环获取ENT中的函数名，并与传入值对比对，如能匹配上
	//    则在EAT中以指定序号作为索引，并取出其地址值。
	DWORD dwFunAddr;
	for (DWORD i = 0; i < pExport->NumberOfNames; i++)
	{
		PCHAR lpFunName = (PCHAR)(pAddrOfNames[i] + dwAddrBase);
		if (strcmp(lpFunName, "GetProcAddress") == 0)
		{
			dwFunAddr = pAddrOfFun[pAddrOfOrdinals[i]] + dwAddrBase;
			return dwFunAddr;
		}
		if (i == pExport->NumberOfNames - 1)
			return 0;
	}
	return dwFunAddr;
}


typedef HMODULE(WINAPI*PEGetModuleHandleW)(_In_opt_ LPCWSTR lpModuleName);

typedef HMODULE(WINAPI*PELoadLibraryExA)(_In_ LPCSTR lpLibFileName, HANDLE file, DWORD mode);

typedef  DWORD(WINAPI *PEGetProcAddress)(_In_ HMODULE hModule, _In_ LPCSTR lpProcName);

typedef BOOL(WINAPI *LPVIRTUALPROTECT)(LPVOID, SIZE_T, DWORD, PDWORD); // VirtualProtect

typedef BOOL
(WINAPI
	*PEVirtualFree)(
		LPVOID lpAddress,
		_In_ SIZE_T dwSize,
		_In_ DWORD dwFreeType
		);

typedef LPVOID
(WINAPI
	*PEVirtualAlloc)(
		_In_opt_ LPVOID lpAddress,
		_In_ SIZE_T dwSize,
		_In_ DWORD flAllocationType,
		_In_ DWORD flProtect
		);

PEGetProcAddress gGetProcAddress;
PELoadLibraryExA gLoadLibraryExA;
PEGetModuleHandleW gGetModuleHandleW;
LPVIRTUALPROTECT g_VirtualProtect;
PEVirtualFree gVirtualFree;
PEVirtualAlloc gVirtualAlloc;
DWORD g_hImageBase;
PIMAGE_TLS_DIRECTORY pTLSDirectory;

void initFunction()
{
	gGetProcAddress = (PEGetProcAddress)GetGPAFunAddr();
	gLoadLibraryExA = (PELoadLibraryExA)gGetProcAddress((HMODULE)GetKernel32Base(), "LoadLibraryExA");
	gGetModuleHandleW = (PEGetModuleHandleW)gGetProcAddress((HMODULE)GetKernel32Base(), "GetModuleHandleW");
	g_VirtualProtect = (LPVIRTUALPROTECT)gGetProcAddress((HMODULE)GetKernel32Base(), "VirtualProtect");
	gVirtualFree = (PEVirtualFree)gGetProcAddress((HMODULE)GetKernel32Base(), "VirtualFree");
	gVirtualAlloc = (PEVirtualAlloc)gGetProcAddress((HMODULE)GetKernel32Base(), "VirtualAlloc");
	g_hImageBase = (DWORD)gGetModuleHandleW(NULL);

	IMAGE_DOS_HEADER* lpDosHeader = (IMAGE_DOS_HEADER*)g_hImageBase;
	IMAGE_NT_HEADERS* lpNtHeader = (IMAGE_NT_HEADERS*)(lpDosHeader->e_lfanew + (DWORD)g_hImageBase);
	//rva
	pTLSDirectory=(PIMAGE_TLS_DIRECTORY)(lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress+g_hImageBase);
}
void *mmemcpy(void* _Dst,
	void const* _Src,
	size_t      _Size)
{
	void *orignal = _Dst;
	for (int i = 0; i < _Size; i++)
	{
		((char*)_Dst)[i] = ((char*)_Src)[i];
	}
	return orignal;
}

void memsetZero(void *src, size_t length)
{
	for (int i = 0; i < length; i++)
	{
		((char*)src)[i] = 0;
	}
}

#define _DLL_SAMPLE
#ifdef __cplusplus
extern "C" {
#endif
	// 通过宏来控制是导入还是导出
#ifdef _DLL_SAMPLE
#define DLL_SAMPLE_API __declspec(dllexport)
#else
#define DLL_SAMPLE_API __declspec(dllimport)
#endif
	// 导出/导入变量声明
	DLL_SAMPLE_API  GlogalExternVar g_globalVar;
#undef DLL_SAMPLE_API

#ifdef __cplusplus
}
#endif




/*
	IMAGE_TLS_DIRECTORY中的地址就是虚拟地址直接用
*/
void InitTLS(PIMAGE_TLS_DIRECTORY pFileTls, PIMAGE_TLS_DIRECTORY pStubTls)
{
	PIMAGE_TLS_CALLBACK* pTlsCallBack = (PIMAGE_TLS_CALLBACK*)pFileTls->AddressOfCallBacks;
	PIMAGE_TLS_CALLBACK* pStubCallBack = (PIMAGE_TLS_CALLBACK*)pStubTls->AddressOfCallBacks;
	if (pTlsCallBack&&pStubCallBack)
	{
		while (*pTlsCallBack)
		{
			(*pTlsCallBack)((PVOID)g_hImageBase,DLL_PROCESS_ATTACH,0);
			*pStubCallBack = *pTlsCallBack;
			pStubCallBack++;
			pTlsCallBack++;
		}
	}
}
void RecoverIAT()
{
	HMODULE hModule = gGetModuleHandleW(NULL);
	IMAGE_DOS_HEADER* lpDosHeader = (IMAGE_DOS_HEADER*)hModule;
	IMAGE_NT_HEADERS* lpNtHeader = (IMAGE_NT_HEADERS*)(lpDosHeader->e_lfanew + (DWORD)hModule);
	LPVOID lpImageBase = (LPVOID)lpNtHeader->OptionalHeader.ImageBase;
	//导入表处理
	IMAGE_IMPORT_DESCRIPTOR* lpImportTable = (IMAGE_IMPORT_DESCRIPTOR*)((DWORD)lpImageBase + g_globalVar.dwIATVirtualAddress);

	int DllNameOffset = 0;
	int ThunkRVA = 0;
	HMODULE hDll = NULL;
	int* lpIAT = NULL;

	while (lpImportTable->Name)
	{
		DllNameOffset = lpImportTable->Name + (DWORD)lpImageBase;
		hDll = gLoadLibraryExA((char*)DllNameOffset, NULL, 0);

		if (lpImportTable->FirstThunk == 0)
		{
			lpImportTable++;
			continue;
		}
		lpIAT = (int*)(lpImportTable->FirstThunk + (DWORD)lpImageBase);

		if (lpImportTable->OriginalFirstThunk == 0)
		{
			ThunkRVA = lpImportTable->FirstThunk;
		}
		else
		{
			ThunkRVA = lpImportTable->OriginalFirstThunk;
		}

		IMAGE_THUNK_DATA* lpThunkData = (IMAGE_THUNK_DATA*)((DWORD)lpImageBase + ThunkRVA);
		int funAddress = 0;
		int FunName = 0;
		while (lpThunkData->u1.Ordinal != 0)
		{
			//名字导出
			if ((lpThunkData->u1.Ordinal & 0x80000000) == 0)
			{
				IMAGE_IMPORT_BY_NAME* lpImprotName = (IMAGE_IMPORT_BY_NAME*)((DWORD)lpImageBase + lpThunkData->u1.Ordinal);
				FunName = (int)&(lpImprotName->Name);
			}
			else
			{
				FunName = lpThunkData->u1.Ordinal & 0xffff;
			}



			int funAddress = (int)gGetProcAddress(hDll, (char*)FunName);
			DWORD dwOld;



			g_VirtualProtect(lpIAT, 4, PAGE_EXECUTE_READWRITE, &dwOld);
			*(lpIAT) = funAddress;
			g_VirtualProtect(lpIAT, 4, dwOld, NULL);
			lpIAT++;

			lpThunkData++;

		}
		lpImportTable++;
	}


}
typedef struct _TYPEOFFSET
{
	WORD offset : 12;			//偏移值
	WORD Type : 4;			//重定位属性(方式)
}TYPEOFFSET, *PTYPEOFFSET;
//修复原始重定位表
void fixRelocation()
{
	if (g_globalVar.dwRelocationRva == 0)
		return;
	DWORD dwImageBase = (DWORD)gGetModuleHandleW(NULL);
	PIMAGE_BASE_RELOCATION	pReloc =
		(PIMAGE_BASE_RELOCATION)((DWORD)dwImageBase + g_globalVar.dwRelocationRva);
	while (pReloc->VirtualAddress)
	{
		PTYPEOFFSET pTypeOffset = (PTYPEOFFSET)(pReloc+1);
		DWORD dwNumber = (pReloc->SizeOfBlock - 8) / 2;
		for (int i = 0; i < dwNumber; i++)
		{
			if (*(PWORD)(&pTypeOffset[i]) == 0)
			{
				break;
			}
			DWORD dwRVA = pTypeOffset[i].offset + pReloc->VirtualAddress;
			DWORD dwAddressOfReloc = *(PDWORD)(dwImageBase+dwRVA);
			*(PDWORD)((DWORD)dwImageBase + dwRVA) =
				dwAddressOfReloc - g_globalVar.dwOrignalImageBase + dwImageBase;
		}
		pReloc = (PIMAGE_BASE_RELOCATION)((DWORD)pReloc + pReloc->SizeOfBlock);
	}
}


void fixReloc()
{

}

int decompress()
{



	HMODULE hModule = gGetModuleHandleW(NULL);
	
	int i = 0;
	
	
	
	IMAGE_DOS_HEADER* lpDosHeader = (IMAGE_DOS_HEADER*)hModule;
	IMAGE_NT_HEADERS* lpNtHeader = (IMAGE_NT_HEADERS*)(lpDosHeader->e_lfanew + (DWORD)hModule);
	IMAGE_SECTION_HEADER* lpSecHeader = (IMAGE_SECTION_HEADER*)((DWORD)hModule +
		lpDosHeader->e_lfanew + sizeof(lpNtHeader->Signature) +
		sizeof(lpNtHeader->FileHeader) +
		lpNtHeader->FileHeader.SizeOfOptionalHeader);
	DWORD dwPackedSize = lpSecHeader->Misc.VirtualSize;
	/* decompress data */

	char* lpPacked = ((char*)hModule + lpSecHeader->VirtualAddress);
	dwPackedSize = aPsafe_get_orig_size(lpPacked);
	if (g_globalVar.dwPressSize != dwPackedSize)
		return 0;
	char* lpBuffer = (char*)gVirtualAlloc(NULL, dwPackedSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memsetZero(lpBuffer, sizeof(dwPackedSize));
	lpBuffer[0] = '1';
	DWORD dwOutSize = aPsafe_depack(lpPacked, lpSecHeader->SizeOfRawData, lpBuffer, dwPackedSize);

	DWORD distance = 0;
	 i = 0;
	while (g_globalVar.mSectionNodeArray[i].SectionRva != 0)
	{
		mmemcpy((void*)(g_hImageBase+ g_globalVar.mSectionNodeArray[i].SectionRva), lpBuffer+distance, g_globalVar.mSectionNodeArray[i].SizeOfRawData);
		distance += g_globalVar.mSectionNodeArray[i].SizeOfRawData;
		i++;
	}
	/*
	/*if (dwOutSize != dwPackedSize)
	{
		gVirtualFree(lpBuffer, lpSecHeader->Misc.VirtualSize, MEM_DECOMMIT);
		return -1;
	}
	DWORD dwAlign = lpNtHeader->OptionalHeader.SectionAlignment;

	//对齐的拷贝所有节区
	DWORD dwCurPos = lpSecHeader->VirtualAddress;
	DWORD dwCurPos2 = 0;

	DWORD dwSecCount = lpNtHeader->FileHeader.NumberOfSections;
	lpSecHeader += dwSecCount;
	lpSecHeader--;

	DWORD* lpDwAddress = (DWORD*)((DWORD)hModule + lpSecHeader->VirtualAddress);

	//首先处理tls
	//tls
	DWORD dwSizeOfRawData = *lpDwAddress;
	


	DWORD nPressSecCount = *lpDwAddress;
	lpDwAddress++;
	while (nPressSecCount--)
	{
		mmemcpy(((char*)hModule + dwCurPos), (lpBuffer + dwCurPos2), *lpDwAddress);
		dwCurPos2 += *lpDwAddress;
		lpDwAddress++;
		lpDwAddress++;
		dwCurPos = lpDwAddress[1];

	}

	*/

	gVirtualFree(lpBuffer, dwPackedSize, MEM_DECOMMIT);
	return dwOutSize;
}
DWORD go;
void __declspec(naked)  MyMain()
{
	__asm pushad
	__asm pushfd

	initFunction();
	//解压数据
	decompress();

	fixRelocation();
	//恢复IAT
	RecoverIAT();
	//看是否有TLS函数 如果有 则调用
	InitTLS((PIMAGE_TLS_DIRECTORY)(g_globalVar.dwTLSVirtualAddress+g_hImageBase), pTLSDirectory);
	 go= g_globalVar.dwOrignalOEP + g_hImageBase;
	__asm popfd
	__asm popad
	__asm jmp go
}
