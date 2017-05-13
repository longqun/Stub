#pragma once
#include "windows.h"
typedef struct _SectionNode
{
	//解压区段
	DWORD SizeOfRawData;
	DWORD SectionRva;
}SectionNode;
typedef struct _GlogalExternVar 
{
	SectionNode mSectionNodeArray[16];
	//加壳的导入表地址
	DWORD dwIATVirtualAddress;
	//加壳的tls数据大小
	DWORD dwTLSSize;
	//加壳的tls虚拟地址 rva
	DWORD dwTLSVirtualAddress;
	//加壳的原始oep
	DWORD dwOrignalOEP;
	//重定位rva
	DWORD dwRelocationRva;

	DWORD dwBaseOfCode;

	DWORD dwOrignalImageBase;
	DWORD dwPressSize;
}GlogalExternVar;

typedef struct _Password
{
	bool isSetPassword;
	char password[13];
}Password;

typedef HMODULE(WINAPI*PEGetModuleHandleW)(_In_opt_ LPCWSTR lpModuleName);

typedef HMODULE(WINAPI*PELoadLibraryExA)(_In_ LPCSTR lpLibFileName, HANDLE file, DWORD mode);

typedef  DWORD(WINAPI *PEGetProcAddress)(_In_ HMODULE hModule, _In_ LPCSTR lpProcName);

typedef BOOL(WINAPI *LPVIRTUALPROTECT)(LPVOID, SIZE_T, DWORD, PDWORD); // VirtualProtect

typedef BOOL(WINAPI*PEVirtualFree)(LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD dwFreeType);

typedef LPVOID(WINAPI*PEVirtualAlloc)(_In_opt_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flAllocationType, _In_ DWORD flProtect);

typedef HWND (WINAPI *PECreateWindowExW)(_In_ DWORD dwExStyle,_In_opt_ LPCWSTR lpClassName,_In_opt_ LPCWSTR lpWindowName,_In_ DWORD dwStyle,_In_ int X,_In_ int Y,_In_ int nWidth,_In_ int nHeight,_In_opt_ HWND hWndParent,_In_opt_ HMENU hMenu,_In_opt_ HINSTANCE hInstance,_In_opt_ LPVOID lpParam);

typedef WORD (WINAPI* PERegisterClassExW)(_In_ CONST WNDCLASSEXW *lpWndClass);

typedef BOOL (WINAPI* PEShowWindow)(_In_ HWND hWnd,_In_ int nCmdShow);

typedef BOOL (WINAPI* PEUpdateWindow)(_In_ HWND hWnd);

typedef BOOL (WINAPI* PEGetMessageW)(_Out_ LPMSG lpMsg,_In_opt_ HWND hWnd,_In_ UINT wMsgFilterMin,_In_ UINT wMsgFilterMax);

typedef BOOL (WINAPI* PETranslateMessage)(_In_ CONST MSG *lpMsg);

typedef LRESULT (WINAPI* PEDispatchMessageW)(_In_ CONST MSG *lpMsg);

typedef  LRESULT (WINAPI* PEDefWindowProcW)(_In_ HWND hWnd,_In_ UINT Msg,_In_ WPARAM wParam,_In_ LPARAM lParam);

typedef VOID (WINAPI *PEPostQuitMessage)(_In_ int nExitCode);

typedef VOID (WINAPI* PEExitProcess)(_In_ UINT uExitCode);

typedef BOOL (WINAPI* PEDestroyWindow)(_In_ HWND hWnd);

typedef struct _SHELLWINDOWSINF
{
	HWND hWnd;
	HMENU Id;
}SHELLWINDOWSINF, *PSHELLWINDOWSINF;
typedef struct _Apier 
{
	PEGetProcAddress GetProcAddress;
	PELoadLibraryExA LoadLibraryExA;
	PEGetModuleHandleW GetModuleHandleW;
	LPVIRTUALPROTECT VirtualProtect;
	PEVirtualFree VirtualFree;
	PEVirtualAlloc VirtualAlloc;

	PEDefWindowProcW DefWindowsProcW;
	PERegisterClassExW RegisterClassExW;
	PECreateWindowExW CreateWindowExW;
	PEShowWindow ShowWindow;
	PEUpdateWindow UpdateWindow;
	PEGetMessageW GetMessageW;
	PETranslateMessage TranslateMessage;
	PEDispatchMessageW DispatchMessageW;

	PEExitProcess ExitProcess;
	PEPostQuitMessage PostQuitMessage;
	PEDestroyWindow DestroyWindow;
	DWORD ImageBase;
	PIMAGE_TLS_DIRECTORY pTLSDirectory;
	HWND ParentHwnd;
	SHELLWINDOWSINF ExeWindowsInf[3];
}Apier,*PApier;

