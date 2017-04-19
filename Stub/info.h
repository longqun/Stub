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