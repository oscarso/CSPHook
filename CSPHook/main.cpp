#include "stdafx.h"
#include <stdio.h>
#include <mutex>
#include "mhook/mhook-lib/mhook.h"
#include "Logger.h"
#include <wincrypt.h>


// Global Variables
#define				LOG_PATH		"C:\\Logs\\"
#define				APP_HOOKING		L"C:\\Windows\\system32\\LogonUI.exe"
#define				DLL_HOOKED_W	L"advapi32.dll"
#define				DLL_HOOKED		"advapi32.dll"
LOGGER::CLogger*	logger = NULL;
HMODULE				g_hDll = 0;


//typedef and initialization of CSP API function pointers
#ifdef UNICODE
typedef BOOL	(WINAPI *PFN_CRYPT_ACQUIRE_CONTEXT)(_Out_ HCRYPTPROV*, _In_opt_	LPCWSTR, _In_opt_ LPCWSTR, _In_ DWORD, _In_ DWORD);
PFN_CRYPT_ACQUIRE_CONTEXT	pOrigCryptAcquireContextW = NULL;
#else
typedef BOOL	(WINAPI *PFN_CRYPT_ACQUIRE_CONTEXT)(_Out_ HCRYPTPROV*, _In_opt_ LPCSTR, _In_opt_ LPCSTR, _In_ DWORD, _In_ DWORD);
PFN_CRYPT_ACQUIRE_CONTEXT	pOrigCryptAcquireContextA = NULL;
#endif


#ifdef UNICODE
//CryptAcquireContextW
BOOL WINAPI
pHookCryptAcquireContextW(
	_Out_		HCRYPTPROV*	phProv,
	_In_opt_	LPCWSTR		szContainer,
	_In_opt_	LPCWSTR		szProvider,
	_In_		DWORD		dwProvType,
	_In_		DWORD		dwFlags
)
{
	if (logger) {
		logger->TraceInfo("CryptAcquireContext");
		logger->TraceInfo("IN dwProvType: 0x%x", dwProvType);
		logger->TraceInfo("IN dwFlags: 0x%x", dwFlags);
	}
	return pOrigCryptAcquireContextW(phProv, szContainer, szProvider, dwProvType, dwFlags);
}
#else
//CryptAcquireContextA
BOOL WINAPI
pHookCryptAcquireContextA(
	_Out_		HCRYPTPROV*	phProv,
	_In_opt_	LPCSTR		szContainer,
	_In_opt_	LPCSTR		szProvider,
	_In_		DWORD		dwProvType,
	_In_		DWORD		dwFlags
)
{
	if (logger) {
		logger->TraceInfo("CryptAcquireContext");
		logger->TraceInfo("IN szContainer: %s", szContainer);
		logger->TraceInfo("IN szProvider: %s", szProvider);
		logger->TraceInfo("IN dwProvType: 0x%x", dwProvType);
		logger->TraceInfo("IN dwFlags: 0x%x", dwFlags);
	}
	return pOrigCryptAcquireContext(phProv, szContainer, szProvider, dwProvType, dwFlags);
}
#endif


//////////////////////////////////////////////////////////////////////////////////////
//
//	Private Helper Functions
//
//////////////////////////////////////////////////////////////////////////////////////

//shouldHook
bool shouldHook() {
	wchar_t	wProcessName[MAX_PATH];
	GetModuleFileName(NULL, wProcessName, MAX_PATH);
	std::wstring wsPN(wProcessName);//convert wchar* to wstring
	std::string strProcessNameFullPath(wsPN.begin(), wsPN.end());
	logger = LOGGER::CLogger::getInstance(LOGGER::LogLevel_Info, LOG_PATH, "");
	if (0 == wcscmp(APP_HOOKING, wProcessName)) {
		if (logger) { logger->TraceInfo("%s is hooking onto a %s", strProcessNameFullPath.c_str(), DLL_HOOKED); }
		return true;
	}
	return false;
}


//hookInitialize
void hookInitialize() {
	g_hDll = LoadLibrary(DLL_HOOKED_W);

#ifdef UNICODE
	//GetProcAddress
	pOrigCryptAcquireContextW = (PFN_CRYPT_ACQUIRE_CONTEXT)GetProcAddress(g_hDll, "CryptAcquireContext");

	//Mhook_SetHook
	Mhook_SetHook((PVOID *)&pOrigCryptAcquireContextW, pHookCryptAcquireContextW);
#else
	//GetProcAddress
	pOrigCryptAcquireContextA = (PFN_CRYPT_ACQUIRE_CONTEXT)GetProcAddress(g_hDll, "CryptAcquireContext");

	//Mhook_SetHook
	Mhook_SetHook((PVOID *)&pOrigCryptAcquireContextA, pHookCryptAcquireContextA);
#endif
}


//hookFinalize
void hookFinalize() {
#ifdef UNICODE
	//Mhook_Unhook
	Mhook_Unhook((PVOID *)&pOrigCryptAcquireContextW);
#else
	//Mhook_Unhook
	Mhook_Unhook((PVOID *)&pOrigCryptAcquireContextA);
#endif
}


//DllMain
BOOL WINAPI DllMain(
	__in HINSTANCE  hInstance,
	__in DWORD      Reason,
	__in LPVOID     Reserved
)
{
	switch (Reason) {
	case DLL_PROCESS_ATTACH:
		if (shouldHook()) {
			hookInitialize();
		} else {
			return FALSE;
		}
		break;

	case DLL_PROCESS_DETACH:
		hookFinalize();
		break;
	}
	return TRUE;
}