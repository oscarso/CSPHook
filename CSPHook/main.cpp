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


//typedef of CSP API function pointers
typedef BOOL	(WINAPI *PFN_CRYPT_ACQUIRE_CONTEXT)(__out HCRYPTPROV*, __in LPCSTR, __in LPCSTR, __in DWORD, __in DWORD);


//initialization of CSP API function pointers
PFN_CRYPT_ACQUIRE_CONTEXT	pOrigCryptAcquireContext = NULL;


//CardAcquireContext
BOOL WINAPI
pHookCryptAcquireContext(
	__out HCRYPTPROV*	phProv,
	__in LPCSTR			pszContainer,
	__in LPCSTR			pszProvider,
	__in DWORD			dwProvType,
	__in DWORD			dwFlags
)
{
	if (logger) {
		logger->TraceInfo("CryptAcquireContext");
		logger->TraceInfo("IN pszContainer: %s", pszContainer);
		logger->TraceInfo("IN pszProvider: %s", pszProvider);
		logger->TraceInfo("IN dwProvType: 0x%x", dwProvType);
		logger->TraceInfo("IN dwFlags: 0x%x", dwFlags);
	}
	return pOrigCryptAcquireContext(phProv, pszContainer, pszProvider, dwProvType, dwFlags);
}


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
	std::string strProcessName(wsPN.begin(), wsPN.end());
	if (0 == wcscmp(APP_HOOKING, wProcessName)) {
		if (logger) { logger->TraceInfo("%s is hooking onto a %s", strProcessName.c_str(), DLL_HOOKED); }
		return true;
	} else {
		if (logger) { logger->TraceInfo("%s is NOT hooking onto anything", strProcessName.c_str()); }
	}
	return false;
}


//hookInitialize
void hookInitialize() {
	g_hDll = LoadLibrary(DLL_HOOKED_W);

	//GetProcAddress
	pOrigCryptAcquireContext = (PFN_CRYPT_ACQUIRE_CONTEXT)GetProcAddress(g_hDll, "CryptAcquireContext");

	//Mhook_SetHook
	Mhook_SetHook((PVOID *)&pOrigCryptAcquireContext, pHookCryptAcquireContext);
}


//hookFinalize
void hookFinalize() {
	//Mhook_Unhook
	Mhook_Unhook((PVOID *)&pOrigCryptAcquireContext);
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
			logger = LOGGER::CLogger::getInstance(LOGGER::LogLevel_Info, LOG_PATH, "");
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