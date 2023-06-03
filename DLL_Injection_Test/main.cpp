#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	if (fdwReason != DLL_PROCESS_ATTACH)
		return FALSE;

	MessageBoxW(NULL, L"BLA BLA BLA BLA", L"bonjour !", MB_OK);
	system(
		"echo \"je suis un test !\""
		"&& pause"
	);

	return TRUE;
}