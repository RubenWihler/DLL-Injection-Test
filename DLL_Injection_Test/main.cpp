#include <windows.h>
#include <stdlib.h>
#include <time.h>

struct beepParams
{
	int freq;
	int mil;
};

void beepTone(beepParams params)
{
	Beep(params.freq, params.mil);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	if (fdwReason != DLL_PROCESS_ATTACH)
		return FALSE;

	srand(time(NULL));

	int timer = 0;

	while (timer < 20) {
		int freq = rand() % 1500 +500;
		beepTone({ freq, 500 });
		timer++;
	}

	return TRUE;
}