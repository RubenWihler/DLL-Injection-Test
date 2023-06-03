#include <windows.h>
#include <stdio.h>
#include <string>

#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_CYAN    "\x1b[36m"
#define COLOR_RESET   "\x1b[0m"

DWORD PID = NULL;
DWORD TID = NULL;
LPVOID buffer = NULL;
HMODULE hKernel32 = NULL;
HANDLE hProcess = NULL;
HANDLE hThread = NULL;

wchar_t dllPath[MAX_PATH] = L"";
size_t dllPathSize = sizeof(dllPath);

bool FileExists(const std::string& filename);

int main(int argc, char* argv[]) {

	if (argc < 3 || argc > 3) {
		printf("%s %s format : program.exe <PID> <DLL_PATH> %s", COLOR_RED,"[-]", COLOR_RESET);
		return EXIT_FAILURE;
	}

	PID = atoi(argv[1]);

	if (!FileExists(argv[2])) {
		printf("%s %s le chemin vers la dll est invalide ! %s", COLOR_RED, "[-]", COLOR_RESET);
		return EXIT_FAILURE;
	}

	mbstowcs_s(NULL, dllPath, argv[2], MAX_PATH);
	dllPathSize = sizeof(dllPath);

	printf("%s tentative d'ouverture d'un handle sur le processus (%ld)\n", "[*]", PID);
	
	//ouvre un handle sur le processus
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);

	if (hProcess == NULL)
	{
		printf("%s %s impossible d'ouvrir un handle sur le processus (%ld), erreur: %ld %s", COLOR_RED, "[-]", PID, GetLastError(), COLOR_RESET);
		return EXIT_FAILURE;
	}

	printf("%s %s a obtenu un acces au processus !\n--> 0x%p\n %s", COLOR_GREEN, "[+]", hProcess, COLOR_RESET);


	printf("%s allocation de %zu-octets avec les permissions PAGE_READWRITE dans le processus (%ld)\n", "[*]", dllPathSize, PID);
	//alloue de la memoire dans le processus distant
	buffer = VirtualAllocEx(hProcess, NULL, dllPathSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);

	if (buffer == NULL)
	{
		printf("%s %s impossible de creer le buffer, erreur: %ld %s", COLOR_RED, "[-]", GetLastError(), COLOR_RESET);
		return EXIT_FAILURE;
	}

	printf("%s ecriture de [%S] dans la memoire du processus (%ld)\n", "[*]", dllPath, PID);
	//ecrit le chemin de la dll dans le processus distant
	WriteProcessMemory(hProcess, buffer, dllPath, dllPathSize, NULL);


	printf("%s recuperation du module Kernel32.dll dans le processus (%ld)\n", "[*]", PID);
	//recupere l'adresse du module kernel32.dll dans le processus distant
	hKernel32 = GetModuleHandleW(L"Kernel32");

	if (hKernel32 == NULL)
	{
		printf("%s %s impossible de recuperer le module kernel32.dll dans le processus (%ld), erreur: %ld %s", COLOR_RED, "[-]", PID, GetLastError(), COLOR_RESET);
		CloseHandle(hProcess);
		return EXIT_FAILURE;
	}

	printf("%s %s recuperation du module Kernel32.dll dans le processus (%ld) reussie !\n\\---> 0x%p\n%s", COLOR_GREEN, "[+]", PID, hKernel32, COLOR_RESET);


	printf("%s recuperation de l'adresse de la fonction LoadLibraryW dans le processus (%ld)\n", "[*]", PID);
	//recupere l'adresse de la fonction LoadLibraryW dans le processus distant
	LPTHREAD_START_ROUTINE lpStartAddress = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
	printf("%s %s recuperation de l'adresse de la fonction LoadLibraryW dans le processus (%ld) reussie !\n\\---> 0x%p\n%s", COLOR_GREEN, "[+]", PID, lpStartAddress, COLOR_RESET);


	printf("%s creation d'un thread dans le processus (%ld)\n", "[*]", PID);
	//cree un thread dans le processus distant
	hThread = CreateRemoteThread(hProcess, NULL, 0, lpStartAddress, buffer, 0, &TID);

	if (hThread == NULL)
	{
		printf("%s %s impossible de creer un thread dans le processus (%ld), erreur: %ld %s", COLOR_RED, "[-]", PID, GetLastError(), COLOR_RESET);
		CloseHandle(hProcess);
		return EXIT_FAILURE;
	}

	printf("%s %s creation d'un thread dans le processus (%ld) reussie !\n\\---> 0x%p\n%s", COLOR_GREEN, "[+]", PID, hThread, COLOR_RESET);

	printf(
		"%s %s Informations :\n"
		"  --> Processus : %ld\n"
		"  --> DLL : %S\n"
		"  --> Taille de la DLL : %zu octets\n"
		"  --> Adresse de la DLL : 0x%p\n"
		"  --> Adresse du module Kernel32.dll : 0x%p\n"
		"  --> Adresse de la fonction LoadLibraryW : 0x%p\n"
		"  --> Handle du processus : 0x%p\n"
		"  --> Handle du thread : 0x%p\n"
		"  --> Thread ID : %ld\n%s"
		, COLOR_CYAN, "[+]", PID, dllPath, dllPathSize, buffer, hKernel32, lpStartAddress, hProcess, hThread, TID, COLOR_RESET
	);


	printf("%s attente de la fin du thread dans le processus (%ld)\n", "[*]", PID);
	//attend la fin du thread
	WaitForSingleObject(hThread, INFINITE);
	printf("%s %s le thread a ete execute avec succes dans le processus (%ld)\n%s", COLOR_GREEN, "[+]", PID, COLOR_RESET);

	
	CloseHandle(hThread);
	CloseHandle(hProcess);

	printf("%s %s l'injection a ete effectuee avec succes !\n%s", COLOR_GREEN, "[+]", COLOR_RESET);

	return EXIT_SUCCESS;
}

bool FileExists(const std::string& filename)
{
	WIN32_FIND_DATAA fd = { 0 };
	HANDLE hFound = FindFirstFileA(filename.c_str(), &fd);
	bool retval = hFound != INVALID_HANDLE_VALUE;
	FindClose(hFound);

	return retval;
}