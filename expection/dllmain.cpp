
#define WIN32_LEAN_AND_MEAN             // Excluir itens raramente utilizados dos cabeçalhos do Windows
#include <windows.h>
#include <wininet.h> // InternetOpenUrlA
#include <mh/MinHook.h>// MinHook functions
#include <iostream> // printf
#include <xor_str.hpp>
#pragma comment(lib, "wininet.lib")

std::string this_app_exe_name() {
	TCHAR buf[MAX_PATH];
	GetModuleFileNameA(nullptr, buf, MAX_PATH);
	std::string sp = buf;
	return sp;
}

std::string base_name(std::string const& path) {
	return path.substr(path.find_last_of("/\\") + 1);
}

DWORD64 base_addr;

void* m_internet_open_url;
// function template of InternetOpenUrlA
using internet_open_url_fn = void(__stdcall*)(HINTERNET, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);

// store pointer to the original InternetOpenUrlA function
internet_open_url_fn o_internet_open_url = nullptr;

// the actual hook
void h_internet_open_url(HINTERNET hInternet, LPCSTR lpszUrl, LPCSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwFlags, DWORD_PTR dwContext)
{
	const auto new_title = xor ("buy neverfall.cc");
	const auto new_coded_by = xor ("Cracked by six    ");
	WriteProcessMemory(GetCurrentProcess(), reinterpret_cast<LPVOID>(base_addr + 0x732E1), new_title, strlen(new_title) + 1, 0);
	WriteProcessMemory(GetCurrentProcess(), reinterpret_cast<LPVOID>(base_addr + 0x73890), new_coded_by, strlen(new_coded_by), 0);
	return o_internet_open_url(hInternet, xor("https://pastebin.com/raw/1vR1s8pd"), lpszHeaders, dwHeadersLength, dwFlags, dwContext);
}

BOOL DllMain(HMODULE module, DWORD call_reason, LPVOID reserved) {

	if (call_reason == DLL_PROCESS_ATTACH)
	{
		if (!GetModuleHandleA(xor ("Wininet.dll")))
			LoadLibraryA(xor("Wininet.dll"));

		base_addr = reinterpret_cast<DWORD64>(GetModuleHandleA(base_name(this_app_exe_name()).c_str()));

		MH_Initialize();
		MH_CreateHook(&InternetOpenUrlA, &h_internet_open_url, reinterpret_cast<void**>(&o_internet_open_url));
		MH_EnableHook(&InternetOpenUrlA);

		const auto checking_chr = (char*)base_addr + 0x7310E;
		if (checking_chr) {
			while (strlen((char*)(checking_chr)) == 0) { Sleep(50); }
			const auto cracking = xor ("Cracking...");
			WriteProcessMemory(GetCurrentProcess(), reinterpret_cast<LPVOID>(base_addr + 0x7310E), cracking, strlen(cracking), 0);
		}

		const auto version_chr = (char*)base_addr + 0x73089;
		if (version_chr) {
			while (strlen((char*)(version_chr)) == 0) { Sleep(50); }
			const auto version_cracked = xor ("version: cracked");
			WriteProcessMemory(GetCurrentProcess(), reinterpret_cast<LPVOID>(base_addr + 0x73089), version_cracked, strlen(version_cracked) + 1, 0);
		}
		const auto autenticated_chr = (char*)base_addr + 0x72E64;
		if (autenticated_chr) {
			while (strlen((char*)(autenticated_chr)) == 0) { Sleep(50); }
			const auto crackeado_com_sucesso = xor ("Crackeado com sucesso!");
			WriteProcessMemory(GetCurrentProcess(), reinterpret_cast<LPVOID>(base_addr + 0x72E64), crackeado_com_sucesso, strlen(crackeado_com_sucesso) + 1, 0);
		}
	}
	if (call_reason == DLL_PROCESS_DETACH)
	{
		FreeLibraryAndExitThread(module, 0);
		return TRUE;
	}
	return TRUE;
}
