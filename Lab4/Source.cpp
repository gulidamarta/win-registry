#include <windows.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <AclAPI.h>
#include <sddl.h>
#include <string.h>


BOOL CreateRegistryKey(HKEY, LPCSTR);
BOOL WriteDwordInRegistry(HKEY, LPCSTR, LPCSTR, DWORD);
BOOL WriteStringInRegistry(HKEY, LPCSTR, LPCSTR, LPCSTR);
BOOL ReadDwordValueRegistry(HKEY, LPCSTR, LPCSTR, DWORD *);
BOOL ReadFlags(HKEY, LPCSTR);
VOID QueryKey(HKEY hKey);
VOID PrintParsedAceString(char *);
VOID NotifyAboutChangingTheKey(LPCSTR, LPCSTR);

#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383


INT main() {

	HKEY hTestKey;

	BOOL status;
	DWORD readData;
	PWCHAR readMessage = nullptr;

	BOOL manage_var = TRUE;
	while (manage_var) {
		printf("1 - Creation of the key.\n");
		printf("2 - Opening and writing DWORD data to the key. And closing after all operations.\n");
		printf("3 - Reading DWORD data from the key.\n");
		printf("4 - Enumerate the subkeys of the specified key.\n");
		printf("5 - Get the mask of flags of the key.\n");
		printf("6 - Notify about changing the key value.\n");
		printf("7 - End application.\n");
		int choice;
		if (!scanf_s("%d", &choice)) {
			printf("Wrong input. Try one more time.\n");
			continue;
		}
		switch (choice)
		{
		case 1:
			status = CreateRegistryKey(HKEY_CURRENT_USER, "Lab4");							//create key
			if (status != TRUE)
				return FALSE;
			break;
		case 2:
			int data_to_write;
			printf("Enter data, that you want to write: \n");
			if (!scanf_s("%d", &data_to_write)) {
				printf("Wrong input. Try one more time.\n");
				continue;
			}
			status = WriteDwordInRegistry(HKEY_CURRENT_USER, "Lab4", "date", data_to_write);		//write dword
			if (status != TRUE)
				return FALSE;
			break;
		case 3:
			status = ReadDwordValueRegistry(HKEY_CURRENT_USER, "Lab4", "date", &readData);	//read dword
			if (status != TRUE)
				return FALSE;
			printf("%ld\n", readData);
			break;
		case 4:
			if (RegOpenKeyEx(HKEY_CURRENT_USER,
				TEXT("SOFTWARE\\Microsoft"),
				0,
				KEY_READ,
				&hTestKey) == ERROR_SUCCESS
				)
			{
				QueryKey(hTestKey);
			}

			RegCloseKey(hTestKey);
			break;
		case 5:
			status = ReadFlags(HKEY_CURRENT_USER, "Lab4");		
			if (status != TRUE)
				return FALSE;
			break;
		case 6:
			// но вообще по хорошему - это установка callback-ов ядра на изменения реестра (то есть писать драйвер)
			char hMainKey[100];
			char subKey[100];
			//fgets(hMainKey, 100, stdin);
			//fgets(subKey, 100, stdin);
			//printf("Enter a subkey: \n");
			//while (!(gets_s(subKey)));
			//if (!(scanf_s("%s", hMainKey))) {
			//	printf("Error in main key.\n");
			//	continue;
			//}
			//printf("Enter a subkey: \n");
			//if (!(scanf_s("%s", subKey))) {
			//	printf("Error in sub key.\n");
			//	continue;
			//}
			NotifyAboutChangingTheKey(hMainKey, subKey);
			break;
		case 7:
			manage_var = FALSE;
			break;
		default:
			break;
		}
	}

	getchar();
	return 0;
}

BOOL CreateRegistryKey(HKEY hKeyParent, LPCSTR subkey)
{
	DWORD dwDisposition;		// It verify new key is created or open existing key
	HKEY  hKey;
	DWORD Ret;					// Use to check status


	Ret =
		RegCreateKeyEx(
			hKeyParent,
			subkey,
			0,
			NULL,
			REG_OPTION_NON_VOLATILE,
			KEY_ALL_ACCESS,
			NULL,
			&hKey,
			&dwDisposition);

	if (Ret != ERROR_SUCCESS)
	{
		printf("Error opening or creating new key\n");
		return FALSE;
	}
	else {
		printf("Key was succesfully created and opened.\n");
	}

	// Close the key
	RegCloseKey(hKey); 
	return TRUE;
}


BOOL SearchKey(HKEY hKeyParent, LPCSTR subkey) {
	DWORD Ret;				// Use to check status
	HKEY hKey;				


	// Open the key
	Ret = RegOpenKeyEx(
		hKeyParent,
		subkey,
		0,
		KEY_WRITE,
		&hKey
	);

	if (Ret == ERROR_FILE_NOT_FOUND) {
		return FALSE;
	}

	// Close the key
	RegCloseKey(hKey);
	return TRUE;
}

BOOL ReadFlags(HKEY hKeyParent, LPCSTR subkey) {
	DWORD Ret;			// Use to check status
	HKEY hKey;


	// Open the key and check if the registry exists
	Ret = RegOpenKeyEx(
		hKeyParent,
		subkey,
		0,
		KEY_WRITE,
		&hKey
	);

	if (Ret == ERROR_SUCCESS)
	{
		DWORD size = 1024;
		PSECURITY_DESCRIPTOR psd = LocalAlloc(LMEM_FIXED, size);
		LPSTR* DACL = new LPSTR;
		if (RegGetKeySecurity(hKey, DACL_SECURITY_INFORMATION, psd, &size) == ERROR_SUCCESS)
		{
			ConvertSecurityDescriptorToStringSecurityDescriptor(psd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, DACL, NULL);
			//std::string resStr = ParseAceString(DACL);
			PrintParsedAceString(*DACL);
			//std::cout << *DACL;
			//std::cin.get();
		}
		printf("\n");
		return TRUE;
	}

	return FALSE;
}

BOOL WriteDwordInRegistry(HKEY hKeyParent, LPCSTR subkey, LPCSTR valueName, DWORD data)
{
	DWORD Ret;			// Use to check status
	HKEY hKey;			


	// Open the key and check if the registry exists
	Ret = RegOpenKeyEx(
		hKeyParent,
		subkey,
		0,
		KEY_WRITE,
		&hKey
	);


	if (Ret == ERROR_SUCCESS)
	{

		//Set the value in key
		if (ERROR_SUCCESS !=
			RegSetValueEx(
				hKey,
				valueName,
				0,
				REG_DWORD,
				reinterpret_cast<BYTE *>(&data),
				sizeof(data)))
		{
			RegCloseKey(hKey);
			return FALSE;
		}

		// Close the key
		RegCloseKey(hKey);
		printf("Data was successfully written.\n");
		return TRUE;
	}

	return FALSE;
}


BOOL ReadDwordValueRegistry(HKEY hKeyParent, LPCSTR subkey, LPCSTR valueName, DWORD *readData)
{

	HKEY hKey;
	DWORD Ret;

	// Open and Check if the registry exists
	Ret = RegOpenKeyEx(
		hKeyParent,
		subkey,
		0,
		KEY_READ,
		&hKey
	);

	if (Ret == ERROR_SUCCESS)
	{

		DWORD data;
		DWORD len = sizeof(DWORD);		//	Size of data

		Ret = RegQueryValueEx(
			hKey,
			valueName,
			NULL,
			NULL,
			(LPBYTE)(&data),
			&len
		);

		if (Ret == ERROR_SUCCESS)
		{
			RegCloseKey(hKey);
			(*readData) = data;
			return TRUE;
		}

		RegCloseKey(hKey);
		printf("Data was successfully read.\n");
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

BOOL WriteStringInRegistry(HKEY hKeyParent, LPCSTR subkey, LPCSTR valueName, LPCSTR strData)
{
	DWORD Ret;
	HKEY hKey;

	// Check if the registry exists
	Ret = RegOpenKeyEx(
		hKeyParent,
		subkey,
		0,
		KEY_WRITE,
		&hKey
	);

	if (Ret == ERROR_SUCCESS)
	{
		if (ERROR_SUCCESS !=
			RegSetValueEx(
				hKey,
				valueName,
				0,
				REG_SZ,
				(LPBYTE)(strData),
				((((DWORD)lstrlen(strData) + 1)) * 2)))
		{
			RegCloseKey(hKey);
			return FALSE;
		}

		RegCloseKey(hKey);
		return TRUE;
	}

	return FALSE;
}

// enumerate the subkeys of the specified key
VOID QueryKey(HKEY hKey)
{
	TCHAR    tcBuffSubKeyName[MAX_KEY_LENGTH];
	DWORD    dwSizeNameString;

	TCHAR    tcBuffClassName[MAX_PATH];
	DWORD    dwSizeClassName = MAX_PATH;
	DWORD    dwNumberSubKeys = 0;
	DWORD    dwMaxSubKeyLen;
	DWORD    dwMaxClassLen;
	DWORD    dwNumberValuesOfThatKey;
	DWORD    dwMaxValueNameLen;
	DWORD    dwbMaxValueLen;
	DWORD    dwSecurityDescriptor;
	FILETIME ftLastWriteTime;

	DWORD i, retCode;

	TCHAR  achValue[MAX_VALUE_NAME];
	DWORD cchValue = MAX_VALUE_NAME;

	// Get the class name and the value count. 
	retCode = RegQueryInfoKey(
		hKey,							// key handle 
		tcBuffClassName,                // buffer for class name 
		&dwSizeClassName,				// size of class string 
		NULL,							// reserved (should always be null) 
		&dwNumberSubKeys,               // number of subkeys 
		&dwMaxSubKeyLen,				// longest subkey size 
		&dwMaxClassLen,					// longest class string 
		&dwNumberValuesOfThatKey,       // number of values for this key 
		&dwMaxValueNameLen,				// longest value name 
		&dwbMaxValueLen,				// longest value data 
		&dwSecurityDescriptor,			// security descriptor 
		&ftLastWriteTime				// last write time
	);


	// Enumerate the subkeys, until RegEnumKeyEx fails.
	if (dwNumberSubKeys)
	{
		printf("\nNumber of subkeys: %d\n", dwNumberSubKeys);

		for (i = 0; i < dwNumberSubKeys; i++)
		{
			dwSizeNameString = MAX_KEY_LENGTH;
			retCode = RegEnumKeyEx(hKey, i,
				tcBuffSubKeyName,
				&dwSizeNameString,
				NULL,
				NULL,
				NULL,
				&ftLastWriteTime);
			if (retCode == ERROR_SUCCESS)
			{
				printf("(%d) %s\n", i + 1, tcBuffSubKeyName);
			}
		}
	}

	// Enumerate the key values. 
	if (dwNumberValuesOfThatKey)
	{
		printf("\nNumber of values: %d\n", dwNumberValuesOfThatKey);

		for (i = 0, retCode = ERROR_SUCCESS; i< dwNumberValuesOfThatKey; i++)
		{
			cchValue = MAX_VALUE_NAME;
			achValue[0] = '\0';
			retCode = RegEnumValue(hKey, i,
				achValue,
				&cchValue,
				NULL,
				NULL,
				NULL,
				NULL);

			if (retCode == ERROR_SUCCESS)
			{
				printf(("(%d) %s\n"), i + 1, achValue);
			}
		}
	}
}

VOID PrintParsedAceString(char* str) {
	
	char ace_type[100] = "";
	char key_rights[100] = "";
	char file_rights[100] = "";
	char res_string[200] = "";
	char ace_sid[150] = "";

	int j = 1;
	ace_sid[0] = '(';

	int amount_dots = 0;
	int i = 0;
	while (str[i] != ')') {
		if (str[i] == ';') {
			amount_dots += 1;
		}
		if (amount_dots == 5) {
			while ((str[i] != ')') && (strlen(str) > i + 1)) {
				ace_sid[j] = str[i + 1];
				j++;
				i += 1;
			}
			if (str[i] == ')')
				break;
		}
		if ((str[i] == '(') && (strlen(str) > i + 1)) {
			switch (str[i + 1]) {
				case 'A':
					strncpy_s(ace_type, "ACCESS_ALLOWED_ACE_TYPE", sizeof("ACCESS_ALLOWED_ACE_TYPE"));
					break;
				case 'D':
					strncpy_s(ace_type, "ACCESS_DENIED_ACE_TYPE", sizeof("ACCESS_DENIED_ACE_TYPE"));
					break;
				default:
					strncpy_s(ace_type, "0x00", sizeof("0x00"));
					break;
			}
		}
		if ((str[i + 2] == ';') && (strlen(str) > i + 4)) {
			if (str[i + 3] == 'K') {
				if (str[i + 4] == 'A')
					strncpy_s(key_rights, "KEY_ALL_ACCESS", sizeof("KEY_ALL_ACCESS"));
				if (str[i + 4] == 'R')
					strncpy_s(key_rights, "KEY_READ", sizeof("KEY_READ"));
				if (str[i + 4] == 'W')
					strncpy_s(key_rights, "KEY_WRITE", sizeof("KEY_WRITE"));
				if (str[i + 4] == 'X')
					strncpy_s(key_rights, "KEY_EXECUTE", sizeof("KEY_EXECUTE"));
			}
			
			if (str[i + 3] == 'F') {
				if (str[i + 4] == 'A')
					strncpy_s(file_rights, "FILE_ALL_ACCESS", sizeof("FILE_ALL_ACCESS"));
				if (str[i + 4] == 'R')
					strncpy_s(file_rights, "FILE_GENERIC_READ", sizeof("FILE_GENERIC_READ"));
				if (str[i + 4] == 'W')
					strncpy_s(file_rights, "FILE_GENERIC_WRITE", sizeof("FILE_GENERIC_WRITE"));
				if (str[i + 4] == 'X')
					strncpy_s(file_rights, "FILE_GENERIC_EXECUTE", sizeof("FILE_GENERIC_EXECUTE"));
			}
			
		}
		i += 1;
	}
	ace_sid[j] = '\0';

	printf("Ace sid: \t%s\n", ace_sid);
	printf("Ace type: \t%s\n", ace_type);
	printf("Key rights: \t%s\n", key_rights);
	if (strcmp(file_rights, "") > 0)
		printf("File rights: \t%s\n", file_rights);
	else
		printf("File rights: \t0x00\n");
}


VOID NotifyAboutChangingTheKey(LPCSTR hMainKeyStr, LPCSTR subKey) {
	hMainKeyStr = "HKCU";
	subKey = "Software\\Microsoft\\Notepad";
	
	HKEY hMainKey;
	DWORD  dwFilter = REG_NOTIFY_CHANGE_NAME |
		REG_NOTIFY_CHANGE_ATTRIBUTES |
		REG_NOTIFY_CHANGE_LAST_SET |
		REG_NOTIFY_CHANGE_SECURITY;

	HANDLE hEvent;
	HKEY   hKey;
	LONG   lErrorCode;

	// Convert parameters to appropriate handles.
	if (strcmp("HKLM", hMainKeyStr) == 0) hMainKey = HKEY_LOCAL_MACHINE;
	else if(strcmp("HKU", hMainKeyStr) == 0) hMainKey = HKEY_USERS;
	else if (strcmp("HKCU", hMainKeyStr) == 0) hMainKey = HKEY_CURRENT_USER;
	else if (strcmp("HKCR", hMainKeyStr) == 0) hMainKey = HKEY_CLASSES_ROOT;
	else if (strcmp("HCC", hMainKeyStr) == 0) hMainKey = HKEY_CURRENT_CONFIG;
	else
	{
		printf("Usage: notify [HKLM|HKU|HKCU|HKCR|HCC] [<subkey>]\n");
		return;
	}

	// Open a key.
	lErrorCode = RegOpenKeyEx(hMainKey, subKey, 0, KEY_NOTIFY, &hKey);
	if (lErrorCode != ERROR_SUCCESS)
	{
		printf("Error in RegOpenKeyEx (%d).\n", lErrorCode);
		return;
	}

	// Create an event.
	hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (hEvent == NULL)
	{
		printf("Error in CreateEvent (%d).\n", GetLastError());
		return;
	}

	// Watch the registry key for a change of value.
	lErrorCode = RegNotifyChangeKeyValue(hKey,
		TRUE,
		dwFilter,
		hEvent,
		TRUE);
	if (lErrorCode != ERROR_SUCCESS)
	{
		printf("Error in RegNotifyChangeKeyValue (%d).\n", lErrorCode);
		return;
	}

	// Wait for an event to occur.
	printf("Waiting for a change in the specified key...\n");
	if (WaitForSingleObject(hEvent, INFINITE) == WAIT_FAILED)
	{
		printf("Error in WaitForSingleObject (%d).\n", GetLastError());
		return;
	}
	else printf("\nChange has occurred.\n");

	// Close the key.
	lErrorCode = RegCloseKey(hKey);
	if (lErrorCode != ERROR_SUCCESS)
	{
		printf("Error in RegCloseKey (%d).\n", GetLastError());
		return;
	}

	// Close the handle.
	if (!CloseHandle(hEvent))
	{
		printf("Error in CloseHandle.\n");
		return;
	}
}


