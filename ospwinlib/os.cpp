/*
One Strong Password Generator Windows library

Copyright(c) Robert Richard Flores. (MIT License)

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files(the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:
- The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.
- The Software is provided "as is", without warranty of any kind, express or
implied, including but not limited to the warranties of merchantability,
fitness for a particular purpose and noninfringement.In no event shall the
authors or copyright holders be liable for any claim, damages or other
liability, whether in an action of contract, tort or otherwise, arising from,
out of or in connection with the Software or the use or other dealings in the
Software.
*/

#include <windows.h>
#include "../osp/os.h"

const char* AppTitle = "One Strong Password";
const size_t OSP_MAX_PASSWORD_LENGTH = 64;

using namespace std;

string MsgBoxTitle;
HHOOK Hook;

LRESULT CALLBACK MsgBoxTextProc(int nCode, WPARAM wParam, LPARAM lParam)
{
	if (nCode == HCBT_ACTIVATE)
	{
		HGDIOBJ font = GetStockObject(ANSI_FIXED_FONT);

		HWND parent = (HWND)wParam;
		HWND child = GetWindow(parent, GW_CHILD);
		while (child)
		{
			CHAR className[16];
			if (GetClassNameA(child, className, 16) && _strnicmp(className, "Static", 16) == 0)
				SendMessage(child, WM_SETFONT, (WPARAM)font, MAKELPARAM(FALSE, 0));
			child = GetNextWindow(child, GW_HWNDNEXT);
		}
		SetWindowTextA(parent, MsgBoxTitle.c_str());
		UnhookWindowsHookEx(Hook);
	}
	else
		return CallNextHookEx(Hook, nCode, wParam, lParam);
	return 0;
}

using namespace OneStrongPassword;

bool OS::checkError(bool success, OSPError* ospError)
{
	if (!success)
	{
		DWORD error = GetLastError();
		OS::SetOSPError(ospError, OSP_System_Error, error);

#ifdef _DEBUG
		LPVOID errormsg;

		FormatMessage(
			FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL,
			error,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPTSTR)&errormsg,
			0,
			NULL
		);

		OutputDebugString((LPTSTR)errormsg);

		LocalFree(errormsg);
#endif

		return false;
	}
	return true;
}

#pragma region Public Static Methods

bool OS::SetOSPError(OSPError* ospError, OSPErrorType type, uint32_t error)
{
	if (ospError && ospError->Type == OSP_No_Error)
	{
		ospError->Type = type;
		ospError->Code = error;
	}
	return false;
}

OS::byte* OS::Zero(byte* const data, size_t size)
{
	if (data && size > 0)
		return static_cast<byte*>(SecureZeroMemory(data, size));
	return data;
}

bool OS::Zeroed(const byte* const data, size_t size) 
{
	if (!size)
		return true;

	for (size_t n = 0; n < size; n++)
	{
		if (data[n])
			return false;
	}
	return true;
}

int32_t OS::Show(
	char* const data, size_t size, size_t width, const string& title, uint32_t type, OSPError* error
) {
	// Trick MessageBox to be larger for when font changes, by making the title larger
	//--------------------------------------------------------------------------------
	HGDIOBJ sysObj = GetStockObject(SYSTEM_FONT);
	LOGFONT sysFont;
	memset(&sysFont, 0, sizeof(LOGFONT));
	GetObject(sysObj, sizeof(LOGFONT), &sysFont);

	HGDIOBJ fixedObj = GetStockObject(ANSI_FIXED_FONT);
	LOGFONT fixedFont;
	memset(&fixedFont, 0, sizeof(LOGFONT));
	GetObject(fixedObj, sizeof(LOGFONT), &fixedFont);

	if (width == 0)
		width = size;

	size_t length = min(strnlen(data, size), width);
	if (sysFont.lfWidth && fixedFont.lfWidth)
		length = length * fixedFont.lfWidth / sysFont.lfWidth;

	string header;
	while (header.size() < length)
		header += 'X';
	//--------------------------------------------------------------------------------

	MsgBoxTitle = title;
	if (MsgBoxTitle.empty())
		MsgBoxTitle = AppTitle;

	Hook = SetWindowsHookEx(WH_CBT, (HOOKPROC)&MsgBoxTextProc, NULL, GetCurrentThreadId());
	auto response = MessageBoxA(NULL, data, header.c_str(), MB_TASKMODAL | type);
	checkError(response > 0, error);
	return response;
}

bool OS::CopyToClipboard(char* const data, size_t size, OSPError* error)
{
	if (!checkError(OpenClipboard(NULL), error))
		return false;

	HGLOBAL hglob = 0;
	PVOID pcopy = 0;

	bool success = checkError(EmptyClipboard(), error);
	if (success)
	{
		success = checkError(hglob = GlobalAlloc(GMEM_FIXED, size + sizeof(char)), error);
		if (hglob)
		{
			success = checkError(pcopy = GlobalLock(hglob), error);
			if (pcopy)
			{
				strcpy_s(static_cast<char*>(pcopy), size + sizeof(char), data);
				success = checkError(NULL != ::SetClipboardData(CF_TEXT, hglob), error);
				success = checkError(GlobalUnlock(hglob), error) && success;
			}
		}
	}

	success = checkError(CloseClipboard(), error) && success;
	if (!success && hglob)
		GlobalFree(hglob);

	if (success)
		Zero(reinterpret_cast<byte* const>(data), size);

	return success;
}

bool OS::PasteFromClipboard(char* const data, size_t size, OSPError* error)
{
	const int timeout = 20;
	int safety = 0;

	while (!IsClipboardFormatAvailable(CF_TEXT) && safety++ < timeout)
		Sleep(500);

	if (safety >= timeout)
		return SetOSPError(error, OSP_API_Error, OSP_ERROR_TIMEOUT);

	if (!checkError(OpenClipboard(NULL), error))
		return false;

	HGLOBAL hglob = GetClipboardData(CF_TEXT);
	bool success = checkError(hglob, error);
	if (hglob)
	{
		LPVOID ppaste = 0;
		success = checkError(ppaste = GlobalLock(hglob), error);
		if (ppaste)
		{
			strcpy_s(data, size, (const char*)ppaste);
			success = checkError(GlobalUnlock(hglob), error);
		}
	}

	success = checkError(EmptyClipboard(), error) && success;
	success = checkError(CloseClipboard(), error) && success;

	return success;
}

#pragma endregion

#pragma region Public Overridable Interface

const size_t OS::MAX_HEAP_SIZE = 16 * 1024;

bool OS::Initialize(size_t count, size_t maxsize, size_t additional, OSPError* error)
{
	if (_available || heap)
		return SetOSPError(error, OSP_API_Error, OSP_ERROR_ALREADY_INITIALIZED);

	if (count && maxsize)
	{
		_maxdatasize = maxsize;
		_available = (maxsize * count) + additional;
		heap = HeapCreate(0, 0, 0);
		return checkError(NULL != heap, error);
	}

	return true;
}

bool OS::Reset(size_t blocks, size_t maxsize, size_t additional, OSPError* error)
{
	if (Destroy(error))
	{
		if (blocks && maxsize)
			return Initialize(blocks, maxsize, additional, error);
		return true;
	}
	return false;
}

bool OS::Destroy(OSPError* error)
{
	bool success = true;

	if (heap)
	{
		success = HeapDestroy(heap) && success;
		heap = 0;
		_available = _memory = 0;
	}

	return checkError(success, error);
}

#pragma endregion

OS::byte* OS::Alloc(size_t size, OSPError* error)
{
	if (heap && size > 0)
	{
		assert(AvailableMemory() > 0);
		if (AvailableMemory() <= 0)
		{
			SetOSPError(error, OSP_API_Error, OSP_ERROR_NO_AVAILABLE_HEAP_MEMORY);
			return nullptr;
		}
	#ifdef _DEBUG
		void* data = HeapAlloc(heap, HEAP_GENERATE_EXCEPTIONS | HEAP_ZERO_MEMORY, size);
	#else
		void* data = HeapAlloc(heap, HEAP_ZERO_MEMORY, size);
	#endif
		assert(data);
		if (data)
			_memory += HeapSize(heap, 0, data);
		return static_cast<byte*>(data);
	}
	
	if (!heap)
		SetOSPError(error, OSP_API_Error, OSP_ERROR_NOT_INITIALIZED);
	else if (!size)
		SetOSPError(error, OSP_API_Error, OSP_ERROR_SIZE_IS_0);
	return nullptr;
}

bool OS::Destroy(byte*& data, size_t size, OSPError* error)
{
	bool success = true;

	if (heap && data)
	{
		_memory -= HeapSize(heap, 0, data);
		success = HeapFree(heap, 0, Zero(data, size));
		data = 0;
	}

	return checkError(success, error);
}
