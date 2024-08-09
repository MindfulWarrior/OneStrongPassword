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

#include "heap.h"

using namespace std;
using namespace OneStrongPassword;

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
	if (data) {
		for (size_t n = 0; n < size; n++)
			data[n] = 0;
	}
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
	SetOSPError(error, OSP_API_Error, OSP_ERROR_NOT_SUPPORTED);
	return 0;
}

bool OS::CopyToClipboard(char* const data, size_t size, OSPError* error)
{
	SetOSPError(error, OSP_API_Error, OSP_ERROR_NOT_SUPPORTED);
	return 0;
}

bool OS::PasteFromClipboard(char* const data, size_t size, OSPError* error)
{
	SetOSPError(error, OSP_API_Error, OSP_ERROR_NOT_SUPPORTED);
	return 0;
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
		try {
			heap = new Heap(_available);
		}
		catch (bad_alloc) {
			return SetOSPError(error, OSP_API_Error, OSP_ERROR_NO_AVAILABLE_HEAP_MEMORY);
		}
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
	if (heap)
	{
		try {
			delete static_cast<Heap*>(heap);
		}
		catch (...) {
			return SetOSPError(error, OSP_API_Error, OSP_ERROR_UNKNOWN);
		}
		heap = 0;
		_available = _memory = 0;
	}
	return true;
}

#pragma endregion

OS::byte* OS::Alloc(size_t size, OSPError* error)
{
	if (heap && size > 0)
	{
		assert(AvailableMemory() > 0);
		if (AvailableMemory() <= 0) {
			SetOSPError(error, OSP_API_Error, OSP_ERROR_NO_AVAILABLE_HEAP_MEMORY);
			return nullptr;
		}

		auto ptr = static_cast<Heap*>(heap);
		byte* data = ptr->alloc(size, error);
		if (!data)
			return nullptr;
		
		_memory += size;
		return data;
	}
	
	if (!heap)
		SetOSPError(error, OSP_API_Error, OSP_ERROR_NOT_INITIALIZED);
	else if (!size)
		SetOSPError(error, OSP_API_Error, OSP_ERROR_SIZE_IS_0);
	return nullptr;
}

bool OS::Destroy(byte*& data, size_t size, OSPError* error)
{
	if (!heap)
		return true; // Already destroyed.

	bool success = true;

	if (Zero(data, size)) {
		auto ptr = static_cast<Heap*>(heap);
		if (success = ptr->dealloc(data, size, error)) {
			data = 0;
			_memory -= size;
		}
	}

	return success;
}
