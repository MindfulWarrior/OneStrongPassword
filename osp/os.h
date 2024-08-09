/*
One Strong Password Generator

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

#pragma once

#include "osp.h"
#include <string>

namespace OneStrongPassword
{
	class OS
	{
	public:
		typedef unsigned char byte;

		static const size_t MAX_HEAP_SIZE;

		static bool SetOSPError(OSPError* ospError, OSPErrorType type, uint32_t error);

		static byte* Zero(byte* const data, size_t size);
		static bool Zeroed(const byte* const data, size_t size);

		static int32_t Show(
			char* const data, size_t size, size_t width, const std::string& title, uint32_t type, OSPError* error
		);

		static bool CopyToClipboard(char* const data, size_t size, OSPError* error);
		static bool PasteFromClipboard(char* const data, size_t size, OSPError* error);

		OS() { }

		OS(size_t count, size_t maxsize, OSPError* error = nullptr) { Initialize(count, maxsize, error); }

		virtual ~OS() { Destroy(nullptr); }

		size_t AvailableMemory() const { return _available - _memory; }
		size_t MaxDataSize() const { return _maxdatasize; }

		bool Initialize(size_t count, size_t maxsize, OSPError* error)
			{ return Initialize(count, maxsize, 0, error); }

		bool Reset(size_t count, size_t maxsize, OSPError* error)
			{ return Reset(count, maxsize, 0, error); }

		bool Destroy(OSPError* error);

		byte* Alloc(size_t size, OSPError* error);
		bool Destroy(byte*& data, size_t size, OSPError* error);

	protected:
		bool Initialize(size_t count, size_t maxsize, size_t additional, OSPError* error);
		bool Reset(size_t count, size_t maxsize, size_t additional, OSPError* error);

	private:
		static bool checkError(bool success, OSPError* error);

		size_t _maxdatasize = 0;
		size_t _available = 0;
		size_t _memory = 0;

		void* heap = NULL;
	};

}
