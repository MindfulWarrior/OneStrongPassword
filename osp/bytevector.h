/*
One Strong Password

Copyright(c) Robert Richard Flores. (MIT License)

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files(the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions :
-The above copyright notice and this permission notice shall be included in
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

#include "icryptography.h"
#include <string>

namespace OneStrongPassword
{
	class ByteVector
	{
	public:
		typedef ICryptography::byte byte;

		explicit ByteVector(ICryptography& cryptography)
			: cryptography(&cryptography), bytes(nullptr), size(0), fixed(false) { }

		explicit ByteVector(ICryptography* cryptography, byte* bytes, size_t size, bool fixed = true)
			: cryptography(cryptography), bytes(bytes), size(size), fixed(fixed) { }

		virtual ~ByteVector() { Destroy(nullptr); }

		size_t Size() const { return size; }

		bool Fixed() const { return fixed; }
		bool Zeroed() const { return OS::Zeroed(bytes, size); }

		bool Alloc(size_t sz, OSPError* error = nullptr);
		bool Realloc(size_t sz, OSPError* error = nullptr);
		bool Release(OSPError* error = nullptr);
		bool Destroy(OSPError* error = nullptr);

		void Zero();

		bool CopyTo(byte* const dst, size_t sz, OSPError* error = nullptr) const;
		bool CopyFrom(const byte* const src, size_t sz, size_t pos = 0, OSPError* error = nullptr);

		bool CopyFrom(const ByteVector& v, OSPError* error = nullptr);
		bool CopyFrom(const std::string& str, OSPError* error = nullptr);

		bool MoveTo(byte*& dst, size_t& sz, OSPError* error = nullptr);
		bool MoveTo(ByteVector& v, OSPError* error = nullptr);

		      byte& operator[](size_t n)       { return bytes[n]; }
		const byte& operator[](size_t n) const { return bytes[n]; }

		operator       byte*()       { return bytes; }
		operator const byte*() const { return bytes; }

		operator       char*()       { return (char*)bytes; }
		operator const char*() const { return (const char*)bytes; }

		operator       void*()       { return bytes; }
		operator const void*() const { return bytes; }

		bool operator==(const ByteVector& v) const
			{ return Size() == v.Size() && 0 == memcmp(bytes, v.bytes, Size()); }

		bool operator!=(const ByteVector& v) const
			{ return Size() != v.Size() || 0 != memcmp(bytes, v.bytes, Size()); }

	protected:
		ICryptography* cryptography;
		byte* bytes;
		size_t size;
		bool fixed;
	};

	template<size_t sz> class ByteArray : public ByteVector
	{
	public:
		explicit ByteArray() : ByteVector(nullptr, data, sz) { Zero(); }

	protected:
		byte data[sz];
	};
}