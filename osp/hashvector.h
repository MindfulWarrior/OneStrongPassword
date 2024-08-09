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

#include "bytevector.h"

namespace OneStrongPassword
{
	class HashVector : public ByteVector
	{
	public:
		explicit HashVector(ICryptography& cryptography) : ByteVector(cryptography) { }
		virtual ~HashVector() { }

		bool Initialize(OSPError* error = nullptr)
			{ return ByteVector::Alloc(cryptography->HashSize(error), error); }

		bool Realloc(OSPError* error = nullptr)
			{ return ByteVector::Realloc(cryptography->HashSize(error), error); }

		bool Destroy(OSPError* error = nullptr) { return ByteVector::Destroy(error); }

		bool Alloc(size_t sz, OSPError* error = nullptr) { return false; }
		bool Realoc(size_t sz, OSPError* error = nullptr) { return false; }
	};
}
