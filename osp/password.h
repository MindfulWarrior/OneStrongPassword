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
	class PasswordVector : public ByteVector
	{
	public:
		explicit PasswordVector(ICryptography& cryptography) : ByteVector(cryptography) { }
		explicit PasswordVector(ICryptography* cryptography, char* const password, size_t maxLength)
			: ByteVector(cryptography, (byte* const)password, maxLength * sizeof(char)) { }

		size_t MaxLength() const { return Size() / sizeof(char); }

		      char& operator[](size_t n) { return (char&)ByteVector::operator[](n); }
		const char& operator[](size_t n) const { return (char&)ByteVector::operator[](n); }

		operator       char*()       { return (char*)ByteVector::operator byte*(); }
		operator const char*() const { return (const char*)ByteVector::operator const byte*(); }

	protected:
		PasswordVector() : PasswordVector(nullptr, 0, 0) { }
	};

	template<size_t sz> class PasswordArray : public PasswordVector
	{
	public:
		explicit PasswordArray() : PasswordVector(nullptr, (char* const)password, sz) { Zero(); }

	protected:
		byte password[sz];
	};
}