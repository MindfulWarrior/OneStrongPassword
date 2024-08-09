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
#include "os.h"

namespace OneStrongPassword
{
	class ByteVector;
	class Cipher;

	class ICryptography
	{
	public:
		typedef OS::byte byte;

		virtual byte* const Randomize(byte* const data, size_t size, OSPError* error) const = 0;

		virtual bool Initialize(size_t count, size_t maxsize, OSPError* error) = 0;
		virtual bool Reset(size_t count, size_t maxsize, OSPError* error) = 0;
		virtual bool Destroy(OSPError* error) = 0;

		virtual size_t BlockSize(OSPError* error) const = 0;
		virtual size_t HashSize(OSPError* error) const = 0;

		virtual byte* Alloc(size_t size, OSPError* error) = 0;
		virtual bool Destroy(byte*& data, size_t size, OSPError* error) = 0;

	protected:
		virtual bool PrepareCipher(const ByteVector& secret, Cipher& cipher, OSPError* error) const = 0;
		virtual bool CompleteCipher(Cipher& cipher, OSPError* error) const = 0;
		virtual bool ZeroCipher(Cipher& cipher, OSPError* error) const = 0;

		virtual bool Initialize(size_t count, size_t maxsize, size_t additonal, OSPError* error) = 0;
		virtual bool Reset(size_t count, size_t maxsize, size_t additonal, OSPError* error) = 0;

		friend Cipher;
	};

}
