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

#include "osp.h"
#include "os.h"
#include "icryptography.h"
#include "cipher.h"
#include "hashvector.h"

namespace OneStrongPassword
{
	class Cryptography : protected OS, public ICryptography
	{
	public:
		typedef ICryptography::byte byte;

		Cryptography();
		Cryptography(size_t count, size_t maxsize = 0, OSPError* error = nullptr);

		virtual ~Cryptography() { Destroy(nullptr); }

		size_t AvailableMemory() const { return OS::AvailableMemory(); }
		size_t MaxDataSize() const { return OS::MaxDataSize(); }
		size_t MinDataSize() const { return HashSize(); }

		virtual size_t BlockSize(OSPError* error = nullptr) const;
		virtual size_t HashSize(OSPError* error = nullptr) const;

		virtual byte * const Randomize(byte* const data, size_t size, OSPError* error = nullptr) const;

		virtual bool Initialize(size_t count, size_t maxsize = 0, OSPError* error = nullptr)
			{ return Initialize(count, maxsize, 0, error); }

		virtual bool Reset(size_t count, size_t maxsize = 0, OSPError* error = nullptr)
			{ return Reset(count, maxsize, 0, error); }

		virtual bool Destroy(OSPError* error = nullptr);

		virtual byte* Alloc(size_t size, OSPError* error = nullptr)
			{ return OS::Alloc(size, error); }

		virtual bool Destroy(byte*& data, size_t size, OSPError* error = nullptr)
			{ return OS::Destroy(data, size, error); }

		size_t DataSize(size_t size) { return BlockSize() * (size / BlockSize() + (size % BlockSize() ? 1 : 0)); }
		size_t EncryptSize(const Cipher& cipher, size_t size, OSPError* error = nullptr);

		bool Encrypt(
			const Cipher& cipher,
			const ByteVector& iv,
			ByteVector& data,
			ByteVector& encrypted,
			OSPError* error = nullptr
		);

		bool Decrypt(
			const Cipher& cipher,
			const ByteVector& iv,
			ByteVector& encrypted,
			ByteVector& decrypted,
			OSPError* error = nullptr
		);

		bool Hash(const ByteVector& data, ByteVector& hash, OSPError* error = nullptr);

		void* State(OSPError* error = nullptr);
		const void* State(OSPError* error = nullptr) const;

	protected:
		virtual bool PrepareCipher(const ByteVector& secret, Cipher& cipher, OSPError* error) const;
		virtual bool CompleteCipher(Cipher& cipher, OSPError* error) const;
		virtual bool ZeroCipher(Cipher& cipher, OSPError* error) const;

		virtual bool Initialize(size_t count, size_t maxsize, size_t additional, OSPError* error);
		virtual bool Reset(size_t count, size_t maxsize, size_t additional, OSPError* error);

	private:
		mutable void* _state = NULL;
	};
}
