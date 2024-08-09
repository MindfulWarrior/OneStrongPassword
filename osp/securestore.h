/*
One Strong Password

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

#include <map>
#include <string>

#include "bytevector.h"
#include "cryptography.h"

namespace OneStrongPassword
{
	class StrongPassword;

	class SecureStore : public Cryptography
	{
	public:
		typedef Cryptography::byte byte;

		static const int DEFAULT_COUNT = 10;
		static const int DEFAULT_SIZE = 512;

		static bool ReleaseDecrypted(ByteVector& decrypted, OSPError* error = nullptr);

		SecureStore() : Cryptography(), IV(*this) { }
		SecureStore(size_t blocks, size_t maxsize, OSPError* error = nullptr)
			: Cryptography(), IV(*this) { Initialize(blocks, maxsize, 0, error); }

		virtual ~SecureStore() { Destroy(nullptr); }

		virtual bool Initialize(size_t count, size_t maxsize = 0, OSPError* error = nullptr)
			{ return Initialize(count, maxsize, 0, error); }

		virtual bool Reset(size_t count, size_t maxsize = 0, OSPError* error = nullptr)
			{ return Reset(count, maxsize, 0, error); }

		virtual bool Destroy(OSPError* error = nullptr);

		byte* Alloc(size_t size, OSPError* error = nullptr) { return Cryptography::Alloc(size, error); }
		bool Destroy(byte*& data, size_t size, OSPError* error = nullptr)
			{ return Cryptography::Destroy(data, size, error); }

		size_t DataSize(const std::string& name) const;

		bool Encrypt(
			const Cipher& cipher,
			ByteVector& data,
			ByteVector& encrypted,
			OSPError* error = nullptr
		);

		bool Decrypt(
			const Cipher& cipher,
			ByteVector& encrypted,
			ByteVector& decrypted,
			OSPError* error = nullptr
		);

		bool StoreData(
			const std::string& name,
			Cipher& cipher,
			ByteVector& data,
			size_t esize = 0,
			OSPError* error = nullptr
		);
		
		bool DispenseData(
			const std::string& name,
			Cipher& cipher,
			ByteVector& data,
			OSPError* error = nullptr
		);
		
		bool DestroyData(const std::string& name, OSPError* error = nullptr);

		bool StrongHash(const ByteVector& data, ByteVector& hash, OSPError* error = nullptr);

	protected:
		virtual bool Initialize(size_t count, size_t maxsize, size_t additional, OSPError* error);
		virtual bool Reset(size_t count, size_t maxsize, size_t additional, OSPError* error)
			{ return Cryptography::Reset(count, maxsize, additional, error); }

		bool ParametersValid(size_t dsize, size_t esize);

		byte* PrepareEncyption(ByteVector& data, ByteVector& encrypted, OSPError* error);
		byte* PrepareDecryption(ByteVector& decrypted, size_t esize, OSPError* error);

		size_t UpdateStored(const std::string& name, ByteVector& encrypted, size_t dsize, OSPError* error);

	private:
		typedef struct Block { byte* Data; size_t DataSize; size_t StoredSize; } Block;
		typedef std::map<std::string, Block> LabeledStore;

		LabeledStore labeled;

		class InitVector : public ByteVector
		{
		public:
			InitVector(SecureStore& store) : ByteVector(store), store(store), init(true) { }
			~InitVector() { }

			bool Init(OSPError* error);
			bool Destroy(OSPError* error) { init = true; return ByteVector::Destroy(error); }
		private:
			SecureStore & store;
			bool init;
		};

		InitVector IV;
	};

}
