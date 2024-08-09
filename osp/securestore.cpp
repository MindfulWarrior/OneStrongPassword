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

#include "securestore.h"

using namespace OneStrongPassword;
using namespace std;

bool SecureStore::Initialize(size_t count, size_t maxsize, size_t additional, OSPError* error)
{
	// Additional 
	// 1. initialization vector
	// Add to count for
	// 1. secure store buffer
	// 2. salted encryption/decryption buffer

	bool success = Cryptography::Initialize(count + 2, maxsize, additional + IV.Size(), error);
	if (success)
		success = IV.Init(error);
	return success;
}

bool SecureStore::Destroy(OSPError* error)
{
	bool success = true;

	 IV.Destroy(error);

	for (auto itr : labeled)
		success = Destroy(itr.second.Data, itr.second.StoredSize, error) && success;
	labeled.clear();

	Cryptography::Destroy(error);

	CLEAR_EXPOSURE;
	return success;
}

size_t SecureStore::DataSize(const string& name) const
{
	auto block = labeled.find(name);
	if (block == labeled.end())
		return 0;
	return block->second.DataSize;
}

bool SecureStore::Encrypt(
	const Cipher& cipher, ByteVector& data, ByteVector& encrypted, OSPError* error
) {
	assert(EXPOSED(0));

	BEGIN_MEMORY_CHECK(AvailableMemory());
	INCREASE_EXPOSURE; // For exisiting data

	if (!cipher.Prepared() && !cipher.Completed())
		return OS::SetOSPError(error, OSP_API_Error, OSP_ERROR_CIPHER_NOT_IN_THE_RIGHT_STATE);

	byte* ptr = PrepareEncyption(data, encrypted, error);
	if (!ptr)
		return false;

	bool success = false;

	if (ptr == data)
		success = Cryptography::Encrypt(cipher, IV, data, encrypted, error);
	else
	{
		ByteVector buffer(this, ptr, encrypted.Size(), false);

		if (Cryptography::Encrypt(cipher, IV, buffer, encrypted, error))
		{
			buffer.Destroy(error);
			DECREASE_EXPOSURE;
			success = true;
		}
	}

	if (success)
	{
		data.Zero();
		DECREASE_EXPOSURE;
		assert(EXPOSED(0));
	}

	END_MEMORY_CHECK(AvailableMemory());
	return success;
}

bool SecureStore::Decrypt(
	const Cipher& cipher, ByteVector& encrypted, ByteVector& decrypted, OSPError* error
) {
	assert(EXPOSED(0));

	BEGIN_MEMORY_CHECK(AvailableMemory());

	byte* ptr = PrepareDecryption(decrypted, encrypted.Size(), error);
	if (!ptr)
		return false;

	bool success = false;

	if (ptr == decrypted)
		 success = Cryptography::Decrypt(cipher, IV, encrypted, decrypted, error);
	else
	{
		ByteVector buffer(this, ptr, encrypted.Size(), false);

		if (Cryptography::Decrypt(cipher, IV, encrypted, buffer, error))
		{
			INCREASE_EXPOSURE;
			decrypted.CopyFrom(buffer, error);
			success = true;
		}

		if (buffer.Destroy(error) && success)
			DECREASE_EXPOSURE;
	}

	if (!success)
		decrypted.Destroy(error);
	else
	{
		assert(EXPOSED(0));
		INCREASE_EXPOSURE;
	}

	END_MEMORY_CHECK(AvailableMemory());
	return success;
}

bool SecureStore::ReleaseDecrypted(ByteVector& decrypted, OSPError* error)
{
	if (decrypted.Destroy(error))
	{
		DECREASE_EXPOSURE;
		return true;
	}
	return false;
}

bool SecureStore::StoreData(
	const string& name, Cipher& cipher, ByteVector& data, size_t esize, OSPError* error
) {
	BEGIN_MEMORY_CHECK(AvailableMemory());

	bool success = false;

	size_t storedsize = 0;

	if (esize == 0)
		esize = MaxDataSize();

	ByteVector encrypted(*this);
	if (encrypted.Alloc(esize, error) && Encrypt(cipher, data, encrypted, error))
		success = 0 <= (storedsize = UpdateStored(name, encrypted, data.Size(), error));
	else
		encrypted.Destroy(error);

	END_MEMORY_CHECK(AvailableMemory() + (success ? esize - storedsize : 0));
	return success;
}

bool SecureStore::DispenseData(
	const string& name, Cipher& cipher, ByteVector& data, OSPError* error
) {
	BEGIN_MEMORY_CHECK(AvailableMemory());

	auto block = labeled.find(name);
	if (block == labeled.end())
		return OS::SetOSPError(error, OSP_API_Error, OSP_ERROR_DATA_NOT_FOUND);

	ByteVector encrypted(this, block->second.Data, block->second.StoredSize);

	if (block->second.DataSize > data.Size())
		return OS::SetOSPError(error, OSP_API_Error, OSP_ERROR_BUFFER_TOO_SMALL);

	size_t freed = encrypted.Size();

	bool success = Decrypt(cipher, encrypted, data, error);

	encrypted.Release(error);

	if (success)
	{
		success = DestroyData(name, error);
		cipher.Zero(error);
	}

	END_MEMORY_CHECK(AvailableMemory() - (success ? freed : 0));
	return success;
}

bool SecureStore::DestroyData(const string& name, OSPError* error)
{
	BEGIN_MEMORY_CHECK(AvailableMemory());

	auto block = labeled.find(name);
	if (block == labeled.end())
		return true;

	Block& stored = block->second;
	size_t freed = stored.StoredSize;

	bool success = false;

	if (Destroy(stored.Data, stored.StoredSize, error))
	{
		labeled.erase(block);
		success = true;
	}

	END_MEMORY_CHECK(AvailableMemory() - (success ? freed : 0));
	return success;
}

bool SecureStore::StrongHash(const ByteVector& data, ByteVector& hash, OSPError* error)
{
	ByteVector tmp(*this);
	if (!tmp.Alloc(hash.Size(), error))
		return false;

	bool success = Hash(data, hash, error);
	for (int n = 0; success && n < 10000; n++)
	{
		success = Hash(hash, tmp, error);
		if (success)
			success = Hash(tmp, hash, error);
	}

	tmp.Destroy(error);
	return success;
}

bool SecureStore::ParametersValid(size_t dsize, size_t esize)
{
	if (dsize > esize)
		return false;

	if (esize > MaxDataSize())
		return false;

	return true;
}

SecureStore::byte* SecureStore::PrepareEncyption(ByteVector& data, ByteVector& encrypted, OSPError* error)
{
	if (!ParametersValid(data.Size(), encrypted.Size()))
		return nullptr;

	encrypted.Zero();

	size_t saltsize = encrypted.Size() - data.Size();

	byte* buffer = data;
	if (saltsize > 0)
	{
		buffer = Alloc(encrypted.Size(), error);

		INCREASE_EXPOSURE;
		if (!data.CopyTo(buffer, data.Size(), error) || !Randomize(&buffer[data.Size()], saltsize, error))
		{
			Destroy(buffer, encrypted.Size(), error);
			return nullptr;
		}
	}

	return buffer;
}

SecureStore::byte* SecureStore::PrepareDecryption(ByteVector& decrypted, size_t esize, OSPError* error)
{
	byte* buffer = decrypted;
	if (esize > decrypted.Size())
		buffer = Alloc(esize, error);
	decrypted.Zero();
	return buffer;
}

size_t SecureStore::UpdateStored(const string& name, ByteVector& encrypted, size_t dsize, OSPError* error)
{
	bool success = false;

	Block& stored = labeled[name];

	size_t storedsize = stored.StoredSize;

	if (!Destroy(stored.Data, stored.StoredSize, error))
		storedsize = -1;
	else
	{
		encrypted.MoveTo(stored.Data, stored.StoredSize, error);
		stored.DataSize = dsize;
	}

	return storedsize;
};

bool SecureStore::InitVector::Init(OSPError* error)
{
	if (init)
		init = (Alloc(store.BlockSize(error), error) && (NULL == store.Randomize(bytes, Size(), error)));
	return !init;
}
