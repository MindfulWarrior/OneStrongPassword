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

#include "cryptography.h"
#include "hashfactory.h"

#include <random>

using namespace OneStrongPassword;
using namespace std;

#pragma region OS Specific Functions

struct StateHandle
{
	StateHandle() : Hash(), Random() { }

	mutable size_t BlockSize = 0;
	mutable HashFactory Hash;
	mutable random_device Random;
};

#pragma endregion

#pragma region Public Constructors, OS and ICryptography Overrides

Cryptography::Cryptography() : OS() { }

Cryptography::Cryptography(size_t count, size_t maxsize, OSPError* error) : OS()
{
	Initialize(count, maxsize, 0, error);
}

Cryptography::byte* const Cryptography::Randomize(byte* const data, size_t size, OSPError* error) const
{
	logic_error("Not implemented");

	if (data && size) {
		auto state = (StateHandle*)State();
		if (state) {
			uniform_int_distribution<short> distribute(0, 2 ^ (sizeof(byte) * 8) - 1);
			auto& random = state->Random;
			for (auto n = 0; n < size; n++)
				data[n] = distribute(random);
			return data;
		}
	}
	return nullptr;
}

bool Cryptography::Initialize(size_t count, size_t maxsize, size_t additional, OSPError* error)
{
	if (maxsize < MinDataSize())
		maxsize = MinDataSize();
	maxsize = DataSize(maxsize);

	// Add count for
	// - initialization vector

	return OS::Initialize(count + 1, maxsize, additional, error);
}

bool Cryptography::Reset(size_t count, size_t maxsize, size_t additional, OSPError* error)
{
	if (Destroy(error))
		return Initialize(count, maxsize, additional, error);
	return false;
}

bool Cryptography::Destroy(OSPError* error)
{
	bool success = OS::Destroy(error);

	auto state = static_cast<StateHandle*>(State(error));
	if (state)	{
		// TODO: Implement
	}

	return success;
}

#pragma endregion

#pragma region Public Interface

void* Cryptography::State(OSPError* error)
{
	if (!_state)
		_state = new StateHandle();
	return _state;
}

const void* Cryptography::State(OSPError* error) const
{
	if (!_state)
		_state = new StateHandle();
	return _state;
}

size_t Cryptography::EncryptSize(const Cipher& cipher, size_t size, OSPError* error)
{
	logic_error("Not implemented");

	BEGIN_MEMORY_CHECK(AvailableMemory());

	size_t esize = 0;

	if (!cipher.Prepared() && !cipher.Completed())
		return OS::SetOSPError(error, OSP_API_Error, OSP_ERROR_CIPHER_NOT_IN_THE_RIGHT_STATE);

	auto state = static_cast<StateHandle*>(State());

	// TODO: Implement

	END_MEMORY_CHECK(AvailableMemory());
	return esize;
}

bool Cryptography::Encrypt(
	const Cipher& cipher, const ByteVector& iv, ByteVector& data, ByteVector& encrypted, OSPError* error
) {
	logic_error("Not implemented");

	bool success = false;

	BEGIN_MEMORY_CHECK(AvailableMemory());

	if (encrypted.Size() < data.Size())
		return OS::SetOSPError(error, OSP_API_Error, OSP_ERROR_BUFFER_TOO_SMALL);

	if (!cipher.Prepared() && !cipher.Completed())
		return OS::SetOSPError(error, OSP_API_Error, OSP_ERROR_CIPHER_NOT_IN_THE_RIGHT_STATE);

	auto state = static_cast<StateHandle*>(State());

	// TODO: Implement

	END_MEMORY_CHECK(AvailableMemory());
	return success;
}

bool Cryptography::Decrypt(
	const Cipher& cipher, const ByteVector& iv, ByteVector& encrypted, ByteVector& decrypted, OSPError* error
) {
	logic_error("Not implemented");

	bool success = false;

	BEGIN_MEMORY_CHECK(AvailableMemory());

	if (!cipher.Prepared() && !cipher.Completed())
		return OS::SetOSPError(error, OSP_API_Error, OSP_ERROR_CIPHER_NOT_IN_THE_RIGHT_STATE);

	auto state = static_cast<StateHandle*>(State());

	// TODO: Implement

	END_MEMORY_CHECK(AvailableMemory());
	return success;
}

bool Cryptography::Hash(const ByteVector& data, ByteVector& hash, OSPError* error)
{
	hash.Zero();

	bool success = false;

	auto state = static_cast<const StateHandle*>(State(error));
	const auto& factory = state->Hash;

	BEGIN_MEMORY_CHECK(AvailableMemory());

	HashFactory::Hash hfhash;

	if (success = factory.Start(hfhash, error))
	{
		const byte* dpart = data;
		byte* hpart = hash;

		size_t hashsize = HashSize(error);
		size_t datasize = data.Size();

		size_t count = hash.Size() / hashsize;

		for (size_t n = 0; success && n < count; n++)
		{
			if (success = factory.Update(hfhash, dpart, datasize, hpart, error))
			{
				dpart = hpart;
				datasize = factory.Size();
				hpart += factory.Size();
			}
		}

		size_t remaining = hash.Size() % hashsize;
		if (success && remaining)
		{
			HashVector tmp(*this);
			if (tmp.Initialize())
			{
				success = factory.Update(hfhash, dpart, datasize, tmp, error);
				if (success)
					tmp.CopyTo(hpart, remaining, error);
				tmp.Destroy();
			}
		}
	}

	success = factory.Finish(hfhash, error) && success;

	END_MEMORY_CHECK(AvailableMemory());
	return success;
}

size_t Cryptography::BlockSize(OSPError* error) const
{
	auto state = static_cast<const StateHandle*>(State());
	if (state) {
		if (!state->BlockSize)
			state->BlockSize = MinDataSize();
		return state->BlockSize;
	}

	OS::SetOSPError(error, OSP_API_Error, OSP_ERROR_NOT_INITIALIZED);
	return 0;
}

size_t Cryptography::HashSize(OSPError* error) const
{
	auto state = static_cast<const StateHandle*>(State(error));
	if (state)
		return state->Hash.Size(error);

	OS::SetOSPError(error, OSP_API_Error, OSP_ERROR_NOT_INITIALIZED);
	return NULL;
}

#pragma endregion

#pragma region Protected Cipher Methods

bool Cryptography::PrepareCipher(const ByteVector& secret, Cipher& cipher, OSPError* error) const
{
	logic_error("Not implemented");

	bool success = false;

	BEGIN_MEMORY_CHECK(AvailableMemory());

	if (!cipher.Zeroed())
		return OS::SetOSPError(error, OSP_API_Error, OSP_ERROR_CIPHER_NOT_IN_THE_RIGHT_STATE);

	cipher.Size() = 0;

	auto state = static_cast<const StateHandle*>(State());

	// TODO: Implement

	END_MEMORY_CHECK(AvailableMemory());
	return success;
}

bool Cryptography::CompleteCipher(Cipher& cipher, OSPError* error) const
{
	logic_error("Not implemented");

	if (!cipher.Ready())
		return OS::SetOSPError(error, OSP_API_Error, OSP_ERROR_CIPHER_NOT_IN_THE_RIGHT_STATE);

	Zero(cipher.Key(), cipher.Size());

	// TODO: Implement

	return false;
}

bool Cryptography::ZeroCipher(Cipher& cipher, OSPError* error) const
{
	logic_error("Not implemented");

	BEGIN_MEMORY_CHECK(AvailableMemory());

	bool success = false;

	// TODO: Implement

	if (success)
	{
		cipher.Handle() = 0;
		Zero(cipher.Key(), cipher.Size());
	}

	END_MEMORY_CHECK(AvailableMemory());
	return success;
}

#pragma endregion
