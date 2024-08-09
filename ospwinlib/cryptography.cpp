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

#include <windows.h>
#include "ospwin.h"
#include "cryptography.h"
#include "hashfactory.h"

#include <safeint.h>

using namespace msl::utilities;
using namespace OneStrongPassword;

#pragma region OS Specific Functions

struct StateHandle
{
	StateHandle() : Hash() { }

	mutable BCRYPT_ALG_HANDLE Encrypt = NULL;
	mutable size_t BlockSize = 0;
	mutable size_t KeySize = 0;

	mutable HashFactory Hash;
};

bool checkStatus(NTSTATUS status, OSPError* error)
{
	if (status < 0)
	{
		OS::SetOSPError(error, OSP_NT_Error, status);

#ifdef _DEBUG
		wchar_t error[64];
		switch (status)
		{
		case STATUS_INVALID_HANDLE:
			OutputDebugString(L"Invalid Handle");
			break;
		case STATUS_INVALID_PARAMETER:
			OutputDebugString(L"Invalid Parameter");
			break;
		default:
			_snwprintf_s(error, sizeof(error) / sizeof(error[0]), L"Unknown: %X", status);
			OutputDebugString(error);
		}
#endif
		return false;
	}
	return true;
}

BCRYPT_ALG_HANDLE EncryptAlgorithm(const StateHandle* state, OSPError* error)
{
	if (state)
	{
		if (!state->Encrypt)
			checkStatus(BCryptOpenAlgorithmProvider(&(state->Encrypt), BCRYPT_AES_ALGORITHM, NULL, 0), error);
		return state->Encrypt;
	}
	
	OS::SetOSPError(error, OSP_API_Error, OSP_ERROR_NOT_INITIALIZED);
	return NULL;
}

size_t KeySize(const StateHandle* state, OSPError* error)
{
	if (state)
	{
		if (!state->KeySize)
		{
			ULONG result;
			checkStatus(BCryptGetProperty(
				EncryptAlgorithm(state, error), BCRYPT_OBJECT_LENGTH, (PUCHAR)&(state->KeySize), sizeof(state->KeySize), &result, 0
			), error);
		}
		return state->KeySize;
	}

	OS::SetOSPError(error, OSP_API_Error, OSP_ERROR_NOT_INITIALIZED);
	return NULL;
}

void DestroyKey(BCRYPT_KEY_HANDLE& hkey, PUCHAR& keyobj, OSPError* error)
{
	if (hkey)
		checkStatus(BCryptDestroyKey(hkey), error);
	else if (keyobj)
		delete[] keyobj;
	hkey = keyobj = 0;
}

bool RetreiveKey(
	const StateHandle* state, const Cipher& cipher, BCRYPT_KEY_HANDLE& hkey, PBYTE& keyobj, OSPError* error
) {
	if (!cipher.Completed())
		return OS::SetOSPError(error, OSP_API_Error, OSP_ERROR_CIPHER_NOT_IN_THE_RIGHT_STATE);

	size_t keysz = KeySize(state, error);
	keyobj = new byte[keysz];

	bool success = false;

	if (keyobj)
	{
		if (checkStatus(BCryptImportKey(
			EncryptAlgorithm(state, error),
			NULL,
			BCRYPT_OPAQUE_KEY_BLOB,
			&hkey,
			keyobj,
			SafeInt<ULONG>(keysz),
			(PUCHAR)cipher.Key(),
			SafeInt<ULONG>(cipher.Size()),
			0
		), error)) {
			success = true;
		}
		else
			DestroyKey(hkey, keyobj, error);
	}

	return success;
}

size_t EncryptSize(BCRYPT_KEY_HANDLE hkey, size_t data_size, size_t size, OSPError* error)
{
	DWORD result = 0;

	if (checkStatus(BCryptEncrypt(
		hkey, NULL, SafeInt<ULONG>(data_size), NULL, NULL, 0, NULL, 0, &result, 0
	), error))
		return result;

	return 0;
}

#pragma endregion

#pragma region Public Constructors, OS and ICryptography Overrides

Cryptography::Cryptography() : OS() { }

Cryptography::Cryptography(size_t count, size_t maxsize, OSPError* error) : OS()
{
	Initialize(count, maxsize, 0, error);
}

Cryptography::byte* const Cryptography::Randomize(byte* const data, size_t size, OSPError* error) const
{
	if (
		data && size &&
		checkStatus(BCryptGenRandom(NULL, data, (ULONG)size, BCRYPT_USE_SYSTEM_PREFERRED_RNG), error)
	)
		return data;
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
	if (state) {
		if (state->Encrypt) {
			success = checkStatus(BCryptCloseAlgorithmProvider(state->Encrypt, 0), error) && success;
			state->Encrypt = 0;
		}

		success = state->Hash.Destroy(error) && success;

		delete state;
		_state = nullptr;
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
	BEGIN_MEMORY_CHECK(AvailableMemory());

	size_t esize = 0;

	if (!cipher.Prepared() && !cipher.Completed())
		return OS::SetOSPError(error, OSP_API_Error, OSP_ERROR_CIPHER_NOT_IN_THE_RIGHT_STATE);

	auto state = static_cast<StateHandle*>(State());
	BCRYPT_ALG_HANDLE halg = EncryptAlgorithm(state, error);
	BCRYPT_KEY_HANDLE hkey = cipher.Handle();
	PBYTE keyobj = NULL;
	if (!hkey && !RetreiveKey(state, cipher, hkey, keyobj, error))
		return false;

	esize = ::EncryptSize(hkey, DataSize(size), DataSize(size), error);

	if (hkey != cipher.Handle())
		::DestroyKey(hkey, keyobj, error);

	END_MEMORY_CHECK(AvailableMemory());
	return esize;
}

bool Cryptography::Encrypt(
	const Cipher& cipher, const ByteVector& iv, ByteVector& data, ByteVector& encrypted, OSPError* error
) {
	BEGIN_MEMORY_CHECK(AvailableMemory());

	if (encrypted.Size() < data.Size())
		return OS::SetOSPError(error, OSP_API_Error, OSP_ERROR_BUFFER_TOO_SMALL);

	if (!cipher.Prepared() && !cipher.Completed())
		return OS::SetOSPError(error, OSP_API_Error, OSP_ERROR_CIPHER_NOT_IN_THE_RIGHT_STATE);

	auto state = static_cast<StateHandle*>(State());
	BCRYPT_KEY_HANDLE hkey = cipher.Handle();
	PBYTE keyobj = NULL;
	if (!hkey && !RetreiveKey(state, cipher, hkey, keyobj, error))
		return false;

	size_t extra = 0;
	size_t esize = ::EncryptSize(hkey, DataSize(data.Size()), data.Size(), error);

	ULONG result;
	ByteVector vector(*this);

	bool success = vector.Alloc(iv.Size(), error);
	if (success)
	{
		vector.CopyFrom(iv, error);

		if (encrypted.Size() < esize)
		{
			if (encrypted.Fixed() || esize > MaxDataSize())
				success = false;
			else
			{
				extra = esize - encrypted.Size();
				success = encrypted.Realloc(esize, error);
			}
		}

		if (success)
		{
			size_t dsize = DataSize(data.Size());
			if (data.Size() == dsize)
			{
				success = checkStatus(BCryptEncrypt(
					hkey,
					data,
					SafeInt<ULONG>(data.Size()),
					NULL,
					vector,
					SafeInt<ULONG>(vector.Size()),
					encrypted,
					SafeInt<ULONG>(data.Size()),
					&result,
					0
				), error);
			}
			else
			{
				ByteVector buffer(*this);
				if (success = buffer.Alloc(dsize, error))
				{
					success = checkStatus(BCryptEncrypt(
						hkey,
						buffer,
						SafeInt<ULONG>(buffer.Size()),
						NULL,
						vector,
						SafeInt<ULONG>(vector.Size()),
						encrypted,
						SafeInt<ULONG>(encrypted.Size()),
						&result,
						0
					), error);
					data.CopyFrom(buffer, error);
					buffer.Destroy(error);
				}
			}
		}

		if (success)
			data.Zero();

		vector.Destroy(error);
	}

	if (hkey != cipher.Handle())
		DestroyKey(hkey, keyobj, error);

	END_MEMORY_CHECK(AvailableMemory() + extra);
	return success;
}

bool Cryptography::Decrypt(
	const Cipher& cipher, const ByteVector& iv, ByteVector& encrypted, ByteVector& decrypted, OSPError* error
) {
	BEGIN_MEMORY_CHECK(AvailableMemory());

	if (!cipher.Prepared() && !cipher.Completed())
		return OS::SetOSPError(error, OSP_API_Error, OSP_ERROR_CIPHER_NOT_IN_THE_RIGHT_STATE);

	auto state = static_cast<StateHandle*>(State());
	BCRYPT_KEY_HANDLE hkey = cipher.Handle();
	PBYTE keyobj = NULL;
	if (!hkey && !RetreiveKey(state, cipher, hkey, keyobj, error))
		return false;

	ULONG result = 0;
	ByteVector vector(*this);

	bool success = vector.Alloc(iv.Size(), error);
	if (success)
		vector.CopyFrom(iv, error);

	success = checkStatus(BCryptDecrypt(
		hkey,
		encrypted,
		SafeInt<ULONG>(decrypted.Size()),
		NULL,
		vector,
		SafeInt<ULONG>(vector.Size()),
		decrypted,
		SafeInt<ULONG>(decrypted.Size()),
		&result,
		0
	), error);

	if (success)
		encrypted.Zero();

	vector.Destroy(error);
	if (hkey != cipher.Handle())
		DestroyKey(hkey, keyobj, error);

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

	if (success = factory.Start(hfhash, BCRYPT_HASH_REUSABLE_FLAG, error))
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
		if (!state->BlockSize) {
			ULONG result;
			checkStatus(BCryptGetProperty(
				EncryptAlgorithm(state, error), BCRYPT_BLOCK_LENGTH, (PUCHAR)&(state->BlockSize), sizeof(state->BlockSize), &result, 0
			), error);
		}
		return state->BlockSize;
	}

	OS::SetOSPError(error, OSP_API_Error, OSP_ERROR_NOT_INITIALIZED);
	return NULL;
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
	BEGIN_MEMORY_CHECK(AvailableMemory());

	if (!cipher.Zeroed())
		return OS::SetOSPError(error, OSP_API_Error, OSP_ERROR_CIPHER_NOT_IN_THE_RIGHT_STATE);

	cipher.Size() = 0;

	auto state = static_cast<const StateHandle*>(State());
	BCRYPT_ALG_HANDLE halg = EncryptAlgorithm(state, error);

	if (!checkStatus(BCryptSetProperty(
		halg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0
	), error)) {
		return false;
	}

	bool success = false;

	PBYTE keyobj = new byte[KeySize(state, error)];
	if (!keyobj)
		return false;

	BCRYPT_KEY_HANDLE hkey = 0;
	ULONG size = 0;

	if (checkStatus(BCryptGenerateSymmetricKey(
		halg,
		&hkey, keyobj,
		SafeInt<ULONG>(KeySize(state, error)),
		(PUCHAR)((const byte*)secret),
		SafeInt<ULONG>(secret.Size()),
		0
	), error)) {
		if (checkStatus(
			BCryptExportKey(hkey, NULL, BCRYPT_OPAQUE_KEY_BLOB, NULL, 0, &size, 0), error
		)) {
			success = (size > 0);
		}
	}

	if (!success)
		DestroyKey(hkey, keyobj, error);
	else
	{
		cipher.Handle() = hkey;
		cipher.Size() = size;
	}

	END_MEMORY_CHECK(AvailableMemory());
	return success;
}

bool Cryptography::CompleteCipher(Cipher& cipher, OSPError* error) const
{
	if (!cipher.Ready())
		return OS::SetOSPError(error, OSP_API_Error, OSP_ERROR_CIPHER_NOT_IN_THE_RIGHT_STATE);

	ULONG result;
	Zero(cipher.Key(), cipher.Size());
	if (checkStatus(BCryptExportKey(
		cipher.Handle(), NULL, BCRYPT_OPAQUE_KEY_BLOB, cipher.Key(), SafeInt<ULONG>(cipher.Size()), &result, 0
	), error)) {
		if (checkStatus(BCryptDestroyKey(cipher.Handle()), error))
		{
			cipher.Handle() = 0;
			return true;
		}
	}

	return false;
}

bool Cryptography::ZeroCipher(Cipher& cipher, OSPError* error) const
{
	BEGIN_MEMORY_CHECK(AvailableMemory());

	bool success = false;

	if (cipher.Handle())
		success = checkStatus(BCryptDestroyKey(cipher.Handle()), error);
	else
	{
		BCRYPT_KEY_HANDLE hkey = 0;
		PBYTE keyobj = NULL;
		if (checkStatus(RetreiveKey(static_cast<const StateHandle*>(State()), cipher, hkey, keyobj, error), error))
			success = checkStatus(BCryptDestroyKey(hkey), error);
	}

	if (success)
	{
		cipher.Handle() = 0;
		Zero(cipher.Key(), cipher.Size());
	}

	END_MEMORY_CHECK(AvailableMemory());
	return success;
}

#pragma endregion
