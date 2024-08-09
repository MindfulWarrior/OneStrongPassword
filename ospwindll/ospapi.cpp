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

#include <windows.h>
#include <bcrypt.h>

#define OSPDLL_EXPORT
#include "ospapi.h"

#include "../osp/passwordmanager.h"

using namespace OneStrongPassword;
using namespace std;

PasswordManager Manager;

int32_t OSPAPI OSPSetError(OSPErrorType type, uint32_t code, OSPError* error)
{
	return OS::SetOSPError(error, type, code);
}

int32_t OSPAPI OSPInit(size_t count, size_t length, OSPError* error)
{
	return Manager.Initialize(count, length, error);
}

int32_t OSPAPI OSPReset(size_t count, size_t length, OSPError* error)
{
	return Manager.Reset(count, length, error);
}

int32_t OSPAPI OSPDestroy(OSPError* error)
{
	return Manager.Destroy(error);
}

int32_t OSPAPI OSPDestroyed()
{
	return Manager.Destroyed();
}

size_t OSPAPI OSPMinLength()
{
	return Manager.MinLength();
}

size_t OSPAPI OSPMaxLength()
{
	return Manager.MaxLength();
}

size_t OSPAPI OSPBlockLength(OSPError* error)
{
	return Manager.BlockLength(error);
}

int32_t OSPAPI OSPPrepareCipher(OSPCipher* cipher, OSPError* error)
{
	return Manager.PrepareCipher(*cipher, error);
}

int32_t OSPAPI OSPCompleteCipher(OSPCipher* cipher, OSPError* error)
{
	return Manager.CompleteCipher(*cipher, error);
}

int32_t OSPAPI OSPZeroCipher(OSPCipher* cipher, OSPError* error)
{
	return Manager.ZeroCipher(*cipher, error);
}

int32_t OSPAPI OSPCipherPrepared(const OSPCipher* const cipher)
{
	return Manager.CipherPrepared(*cipher);
}

int32_t OSPAPI OSPCipherReady(const OSPCipher* const cipher)
{
	return Manager.CipherReady(*cipher);
}

int32_t OSPAPI OSPCipherCompleted(const OSPCipher* const cipher)
{
	return Manager.CipherCompleted(*cipher);
}

int32_t OSPAPI OSPCipherZeroed(const OSPCipher* const cipher)
{
	return Manager.CipherZeroed(*cipher);
}

int32_t OSPAPI OSPStoreStrongPassword(
	const char* name,
	size_t nlen,
	const OSPCipher* cipher,
	char* const password,
	size_t length,
	OSPError* error
) {
	return Manager.Store(string(name, nlen), *cipher, password, length, error);
}

int32_t OSPAPI OSPDispenseStrongPassword(
	const char* name,
	size_t nlen,
	OSPCipher* cipher,
	char* const password,
	size_t length,
	OSPError* error
) {
	if (Manager.Dispense(string(name, nlen), *cipher, password, length, error))
	{
		DECREASE_EXPOSURE; // Increased by DispenseData. Now the caller's responsbility.
		return true;
	}
	return false;
}

int32_t OSPAPI OSPDestroyStrongPassword(const char* name, size_t nlen, OSPError* error)
{
	return Manager.Destroy(string(name, nlen), error);
}

size_t OSPAPI OSPStrongPasswordSize(const char* name, size_t nlen)
{
	return Manager.DataSize(string(name, nlen));
}

int32_t OSPAPI OSPStrongPasswordStart(size_t length, OSPError* error)
{
	return Manager.StrongPasswordStart(length, error);
}

int32_t OSPAPI OSPStrongPasswordPut(char ch, OSPError* error)
{
	return Manager.StrongPasswordPut(ch, error);
}

int32_t OSPAPI OSPStrongPasswordFinish(
	const char* name, size_t length, OSPCipher* const cipher, OSPError* error
) {
	return Manager.StrongPasswordFinish(string(name, length), *cipher, error);
}

int32_t OSPAPI OSPStrongPasswordAbort(OSPError* error)
{
	return Manager.StrongPasswordAbort(error);
}

int32_t OSPAPI OSPShowStrongPassword(
	const char* name,
	size_t nlen,
	OSPCipher* cipher,
	size_t width,
	const char* title,
	size_t tlen,
	uint32_t type,
	OSPError* error
) {
	return Manager.ShowStrongPassword(
		string(name, strnlen(name, nlen)), *cipher, width, string(title, strnlen(title, tlen)), type, error
	);
}

int32_t OSPAPI OSPGeneratePassword(
	const char* name,
	size_t nlen,
	const char* mnemonic,
	size_t mlen,
	const OSPCipher* cipher,
	char* const password,
	size_t length,
	const OSPRecipe* recipe,
	OSPError* error
) {
	PasswordVector buffer(nullptr, password, (length + 1)*sizeof(char));

	bool success = Manager.GeneratePassword(
		string(name, strnlen(name, nlen)),
		string(mnemonic, strnlen(mnemonic, mlen)),
		*cipher,
		buffer,
		length,
		*recipe,
		error
	);

	if (success)
		DECREASE_EXPOSURE; // Increased by GeneratePassword.
	return success && buffer.Release(error);
}

int32_t OSPAPI OSPPasswordToClipboard(
	const char* name,
	size_t nlen,
	const char* mnemonic,
	size_t mlen,
	const OSPCipher* cipher,
	size_t length,
	const OSPRecipe* recipe,
	OSPError* error
) {
	return Manager.PasswordToClipboard(
		string(name, strnlen(name, nlen)),
		string(mnemonic, strnlen(mnemonic, mlen)),
		*cipher,
		length,
		*recipe,
		error
	);
}

int32_t OSPAPI OSPShowPassword(
	const char* name,
	size_t nlen,
	const char* mnemonic,
	size_t mlen,
	const OSPCipher* cipher,
	size_t length,
	const OSPRecipe* recipe,
	size_t width,
	const char* title,
	size_t tlen,
	uint32_t type,
	OSPError* error
) {
	return Manager.ShowPassword(
		string(name, strnlen(name, nlen)),
		string(mnemonic, strnlen(mnemonic, mlen)),
		*cipher,
		length,
		*recipe,
		width,
		string(title, strnlen(title, tlen)),
		type,
		error
	);
}
