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

#include <stddef.h>

#include "../osp/osp.h"

#ifdef OSPDLL_EXPORT

#define OSPAPI __declspec(dllexport) __stdcall

#else

#define OSPAPI __declspec(dllimport) __stdcall

#endif

// Global

extern "C" int32_t OSPAPI OSPSetError(OSPErrorType type, uint32_t code, OSPError* error);

extern "C" int32_t OSPAPI OSPInit(size_t count, size_t length, OSPError* error);

extern "C" int32_t OSPAPI OSPReset(size_t count, size_t length, OSPError* error);

extern "C" int32_t OSPAPI OSPDestroy(OSPError* error);

extern "C" int32_t OSPAPI OSPDestroyed();

extern "C" size_t OSPAPI OSPMinLength();

extern "C" size_t OSPAPI OSPMaxLength();

extern "C" size_t OSPAPI OSPBlockLength(OSPError* error);

// Cipher

extern "C" int32_t OSPAPI OSPPrepareCipher(OSPCipher* const cipher, OSPError* error);

extern "C" int32_t OSPAPI OSPCompleteCipher(OSPCipher* const cipher, OSPError* error);

extern "C" int32_t OSPAPI OSPZeroCipher(OSPCipher* const cipher, OSPError* error);

extern "C" int32_t OSPAPI OSPCipherPrepared(const OSPCipher* const cipher);

extern "C" int32_t OSPAPI OSPCipherReady(const OSPCipher* const cipher);

extern "C" int32_t OSPAPI OSPCipherCompleted(const OSPCipher* const cipher);

extern "C" int32_t OSPAPI OSPCipherZeroed(const OSPCipher* const cipher);

// Strong Password

extern "C" int32_t OSPAPI OSPStoreStrongPassword(
	const char* name,
	size_t nlen,
	const OSPCipher* cipher,
	char* const password,
	size_t length,
	OSPError* error
);

extern "C" int32_t OSPAPI OSPDispenseStrongPassword(
	const char* name,
	size_t nlen,
	OSPCipher* cipher,
	char* const password,
	size_t length,
	OSPError* error
);

extern "C" int32_t OSPAPI OSPDestroyStrongPassword(const char* name, size_t nlen, OSPError* error);

extern "C" int32_t OSPAPI OSPStrongPasswordStart(size_t length, OSPError* error);

extern "C" int32_t OSPAPI OSPStrongPasswordPut(char ch, OSPError* error);

extern "C" int32_t OSPAPI OSPStrongPasswordFinish(
	const char* name, size_t length, OSPCipher* const cipher, OSPError* error
);

extern "C" int32_t OSPAPI OSPStrongPasswordAbort(OSPError* error);

extern "C" int32_t OSPAPI OSPShowStrongPassword(
	const char* name,
	size_t nlen,
	OSPCipher* cipher,
	size_t width,
	const char* title,
	size_t tlen,
	uint32_t type,
	OSPError* error
);

extern "C" size_t OSPAPI OSPStrongPasswordSize(const char* name, size_t nlen);

// Generate Password

extern "C" int32_t OSPAPI OSPGeneratePassword(
	const char* name,
	size_t nlen,
	const char* mnemonic,
	size_t mlen,
	const OSPCipher* cipher,
	char* const password,
	size_t length,
	const OSPRecipe* recipe,
	OSPError* error
);

extern "C" int32_t OSPAPI OSPPasswordToClipboard(
	const char* name,
	size_t nlen,
	const char* mnemonic,
	size_t mlen,
	const OSPCipher* cipher,
	size_t length,
	const OSPRecipe* recipe,
	OSPError* error
);

extern "C" int32_t OSPAPI OSPShowPassword(
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
);
