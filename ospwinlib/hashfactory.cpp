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
#include "hashfactory.h"

#include <safeint.h>

using namespace msl::utilities;
using namespace OneStrongPassword;

HashFactory::HashFactory()
{
}

HashFactory::~HashFactory()
{
	Destroy();
}

BCRYPT_ALG_HANDLE HashFactory::Algorithm(OSPError* error) const
{
	if (!algorithm)
		checkStatus(BCryptOpenAlgorithmProvider(
			&algorithm, BCRYPT_SHA512_ALGORITHM, NULL, BCRYPT_HASH_REUSABLE_FLAG
		), error);
	return algorithm;
}

size_t HashFactory::Size(OSPError * error) const
{
	if (!size) {
		ULONG result;
		checkStatus(BCryptGetProperty(
			Algorithm(error), BCRYPT_HASH_LENGTH, (PUCHAR)&size, sizeof(size), &result, 0
		), error);
	}
	return size;
}

bool HashFactory::Destroy(OSPError * error)
{
	bool success = true;
	if (algorithm) {
		success = checkStatus(BCryptCloseAlgorithmProvider(algorithm, 0), error) && success;
		algorithm = 0;
	}
	return success;
}

bool HashFactory::Start(Hash& hfhash, ULONG flags, OSPError * error) const
{
	bool success = false;

	BCRYPT_ALG_HANDLE halg = Algorithm(error);
	if (halg)
		success = hfhash.Initialize(halg, flags, error);

	if (!success)
		hfhash.Destroy(error);

	return success;
}

bool HashFactory::Update(Hash& hfhash, const byte * const data, size_t dsize, byte * const hpart, OSPError * error) const
{
	bool success = false;
	OS::Zero(hpart, Size(error));
	if (success = checkStatus(BCryptHashData(hfhash.Handle(), (PUCHAR)data, SafeInt<ULONG>(dsize), 0), error))
		success = checkStatus(BCryptFinishHash(hfhash.Handle(), hpart, SafeInt<ULONG>(Size()), 0), error);
	return success;
}

bool HashFactory::Finish(Hash& hfhash, OSPError * error) const
{
	return hfhash.Destroy(error);
}

HashFactory::Hash::Hash()
{
}

OneStrongPassword::HashFactory::Hash::~Hash()
{
	Destroy();
}

bool OneStrongPassword::HashFactory::Hash::Initialize(BCRYPT_ALG_HANDLE halg, ULONG flags, OSPError * error)
{
	bool success = false;

	ULONG result;

	success = checkStatus(BCryptGetProperty(
		halg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&obj_size, sizeof(obj_size), &result, 0), error
	);

	if (success) {
		hashobj = new UCHAR[obj_size];
		if (hashobj)
			success = checkStatus(
				BCryptCreateHash(halg, &handle, hashobj, obj_size, NULL, 0, flags), error
			);
	}

	if (!success && hashobj) {
		OS::Zero(hashobj, obj_size);
		delete[] hashobj;
	}

	return success;
}

bool OneStrongPassword::HashFactory::Hash::Destroy(OSPError * error)
{
	bool success = true;

	if (handle) {
		success = checkStatus(BCryptDestroyHash(handle), error);
		handle = 0;
		hashobj = NULL; // destroying handle also destroys hashobj
	}

	if (hashobj) {
		OS::Zero(hashobj, obj_size);
		delete[] hashobj;
		hashobj = NULL;
	}

	return success;
}
