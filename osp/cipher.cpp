#include "cipher.h"
#include "bytevector.h"

#include <memory.h>

using namespace OneStrongPassword;

const size_t SECRET_SIZE = 16;

bool Cipher::Prepare(OSPError* error)
{
	ByteArray<SECRET_SIZE> secret;
	cryptography.Randomize(secret, secret.Size(), error);
	return Prepare(secret, error);
}

bool Cipher::Prepare(const ByteVector& secret, OSPError* error)
{
	return cryptography.PrepareCipher(secret, *this, error);
}
