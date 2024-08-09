#include "strongpassword.h"
#include "hashvector.h"

using namespace OneStrongPassword;
using namespace std;

bool StrongPassword::Restore(Cipher& cipher, ByteVector& password, OSPError* error)
{
	if (cipher.Prepare(error))
	{
		bool success = true;
		if (cipher.Ready())
			success = cipher.Complete(error);
		DECREASE_EXPOSURE; // Increased by Dispense and deceased by Store
		success = success && Store(cipher, password, error);
		return success;
	}
	return false;
}

bool StrongPassword::GeneratePassword(
	const string& mnemonic,
	Cipher& cipher,
	PasswordVector& password,
	size_t length,
	const Recipe & recipe,
	OSPError* error
) {
	assert(EXPOSED(0));

	if (length + 1 > password.MaxLength())
		return OS::SetOSPError(error, OSP_API_Error, OSP_ERROR_BUFFER_TOO_SMALL);

	password.Zero();

	bool success = false;

	ByteVector strongmnemonic(store);
	if (StrongMnemonic(mnemonic, cipher, strongmnemonic, error))
	{
		success = GeneratePassword(strongmnemonic, password, length, recipe, error);
		if (success)
		{
			assert(EXPOSED(0));
			INCREASE_EXPOSURE;
		}
		success = strongmnemonic.Destroy(error) && success;
	}

	return success;
}

bool StrongPassword::DestroyPassword(PasswordVector& password, OSPError* error)
{
	bool success = password.Destroy(error);
	if (success)
		DECREASE_EXPOSURE;
	return success;
}

bool StrongPassword::ReleasePassword(PasswordVector& password, OSPError* error)
{
	bool success = password.Release(error);
	if (success)
		DECREASE_EXPOSURE;
	return success;
}

bool StrongPassword::StrongMnemonic(
	const string& mnemonic, const ByteVector& strongbuff, ByteVector& retbuff, OSPError* error
) {
	size_t mneomicsize = mnemonic.size() * sizeof(char);
	size_t totalsize = strongbuff.Size() + mneomicsize;

	if (!retbuff.Alloc(strongbuff.Size() + mneomicsize, error))
		return false;

	retbuff.CopyFrom(mnemonic, error);
	retbuff.CopyFrom(strongbuff, strongbuff.Size(), mneomicsize, error);

	return true;
}

bool StrongPassword::StrongMnemonic(
	const string& mnemonic, Cipher& cipher, ByteVector& retbuff, OSPError* error
) {
	bool success = false;

	size_t size = DataSize();
	if (!size)
		return OS::SetOSPError(error, OSP_API_Error, OSP_ERROR_NO_STRONG_PASSWORD_STORED);

	ByteVector strongbuff(store);
	if (strongbuff.Alloc(size, error) && Dispense(cipher, strongbuff, error))
	{
		success = StrongMnemonic(mnemonic, strongbuff, retbuff, error);
		success = Restore(cipher, strongbuff, error) && success;
		success = strongbuff.Destroy(error) && success;
	}
	return success;
}

bool StrongPassword::GeneratePassword(
	ByteVector& strongmnemonic,
	PasswordVector& password,
	size_t length,
	const Recipe& recipe,
	OSPError* error
) {
	HashVector hashbuff(store);
	if (!hashbuff.Initialize(error))
		return false;

	bool success = false;

	if (success = store.StrongHash(strongmnemonic, hashbuff, error))
	{
		success = strongmnemonic.Destroy(error);

		size_t plen = 0;
		size_t pos = 0;
		bool verified = false;
		int safety = 10000;

		while (success && !verified)
		{
			while (success && plen < length)
			{
				for (; plen < length && pos < store.HashSize(); pos++)
				{
					char ch = abs((char)hashbuff[pos]);
					if (recipe.HasChar(ch))
						password[plen++] = ch;
				}

				if (pos >= store.HashSize())
				{
					// Generate a new hash
					HashVector tmp(store);
					success = success && hashbuff.MoveTo(tmp, error);
					success = success && hashbuff.Realloc(error);
					success = success && store.StrongHash(tmp, hashbuff, error);
					tmp.Destroy();
					pos = 0;
				}
			}

			if (success)
			{
				verified = recipe.Verified(password, length);
				if (!verified)
				{
					if (--safety < 0)
						success = OS::SetOSPError(
							error, OSP_API_Error, OSP_ERROR_UNABLE_TO_MEET_PASSWORD_REQUIREMENTS
						);
					else
					{
						plen = length - 1;
						for (size_t n = 0; n < plen; n++)
							password[n] = password[n + 1];
						password[plen] = 0;
					}
				}
			}
		}
	}

	hashbuff.Destroy();

	return success;
}
