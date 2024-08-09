#include "passwordmanager.h"
#include "password.h"
#include "strongpassword.h"
#include "os.h"

using namespace OneStrongPassword;
using namespace std;

size_t PasswordManager::SeperatedBlocksNeeded(size_t length)
{
	if (length < 6)
		return 1;

	size_t blocks = 1;

	if (0 == length % 5)
		blocks = length / 5;
	else if (0 == length % 4)
		blocks = length / 4;
	else if (0 == length % 3)
		blocks = length / 3;
	else
		blocks = length / 5 + 1;

	if (blocks > 4)
	{
		if (0 == length % 8)
			blocks = length / 8;
		else if (0 == length % 7)
			blocks = length / 7;
		else if (0 == length % 6)
			blocks = length / 6;
		else if (0 == length % 5)
			blocks = length / 5;
		else
			blocks = length / 5 + 1;
	}

	return blocks;
}

bool addPer(size_t b, size_t blocks, size_t per, size_t remainder)
{
	return (per && !((b + 1) % per)) || (remainder && (blocks - b) <= remainder);
}

size_t PasswordManager::AddSeperators(
	const PasswordVector& src, PasswordVector& dst, char seperator, size_t max, OSPError* error
) {
	size_t len = strnlen(src, src.Size());
	size_t blocks = SeperatedBlocksNeeded(len);
	size_t slen = len + blocks - 1;

	if (dst.Size() < slen)
	{
		if (dst.Fixed())
			return src.Size();
		if (!dst.Alloc(slen, error))
			return 0;
	}

	dst.Zero();

	size_t pidx = 0, sidx = 0, lidx = 0;
	size_t block = src.Size() / blocks;
	size_t remainder = len % blocks;
	size_t per = 0;

	if (remainder)
		per = blocks / remainder + (blocks < (2 * remainder) ? 1 : 0);

	if (!max)
		max = slen;

	int b = 0;
	for (size_t n = 0; n < blocks - 1; n++, b++)
	{
		assert(pidx + block <= len && sidx + block <= slen);
		for (size_t m = 0; m < block; m++, lidx++)
			dst[sidx++] = src[pidx++];

		if (addPer(b, blocks, per, remainder))
		{
			dst[sidx++] = src[pidx++];
			lidx++;
			remainder--;
		}

		assert(sidx < slen);
		size_t nxt = block
			+ (addPer(size_t(b) + 1, blocks, per, remainder) ? 1 : 0)
			+ (n < blocks - 2 ? 1 : 0)
			;

		if (lidx++ + nxt <= max)
			dst[sidx++] = seperator;
		else
		{
			dst[sidx++] = '\n';
			if (remainder)
				per = (blocks - b) / remainder + (blocks < (2 * remainder) ? 1 : 0);
			lidx = b = -1; // 'for' will make 0
		}
	}

	assert(sidx + len - pidx <= slen);
	for (size_t m = pidx; m < len; m++)
		dst[sidx++] = src[m];

	return slen;
}

bool PasswordManager::Initialize(size_t count, size_t length, OSPError* error)
{
	// Add to count for
	// - password buffer

	return store.Initialize(count + 1, length * sizeof(char), error);
}

bool PasswordManager::Reset(size_t count, size_t length, OSPError* error)
{
	return store.Reset(count, length * sizeof(char), error);
}

bool PasswordManager::Destroy(OSPError* error)
{
	bool success = strongPassword.Destroy();
	success = store.Destroy(error) && success;
	strongPassword.Zero();
	strongPasswordLength = 0;
	CLEAR_EXPOSURE;
	return success;
}

bool PasswordManager::CipherPrepared(const OSPCipher& cipher) const
{
	return Cipher(const_cast<SecureStore&>(store), const_cast<OSPCipher&>(cipher)).Prepared();
}

bool PasswordManager::CipherReady(const OSPCipher& cipher) const
{
	return Cipher(const_cast<SecureStore&>(store), const_cast<OSPCipher&>(cipher)).Ready();
}

bool PasswordManager::CipherCompleted(const OSPCipher& cipher) const
{
	return Cipher(const_cast<SecureStore&>(store), const_cast<OSPCipher&>(cipher)).Completed();
}

bool PasswordManager::CipherZeroed(const OSPCipher& cipher) const
{
	return Cipher(const_cast<SecureStore&>(store), const_cast<OSPCipher&>(cipher)).Zeroed();
}

bool PasswordManager::PrepareCipher(OSPCipher& cipher, OSPError* error) const
{
	return Cipher(store, cipher).Prepare(error);
}

bool PasswordManager::CompleteCipher(OSPCipher& cipher, OSPError* error) const
{
	return Cipher(store, cipher).Complete(error);
}

bool PasswordManager::ZeroCipher(OSPCipher& cipher, OSPError* error) const
{
	return Cipher(store, cipher).Zero(error);
}

size_t PasswordManager::DataSize(const string& name) const
{
	return store.DataSize(name);
}

bool PasswordManager::Store(
	const string& name, const OSPCipher& ospCipher, char* const password, size_t length, OSPError* error
) {
	Cipher cipher(store, const_cast<OSPCipher&>(ospCipher));
	PasswordVector buffer(nullptr, password, length * sizeof(char));
	return store.StoreData(name, cipher, buffer, 0, error) && buffer.Destroy();
}

bool PasswordManager::Dispense(
	const string& name, OSPCipher& ospCipher, char* const password, size_t length, OSPError* error
) {
	Cipher cipher(store, ospCipher);
	PasswordVector buffer(nullptr, password, length * sizeof(char));

	bool success = store.DispenseData(name, cipher, buffer, error);
	success = success && buffer.Release(error);
	return success;
}

bool PasswordManager::Destroy(const string& name, OSPError* error)
{
	return store.DestroyData(name, error);
}

bool PasswordManager::StrongPasswordStart(size_t length, OSPError* error)
{
	if (strongPassword.Size())
		return OS::SetOSPError(error, OSP_API_Error, OSP_ERROR_STRONG_PASSWORD_ENTRY_ALREADY_STARTED);
	if (!length)
		return OS::SetOSPError(error, OSP_API_Error, OSP_ERROR_SIZE_IS_0);

	bool success = strongPassword.Alloc(length * sizeof(char), error);

	strongPassword.Zero();
	strongPasswordLength = 0;

	return success;
}

bool PasswordManager::StrongPasswordPut(char ch, OSPError* error)
{
	if (!strongPassword.Size())
		return OS::SetOSPError(error, OSP_API_Error, OSP_ERROR_STRONG_PASSWORD_ENTRY_NOT_STARTED);

	if (strongPasswordLength > strongPassword.Size())
		return OS::SetOSPError(error, OSP_API_Error, OSP_ERROR_STRONG_PASSWORD_ENTRY_FULL);

	if (ch != '\b')
		strongPassword[(size_t)strongPasswordLength++] = ch;
	else if (strongPasswordLength >  0)
		strongPassword[(size_t)strongPasswordLength--] = 0;
	else
		strongPassword[(size_t)strongPasswordLength] = 0;

	return true;
}

bool PasswordManager::StrongPasswordFinish(const string& name, OSPCipher & cipher, OSPError* error)
{
	if (!strongPassword.Size() || strongPassword.Zeroed())
		return OS::SetOSPError(error, OSP_API_Error, OSP_ERROR_STRONG_PASSWORD_ENTRY_NOT_STARTED);
	bool success = Store(name, cipher, strongPassword, strongPasswordLength + 1, error);
	strongPasswordLength = 0;
	return strongPassword.Destroy(error) && success;
}

bool PasswordManager::StrongPasswordAbort(OSPError* error)
{
	strongPasswordLength = 0;
	return strongPassword.Destroy(error);
}

int PasswordManager::ShowStrongPassword(
	const std::string& name, OSPCipher& ospCipher, size_t width, const std::string& title, uint32_t type, OSPError* error
) {
	size_t size = DataSize(name);
	if (!size)
		return OS::SetOSPError(error, OSP_API_Error, OSP_ERROR_DATA_NOT_FOUND);

	PasswordVector buffer(store);
	if (!buffer.Alloc(size, error))
		return false;
	
	Cipher cipher(store, ospCipher);

	bool success = false;

	StrongPassword password(store, name);

	int response = 0;
	if (password.Dispense(cipher, buffer, error))
	{
		response = OS::Show(buffer, buffer.Size(), width, title, type, error);
		success = password.Restore(cipher, buffer, error) && password.Release() && response > 0;
	}

	return response;
}

bool PasswordManager::GeneratePassword(
	const string& name,
	const string& mnemonic,
	const OSPCipher& ospCipher,
	PasswordVector& password,
	size_t length,
	const OSPRecipe& recipe,
	OSPError* error
) {
	StrongPassword strongPassword(store, name);
	Cipher cipher(store, const_cast<OSPCipher&>(ospCipher));
	return strongPassword.GeneratePassword(
		mnemonic, cipher, password, length, recipe, error
	) && strongPassword.Release();
}

bool PasswordManager::PasswordToClipboard(
	const string& name,
	const string& mnemonic,
	const OSPCipher& cipher,
	size_t length,
	const OSPRecipe& recipe,
	OSPError* error
) {
	PasswordVector password(store);
	if (!password.Alloc((length + 1) * sizeof(char)))
		return false;

	bool success = false;

	if (GeneratePassword(name, mnemonic, cipher, password, length, recipe, error))
	{
		success = OS::CopyToClipboard(password, password.Size(), error);
		DECREASE_EXPOSURE;
	}

	return success;
}

int32_t PasswordManager::ShowPassword(
	const string& name,
	const string& mnemonic,
	const OSPCipher& cipher,
	size_t length,
	const OSPRecipe& recipe,
	size_t width,
	const string& title,
	uint32_t type,
	OSPError* error
) {
	PasswordVector password(store);
	if (!password.Alloc((length + 1) * sizeof(char)))
		return false;

	bool success = false;

	int response = 0;
	if (GeneratePassword(name, mnemonic, cipher, password, length, recipe, error))
	{
		if (!Recipe(recipe).GetSeperator())
			response = OS::Show(password, password.Size(), width, title.c_str(), type, error);
		else
		{
			PasswordVector buffer(store);
			if (AddSeperators(password, buffer, recipe.Seperator, width, error))
				response = OS::Show(buffer, buffer.Size(), width, title.c_str(), type, error);
			buffer.Destroy();
		}
		DECREASE_EXPOSURE;
	}

	password.Destroy(error);

	return response;
}

bool PasswordManager::DestroyPassword(PasswordVector& password, OSPError* error)
{
	bool success = password.Destroy(error);
	if (success)
		DECREASE_EXPOSURE;
	return success;
}

bool PasswordManager::ReleasePassword(PasswordVector& password, OSPError* error)
{
	bool success = password.Release(error);
	if (success)
		DECREASE_EXPOSURE;
	return success;
}
