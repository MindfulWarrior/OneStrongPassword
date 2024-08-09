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

#include "securestore.h"
#include "password.h"

namespace OneStrongPassword
{
	class PasswordManager
	{
	public:
		typedef SecureStore::byte byte;
		
		static size_t AddSeperators(
			const PasswordVector& src,
			PasswordVector& dst,
			char seperator,
			size_t width = 0,
			OSPError* error = nullptr
		);

		PasswordManager() : store(), strongPassword(store), strongPasswordLength(0) { }
		~PasswordManager() { Destroy(nullptr);  }

		// Global

		size_t BlockLength(OSPError* error) const { return store.BlockSize(error) / sizeof(char); }
		size_t MinLength() const { return store.MinDataSize() / sizeof(char); }
		size_t MaxLength() const { return store.MaxDataSize() / sizeof(char); }

		bool Destroyed() const { return store.AvailableMemory() <= 0; }

		bool Initialize(size_t count, size_t length, OSPError* error);
		bool Reset(size_t count, size_t length, OSPError* error);
		bool Destroy(OSPError* error);

		// Cipher

		bool CipherPrepared(const OSPCipher& cipher) const;
		bool CipherReady(const OSPCipher& cipher) const;
		bool CipherCompleted(const OSPCipher& cipher) const;
		bool CipherZeroed(const OSPCipher& cipher) const;

		bool PrepareCipher(OSPCipher& cipher, OSPError* error) const;
		bool CompleteCipher(OSPCipher& cipher, OSPError* error) const;
		bool ZeroCipher(OSPCipher& cipher, OSPError* error) const;

		// Strong Password

		size_t DataSize(const std::string& name) const;

		bool Store(
			const std::string& name,
			const OSPCipher& cipher,
			char* const password,
			size_t length,
			OSPError* error
		);

		bool Dispense(
			const std::string& name,
			OSPCipher& cipher,
			char* const password,
			size_t length,
			OSPError* error
		);

		bool Destroy(const std::string& name, OSPError* error);

		bool StrongPasswordStart(size_t length, OSPError* error);
		bool StrongPasswordPut(char ch, OSPError* error);
		bool StrongPasswordFinish(const std::string& name, OSPCipher& cipher, OSPError* error);
		bool StrongPasswordAbort(OSPError* error);

		int ShowStrongPassword(
			const std::string& name,
			OSPCipher& cipher,
			size_t width,
			const std::string& title,
			uint32_t type,
			OSPError* error
		);

		// Generate Password

		bool GeneratePassword(
			const std::string& name,
			const std::string& mnemonic,
			const OSPCipher& cipher,
			PasswordVector& password,
			size_t length,
			const OSPRecipe& recipe,
			OSPError* error
		);

		bool PasswordToClipboard(
			const std::string& name,
			const std::string& mnemonic,
			const OSPCipher& cipher,
			size_t length,
			const OSPRecipe& recipe,
			OSPError* error
		);

		int32_t ShowPassword(
			const std::string& name,
			const std::string& mnemonic,
			const OSPCipher& cipher,
			size_t length,
			const OSPRecipe& recipe,
			size_t width,
			const std::string& title,
			uint32_t type,
			OSPError* error
		);

		bool DestroyPassword(PasswordVector& password, OSPError* error);
		bool ReleasePassword(PasswordVector& password, OSPError* error);

	private:
		static size_t SeperatedBlocksNeeded(size_t length);

		SecureStore store;
		PasswordVector strongPassword;
		size_t strongPasswordLength;
	};
}
