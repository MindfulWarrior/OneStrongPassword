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

#pragma once
#include "osp.h"

#include <string>

#include "password.h"
#include "securestore.h"
#include "recipe.h"

namespace OneStrongPassword
{

	class StrongPassword
	{
	public:
		typedef SecureStore::byte byte;

		StrongPassword(SecureStore& store, const std::string& name)
			: store(store), name(name), stored(true) { }

		virtual ~StrongPassword() { if (stored) Destroy(nullptr); }

		const std::string& Name() const { return name; }

		size_t DataSize() const { return stored ? store.DataSize(name) : 0; }

		bool Store(Cipher& cipher, ByteVector& password, OSPError* error = nullptr)
			{ return store.StoreData(Name(), cipher, password, 0, error) && (stored = true) == true; }

		bool Dispense(Cipher& cipher, ByteVector& password, OSPError* error = nullptr)
			{ return store.DispenseData(Name(), cipher, password, error) && (stored = false) == false; }

		bool Restore(Cipher& cipher, ByteVector& password, OSPError* error = nullptr);

		bool Destroy(OSPError* error = nullptr)
			{ return store.DestroyData(Name(), error) && (stored = false) == false; }

		bool Release() { return (stored = false) == false; }

		bool GeneratePassword(
			const std::string& mnemonic,
			Cipher& cipher,
			PasswordVector& password,
			size_t length,
			const Recipe& recipe,
			OSPError* error = nullptr
		);

		bool DestroyPassword(PasswordVector& password, OSPError* error = nullptr);
		bool ReleasePassword(PasswordVector& password, OSPError* error = nullptr);

	protected:
		bool StrongMnemonic(
			const std::string& mnemonic, const ByteVector& strongbuff, ByteVector& retbuff, OSPError* error
		);
		
		bool StrongMnemonic(
			const std::string& mnemonic, Cipher& cipher, ByteVector& retbuff, OSPError* error
		);

		bool GeneratePassword(
			ByteVector& strongmnemonic,
			PasswordVector& password,
			size_t length,
			const Recipe& recipe,
			OSPError* error
		);

	private:
		SecureStore& store;
		const std::string name;
		bool stored;
	};
}
