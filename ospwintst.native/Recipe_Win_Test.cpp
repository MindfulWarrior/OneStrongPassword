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

#include "CppUnitTest.h"

#include <stack>

#include "../osp/strongpassword.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace OneStrongPassword
{
	TEST_CLASS(Recipe_Win_Test)
	{
		static const size_t size0 = 48;

		const char* strong0 = "This is a password. Just a stinkin password.";

		OSPError TestError;

		void* ciphercleanup;

		void Generate(const std::string& mnemonic, char* const gen, size_t size, const Recipe& recipe)
		{
			SecureStore store;
			bool success = store.Initialize(1);
			Assert::IsTrue(success, L"Setting up store failed");

			DECLARE_OSPCipher(ospcipher);
			Cipher cipher(store, ospcipher);

			success = cipher.Prepare();
			if (success)
			{
				ciphercleanup = cipher.Key() = new Cipher::byte[cipher.Size()];
				success = cipher.Complete();
			}
			Assert::IsTrue(success, L"Setting up cipher failed");

			PasswordArray<size0> strong;
			strong.CopyFrom(strong0);
			  
			StrongPassword strongPassword(store, "recipe_test");
			strongPassword.Store(cipher, strong);

			PasswordVector generated(nullptr, gen, size);
			success = strongPassword.GeneratePassword(mnemonic, cipher, generated, generated.Size() - 1, recipe);
			Assert::IsTrue(success, L"GeneratePassword failed");
			generated.Release();
		 }

		TEST_METHOD_CLEANUP(MethodCleanup)
		{
			if (ciphercleanup)
				delete[] ciphercleanup;
			Assert::IsTrue(EXPOSED(0), L"Something is exposed");
			Assert::AreEqual(TestError.Code, OSP_NO_ERROR, L"There was an undected error");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(Recipe_Seperator_Test1)
			TEST_DESCRIPTION("Can remove seperator without changing passwore")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(Recipe_Seperator_Test1)
		{
			size_t length = (size_t)strnlen(OSP_RECIPE_ALL_SUPPORTED_SPECIALS, 32);

			char gen0[64];
			{
				Recipe recipe;

				recipe.SetSpecials(OSP_RECIPE_ALL_SUPPORTED_SPECIALS, length);
				recipe.SetSeperator(' ');
				recipe.AddFlags(OSP_RECIPE_ALPHANUMERIC);

				Generate("test", gen0, sizeof(gen0), recipe);
			}

			char gen1[sizeof(gen0)];
			{
				Recipe recipe;

				recipe.SetSpecials(OSP_RECIPE_ALL_SUPPORTED_SPECIALS, length);
				recipe.AddFlags(OSP_RECIPE_ALPHANUMERIC);

				Generate("test", gen1, sizeof(gen1), recipe);
			}

			Assert::IsTrue(strncmp(gen0, gen1, sizeof(gen0)) == 0, L"Different passwords created");
		}

	};
}