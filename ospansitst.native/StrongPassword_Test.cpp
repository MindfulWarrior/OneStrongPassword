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
	TEST_CLASS(StrongPassword_Test)
	{
		static const unsigned int BLOCK_SIZE = 128;

		static const size_t size0 = 48;

		const char* strong0 = "This is a password. Just a stinkin password.";

		OSPError TestError;

		SecureStore store;

		std::stack<void*> ciphercleanup;

		void Setup(Cipher& cipher, const ByteVector* secret = 0)
		{
			bool success = secret ? cipher.Prepare(*secret, &TestError) : cipher.Prepare(&TestError);
			if (success)
			{
				ciphercleanup.push(cipher.Key() = new StrongPassword::byte[cipher.Size()]);
				success = cipher.Complete(&TestError);
			}
			Assert::IsTrue(success, L"Creating a cipher failed, see Cipher_Test0");
		}

		template<size_t sz> void TestGeneratePassword(const Recipe& recipe)
		{
			char password[] = "This is a password. Just a stinkin password.";

			SecureStore store(1, sizeof(password), &TestError);

			const char* name = "test";

			StrongPassword strong(store, name);

			DECLARE_OSPCipher(c);
			Cipher cipher(store, c);
			Setup(cipher);

			{
				PasswordVector spw(nullptr, password, sizeof(password));
				bool success = strong.Store(cipher, spw, &TestError);
				Assert::IsTrue(success, L"Store failed, see StrongPassword_Store_Destroy_Test0");
			}

			const char* mnemonic0 = "stinkin";
			const char* mnemonic1 = "not stinkin";

			char pw[sz];

			{
				PasswordVector gen(nullptr, pw, sizeof(pw));

				bool success = strong.GeneratePassword(mnemonic0, cipher, gen, gen.Size() - 1, recipe, &TestError);

				Assert::IsTrue(success, L"1st GeneratePassword failed");
				Assert::IsFalse(gen.Zeroed(), L"1st Password not generated");
				Assert::IsTrue(strlen(gen) == gen.Size() - 1, L"1st Password not the right length");

				strong.ReleasePassword(gen, &TestError);
			}

			{
				PasswordArray<sizeof(pw)> gen;

				bool success = strong.GeneratePassword(mnemonic1, cipher, gen, gen.Size() - 1, recipe, &TestError);

				Assert::IsTrue(success, L"2nd GeneratePassword failed");
				Assert::IsFalse(gen.Zeroed(), L"2nd Password not generated");
				Assert::IsTrue(strlen(gen) == gen.Size() - 1, L"2nd Password not the right length");
				Assert::IsTrue(strncmp(pw, gen, sizeof(pw)) != 0, L"Different mnemonics generated the same passowrd");

				strong.DestroyPassword(gen, &TestError);
			}

			{
				PasswordArray<sizeof(pw)> gen;

				bool success = strong.GeneratePassword(mnemonic0, cipher, gen, gen.Size() - 1, recipe, &TestError);

				Assert::IsTrue(success, L"3rd GeneratePassword failed");
				Assert::IsFalse(gen.Zeroed(), L"3rd Password not generated");
				Assert::IsTrue(strlen(gen) == gen.Size() - 1, L"3rd Password not the right length");
				Assert::IsTrue(strncmp(pw, gen, sizeof(pw)) == 0, L"Same mnemonic generated different passwords");

				strong.DestroyPassword(gen, &TestError);
			}
		}

		TEST_CLASS_INITIALIZE(ClassInitialize)
		{
			//const char* strong0 = "This is a password. Just a stinkin password.";
		}

		TEST_METHOD_INITIALIZE(MethodInitialize)
		{
			bool success = store.Reset(10, BLOCK_SIZE, &TestError);
			Assert::IsTrue(success, L"SecureSTore reset failed");
		}

		TEST_METHOD_CLEANUP(MethodCleanup)
		{
			while (!ciphercleanup.empty())
			{
				delete[] ciphercleanup.top();
				ciphercleanup.pop();
			}

			bool success = store.Destroy(&TestError);

			Assert::IsTrue(success, L"OS destroy failed");
			Assert::IsTrue(EXPOSED(0), L"Something is exposed");
			Assert::AreEqual(TestError.Code, OSP_NO_ERROR, L"There was an undected error");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(StrongPassword_Store_Destroy_Test0)
			TEST_DESCRIPTION(L"Store password and destroy.")
			TEST_IGNORE()
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(StrongPassword_Store_Destroy_Test0)
		{
			bool success = true;

			const char* name = "test";

			DECLARE_OSPCipher(c);
			Cipher cipher(store, c);
			Setup(cipher);

			StrongPassword strong(store, name);
			{
				PasswordArray<size0> password;
				password.CopyFrom(strong0, &TestError);

				success = strong.Store(cipher, password, &TestError);

				Assert::IsTrue(success, L"Store failed");
				Assert::IsTrue(password.Zeroed(), L"Password not cleared");
			}

			Assert::AreEqual(strong.DataSize(), size0, L"Size not stored");
			Assert::IsTrue(cipher.Completed(), L"Store changed cipher");

			success = strong.Destroy(&TestError);

			Assert::IsTrue(success, L"Destroy failed");
			Assert::IsTrue(strong.DataSize() == 0, L"Size not cleared");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(StrongPassword_Store_Dispense_Test0)
			TEST_DESCRIPTION(L"Store password and dispensed.")
			TEST_IGNORE()
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(StrongPassword_Store_Dispense_Test0)
		{
			bool success = true;

			const char* name = "test";

			DECLARE_OSPCipher(c);
			Cipher cipher(store, c);
			Setup(cipher);

			StrongPassword strong(store, name);
			{
				PasswordArray<size0> password;
				password.CopyFrom(strong0, &TestError);

				success = strong.Store(cipher, password, &TestError);

				Assert::IsTrue(success, L"Store failed");
				Assert::IsTrue(password.Zeroed(), L"Password not cleared");
			}

			Assert::AreEqual(strong.DataSize(), size0, L"Size not stored");
			Assert::IsTrue(cipher.Completed(), L"Store changed cipher");

			PasswordArray<48> dispenesed;

			success = strong.Dispense(cipher, dispenesed, &TestError);

			Assert::IsTrue(success, L"Dispense failed");
			Assert::IsTrue(strncmp(strong0, dispenesed, size0) == 0, L"Dispense did not return data");
			Assert::IsTrue(strong.DataSize() == 0, L"Size not cleared");
			Assert::IsTrue(cipher.Zeroed(), L"Cipher not cleared");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(StrongPassword_Store_Dispense_Test1)
			TEST_DESCRIPTION(L"Store password and dispensed from different StrongPassword.")
			TEST_IGNORE()
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(StrongPassword_Store_Dispense_Test1)
		{
			bool success = true;

			const char* name = "test";

			DECLARE_OSPCipher(c);
			Cipher cipher(store, c);
			Setup(cipher);

			{
				PasswordArray<size0> password;
				password.CopyFrom(strong0, &TestError);

				StrongPassword strong(store, name);
				success = strong.Store(cipher, password, &TestError);

				Assert::IsTrue(success, L"Store failed");
				Assert::IsTrue(password.Zeroed(), L"Password not cleared");
				Assert::AreEqual(strong.DataSize(), size0, L"Password not stored");

				strong.Release();
			}

			StrongPassword strong(store, name);

			Assert::AreEqual(strong.DataSize(), size0, L"Size not stored");

			PasswordArray<48> dispenesed;

			success = strong.Dispense(cipher, dispenesed, &TestError);

			Assert::IsTrue(success, L"Dispense failed");
			Assert::IsTrue(strncmp(strong0, dispenesed, size0) == 0, L"Dispense did not return data");
			Assert::IsTrue(strong.DataSize() == 0, L"Password not cleared");
			Assert::IsTrue(cipher.Zeroed(), L"Cipher not cleared");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(StrongPassword_Generate_Test0)
			TEST_DESCRIPTION(L"Generate small password with mnemonic.")
			TEST_IGNORE()
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(StrongPassword_Generate_Test0)
		{
			bool success = true;

			Recipe recipe({
				OSP_RECIPE_ALL_SUPPORTED_SPECIALS, strlen(OSP_RECIPE_ALL_SUPPORTED_SPECIALS), OSP_RECIPE_ALPHANUMERIC
			});

			TestGeneratePassword<9>(recipe);
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(StrongPassword_Generate_Test1)
			TEST_DESCRIPTION(L"Generate large password with mnemonic.")
			TEST_IGNORE()
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(StrongPassword_Generate_Test1)
		{
			bool success = true;

			Recipe recipe({
				OSP_RECIPE_ALL_SUPPORTED_SPECIALS, strlen(OSP_RECIPE_ALL_SUPPORTED_SPECIALS), OSP_RECIPE_ALPHANUMERIC
			});

			TestGeneratePassword<129>(recipe);
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(StrongPassword_Generate_Test2)
			TEST_DESCRIPTION(L"Generate password with mnemonic and requirements.")
			TEST_IGNORE()
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(StrongPassword_Generate_Test2)
		{
			bool success = true;

			Recipe recipe({
				"!",
				1,
				OSP_RECIPE_ALPHANUMERIC |
				OSP_RECIPE_NUMERIC_REQUIRED |
				OSP_RECIPE_LOWERCASE_REQUIRED |
				OSP_RECIPE_UPPERCASE_REQUIRED |
				OSP_RECIPE_SPECIAL_REQUIRED
			});

			TestGeneratePassword<5>(recipe);
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(StrongPassword_Generate_Test3)
			TEST_DESCRIPTION(L"Generate with different StrongPasswords.")
			TEST_IGNORE()
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(StrongPassword_Generate_Test3)
		{
			bool success = true;

			Recipe recipe({
				OSP_RECIPE_ALL_SUPPORTED_SPECIALS, strlen(OSP_RECIPE_ALL_SUPPORTED_SPECIALS), OSP_RECIPE_ALPHANUMERIC
				});

			char password[] = "This is a password. Just a stinkin password.";

			SecureStore store(1, sizeof(password), &TestError);

			const char* name = "test";
			const char* mnemonic = "stinkin";

			DECLARE_OSPCipher(c);
			Cipher cipher(store, c);
			Setup(cipher);

			{
				PasswordVector pw(nullptr, password, sizeof(password));
				StrongPassword strong(store, name);
				success = strong.Store(cipher, pw, &TestError);
				Assert::IsTrue(success, L"Store failed, see StrongPassword_Store_Destroy_Test0");
				strong.Release();
			}

			PasswordArray<9> gen0;
			{
				StrongPassword strong(store, name);
				success = strong.GeneratePassword(mnemonic, cipher, gen0, 8, recipe, &TestError);

				Assert::IsTrue(success, L"1st GeneratePassword failed");
				Assert::IsFalse(gen0.Zeroed(), L"1st Password not generated");
				Assert::IsTrue(strlen(gen0) == 8, L"1st Password not the right length");

				strong.ReleasePassword(gen0, &TestError);
				strong.Release();
			}

			PasswordArray<sizeof(gen0)> gen1;
			{
				StrongPassword strong(store, name);
				success = strong.GeneratePassword(mnemonic, cipher, gen1, 8, recipe, &TestError);

				Assert::IsTrue(success, L"2nd GeneratePassword failed");
				Assert::IsFalse(gen1.Zeroed(), L"2nd Password not generated");
				Assert::IsTrue(strlen(gen1) == 8, L"2nd Password not the right length");

				strong.ReleasePassword(gen1, &TestError);
				strong.Release();
			}

			Assert::IsTrue(strncmp(gen0, gen1, gen0.Size()) == 0, L"Different passwords created");
		}

	};
}