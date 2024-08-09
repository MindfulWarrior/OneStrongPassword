/*
One Strong Password Generator Windows Unit Tests

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
#include <algorithm>

#include "../ospwindll/ospapi.h"
#include "../osp/os.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
using namespace std;

namespace OneStrongPassword
{
	TEST_CLASS(OSPDLL_Test)
	{
		static const size_t SizeA = 48;

		OSPError TestError;

		const string PasswordA = "This is password. Just a stinkin password";
		
		volatile void* ciphercleanup = 0;

		bool isZero(const char* const password, size_t size)
		{
			for (size_t n = 0; n < size; n++)
			{
				if (password[n])
					return false;
			}
			return true;
		}

		void Setup(OSPCipher& cipher)
		{
			bool success;

			if (OSPDestroyed())
			{
				const size_t count = 2;
				const size_t maxlength = OSPMinLength();

				success = OSPInit(count, maxlength, &TestError);
				Assert::IsTrue(success, L"Initialize failed, see OSPDLL_Initialize_Test0");
			}

			success = OSPPrepareCipher(&cipher, &TestError);
			if (success)
			{
				ciphercleanup = cipher.Key = new char[cipher.Size / sizeof(char)];
				success = OSPCompleteCipher(&cipher, &TestError);
			}
			Assert::IsTrue(success, L"Creating a cipher failed, see OSPDLL_Cipher_Test0");
		}

		void StoreA(OSPCipher& cipher, const string& name)
		{
			Setup(cipher);

			bool success = OSPStrongPasswordStart(PasswordA.size(), &TestError);
			for (size_t n = 0; success && n < PasswordA.size(); n++)
				success = OSPStrongPasswordPut(PasswordA[n], &TestError);

			if (success)
				success = OSPStrongPasswordFinish(name.c_str(), name.size(), &cipher, &TestError);
			else
				OSPStrongPasswordAbort(&TestError);

			Assert::IsTrue(success, L"Start/Finish failed, see OSPDLL_StrongPassword_Start_Finish_Test0");
		}

		TEST_METHOD_CLEANUP(MethodCleanup)
		{
			if (ciphercleanup)
				delete[] ciphercleanup;
			ciphercleanup = 0;

			Assert::IsTrue(OSPDestroy(&TestError), L"Failure cleaning up");
			Assert::AreEqual(TestError.Code, OSP_NO_ERROR, L"There was an undected error");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(OSPDLL_Error_Test0)
			TEST_DESCRIPTION(L"Confirm error is returned.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(OSPDLL_Error_Test0)
		{
			bool success;

			success = OSPSetError(OSP_API_Error, 1, nullptr);
			Assert::IsFalse(success, L"Should have failed even with null");

			DECLARE_OSPError(error);

			success = OSPSetError(OSP_API_Error, 1, &error);

			Assert::IsFalse(success, L"Should have failed");
			Assert::AreEqual(uint32_t(1), error.Code, L"No error returned");
			Assert::AreEqual((int)OSP_API_Error, (int)error.Type, L"Wrong type");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(OSPDLL_Initialize_Test0)
			TEST_DESCRIPTION(L"Initialize then destroy.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(OSPDLL_Initialize_Test0)
		{
			bool success;

			const size_t count = 2;
			const size_t maxlength = OSPMinLength();

			Assert::IsTrue(maxlength > 0, L"Unable to get minimum length");

			success = OSPInit(count, maxlength, &TestError);

			Assert::IsTrue(success, L"Initialize failed");
			Assert::AreEqual(maxlength, OSPMaxLength(), L"Wrong max length");

			success = OSPDestroy(&TestError);

			Assert::IsTrue(success, L"Destroy failed");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(OSPDLL_Reset_Test0)
			TEST_DESCRIPTION(L"Initialize then Reset")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(OSPDLL_Reset_Test0)
		{
			bool success;

			const size_t count = 2;
			const size_t maxlength = OSPMinLength();

			success = OSPInit(count, maxlength, &TestError);

			Assert::IsTrue(success, L"Initialize failed");
			Assert::AreEqual(maxlength, OSPMaxLength(), L"Wrong max length");

			success = OSPReset(count, maxlength * 2, &TestError);

			Assert::IsTrue(success, L"Reset failed");
			Assert::AreEqual(maxlength * 2, OSPMaxLength(), L"Wrong max length");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(OSPDLL_Cipher_Test0)
			TEST_DESCRIPTION(L"Complete Cipher.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(OSPDLL_Cipher_Test0)
		{
			bool success;

			DECLARE_OSPCipher(cipher);

			success = OSPPrepareCipher(&cipher, &TestError);

			Assert::IsTrue(success, L"Prepare failed");
			Assert::IsTrue(OSPCipherPrepared(&cipher), L"Cipher not perpared");

			ciphercleanup = cipher.Key = new char[cipher.Size/sizeof(char)];

			Assert::IsTrue(OSPCipherReady(&cipher), L"Cipher not completed");

			success = OSPCompleteCipher(&cipher, &TestError);

			Assert::IsTrue(success, L"CompleteCipher failed");
			Assert::IsTrue(OSPCipherCompleted(&cipher), L"Cipher not completed");

			success = OSPZeroCipher(&cipher, &TestError);

			Assert::IsTrue(success, L"Zero cipher failed");
			Assert::IsTrue(OSPCipherZeroed(&cipher), L"Cipher not released");
			Assert::IsFalse(OSPCipherCompleted(&cipher), L"Cipher still complete");
			Assert::IsFalse(OSPCipherPrepared(&cipher), L"Cipher still prepared");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(OSPDLL_Store_Destroy_Test0)
			TEST_DESCRIPTION(L"Store password and destroy.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(OSPDLL_Store_Destroy_Test0)
		{
			const string name = "test";
			size_t length;
			bool success;

			DECLARE_OSPCipher(cipher);
			Setup(cipher);

			{
				char password[SizeA];
				memset(password, 0, sizeof(password));
				memcpy(password, PasswordA.c_str(), std::min(sizeof(password) - 1, PasswordA.size()));

				success = OSPStoreStrongPassword(
					name.c_str(), name.size(), &cipher, password, sizeof(password), &TestError
				);

				Assert::IsTrue(success, L"Store failed");
				Assert::AreEqual(size_t(0), strlen(password), L"Data not cleared");
			}

			length = OSPStrongPasswordSize(name.c_str(), name.size());
			Assert::AreEqual(SizeA, length, L"Size not stored");

			success = OSPDestroyStrongPassword(name.c_str(), name.size(), &TestError);
			Assert::IsTrue(success, L"Destroy failed");

			length = OSPStrongPasswordSize(name.c_str(), name.size());
			Assert::AreEqual(size_t(0), length, L"Size not cleared");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(OSPDLL_Store_Dispense_Test0)
			TEST_DESCRIPTION(L"Store data and dispense.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(OSPDLL_Store_Dispense_Test0)
		{
			const string name = "test";

			bool success;

			DECLARE_OSPCipher(cipher);
			Setup(cipher);

			{
				char password[SizeA];
				memset(password, 0, sizeof(password));
				memcpy(password, PasswordA.c_str(), std::min(sizeof(password) - 1, PasswordA.size()));

				success = OSPStoreStrongPassword(
					name.c_str(), name.size(), &cipher, password, sizeof(password), &TestError
				);

				Assert::IsTrue(success, L"Store failed");
			}

			char password[SizeA];

			success = OSPDispenseStrongPassword(
				name.c_str(), name.size(), &cipher, password, sizeof(password), &TestError
			);

			Assert::IsTrue(success, L"Dispense failed");
			Assert::IsTrue(PasswordA.compare(password) == 0, L"Password not dispensed");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(OSPDLL_StrongPassword_Start_Finish_Test0)
			TEST_DESCRIPTION(L"Add strong password one key at a time.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(OSPDLL_StrongPassword_Start_Finish_Test0)
		{
			const string name = "test";

			bool success;

			DECLARE_OSPCipher(cipher);

			Setup(cipher);

			success = OSPStrongPasswordStart(PasswordA.size(), &TestError);
			Assert::IsTrue(success, L"Could not start strong password.");

			for (size_t n = 0; success && n < PasswordA.size(); n++)
			{
				success = OSPStrongPasswordPut(PasswordA[n], &TestError);
				Assert::IsTrue(success, L"Failure adding to strong password.");
			}

			success = OSPStrongPasswordFinish(name.c_str(), name.size(), &cipher, &TestError);

			Assert::IsTrue(success, L"Could not finish strong password.");

			char password[SizeA];

			success = OSPDispenseStrongPassword(
				name.c_str(), name.size(), &cipher, password, sizeof(password), &TestError
			);

			Assert::IsTrue(success, L"Dispense failed");
			Assert::IsTrue(PasswordA.compare(password) == 0, L"Password not dispensed");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(OSPDLL_StrongPassword_Start_Abort_Test0)
			TEST_DESCRIPTION(L"Abort adding strong password.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(OSPDLL_StrongPassword_Start_Abort_Test0)
		{
			const string name = "test";

			bool success;

			DECLARE_OSPCipher(cipher);

			Setup(cipher);

			success = OSPStrongPasswordStart(PasswordA.size(), &TestError);
			Assert::IsTrue(success, L"Could not start strong password.");

			for (size_t n = 0; success && n < PasswordA.size(); n++)
			{
				success = OSPStrongPasswordPut(PasswordA[n], &TestError);
				Assert::IsTrue(success, L"Failure adding to strong password.");
			}

			success = OSPStrongPasswordAbort(&TestError);

			Assert::IsTrue(success, L"Could not abort strong password.");

			char password[48];

			success = OSPDispenseStrongPassword(
				name.c_str(), name.size(), &cipher, password, sizeof(password), &TestError
			);

			Assert::IsFalse(success, L"Dispense should not have succeeded");
			Assert::IsFalse(PasswordA.compare(password) == 0, L"Password not not aborted");

			CLEAR_OSPError(TestError);
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(OSPDLL_Generate_Test0)
			TEST_DESCRIPTION(L"Generate small password with mnemonic.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(OSPDLL_Generate_Test0)
		{
			bool success = true;

			DECLARE_OSPCipher(cipher);

			const char name[] = "test";

			StoreA(cipher, name);

			DECLARE_OSPRecipe(recipe);
			recipe.Specials = OSP_RECIPE_ALL_SUPPORTED_SPECIALS;
			recipe.SpecialsLength = strlen(OSP_RECIPE_ALL_SUPPORTED_SPECIALS);
			recipe.Flags = OSP_RECIPE_ALPHANUMERIC;

			const char mnemonic[] = "stinkin";

			char gen[9];

			success = OSPGeneratePassword(
				name, sizeof(name), mnemonic, sizeof(mnemonic), &cipher, gen, sizeof(gen) - 1, &recipe, &TestError
			);

			Assert::IsTrue(success, L"1st GeneratePassword failed");
			Assert::IsFalse(isZero(gen, sizeof(gen)), L"Password not generated");
			Assert::IsTrue(strlen(gen) == 8, L"Password not the right length");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(OSPDLL_Clipboard_Test0)
			TEST_DESCRIPTION(L"Generate password to clipboard.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(OSPDLL_Clipboard_Test0)
		{
			bool success = true;

			DECLARE_OSPCipher(cipher);

			const char name[] = "test";

			StoreA(cipher, name);

			DECLARE_OSPRecipe(recipe);
			recipe.Specials = OSP_RECIPE_ALL_SUPPORTED_SPECIALS;
			recipe.SpecialsLength = strlen(OSP_RECIPE_ALL_SUPPORTED_SPECIALS);
			recipe.Flags = OSP_RECIPE_ALPHANUMERIC;

			const char mnemonic[] = "stinkin";

			success = OSPPasswordToClipboard(
				name, sizeof(name), mnemonic, sizeof(mnemonic), &cipher, 8, &recipe, &TestError
			);

			Assert::IsTrue(success, L"1st GeneratePasswordToClipboard failed");

			char gen0[9];

			success = OS::PasteFromClipboard(gen0, sizeof(gen0), &TestError);

			Assert::IsTrue(success, L"1st PasteFromClipboard failed");
			Assert::IsFalse(isZero(gen0, sizeof(gen0)), L"1st Password not generated");
			Assert::IsTrue(strlen(gen0) == 8, L"1st Password not the right length");

			char gen1[sizeof(gen0)];

			success = OSPPasswordToClipboard(
				name, sizeof(name), mnemonic, sizeof(mnemonic), &cipher, 8, &recipe, &TestError
			);

			Assert::IsTrue(success, L"2nd GeneratePasswordToClipboard failed");

			success = OS::PasteFromClipboard(gen1, sizeof(gen1), &TestError);

			Assert::IsTrue(success, L"2nd PasteFromClipboard failed");
			Assert::IsFalse(isZero(gen1, sizeof(gen1)), L"2nd Password not generated");
			Assert::IsTrue(strlen(gen1) == 8, L"2nd Password not the right length");

			Assert::IsTrue(strncmp(gen0, gen1, sizeof(gen0)) == 0, L"2nd Passwords are different");
		}
	};
}