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

#include <Windows.h>
#include "CppUnitTest.h"

#include <stack>

#include "../osp/passwordmanager.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
using namespace std;

namespace OneStrongPassword
{
	TEST_CLASS(PasswordManager_Win_Test)
	{
		static const size_t MAX_PASSSWORD_LENGTH = 64;

		const string PasswordA = "This is password. Just a stinkin password";

		OSPError TestError;

		volatile void* ciphercleanup = 0;

		void Setup(PasswordManager& manager, OSPCipher& cipher)
		{
			bool success;
			
			if (manager.Destroyed())
			{
				success = manager.Initialize(1, MAX_PASSSWORD_LENGTH, &TestError);
				Assert::IsTrue(success, L"Initialize failed, see PasswordManager_Initialize_Test0");
			}
			
			success = manager.PrepareCipher(cipher, &TestError);
			if (success)
			{
				ciphercleanup = cipher.Key = new PasswordManager::byte[cipher.Size];
				success = manager.CompleteCipher(cipher, &TestError);
			}
			Assert::IsTrue(success, L"Creating a cipher failed, see PasswordManager_Cipher_Test0");
		}

		void SetupA(char* const buffer, size_t size)
		{
			memset(buffer, 0, size);
			memcpy(buffer, PasswordA.c_str(), min(size -1, PasswordA.size()));
		}

		void StoreA(PasswordManager& manager, OSPCipher& cipher, const string& name)
		{
			Setup(manager, cipher);

			char password[48];
			SetupA(password, sizeof(password));

			bool success = manager.Store(name, cipher, password, sizeof(password), &TestError);

			Assert::IsTrue(success, L"Store failed, see PasswordManager_Store_Destroy_Test0");
		}

		TEST_METHOD_CLEANUP(MethodCleanup)
		{
			if (ciphercleanup)
				delete[] ciphercleanup;
			ciphercleanup = 0;
			Assert::IsTrue(EXPOSED(0), L"Something is exposed");
			Assert::AreEqual(OSP_NO_ERROR, TestError.Code, L"There was an undected error");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(PasswordManager_Reset_Test1)
			TEST_DESCRIPTION(L"Reset without Initialize")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(PasswordManager_Reset_Test1)
		{
			PasswordManager manager;

			const size_t count = 2;
			const size_t maxlength = 8;

			bool success = manager.Reset(count, maxlength, &TestError);

			Assert::IsTrue(success, L"Reset failed");
			Assert::AreEqual(manager.MinLength(), manager.MaxLength(), L"Length not set to min");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(PasswordManager_Cipher_Test0)
			TEST_DESCRIPTION(L"Complete Cipher.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(PasswordManager_Cipher_Test0)
		{
			bool success;

			PasswordManager manager;

			DECLARE_OSPCipher(cipher);

			success = manager.PrepareCipher(cipher, &TestError);

			Assert::IsTrue(success, L"Prepare failed");
			Assert::IsTrue(manager.CipherPrepared(cipher), L"Cipher not perpared");

			cipher.Key = new Cipher::byte[cipher.Size];

			Assert::IsTrue(manager.CipherReady(cipher), L"Cipher not completed");

			success = manager.CompleteCipher(cipher, &TestError);

			Assert::IsTrue(success, L"CompleteCipher failed");
			Assert::IsTrue(manager.CipherCompleted(cipher), L"Cipher not completed");

			success = manager.ZeroCipher(cipher, &TestError);

			Assert::IsTrue(success, L"Zero cipher failed");
			Assert::IsTrue(manager.CipherZeroed(cipher), L"Cipher not released");
			Assert::IsFalse(manager.CipherCompleted(cipher), L"Cipher still complete");
			Assert::IsFalse(manager.CipherPrepared(cipher), L"Cipher still prepared");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(PasswordManager_Store_Destroy_Test0)
			TEST_DESCRIPTION(L"Store data and destroy.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(PasswordManager_Store_Destroy_Test0)
		{
			const string name = "test";

			bool success;

			PasswordManager manager;
			DECLARE_OSPCipher(cipher);
			Setup(manager, cipher);

			{
				char password[MAX_PASSSWORD_LENGTH / 2];
				SetupA(password, sizeof(password));

				success = manager.Store(name, cipher, password, sizeof(password), &TestError);

				Assert::IsTrue(success, L"Store failed");
				Assert::IsTrue(OS::Zeroed((byte*)password, sizeof(password)), L"Data not cleared");
				Assert::AreEqual(manager.DataSize(name), sizeof(password), L"Size not stored");
			}

			success = manager.Destroy(name, &TestError);

			Assert::IsTrue(success, L"Destroy failed");
			Assert::IsTrue(manager.DataSize(name) == 0, L"Size not cleared");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(PasswordManager_Store_Dispense_Test0)
			TEST_DESCRIPTION(L"Store data and dispense.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(PasswordManager_Store_Dispense_Test0)
		{
			const string name = "test";

			bool success;

			PasswordManager manager;
			DECLARE_OSPCipher(cipher);

			StoreA(manager, cipher, name);

			char password[48];

			success = manager.Dispense(name, cipher, password, sizeof(password), &TestError);

			Assert::IsTrue(success, L"Dispense failed");
			Assert::IsTrue(PasswordA.compare(password) == 0, L"Password not dispensed");
			Assert::IsTrue(manager.DataSize(name) == 0, L"Size not cleared");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(PasswordManager_StrongPassword_Start_Finish_Test0)
			TEST_DESCRIPTION(L"Add strong password one key at a time.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(PasswordManager_StrongPassword_Start_Finish_Test0)
		{
			const string name = "test";

			bool success;

			PasswordManager manager;
			DECLARE_OSPCipher(cipher);

			Setup(manager, cipher);

			success = manager.StrongPasswordStart(PasswordA.size(), &TestError);
			Assert::IsTrue(success, L"Could not start strong password.");

			for (size_t n = 0; success && n < PasswordA.size(); n++)
			{
				success = manager.StrongPasswordPut(PasswordA[n], &TestError);
				Assert::IsTrue(success, L"Failure adding to strong password.");
			}

			success = manager.StrongPasswordFinish(name, cipher, &TestError);

			Assert::IsTrue(success, L"Could not finish strong password.");

			char password[48];

			success = manager.Dispense(name, cipher, password, sizeof(password), &TestError);

			Assert::IsTrue(success, L"Dispense failed");
			Assert::IsTrue(PasswordA.compare(password) == 0, L"Password not dispensed");
			Assert::IsTrue(manager.DataSize(name) == 0, L"Size not cleared");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(PasswordManager_StrongPassword_Start_Finish_Test1)
			TEST_DESCRIPTION(L"Start/finish, reset, then start/finish.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(PasswordManager_StrongPassword_Start_Finish_Test1)
		{
			const string name = "test";

			bool success;

			PasswordManager manager;
			DECLARE_OSPCipher(cipher);

			Setup(manager, cipher);

			success = manager.StrongPasswordStart(PasswordA.size(), &TestError);
			for (size_t n = 0; success && n < PasswordA.size(); n++)
				success = manager.StrongPasswordPut(PasswordA[n], &TestError);
			success = success && manager.StrongPasswordFinish(name, cipher, &TestError);

			Assert::IsTrue(success, L"1st Start/Finish failed.");

			manager.Reset(1, MAX_PASSSWORD_LENGTH, &TestError);

			success = manager.StrongPasswordStart(PasswordA.size(), &TestError);
			for (size_t n = 0; success && n < PasswordA.size(); n++)
				success = manager.StrongPasswordPut(PasswordA[n], &TestError);
			success = success && manager.StrongPasswordFinish(name, cipher, &TestError);

			Assert::IsTrue(success, L"2nd Start/Finish failed.");

			char password[48];

			success = manager.Dispense(name, cipher, password, sizeof(password), &TestError);

			Assert::IsTrue(success, L"Dispense failed");
			Assert::IsTrue(PasswordA.compare(password) == 0, L"Password not dispensed");
			Assert::IsTrue(manager.DataSize(name) == 0, L"Size not cleared");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(PasswordManager_StrongPassword_Start_Finish_Test2)
			TEST_DESCRIPTION(L"Start/finish, backspace past '0'.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(PasswordManager_StrongPassword_Start_Finish_Test2)
		{
			const string name = "test";

			bool success;

			PasswordManager manager;
			DECLARE_OSPCipher(cipher);

			Setup(manager, cipher);

			success = manager.StrongPasswordStart(3, &TestError);
			success = success && manager.StrongPasswordPut('1', &TestError);
			success = success && manager.StrongPasswordPut('2', &TestError);
			for (int n = 0; success && n < 10; n++)
				success = success && manager.StrongPasswordPut('\b', &TestError);
			success = success && manager.StrongPasswordPut('1', &TestError);
			success = success && manager.StrongPasswordPut('2', &TestError);
			success = success && manager.StrongPasswordFinish(name, cipher, &TestError);

			Assert::IsTrue(success, L"Start/Finish failed.");

			char password[3];

			success = manager.Dispense(name, cipher, password, sizeof(password), &TestError);

			Assert::IsTrue(success, L"Dispense failed");
			Assert::IsTrue(strncmp("12", password, 3) == 0, L"Password is wrong");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(PasswordManager_StrongPassword_Start_Abort_Test0)
			TEST_DESCRIPTION(L"Abort adding strong password.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(PasswordManager_StrongPassword_Start_Abort_Test0)
		{
			const string name = "test";

			bool success;

			PasswordManager manager;
			DECLARE_OSPCipher(cipher);

			Setup(manager, cipher);

			success = manager.StrongPasswordStart(PasswordA.size(), &TestError);
			Assert::IsTrue(success, L"Could not start strong password.");

			for (size_t n = 0; success && n < PasswordA.size(); n++)
			{
				success = manager.StrongPasswordPut(PasswordA[n], &TestError);
				Assert::IsTrue(success, L"Failure adding to strong password.");
			}

			success = manager.StrongPasswordAbort(&TestError);

			Assert::IsTrue(success, L"Could not abort strong password.");

			char password[48];

			success = manager.Dispense(name, cipher, password, sizeof(password), &TestError);

			Assert::IsFalse(success, L"Dispense should have failed");
			Assert::IsFalse(PasswordA.compare(password) == 0, L"Password not not aborted");
			Assert::IsTrue(manager.DataSize(name) == 0, L"Size not cleared");

			CLEAR_OSPError(TestError);
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(PasswordManager_Generate_Test0)
			TEST_DESCRIPTION(L"Generate small password with mnemonic.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(PasswordManager_Generate_Test0)
		{
			bool success = true;

			PasswordManager manager;

			DECLARE_OSPCipher(cipher);

			const char* name = "test";

			StoreA(manager, cipher, name);

			DECLARE_OSPRecipe(recipe);
			recipe.Specials = OSP_RECIPE_ALL_SUPPORTED_SPECIALS;
			recipe.SpecialsLength = strlen(OSP_RECIPE_ALL_SUPPORTED_SPECIALS);
			recipe.Flags = OSP_RECIPE_ALPHANUMERIC;

			const char* mnemonic0 = "stinkin";
			const char* mnemonic1 = "not stinkin";

			char pw[9];

			{
				PasswordVector gen(nullptr, pw, sizeof(pw));

				success = manager.GeneratePassword(name, mnemonic0, cipher, gen, gen.Size() - 1, recipe, &TestError);

				Assert::IsTrue(success, L"1st GeneratePassword failed");
				Assert::IsFalse(gen.Zeroed(), L"1st Password not generated");
				Assert::IsTrue(strlen(gen) == gen.Size() - 1, L"1st Password not the right length");

				manager.ReleasePassword(gen, &TestError);
			}

			{
				PasswordArray<sizeof(pw)> gen;

				success = manager.GeneratePassword(name, mnemonic1, cipher, gen, gen.Size() - 1, recipe, &TestError);

				Assert::IsTrue(success, L"2nd GeneratePassword failed");
				Assert::IsFalse(gen.Zeroed(), L"2nd Password not generated");
				Assert::IsTrue(strlen(gen) == gen.Size() - 1, L"2nd Password not the right length");
				Assert::IsTrue(strncmp(pw, gen, gen.Size() - 1) != 0, L"Different mnemonics generated the same passowrd");

				manager.DestroyPassword(gen, &TestError);
			}

			{
				PasswordArray<sizeof(pw)> gen;

				success = manager.GeneratePassword(name, mnemonic0, cipher, gen, gen.Size() - 1, recipe, &TestError);

				Assert::IsTrue(success, L"3rd GeneratePassword failed");
				Assert::IsFalse(gen.Zeroed(), L"3rd Password not generated");
				Assert::IsTrue(strlen(gen) == gen.Size() - 1, L"3rd Password not the right length");
				Assert::IsTrue(strncmp(pw, gen, gen.Size() - 1) == 0, L"Same mnemonic generated different passwords");

				manager.DestroyPassword(gen, &TestError);
			}
		}

		void PasswordCheck(
			PasswordManager& manager,
			const OSPCipher& cipher,
			const OSPRecipe& recipe,
			const char* name,
			const char* mnemonic,
			const char* expected
		) {
			char pw[9];

			PasswordVector gen(nullptr, pw, sizeof(pw));

			bool success = manager.GeneratePassword(name, mnemonic, cipher, gen, gen.Size() - 1, recipe, &TestError);

			Assert::IsTrue(success, L"1st GeneratePassword failed");
			Assert::IsFalse(gen.Zeroed(), L"1st Password not generated");
			Assert::IsTrue(strlen(gen) == gen.Size() - 1, L"1st Password not the right length");
			Assert::IsTrue(0 == strcmp(gen, expected), L"Password not as expected");

			manager.ReleasePassword(gen, &TestError);
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(PasswordManager_Check_Test0)
			TEST_DESCRIPTION(L"Ensure generated passwords stay the same.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(PasswordManager_Check_Test0)
		{
			bool success = true;

			PasswordManager manager;

			DECLARE_OSPCipher(cipher);

			const char* name = "test";

			StoreA(manager, cipher, name);

			DECLARE_OSPRecipe(recipe);
			recipe.Specials = OSP_RECIPE_ALL_SUPPORTED_SPECIALS;
			recipe.SpecialsLength = strlen(OSP_RECIPE_ALL_SUPPORTED_SPECIALS);
			recipe.Flags = OSP_RECIPE_ALPHANUMERIC;

			{
				const char* mnemonic = "password";
				const char* expected = "KF>DQr}Q";
				PasswordCheck(manager, cipher, recipe, name, mnemonic, expected);
			}

			{
				const char* mnemonic = "secret";
				const char* expected = "\\G8?eY2#";
				PasswordCheck(manager, cipher, recipe, name, mnemonic, expected);
			}
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(PasswordManager_Clipboard_Test0)
			TEST_DESCRIPTION(L"Generate password to clipboard.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(PasswordManager_Clipboard_Test0)
		{
			bool success = true;

			PasswordManager manager;

			DECLARE_OSPCipher(cipher);

			const char* name = "test";

			StoreA(manager, cipher, name);

			DECLARE_OSPRecipe(recipe);
			recipe.Specials = OSP_RECIPE_ALL_SUPPORTED_SPECIALS;
			recipe.SpecialsLength = strlen(OSP_RECIPE_ALL_SUPPORTED_SPECIALS);
			recipe.Flags = OSP_RECIPE_ALPHANUMERIC;

			const char* mnemonic = "stinkin";

			success = manager.PasswordToClipboard(name, mnemonic, cipher, 8, recipe, &TestError);

			Assert::IsTrue(success, L"GeneratePasswordToClipboard failed");

			PasswordArray<9> gen0;

			success = OS::PasteFromClipboard(gen0, gen0.Size(), &TestError);

			Assert::IsFalse(gen0.Zeroed(), L"1st Password not generated");
			Assert::IsTrue(strlen(gen0) == 8, L"1st Password not the right length");

			success = manager.PasswordToClipboard(name, mnemonic, cipher, 8, recipe, &TestError);

			Assert::IsTrue(success, L"GeneratePasswordToClipboard failed");

			PasswordArray<sizeof(gen0)> gen1;

			success = OS::PasteFromClipboard(gen1, gen1.Size(), &TestError);

			Assert::IsFalse(gen1.Zeroed(), L"1st Password not generated");
			Assert::IsTrue(strlen(gen1) == 8, L"1st Password not the right length");

			Assert::IsTrue(strncmp(gen0, gen1, gen0.Size()) == 0, L"Different passwords created");
		}
	};
}