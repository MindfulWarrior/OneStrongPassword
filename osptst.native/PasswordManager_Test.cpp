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
	TEST_CLASS(PasswordManager_Test)
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

		BEGIN_TEST_METHOD_ATTRIBUTE(PasswordManager_Initialize_Test0)
			TEST_DESCRIPTION(L"Initialize then destroy.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(PasswordManager_Initialize_Test0)
		{
			bool success;

			PasswordManager manager;

			const size_t count = 2;
			const size_t maxlength = manager.MinLength();

			Assert::IsTrue(maxlength > 0, L"Unable to get minimum length");

			success = manager.Initialize(count, maxlength, &TestError);

			Assert::IsTrue(success, L"Initialize failed");
			Assert::AreEqual(maxlength, manager.MaxLength(), L"Wrong max length");

			success = manager.Destroy(&TestError);

			Assert::IsTrue(success, L"Destroy failed");
			Assert::IsTrue(manager.Destroyed(), L"Manager not marked as destroyed");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(PasswordManager_Initialize_Test1)
			TEST_DESCRIPTION(L"Initialize bellow min length.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(PasswordManager_Initialize_Test1)
		{
			bool success;

			PasswordManager manager;

			const size_t count = 2;
			const size_t maxlength = manager.MinLength();

			success = manager.Initialize(count, maxlength, &TestError);

			Assert::IsTrue(success, L"Initialize failed");
			Assert::AreEqual(maxlength, manager.MaxLength(), L"Wrong max length");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(PasswordManager_Initialize_Test2)
			TEST_DESCRIPTION(L"Initialize less the block length.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(PasswordManager_Initialize_Test2)
		{
			bool success;

			PasswordManager manager;

			const size_t count = 2;
			const size_t maxlength = manager.MinLength() + manager.BlockLength(&TestError);

			success = manager.Initialize(count, maxlength - 1, &TestError);

			Assert::IsTrue(success, L"Initialize failed");
			Assert::AreEqual(maxlength, manager.MaxLength(), L"Wrong max length");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(PasswordManager_Reset_Test0)
			TEST_DESCRIPTION(L"Initialize then Reset")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(PasswordManager_Reset_Test0)
		{
			bool success;

			PasswordManager manager;

			const size_t count = 2;
			const size_t maxlength = manager.MinLength();

			success = manager.Initialize(count, maxlength, &TestError);

			Assert::IsTrue(success, L"Initialize failed");
			Assert::AreEqual(maxlength, manager.MaxLength(), L"Wrong max length");

			success = manager.Reset(count, maxlength * 2, &TestError);

			Assert::IsTrue(success, L"Reset failed");
			Assert::AreEqual(maxlength * 2, manager.MaxLength(), L"Wrong max length");
		}

		template<size_t sz> void TestSpaced(
			const char* pw, const string& spaced, char seperator = ' ', size_t width = 0
		) {
			PasswordArray<sz> src;
			src.CopyFrom((byte*)pw, sz);

			PasswordArray<64> dst;

			PasswordManager::AddSeperators(src, dst, seperator, width, &TestError);
			Assert::IsTrue(spaced.compare(dst) == 0, L"spaces are wrong");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(PasswordManager_AddSeperator_Test0)
			TEST_DESCRIPTION(L"Add seperator to string.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(PasswordManager_AddSeperator_Test0)
		{
			TestSpaced<1>("1", "1");
			TestSpaced<2>("22", "22");
			TestSpaced<3>("333", "333");
			TestSpaced<4>("4444", "4444");
			TestSpaced<5>("55555", "55555");
			TestSpaced<6>("333333", "333 333");
			TestSpaced<7>("3334444", "333 4444");
			TestSpaced<8>("44444444", "4444 4444");
			TestSpaced<9>("333333333", "333 333 333");
			TestSpaced<10>("5555555555", "55555 55555");
			TestSpaced<11>("33344444444", "333 4444 4444");
			TestSpaced<12>("444444444444", "4444 4444 4444");
			TestSpaced<13>("4444444455555", "4444 4444 55555");
			TestSpaced<14>("44445555555555", "4444 55555 55555");
			TestSpaced<15>("555555555555555", "55555 55555 55555");
			TestSpaced<16>("4444444444444444", "4444 4444 4444 4444");
			TestSpaced<17>("44444444444455555", "4444 4444 4444 55555");
			TestSpaced<18>("666666666666666666", "666666 666666 666666");
			TestSpaced<19>("4444555555555555555", "4444 55555 55555 55555");
			TestSpaced<20>("55555555555555555555", "55555 55555 55555 55555");
			TestSpaced<21>("777777777777777777777", "7777777 7777777 7777777");
			TestSpaced<22>("4444555554444555554444", "4444 55555 4444 55555 4444");
			TestSpaced<23>("44445555544445555555555", "4444 55555 4444 55555 55555");
			TestSpaced<24>("888888888888888888888888", "88888888 88888888 88888888");
			TestSpaced<25>("5555555555555555555555555", "55555 55555 55555 55555 55555");
			TestSpaced<26>("44444444555554444444455555", "4444 4444 55555 4444 4444 55555");
			TestSpaced<27>("444455555444455555444455555", "4444 55555 4444 55555 4444 55555");
			TestSpaced<28>("7777777777777777777777777777", "7777777 7777777 7777777 7777777");
			TestSpaced<29>("44445555555555555555555555555", "4444 55555 55555 55555 55555 55555");
			TestSpaced<30>("666666666666666666666666666666", "666666 666666 666666 666666 666666");
			TestSpaced<31>("4444555554444555554444555554444", "4444 55555 4444 55555 4444 55555 4444");
			TestSpaced<32>("888888888888888888888888888888888", "88888888 88888888 88888888 88888888");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(PasswordManager_AddSeperator_Test1)
			TEST_DESCRIPTION(L"Add non-space seperator to string.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(PasswordManager_AddSeperator_Test1)
		{
			TestSpaced<6>("333333", "333-333", '-');
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(PasswordManager_AddSeperator_Test2)
			TEST_DESCRIPTION(L"Add seperator to string with line break")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(PasswordManager_AddSeperator_Test2)
		{
			TestSpaced<1>("1", "1", ' ', 1);
			TestSpaced<2>("22", "22", ' ', 2);
			TestSpaced<3>("333", "333", ' ', 3);
			TestSpaced<4>("4444", "4444", ' ', 4);
			TestSpaced<5>("55555", "55555", ' ', 5);
			TestSpaced<6>("333333", "333 333", ' ', 6);
			TestSpaced<7>("3334444", "333 4444", ' ', 7);
			TestSpaced<8>("44444444", "4444 4444", ' ', 8);
			TestSpaced<9>("333333333", "333 333\n333", ' ', 9);
			TestSpaced<10>("5555555555", "55555\n55555", ' ', 9);
			TestSpaced<11>("33344444444", "333 4444\n4444", ' ', 9);
			TestSpaced<12>("444444444444", "4444 4444\n4444", ' ', 9);
			TestSpaced<13>("4444444455555", "4444 4444\n55555", ' ', 9);
			TestSpaced<14>("44445555555555", "4444 55555\n55555", ' ', 10);
			TestSpaced<15>("555555555555555", "55555 55555\n55555", ' ', 11);
			TestSpaced<16>("4444444444444444", "4444 4444\n4444 4444", ' ',9);
			TestSpaced<17>("44444444444455555", "4444 4444\n4444 55555", ' ', 9);
			TestSpaced<18>("666666666666666666", "666666 666666\n666666", ' ', 13);
			TestSpaced<19>("4444555555555555555", "4444 55555\n55555 55555", ' ', 11);
			TestSpaced<20>("55555555555555555555", "55555 55555\n55555 55555", ' ', 12);
			TestSpaced<21>("777777777777777777777", "7777777 7777777\n7777777", ' ', 17);
			TestSpaced<22>("4444555554444444455555", "4444 55555 4444\n4444 55555", ' ', 17);
			TestSpaced<23>("44445555544445555555555", "4444 55555 4444\n55555 55555", ' ', 17);
			TestSpaced<24>("888888888888888888888888", "88888888 88888888\n88888888", ' ', 17);
			TestSpaced<25>("5555555555555555555555555", "55555 55555 55555\n55555 55555", ' ', 17);
			TestSpaced<26>("44444444555554444444455555", "4444 4444 55555\n4444 4444 55555", ' ', 17);
			TestSpaced<27>("444455555444444445555555555", "4444 55555 4444\n4444 55555 55555", ' ', 17);
			TestSpaced<28>("7777777777777777777777777777", "7777777 7777777\n7777777 7777777", ' ', 17);
			TestSpaced<29>("44445555555555555555555555555", "4444 55555 55555\n55555 55555 55555", ' ', 17);
			TestSpaced<30>("666666666666666666666666666666", "666666 666666\n666666 666666\n666666", ' ', 17);
			TestSpaced<31>("4444555554444444455555444455555", "4444 55555 4444\n4444 55555 4444\n55555", ' ', 17);
			TestSpaced<32>("888888888888888888888888888888888", "88888888 88888888\n88888888 88888888", ' ', 17);
		}
	};
}