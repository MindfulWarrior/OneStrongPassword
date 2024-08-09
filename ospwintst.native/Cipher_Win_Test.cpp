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

#include "../osp/cipher.h"
#include "../osp/cryptography.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
using namespace std;

namespace OneStrongPassword
{

	TEST_CLASS(Cipher_Win_Test)
	{
	public:
		static const size_t DATA_SIZE = 32;
		static const size_t BLOCK_SIZE = 512;

		OSPError TestError;

		ByteArray<16> IV;

		ByteArray<DATA_SIZE> TestData;

		Cryptography cryptography;

		stack<void*> ciphercleanup;

		void Setup(Cipher& cipher)
		{
			bool success = cipher.Prepare(&TestError);
			if (success)
			{
				ciphercleanup.push(cipher.Key() = new Cipher::byte[cipher.Size()]);
				success = cipher.Complete(&TestError);
			}
			Assert::IsTrue(success, L"Creating a cipher failed, see Cipher_Test0");
		}

		void Setup(Cipher& cipher, const ByteVector& secret)
		{
			bool success = cipher.Prepare(secret, &TestError);
			if (success)
			{
				ciphercleanup.push(cipher.Key() = new Cipher::byte[cipher.Size()]);
				success = cipher.Complete(&TestError);
			}
			Assert::IsTrue(success, L"Creating a cipher failed, see Cipher_Test1");
		}

		TEST_METHOD_INITIALIZE(MethodInitialize)
		{
			for (size_t n = 1; n <= IV.Size(); n++)
				IV[n - 1] = (Cipher::byte)n;

			for (size_t n = 1; n <= TestData.Size(); n++)
				TestData[n - 1] = (Cipher::byte)n;

			bool success = cryptography.Reset(10, BLOCK_SIZE, &TestError);
			Assert::IsTrue(success, L"OS reset failed");
		}

		TEST_METHOD_CLEANUP(MethodCleanup)
		{
			while (!ciphercleanup.empty())
			{
				delete[] ciphercleanup.top();
				ciphercleanup.pop();
			}

			bool success = cryptography.Destroy(&TestError);
			Assert::IsTrue(success, L"OS destroy failed");
			Assert::IsTrue(EXPOSED(0), L"Something is exposed");
			Assert::AreEqual(TestError.Code, OSP_NO_ERROR, L"There was an undected error");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(Cipher_Test0)
			TEST_DESCRIPTION(L"Complete Cipher.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(Cipher_Test0)
		{
			bool success;

			DECLARE_OSPCipher(c);
			Cipher cipher(cryptography, c);

			success = cipher.Prepare(&TestError);

			Assert::IsTrue(success, L"Prepare failed");
			Assert::IsTrue(cipher.Prepared(), L"Cipher not perpared");

			cipher.Key() = new Cipher::byte[cipher.Size()];

			Assert::IsTrue(cipher.Ready(), L"Cipher not ready");

			success = cipher.Complete(&TestError);

			Assert::IsTrue(success, L"CompleteCipher failed");
			Assert::IsTrue(cipher.Completed(), L"Cipher not completed");

			success = cipher.Zero(&TestError);

			Assert::IsTrue(success, L"Zero cipher failed");
			Assert::IsTrue(cipher.Zeroed(), L"Cipher not released");
			Assert::IsFalse(cipher.Completed(), L"Cipher still complete");
			Assert::IsFalse(cipher.Prepared(), L"Cipher still prepared");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(Cipher_Test1)
			TEST_DESCRIPTION(L"Complete Cipher with secret.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(Cipher_Test1)
		{
			bool success;

			DECLARE_OSPCipher(c);
			Cipher cipher(cryptography, c);

			success = cipher.Prepare(IV, &TestError);

			Assert::IsTrue(success, L"Prepare failed");
			Assert::IsTrue(cipher.Prepared(), L"Cipher not perpared");

			cipher.Key() = new Cipher::byte[cipher.Size()];
			success = cipher.Complete(&TestError);

			Assert::IsTrue(success, L"CompleteCipher failed");
			Assert::IsTrue(cipher.Completed(), L"Cipher not completed");

			success = cipher.Zero(&TestError);

			Assert::IsTrue(success, L"Zero cipher failed");
			Assert::IsTrue(cipher.Zeroed(), L"Cipher not released");
			Assert::IsFalse(cipher.Completed(), L"Cipher still complete");
			Assert::IsFalse(cipher.Prepared(), L"Cipher still prepared");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(Cipher_Copy_Test0)
			TEST_DESCRIPTION(L"Encrypt with copy and decrypt with original.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(Cipher_Copy_Test0)
		{
			bool success;

			DECLARE_OSPCipher(c);
			Cipher cipher(cryptography, c);
			Setup(cipher);

			ByteArray<BLOCK_SIZE> encrypted;

			{
				ByteArray<DATA_SIZE> data;
				data.CopyFrom(TestData, &TestError);
				
				Cipher copied(cipher);

				Assert::AreEqual(cipher.Size(), copied.Size(), L"Size does not match");
				Assert::AreEqual(cipher.Key(), copied.Key(), L"Key pointer does not match");
				Assert::AreEqual(cipher.Handle(), copied.Handle(), L"Handle does not match");
				Assert::IsTrue(0 == memcmp(cipher.Key(), copied.Key(), cipher.Size()), L"Key does not match");

				success = cryptography.Encrypt(copied, IV, data, encrypted, &TestError);

				Assert::IsTrue(success, L"Encrypt failed");
				Assert::IsFalse(encrypted.Zeroed(), L"Encryption not created");
			}

			ByteArray<DATA_SIZE> data;

			success = cryptography.Decrypt(cipher, IV, encrypted, data, &TestError);

			Assert::IsTrue(success, L"Decrypt failed");
			Assert::IsTrue(memcmp(TestData, data, TestData.Size()) == 0, L"Decrypt did not return data");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(Cipher_Copy_Test1)
			TEST_DESCRIPTION(L"Encrypt/Decrypt with ciphers using the same key.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(Cipher_Copy_Test1)
		{
			bool success;

			DECLARE_OSPCipher(c);
			Cipher cipher(cryptography, c);
			Setup(cipher);

			ByteArray<BLOCK_SIZE> encrypted;

			{
				ByteArray<DATA_SIZE> data;
				data.CopyFrom(TestData, &TestError);

				Cipher copied(cryptography, c);

				Assert::AreEqual(cipher.Size(), copied.Size(), L"Size does not match");
				Assert::AreEqual(cipher.Key(), copied.Key(), L"Key pointer does not match");
				Assert::AreEqual(cipher.Handle(), copied.Handle(), L"Handle does not match");
				Assert::IsTrue(0 == memcmp(cipher.Key(), copied.Key(), cipher.Size()), L"Key does not match");

				success = cryptography.Encrypt(copied, IV, data, encrypted, &TestError);

				Assert::IsTrue(success, L"Encrypt failed");
				Assert::IsFalse(encrypted.Zeroed(), L"Encryption not created");
			}

			ByteArray<DATA_SIZE> data;

			success = cryptography.Decrypt(cipher, IV, encrypted, data, &TestError);

			Assert::IsTrue(success, L"Decrypt failed");
			Assert::IsTrue(memcmp(TestData, data, TestData.Size()) == 0, L"Decrypt did not return data");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(Cipher_Key_Test0)
			TEST_DESCRIPTION(L"Different 'random' ciphers.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(Cipher_Key_Test0)
		{
			DECLARE_OSPCipher(c0);
			Cipher cipher0(cryptography, c0);
			Setup(cipher0);

			DECLARE_OSPCipher(c1);
			Cipher cipher1(cryptography, c1);
			Setup(cipher1);

			Assert::IsFalse(0 == memcmp(cipher0.Key(), cipher1.Key(), cipher0.Size()), L"Keys are the same");
		}

	};

}