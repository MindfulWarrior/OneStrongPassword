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

#include "../osp/cryptography.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
using namespace std;

namespace OneStrongPassword
{
	TEST_CLASS(Cryptography_Test)
	{
	public:
		static const size_t DATA_SIZE = 32;
		static const size_t BLOCK_SIZE = 512;

		OSPError TestError;

		ByteArray<16> IV0;
		ByteArray<16> IV1;

		ByteArray<DATA_SIZE> TestDataA;
		ByteArray<DATA_SIZE> TestDataB;

		stack<Cryptography::byte*> ciphercleanup;

		void Setup(Cipher& cipher)
		{
			bool success = cipher.Prepare(&TestError);
			if (success)
			{
				cipher.Key() = new Cryptography::byte[cipher.Size()];
				ciphercleanup.push(cipher.Key());
				success = cipher.Complete(&TestError);
			}
			Assert::IsTrue(success, L"Creating a cipher failed, see Cipher_Test0");
		}

		void EncryptTestA(Cryptography& cryptography, const Cipher& cipher, ByteVector& encrypted)
		{
			ByteArray<DATA_SIZE> data;
			bool success = data.CopyFrom(TestDataA, &TestError);
			success = success && cryptography.Encrypt(cipher, IV0, data, encrypted, &TestError);
			Assert::IsTrue(success, L"Encryption failed, see Cryptography_Encrypt_Decrypt_Test0");
		}

		void EncryptTestA(
			Cryptography& cryptography, const Cipher& cipher, ByteVector& encrypted, const ByteVector& vector
		) {
			ByteArray<DATA_SIZE> data;
			bool success = data.CopyFrom(TestDataA, &TestError);
			success = success && cryptography.Encrypt(cipher, vector, data, encrypted, &TestError);
			Assert::IsTrue(success, L"1st Encryption failed, see Cryptography_Encrypt_Decrypt_Test1");
		}

		void EncryptTestB(Cryptography& cryptography, const Cipher& cipher, ByteVector& encrypted)
		{
			ByteArray<DATA_SIZE> data;
			data.CopyFrom(TestDataB, &TestError);
			bool success = cryptography.Encrypt(cipher, IV0, data, encrypted, &TestError);
			Assert::IsTrue(success, L"1st Encryption failed, see Cryptography_Encrypt_Decrypt_Test1");
		}

		template<size_t sz> void TestHashing()
		{
			bool success = true;

			ByteArray<DATA_SIZE> testA;
			testA.CopyFrom(TestDataA, &TestError);

			ByteArray<DATA_SIZE> testB;
			testB.CopyFrom(TestDataB, &TestError);

			Cryptography cryptography(0);

			ByteArray<sz> hash0;

			success = cryptography.Hash(testA, hash0, &TestError);

			Assert::IsTrue(success, L"1st Hash failed");
			Assert::IsFalse(hash0.Zeroed(), L"1st Hash not created");

			ByteArray<sz> hash1;

			success = cryptography.Hash(testB, hash1, &TestError);

			Assert::IsTrue(success, L"2nd Hash failed");
			Assert::IsFalse(hash1.Zeroed(), L"2nd Hash not created");
			Assert::IsFalse(memcmp(hash0, hash1, hash0.Size()) == 0, L"Different data produces the same hashes");

			ByteArray<sz> hash2;

			success = cryptography.Hash(testA, hash2, &TestError);

			Assert::IsTrue(success, L"3rd hash failed");
			Assert::IsFalse(hash2.Zeroed(), L"3rd Hash not created");
			Assert::IsTrue(memcmp(hash0, hash2, hash0.Size()) == 0, L"Same data produces different hashes");
		}

		template<size_t sz> void TestIsHashed(size_t from, size_t to)
		{
			bool success = true;

			ByteArray<DATA_SIZE> testA;
			testA.CopyFrom(TestDataA, &TestError);

			Cryptography cryptography(0);

			ByteArray<sz> hash;

			success = cryptography.Hash(testA, hash, &TestError);

			Assert::IsTrue(success, L"Hash failed");
			Assert::IsFalse(hash.Zeroed(), L"Hash not created");

			bool test = true;

			size_t hashsize = cryptography.HashSize();

			if (to - from < hashsize)
			{
				for (size_t n = from; test && n < to; n++)
					test = hash[n - 1] == hash[n];
			}
			else
			{
				size_t count = hash.Size() / hashsize;
				for (size_t n = from; test && n < to; n++)
				{
					for (size_t m = 1; test && m < count; m++)
						test = (hash[n] == hash[n + m]);
				}
			}

			Assert::IsFalse(test, L"Not Hashed");
		}

		TEST_METHOD_INITIALIZE(MethodInitialize)
		{
			for (size_t n = 1; n <= IV0.Size(); n++)
				IV0[n - 1] = (Cryptography::byte)n;
			for (size_t n = IV1.Size(); n > 0; n--)
				IV0[IV1.Size() - n] = (Cryptography::byte)n;

			for (size_t n = 1; n <= TestDataA.Size(); n++)
				TestDataA[n - 1] = (Cryptography::byte)n;
			for (size_t n = TestDataB.Size(); n > 0; n--)
				TestDataB[TestDataB.Size() - n] = (Cryptography::byte)n;
		}

		TEST_METHOD_CLEANUP(MethodCleanup)
		{
			while (!ciphercleanup.empty())
			{
				delete[] ciphercleanup.top();
				ciphercleanup.pop();
			}
			Assert::IsTrue(EXPOSED(0), L"Something is exposed");
			Assert::AreEqual(TestError.Code, OSP_NO_ERROR, L"There was an undected error");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(Cryptography_Initialize_Destroy_Test0)
			TEST_DESCRIPTION(L"Initiialize then destroy.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(Cryptography_Initialize_Destroy_Test0)
		{
			bool success;

			Cryptography cryptography;
			
			const size_t count = 2;
			const size_t maxsize = cryptography.MinDataSize();

			Assert::IsTrue(maxsize > 0, L"Unable to get hash size");

			success = cryptography.Initialize(count, maxsize - 1, &TestError);

			Assert::IsTrue(success, L"Initialize failed");
			Assert::AreEqual(maxsize, cryptography.MaxDataSize(), L"Wrong maxsize");

			success = cryptography.Destroy(&TestError);

			Assert::IsTrue(success, L"Destroy() failed");
			Assert::AreEqual(size_t(0), cryptography.AvailableMemory(), L"Wrong available memory");
		}
	};
}