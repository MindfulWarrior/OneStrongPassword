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

#include "../osp/securestore.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
using namespace std;

namespace OneStrongPassword
{
	TEST_CLASS(SecureStore_Test)
	{
		static const size_t DATA_SIZE = 32;
		static const size_t BLOCK_SIZE = 64;

		OSPError TestError;

		ByteArray<16> SECRET;

		ByteArray<DATA_SIZE> TestDataA;
		ByteArray<DATA_SIZE> TestDataB;

		void* ciphercleanup = 0;

		void Setup(Cipher& cipher)
		{
			bool success = cipher.Prepare(&TestError);
			if (success)
			{
				ciphercleanup = cipher.Key() = new SecureStore::byte[cipher.Size()];
				success = cipher.Complete(&TestError);
			}
			Assert::IsTrue(success, L"Creating a cipher failed, see Cipher_Test0");
		}

		void EncryptTestA(SecureStore& store, const Cipher& cipher, ByteVector& encrypted)
		{
			ByteArray<DATA_SIZE> data;
			data.CopyFrom(TestDataA, &TestError);
			bool success = store.Encrypt(cipher, data, encrypted, &TestError);
			Assert::IsTrue(success, L"1st Encryption failed, see Cryptography_Encrypt_Decrypt_Test1");
		}

		void EncryptTestB(SecureStore& store, const Cipher& cipher, ByteVector& encrypted)
		{
			ByteArray<DATA_SIZE> data;
			data.CopyFrom(TestDataB, &TestError);
			bool success = store.Encrypt(cipher, data, encrypted, &TestError);
			Assert::IsTrue(success, L"1st Encryption failed, see Cryptography_Encrypt_Decrypt_Test1");
		}

		void StoreTestA(SecureStore& store, Cipher& cipher, const string& name)
		{
			ByteArray<DATA_SIZE> data;
			data.CopyFrom(TestDataA, &TestError);
			bool success = store.StoreData(name, cipher, data, 0, &TestError);
			Assert::IsTrue(success, L"Store failed, see SecureStore_Store_Dispense_Test0");
		}

		void StoreTestB(SecureStore& store, Cipher& cipher, const string& name)
		{
			ByteArray<DATA_SIZE> data;
			data.CopyFrom(TestDataB, &TestError);
			bool success = store.StoreData(name, cipher, data, 0, &TestError);
			Assert::IsTrue(success, L"Store failed, see SecureStore_Store_Dispense_Test0");
		}

		TEST_METHOD_INITIALIZE(MethodInitialize)
		{
			for (size_t n = 1; n <= SECRET.Size(); n++)
				SECRET[n - 1] = (SecureStore::byte)n;
			for (size_t n = 1; n <= TestDataA.Size(); n++)
				TestDataA[n - 1] = (SecureStore::byte)n;
			for (size_t n = TestDataB.Size(); n > 0; n--)
				TestDataB[TestDataB.Size() - n] = (SecureStore::byte)n;
			ciphercleanup = 0;
		}

		TEST_METHOD_CLEANUP(MethodCleanup)
		{
			if (ciphercleanup)
				delete[] ciphercleanup;
			Assert::IsTrue(EXPOSED(0), L"Something is exposed");
			Assert::AreEqual(TestError.Code, OSP_NO_ERROR, L"There was an undected error");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(SecureStore_Initialize_Destroy_Test0)
			TEST_DESCRIPTION(L"Initialize then destroy.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(SecureStore_Initialize_Destroy_Test0)
		{
			bool success;

			SecureStore store;

			const size_t count = 2;
			const size_t maxsize = store.MinDataSize();

			Assert::IsTrue(maxsize > 0, L"Unable to get minimum size");

			success = store.Initialize(count, maxsize, &TestError);

			Assert::IsTrue(success, L"Initialize failed");
			Assert::AreEqual(maxsize, store.MaxDataSize(), L"Wrong maxsize");

			success = store.Destroy(&TestError);

			Assert::IsTrue(success, L"Destroy() failed");
			Assert::AreEqual(size_t(0), store.AvailableMemory(), L"Wrong available memory");
		}
	};
}