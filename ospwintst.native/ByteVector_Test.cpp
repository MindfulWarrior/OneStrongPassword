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

#include "../osp/cipher.h"
#include "../ospwinlib/cryptography.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace OneStrongPassword
{
	TEST_CLASS(ByteVector_Test)
	{
	public:
		static const size_t DATA_SIZE = 32;

		ByteArray<16> IV;

		ByteArray<DATA_SIZE> TestData;

		std::stack<Cryptography::byte*> ciphercleanup;

		void Setup(Cipher& cipher)
		{
			bool success = cipher.Prepare();
			if (success)
			{
				cipher.Key = new Cryptography::byte[cipher.Size];
				ciphercleanup.push((byte*)cipher.Key);
				success = cipher.Complete();
			}
			Assert::IsTrue(success, L"Creating a cipher failed, see Cipher_Test0");
		}

		TEST_METHOD_INITIALIZE(MethodInitialize)
		{
			for (size_t n = 1; n <= IV.Size(); n++)
				IV[n - 1] = (Cryptography::byte)n;
			for (size_t n = 1; n <= TestData.Size(); n++)
				TestData[n - 1] = (Cipher::byte)n;
		}

		TEST_METHOD_CLEANUP(MethodCleanup)
		{
			while (!ciphercleanup.empty())
			{
				delete[] ciphercleanup.top();
				ciphercleanup.pop();
			}
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(ByteArray_CopyFrom_Test0)
			TEST_DESCRIPTION(L"Vector copy from Vector.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(ByteArray_CopyFrom_Test0)
		{
			ByteArray<DATA_SIZE> data;
			data.CopyFrom(TestData);

			Assert::IsTrue(memcmp(TestData, data, TestData.Size()) == 0, L"Test data not copied");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(ByteArray_CopyFrom_Test1)
			TEST_DESCRIPTION(L"Vector copy from Vector.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(ByteArray_CopyFrom_Test1)
		{
			bool success;

			Cryptography cryptography(0);

			Cipher cipher(cryptography);
			Setup(cipher);

			ByteArray<sizeof(TestData)> encrypted;
			{
				ByteArray<sizeof(TestData)> data;
				data.CopyFrom(TestData);
				success = cryptography.Encrypt(cipher, IV, data, encrypted);
				Assert::IsTrue(success, L"Encrypt failed");
				Assert::IsTrue(data.Zeroed(), L"Data not cleared");
			}
		}

	};
}