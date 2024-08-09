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

	TEST_CLASS(Cipher_Test)
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
	};

}