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
#include <iomanip>

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

		template<size_t sz> void CheckHash(const char* const data, const OS::byte expected[sz])
		{
			bool success = true;

			Cryptography cryptography(0);

			ByteVector input(cryptography);

			auto dsize = strlen(data);
			input.Alloc(dsize, &TestError);
			input.CopyFrom((const OS::byte* const)data, dsize, 0, &TestError);

			ByteArray<sz> check;
			check.CopyFrom(expected, sz, 0, &TestError);

			ByteArray<sz> hash;

			success = cryptography.Hash(input, hash, &TestError);

			Assert::IsTrue(success, L"Hash failed");
			Assert::IsFalse(hash.Zeroed(), L"Hash not created");
			if (0 != memcmp(hash, check, check.Size())) {
				wstringstream stream;

				stream << L"{";
				stream << L"0x" << setfill(L'0') << setw(2) << hex << hash[size_t(0)];
				for (size_t n = 1; n < hash.Size(); n++)
					stream << L",0x" << setfill(L'0') << setw(2) << hex << hash[n];
				stream << L"}";
				wstring hashstr = stream.str();

				stream.clear();

				stream << L"{";
				stream << L"0x" << setfill(L'0') << setw(2) << hex << check[size_t(0)];
				for (size_t n = 1; n < check.Size(); n++)
					stream << L",0x" << setfill(L'0') << setw(2) << hex << check[n];
				stream << L"}";
				wstring checkstr = stream.str();

				wstring msg = L"Hash has changed,\n is " + hashstr + L",\n should be " + checkstr;
				Assert::Fail(msg.c_str());
			}
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

		BEGIN_TEST_METHOD_ATTRIBUTE(Cryptography_Encrypt_Decrypt_Test0)
			TEST_DESCRIPTION(L"Encrypt then decrypt.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(Cryptography_Encrypt_Decrypt_Test0)
		{
			bool success;

			Cryptography cryptography(0, BLOCK_SIZE);

			DECLARE_OSPCipher(c);
			Cipher cipher(cryptography, c);
			Setup(cipher);

			ByteArray<BLOCK_SIZE> encrypted;
			{
				ByteArray<DATA_SIZE> data;
				data.CopyFrom(TestDataA, &TestError);
				success = cryptography.Encrypt(cipher, IV0, data, encrypted, &TestError);
				Assert::IsTrue(success, L"Encrypt failed");
				Assert::IsTrue(data.Zeroed(), L"Data not cleared");
			}

			Assert::IsFalse(encrypted.Zeroed(), L"Encryption not created");
			Assert::IsTrue(cipher.Completed(), L"Encrypt changed cipher");

			ByteArray<DATA_SIZE> decrypted;

			success = cryptography.Decrypt(cipher, IV0, encrypted, decrypted, &TestError);

			Assert::IsTrue(success, L"Decrypt failed");
			Assert::IsTrue(memcmp(TestDataA, decrypted, TestDataA.Size()) == 0, L"Decrypt did not return data");
			Assert::IsTrue(encrypted.Zeroed(), L"Encryption not cleared");
			Assert::IsTrue(cipher.Completed(), L"Decrypt changed cipher");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(Cryptography_Encrypt_Decrypt_Test1)
			TEST_DESCRIPTION(L"Encrypt then decrypt twice.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(Cryptography_Encrypt_Decrypt_Test1)
		{
			bool success = true;

			Cryptography cryptography(0, BLOCK_SIZE);

			DECLARE_OSPCipher(c);
			Cipher cipher(cryptography, c);
			Setup(cipher);

			ByteArray<BLOCK_SIZE> encrypted;
			EncryptTestA(cryptography, cipher, encrypted);
			{
				ByteArray<DATA_SIZE> data;
				success = cryptography.Decrypt(cipher, IV0, encrypted, data, &TestError);
				Assert::IsTrue(success, L"1st Encryption/Decryption failed, see Cryptography_Encrypt_Decrypt_Test0");
			}

			EncryptTestA(cryptography, cipher, encrypted);

			Assert::IsFalse(encrypted.Zeroed(), L"2nd Encryption not created");

			ByteArray<DATA_SIZE> decrypted;
			success = cryptography.Decrypt(cipher, IV0, encrypted, decrypted, &TestError);

			Assert::IsTrue(success, L"2nd Decrypt failed");
			Assert::IsTrue(memcmp(TestDataA, decrypted, TestDataA.Size()) == 0, L"2nd Decrypt did not return data");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(Cryptography_Encrypt_Decrypt_Test2)
			TEST_DESCRIPTION(L"Encrypt then decrypt different data.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(Cryptography_Encrypt_Decrypt_Test2)
		{
			bool success = true;

			Cryptography cryptography(0, BLOCK_SIZE);

			DECLARE_OSPCipher(c);
			Cipher cipher(cryptography, c);
			Setup(cipher);

			ByteArray<BLOCK_SIZE> encrypted0;
			EncryptTestA(cryptography, cipher, encrypted0);

			ByteArray<BLOCK_SIZE> encrypted1;
			EncryptTestB(cryptography, cipher, encrypted1);

			Assert::IsFalse(0 == memcmp(encrypted0, encrypted1, encrypted0.Size()), L"Different data, same encryption");

			{
				ByteArray<DATA_SIZE> decrypted;
				decrypted.CopyFrom(TestDataA, &TestError);
				success = cryptography.Decrypt(cipher, IV0, encrypted1, decrypted, &TestError);
				Assert::IsTrue(success, L"2nd Decrypt failed");
				Assert::IsTrue(memcmp(TestDataB, decrypted, TestDataB.Size()) == 0, L"2nd Decrypt did not return data");
			}

			ByteArray<BLOCK_SIZE> encrypted2;
			EncryptTestA(cryptography, cipher, encrypted2);

			Assert::IsTrue(0 == memcmp(encrypted0, encrypted2, encrypted0.Size()), L"Same data, different encryption");

			{
				ByteArray<DATA_SIZE> decrypted;
				success = cryptography.Decrypt(cipher, IV0, encrypted2, decrypted, &TestError);
				Assert::IsTrue(success, L"3rd Decrypt failed");
				Assert::IsTrue(memcmp(TestDataA, decrypted, TestDataA.Size()) == 0, L"3rd Decrypt did not return data");
			}
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(Cryptography_Encrypt_Decrypt_Test3)
			TEST_DESCRIPTION(L"Encrypt twice then decrypt.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(Cryptography_Encrypt_Decrypt_Test3)
		{
			bool success = true;

			Cryptography cryptography(0, BLOCK_SIZE);

			DECLARE_OSPCipher(c);
			Cipher cipher(cryptography, c);
			Setup(cipher);

			ByteArray<BLOCK_SIZE> encrypted0;
			EncryptTestA(cryptography, cipher, encrypted0);

			ByteArray<BLOCK_SIZE> encrypted1;
			EncryptTestA(cryptography, cipher, encrypted1, IV1);

			Assert::IsFalse(0 == memcmp(encrypted0, encrypted1, encrypted0.Size()), L"Different vectors, same encryption");

			{
				ByteArray<DATA_SIZE> decrypted;
				success = cryptography.Decrypt(cipher, IV1, encrypted1, decrypted, &TestError);
				Assert::IsTrue(success, L"2nd Decrypt failed");
				Assert::IsTrue(memcmp(TestDataA, decrypted, TestDataA.Size()) == 0, L"2nd Decrypt did not return data");
			}
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(Cryptography_Encrypt_Decrypt_Test4)
			TEST_DESCRIPTION(L"Encrypt same data different ciphers.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(Cryptography_Encrypt_Decrypt_Test4)
		{
			bool success = true;

			Cryptography cryptography(0, BLOCK_SIZE);

			DECLARE_OSPCipher(c0);
			Cipher cipher0(cryptography, c0);
			Setup(cipher0);

			ByteArray<BLOCK_SIZE> encrypted0;
			EncryptTestA(cryptography, cipher0, encrypted0);

			DECLARE_OSPCipher(c1);
			Cipher cipher1(cryptography, c1);
			Setup(cipher1);

			ByteArray<BLOCK_SIZE> encrypted1;
			EncryptTestA(cryptography, cipher1, encrypted1);

			Assert::IsFalse(0 == memcmp(encrypted0, encrypted1, encrypted0.Size()), L"Different ciphers, same encryption");

			{
				ByteArray<DATA_SIZE> decrypted;
				success = cryptography.Decrypt(cipher1, IV0, encrypted1, decrypted, &TestError);
				Assert::IsTrue(success, L"2nd Decrypt failed");
				Assert::IsTrue(memcmp(TestDataA, decrypted, TestDataA.Size()) == 0, L"2nd Decrypt did not return data");
			}
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(Cryptography_Encrypt_Decrypt_Test5)
			TEST_DESCRIPTION(L"Encrypt different sizes.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(Cryptography_Encrypt_Decrypt_Test5)
		{
			bool success = true;

			Cryptography cryptography(0, BLOCK_SIZE);

			DECLARE_OSPCipher(c);
			Cipher cipher(cryptography, c);
			Setup(cipher);

			{
				ByteArray<DATA_SIZE> data;
				data.CopyFrom(TestDataA, &TestError);

				size_t esize = cryptography.EncryptSize(cipher, data.Size(), &TestError);
				Assert::AreNotEqual(size_t(0), esize, L"EncryptSize did not work");

				ByteVector justright(cryptography);
				justright.Alloc(esize, &TestError);
				success = cryptography.Encrypt(cipher, IV0, data, justright, &TestError);
				Assert::IsTrue(success, L"Correct size did not work");
			}

			{
				ByteArray<DATA_SIZE + 1> wrongsize;
				wrongsize.CopyFrom(TestDataA, &TestError);

				size_t esize = cryptography.EncryptSize(cipher, wrongsize.Size(), &TestError);
				Assert::AreNotEqual(size_t(0), esize, L"EncryptSize did not work");

				ByteVector justright(cryptography);
				justright.Alloc(esize, &TestError);
				success = cryptography.Encrypt(cipher, IV0, wrongsize, justright, &TestError);
				Assert::IsTrue(success, L"Could not adjust for wrong data size");
			}

			{
				ByteArray<DATA_SIZE + 1> data;
				data.CopyFrom(TestDataA, &TestError);

				size_t esize = cryptography.EncryptSize(cipher, data.Size(), &TestError);
				Assert::AreNotEqual(size_t(0), esize, L"EncryptSize did not work");

				ByteVector toolarge(cryptography);
				toolarge.Alloc(esize + 1, &TestError);
				success = cryptography.Encrypt(cipher, IV0, data, toolarge, &TestError);
				Assert::IsTrue(success, L"Too small buffer not detected");
			}

			{
				ByteArray<DATA_SIZE + 1> data;
				data.CopyFrom(TestDataA, &TestError);

				ByteArray<DATA_SIZE + 1> toosmall;
				success = cryptography.Encrypt(cipher, IV0, data, toosmall, &TestError);
				Assert::IsFalse(success, L"Too small buffer not detected");
				Assert::IsFalse(data.Zeroed(), L"Data cleared when not necessary");
			}

			{
				ByteArray<DATA_SIZE + 1> data;
				data.CopyFrom(TestDataA, &TestError);

				ByteVector justsmall(cryptography);
				justsmall.Alloc(DATA_SIZE + 1, &TestError);
				success = cryptography.Encrypt(cipher, IV0, data, justsmall, &TestError);
				Assert::IsTrue(success, L"Too small buffer not detected");
			}
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(Cryptography_Encrypt_Decrypt_Test6)
			TEST_DESCRIPTION(L"Encrypt/decrypt, reset, then encrypt/decrypt.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(Cryptography_Encrypt_Decrypt_Test6)
		{
			bool success = true;

			Cryptography cryptography(0, BLOCK_SIZE);

			DECLARE_OSPCipher(c);
			Cipher cipher(cryptography, c);
			Setup(cipher);

			ByteArray<BLOCK_SIZE> encrypted;
			EncryptTestA(cryptography, cipher, encrypted);
			{
				ByteArray<DATA_SIZE> data;
				success = cryptography.Decrypt(cipher, IV0, encrypted, data, &TestError);
				Assert::IsTrue(success, L"1st Encryption/Decryption failed, see Cryptography_Encrypt_Decrypt_Test0");
			}

			cryptography.Reset(0, BLOCK_SIZE, &TestError);

			EncryptTestA(cryptography, cipher, encrypted);

			Assert::IsFalse(encrypted.Zeroed(), L"2nd Encryption not created");

			ByteArray<DATA_SIZE> decrypted;
			success = cryptography.Decrypt(cipher, IV0, encrypted, decrypted, &TestError);

			Assert::IsTrue(success, L"2nd Decrypt failed");
			Assert::IsTrue(memcmp(TestDataA, decrypted, TestDataA.Size()) == 0, L"2nd Decrypt did not return data");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(Cryptography_Encrypt_Decrypt_Leak_Test0)
			TEST_DESCRIPTION(L"Encrypt/Decrypt memory leaks.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(Cryptography_Encrypt_Decrypt_Leak_Test0)
		{
			bool success = true;

			const size_t count = 128;

			ByteArray<64> testData;
			for (size_t b = 1; b <= testData.Size(); b++)
				testData[b - 1] = (Cryptography::byte)b;

			Cryptography cryptography;
			success = cryptography.Initialize(1, testData.Size(), &TestError);
			Assert::IsTrue(success, L"Initialization failed");

			DECLARE_OSPCipher(c);
			Cipher cipher(cryptography, c);
			Setup(cipher);

			for (int n = 0; n < count; n++)
			{
				ByteArray<64> data;
				data.CopyFrom(testData, &TestError);

				ByteVector encrypted(cryptography);
				encrypted.Alloc(data.Size(), &TestError);

				success = cryptography.Encrypt(cipher, IV0, data, encrypted, &TestError);
				
				Assert::IsTrue(success, L"Encrypt failed during leak test");

				ByteArray<64> decrypted;

				success = cryptography.Decrypt(cipher, IV0, encrypted, decrypted, &TestError);

				Assert::IsTrue(success, L"Dispense failed during leak test");
				Assert::IsTrue(memcmp(testData, decrypted, testData.Size()) == 0, L"Dispense did not return data");
			}
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(Cryptograply_Hashing_Test0)
			TEST_DESCRIPTION(L"Hash BLOCK_SIZE.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(Cryptograply_Hashing_Test0)
		{
			TestHashing<BLOCK_SIZE>();
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(Cryptograply_Hashing_Test1)
			TEST_DESCRIPTION(L"Hash BLOCK_SIZE-3.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(Cryptograply_Hashing_Test1)
		{
			TestHashing<BLOCK_SIZE-3>();
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(Cryptograply_Hashing_Test2)
			TEST_DESCRIPTION(L"Hash 19.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(Cryptograply_Hashing_Test2)
		{
			TestHashing<19>();
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(Cryptograply_Hashing_Test3)
			TEST_DESCRIPTION(L"Large even hash.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(Cryptograply_Hashing_Test3)
		{
			TestHashing<BLOCK_SIZE * 3>();
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(Cryptograply_Hashing_Test4)
			TEST_DESCRIPTION(L"Large odd hash.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(Cryptograply_Hashing_Test4)
		{
			TestHashing<BLOCK_SIZE * 3 + 1>();
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(Cryptograply_Hashing_Test5)
			TEST_DESCRIPTION(L"Hash, Reset, Hash.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(Cryptograply_Hashing_Test5)
		{
			bool success = true;

			ByteArray<DATA_SIZE> testA;
			testA.CopyFrom(TestDataA, &TestError);

			Cryptography cryptography(0);

			HashVector hash0(cryptography);
			hash0.Initialize(&TestError);

			success = cryptography.Hash(testA, hash0, &TestError);

			Assert::IsTrue(success, L"1st Hash failed");
			Assert::IsFalse(hash0.Zeroed(), L"1st Hash not created");

			cryptography.Reset(0, 0, &TestError);

			HashVector hash1(cryptography);
			hash1.Initialize(&TestError);

			success = cryptography.Hash(testA, hash1, &TestError);

			Assert::IsTrue(success, L"2nd Hash failed");
			Assert::IsFalse(hash1.Zeroed(), L"2nd Hash not created");

			success = cryptography.Destroy(&TestError);
			success = hash0.Destroy(&TestError) && success;
			success = hash1.Destroy(&TestError) && success;

			Assert::IsTrue(success, L"Failure destroying hashes");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(Cryptograply_IsHashed_Test0)
			TEST_DESCRIPTION(L"Confirm array is hashed.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(Cryptograply_IsHashed_Test0)
		{
			size_t hashsize = Cryptography().HashSize();
			Assert::IsTrue(hashsize < BLOCK_SIZE, L"BlOCK_SIZE is too small for the algorithm");
			TestIsHashed<BLOCK_SIZE>(0, hashsize);
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(Cryptograply_IsHashed_Test1)
			TEST_DESCRIPTION(L"Confirm small array is hashed.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(Cryptograply_IsHashed_Test1)
		{
			const size_t arraySize = BLOCK_SIZE - 3;
			size_t hashsize = Cryptography().HashSize();
			Assert::IsTrue(hashsize < arraySize, L"Array size is too small for the algorithm");
			TestIsHashed<arraySize>(arraySize - (arraySize % hashsize), arraySize);
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(Cryptograply_IsHashed_Test2)
			TEST_DESCRIPTION(L"Confirm odd array is hashed.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(Cryptograply_IsHashed_Test2)
		{
			const size_t arraySize = 19;
			size_t hashsize = Cryptography().HashSize();
			TestIsHashed<arraySize>(arraySize - (arraySize % hashsize), arraySize);
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(Cryptography_Hash_Leak_Test0)
			TEST_DESCRIPTION(L"Hash memory leaks.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(Cryptography_Hash_Leak_Test0)
		{
			bool success = true;

			const size_t count = 128;

			ByteArray<64> test;
			for (size_t b = 1; b <= test.Size(); b++)
				test[size_t(b - 1)] = (Cryptography::byte)b;

			Cryptography cryptography;
			success = cryptography.Initialize(1, test.Size(), &TestError);
			Assert::IsTrue(success, L"Initialization failed");

			for (int n = 0; n < count; n++)
			{
				ByteArray<128> hash;
				success = cryptography.Hash(test, hash, &TestError);
				Assert::IsTrue(success, L"Hash failed during leak test");
			}
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(Cryptography_Hash_Check_Test0)
			TEST_DESCRIPTION(L"Hash has not changed.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(Cryptography_Hash_Check_Test0)
		{
			//const char* const data = "abc";
			OS::byte check[64] = {
				0xdd,0xaf,0x35,0xa1,0x93,0x61,0x7a,0xba,
				0xcc,0x41,0x73,0x49,0xae,0x20,0x41,0x31,
				0x12,0xe6,0xfa,0x4e,0x89,0xa9,0x7e,0xa2,
				0x0a,0x9e,0xee,0xe6,0x4b,0x55,0xd3,0x9a,
				0x21,0x92,0x99,0x2a,0x27,0x4f,0xc1,0xa8,
				0x36,0xba,0x3c,0x23,0xa3,0xfe,0xeb,0xbd,
				0x45,0x4d,0x44,0x23,0x64,0x3c,0xe8,0x0e,
				0x2a,0x9a,0xc9,0x4f,0xa5,0x4c,0xa4,0x9f
			};
			CheckHash<64>("abc", check);
		}
	};
}