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

		BEGIN_TEST_METHOD_ATTRIBUTE(SecureStore_Encrypt_Decrypt_Test0)
			TEST_DESCRIPTION(L"Encrypt then Decrypt.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(SecureStore_Encrypt_Decrypt_Test0)
		{
			bool success;

			SecureStore store(0, BLOCK_SIZE, &TestError);

			DECLARE_OSPCipher(c);
			Cipher cipher(store, c);
			Setup(cipher);

			ByteArray<BLOCK_SIZE> encrypted;
			{
				ByteArray<DATA_SIZE> data;
				data.CopyFrom(TestDataA, &TestError);
				success = store.Encrypt(cipher, data, encrypted, &TestError);
				Assert::IsTrue(success, L"Encrypt failed");
				Assert::IsTrue(data.Zeroed(), L"Data not cleared");
			}

			Assert::IsFalse(encrypted.Zeroed(), L"Encryption not created");
			Assert::IsTrue(cipher.Completed(), L"Encrypt changed cipher");

			ByteArray<DATA_SIZE> decrypted;

			success = store.Decrypt(cipher, encrypted, decrypted, &TestError);

			Assert::IsTrue(success, L"Decrypt failed");
			Assert::IsTrue(memcmp(TestDataA, decrypted, TestDataA.Size()) == 0, L"Decrypt did not return data");
			Assert::IsTrue(encrypted.Zeroed(), L"Encryption not cleared");
			Assert::IsTrue(cipher.Completed(), L"Decrypt changed cipher");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(SecureStore_Encrypt_Decrypt_Test1)
			TEST_DESCRIPTION(L"Encrypt then Decrypt twice.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(SecureStore_Encrypt_Decrypt_Test1)
		{
			bool success = true;

			SecureStore store(0, BLOCK_SIZE, &TestError);

			DECLARE_OSPCipher(c);
			Cipher cipher(store, c);
			Setup(cipher);

			ByteArray<BLOCK_SIZE> encrypted;
			EncryptTestA(store, cipher, encrypted);
			{
				ByteArray<DATA_SIZE> decrypted;
				success = store.Decrypt(cipher, encrypted, decrypted, &TestError);
				if (success)
					success = SecureStore::ReleaseDecrypted(decrypted, &TestError);
				Assert::IsTrue(success, L"1st Encryption/Decryption failed, see Cryptography_Encrypt_Decrypt_Test1");
			}

			EncryptTestA(store, cipher, encrypted);

			Assert::IsFalse(encrypted.Zeroed(), L"2nd Encryption not created");

			ByteArray<DATA_SIZE> decrypted;
			success = store.Decrypt(cipher, encrypted, decrypted, &TestError);

			Assert::IsTrue(success, L"2nd Decrypt failed");
			Assert::IsTrue(memcmp(TestDataA, decrypted, TestDataA.Size()) == 0, L"2nd Decrypt did not return data");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(SecureStore_Encrypt_Decrypt_Test2)
			TEST_DESCRIPTION(L"Encrypt different then Decrypt.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(SecureStore_Encrypt_Decrypt_Test2)
		{
			bool success = true;

			SecureStore store(0, TestDataA.Size(), &TestError);

			DECLARE_OSPCipher(c);
			Cipher cipher(store, c);
			Setup(cipher);

			ByteArray<DATA_SIZE> encrypted0;
			EncryptTestA(store, cipher, encrypted0);

			ByteArray<DATA_SIZE> encrypted1;
			EncryptTestB(store, cipher, encrypted1);

			Assert::IsFalse(0 == memcmp(encrypted0, encrypted1, encrypted0.Size()), L"Different data, same encryption");

			{
				ByteArray<DATA_SIZE> decrypted;
				success = store.Decrypt(cipher, encrypted1, decrypted, &TestError);
				Assert::IsTrue(success, L"2nd Decrypt failed");
				Assert::IsTrue(memcmp(TestDataB, decrypted, TestDataB.Size()) == 0, L"2nd Decrypt did not return data");
				success = SecureStore::ReleaseDecrypted(decrypted, &TestError);
				Assert::IsTrue(success, L"Decrypt not released");
			}

			ByteArray<DATA_SIZE> encrypted2;
			EncryptTestA(store, cipher, encrypted2);

			Assert::IsTrue(0 == memcmp(encrypted0, encrypted2, encrypted0.Size()), L"Same data, different encryption");

			{
				ByteArray<DATA_SIZE> decrypted;
				success = store.Decrypt(cipher, encrypted2, decrypted, &TestError);
				Assert::IsTrue(success, L"3rd Decrypt failed");
				Assert::IsTrue(memcmp(TestDataA, decrypted, TestDataA.Size()) == 0, L"3rd Decrypt did not return data");
			}
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(SecureStore_Encrypt_Decrypt_Test3)
			TEST_DESCRIPTION(L"Encrypt different with salt then Decrypt.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(SecureStore_Encrypt_Decrypt_Test3)
		{
			bool success = true;

			SecureStore store(0, TestDataA.Size() * 2, &TestError);

			DECLARE_OSPCipher(c);
			Cipher cipher(store, c);
			Setup(cipher);

			ByteArray<DATA_SIZE * 2> encrypted0;
			EncryptTestA(store, cipher, encrypted0);

			ByteArray<DATA_SIZE * 2> encrypted1;
			EncryptTestB(store, cipher, encrypted1);

			Assert::IsFalse(0 == memcmp(encrypted0, encrypted1, encrypted0.Size()), L"Different data, same encryption");

			{
				ByteArray<DATA_SIZE> decrypted;
				success = store.Decrypt(cipher, encrypted1, decrypted, &TestError);
				Assert::IsTrue(success, L"2nd Decrypt failed");
				Assert::IsTrue(memcmp(TestDataB, decrypted, TestDataB.Size()) == 0, L"2nd Decrypt did not return data");
				success = SecureStore::ReleaseDecrypted(decrypted, &TestError);
				Assert::IsTrue(success, L"Decrypt not released");
			}

			ByteArray<DATA_SIZE * 2> encrypted2;
			EncryptTestA(store, cipher, encrypted2);

			Assert::IsFalse(0 == memcmp(encrypted0, encrypted2, encrypted0.Size()), L"Salted data, same encryption");

			{
				ByteArray<DATA_SIZE> decrypted;
				success = store.Decrypt(cipher, encrypted2, decrypted, &TestError);
				Assert::IsTrue(success, L"3rd Decrypt failed");
				Assert::IsTrue(memcmp(TestDataA, decrypted, TestDataA.Size()) == 0, L"3rd Decrypt did not return data");
			}
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(SecureStore_Encrypt_Decrypt_Test4)
			TEST_DESCRIPTION(L"Encrypt/decrypt, reset, then encrypt/decrypt.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(SecureStore_Encrypt_Decrypt_Test4)
		{
			bool success = true;

			SecureStore store(0, BLOCK_SIZE, &TestError);

			DECLARE_OSPCipher(c);
			Cipher cipher(store, c);
			Setup(cipher);

			ByteArray<BLOCK_SIZE> encrypted;
			EncryptTestA(store, cipher, encrypted);
			{
				ByteArray<DATA_SIZE> decrypted;
				success = store.Decrypt(cipher, encrypted, decrypted, &TestError);
				if (success)
					success = SecureStore::ReleaseDecrypted(decrypted, &TestError);
				Assert::IsTrue(success, L"1st Encryption/Decryption failed, see Cryptography_Encrypt_Decrypt_Test1");
			}

			store.Reset(0, BLOCK_SIZE, &TestError);

			EncryptTestA(store, cipher, encrypted);

			Assert::IsFalse(encrypted.Zeroed(), L"2nd Encryption not created");

			ByteArray<DATA_SIZE> decrypted;
			success = store.Decrypt(cipher, encrypted, decrypted, &TestError);

			Assert::IsTrue(success, L"2nd Decrypt failed");
			Assert::IsTrue(memcmp(TestDataA, decrypted, TestDataA.Size()) == 0, L"2nd Decrypt did not return data");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(SecureStore_Encrypt_Decrypt_Leak_Test0)
			TEST_DESCRIPTION(L"Encrypt/Decrypt memory leaks.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(SecureStore_Encrypt_Decrypt_Leak_Test0)
		{
			bool success = true;

			const size_t count = 128;

			ByteArray<64> testData;
			for (size_t b = 1; b <= testData.Size(); b++)
				testData[b - 1] = (SecureStore::byte)b;

			SecureStore store;
			success = store.Initialize(0, testData.Size(), &TestError);
			Assert::IsTrue(success, L"Initialization failed");

			Logger::WriteMessage("Encripting/Decrypting");
			for (int n = 0; n < count; n++)
			{
				Logger::WriteMessage((" " + std::to_string(n)).c_str());

				DECLARE_OSPCipher(c);
				Cipher cipher(store, c);
				Setup(cipher);

				ByteArray<64> data;
				data.CopyFrom(testData, &TestError);

				ByteArray<64> encrypted;

				success = store.Encrypt(cipher, data, encrypted, &TestError);

				Assert::IsTrue(success, L"Encrypt failed during leak test");

				ByteArray<64> decrypted;
				success = store.Decrypt(cipher, encrypted, decrypted, &TestError);

				Assert::IsTrue(success, L"Dispense failed during leak test");
				Assert::IsTrue(memcmp(testData, decrypted, testData.Size()) == 0, L"Dispense did not return data");

				SecureStore::ReleaseDecrypted(decrypted, &TestError);

				delete[] cipher.Key();
				ciphercleanup = 0;
			}
			Logger::WriteMessage("\n");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(SecureStore_Encrypt_Decrypt_Leak_Test1)
			TEST_DESCRIPTION(L"Encrypt/Decrypt with salt memory leaks.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(SecureStore_Encrypt_Decrypt_Leak_Test1)
		{
			bool success = true;

			const size_t count = 128;

			ByteArray<64> testData;
			for (size_t b = 1; b <= testData.Size(); b++)
				testData[b - 1] = (SecureStore::byte)b;

			SecureStore store;
			success = store.Initialize(0, testData.Size() * 2, &TestError);
			Assert::IsTrue(success, L"Initialization failed");

			Logger::WriteMessage("Encripting/Decrypting");
			for (int n = 0; n < count; n++)
			{
				Logger::WriteMessage((" " + std::to_string(n)).c_str());

				DECLARE_OSPCipher(c);
				Cipher cipher(store, c);
				Setup(cipher);

				ByteArray<64> data;
				data.CopyFrom(testData, &TestError);

				ByteArray<128> encrypted;

				success = store.Encrypt(cipher, data, encrypted, &TestError);

				Assert::IsTrue(success, L"Encrypt failed during leak test");

				ByteArray<64> decrypted;
				success = store.Decrypt(cipher, encrypted, decrypted, &TestError);

				Assert::IsTrue(success, L"Dispense failed during leak test");
				Assert::IsTrue(memcmp(testData, decrypted, testData.Size()) == 0, L"Dispense did not return data");

				SecureStore::ReleaseDecrypted(decrypted, &TestError);

				delete[] cipher.Key();
				ciphercleanup = 0;
			}
			Logger::WriteMessage("\n");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(SecureStore_Store_Dispense_Test0)
			TEST_DESCRIPTION(L"Stored password is returned by Dispense.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(SecureStore_Store_Dispense_Test0)
		{
			bool success = true;

			string name = "test";

			SecureStore store(1, BLOCK_SIZE, &TestError);

			DECLARE_OSPCipher(c);
			Cipher cipher(store, c);
			Setup(cipher);

			{
				ByteArray<DATA_SIZE> data;
				data.CopyFrom(TestDataA, &TestError);
				success = store.StoreData(name, cipher, data, 0, &TestError);
				Assert::IsTrue(success, L"Store failed");
				Assert::IsTrue(data.Zeroed(), L"Data not cleared");
				Assert::AreEqual(store.DataSize(name), data.Size(), L"Size not stored");
			}

			Assert::IsTrue(cipher.Completed(), L"Encrypt changed cipher");

			ByteArray<DATA_SIZE> dispensed;

			success = store.DispenseData(name, cipher, dispensed, &TestError);

			Assert::IsTrue(success, L"Dispense failed");
			Assert::IsTrue(memcmp(TestDataA, dispensed, TestDataA.Size()) == 0, L"Dispense did not return data");
			Assert::IsTrue(store.DataSize(name) == 0, L"Size not cleared");
			Assert::IsTrue(cipher.Zeroed(), L"Cipher not cleared");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(SecureStore_Store_Dispense_Test1)
			TEST_DESCRIPTION(L"Data under different Names are Stored correctly.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(SecureStore_Store_Dispense_Test1)
		{
			bool success = true;

			string name0 = "test0";
			string name1 = "test1";

			SecureStore store(2, BLOCK_SIZE, &TestError);

			DECLARE_OSPCipher(c0);
			Cipher cipher0(store, c0);
			Setup(cipher0);

			StoreTestA(store, cipher0, name0);

			DECLARE_OSPCipher(c1);
			Cipher cipher1(store, c1);
			Setup(cipher1);

			StoreTestB(store, cipher1, name1);

			{
				ByteArray<DATA_SIZE> dispensed;
				success = store.DispenseData(name0, cipher0, dispensed, &TestError);
				Assert::IsTrue(success, L"1st Dispense failed");
				Assert::IsTrue(memcmp(TestDataA, (byte*)dispensed, TestDataA.Size()) == 0, L"1st Dispense did not return data");
				SecureStore::ReleaseDecrypted(dispensed, &TestError);
			}

			Assert::IsTrue(store.DataSize(name0) == 0, L"1st Size not cleared");
			Assert::IsTrue(cipher0.Zeroed(), L"1st Cipher not cleared");

			{
				ByteArray<DATA_SIZE> dispensed;
				success = store.DispenseData(name1, cipher1, dispensed, &TestError);
				Assert::IsTrue(success, L"2nd Dispense failed");
				Assert::IsTrue(memcmp(TestDataB, dispensed, TestDataB.Size()) == 0, L"2nd Dispense did not return data");
				SecureStore::ReleaseDecrypted(dispensed, &TestError);
			}

			Assert::IsTrue(store.DataSize(name1) == 0, L"2nd Size not cleared");
			Assert::IsTrue(cipher1.Zeroed(), L"2nd Cipher not cleared");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(SecureStore_Store_Dispense_Test2)
			TEST_DESCRIPTION(L"Different Data under same Name is Stored correctly.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(SecureStore_Store_Dispense_Test2)
		{
			bool success = true;

			string name = "test";

			SecureStore store(2, BLOCK_SIZE, &TestError);

			DECLARE_OSPCipher(c);
			Cipher cipher(store, c);
			Setup(cipher);

			StoreTestA(store, cipher, name);
			StoreTestB(store, cipher, name);

			{
				ByteArray<DATA_SIZE> dispensed;
				success = store.DispenseData(name, cipher, dispensed, &TestError);
				Assert::IsTrue(success, L"Dispense failed");
				Assert::IsTrue(memcmp(TestDataB, (byte*)dispensed, TestDataB.Size()) == 0, L"Dispense did not return data");
				SecureStore::ReleaseDecrypted(dispensed, &TestError);
			}
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(SecureStore_Store_Dispense_Test3)
			TEST_DESCRIPTION(L"Store, reset, store again.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(SecureStore_Store_Dispense_Test3)
		{
			bool success = true;

			string name = "test0";

			SecureStore store(1, BLOCK_SIZE, &TestError);

			DECLARE_OSPCipher(c);

			Cipher cipher(store, c);
			Setup(cipher);

			StoreTestA(store, cipher, name);

			store.Reset(1, BLOCK_SIZE, &TestError);

			StoreTestA(store, cipher, name);

			{
				ByteArray<DATA_SIZE> dispensed;
				success = store.DispenseData(name, cipher, dispensed, &TestError);
				Assert::IsTrue(success, L"Dispense failed");
				Assert::IsTrue(memcmp(TestDataA, (byte*)dispensed, TestDataA.Size()) == 0, L"Dispense did not return data");
				SecureStore::ReleaseDecrypted(dispensed, &TestError);
			}
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(SecureStore_Store_Dispense_Leak_Test0)
			TEST_DESCRIPTION(L"Store all then dispnese to check memory leaks.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(SecureStore_Store_Dispense_Leak_Test0)
		{
			bool success = true;

			const size_t count = 128;

			SecureStore::byte testData[64];
			for (int b = 1; b <= _countof(testData); b++)
				testData[b - 1] = (SecureStore::byte)b;

			SecureStore store;
			success = store.Initialize(count, sizeof(testData), &TestError);
			Assert::IsTrue(success, L"Initialization failed");

			std::stack<OSPCipher> ciphers;

			Logger::WriteMessage("Storing");
			for (int n = 0; n < count; n++)
			{
				auto name = "t" + std::to_string(n);
				Logger::WriteMessage((" " + name).c_str());

				DECLARE_OSPCipher(c);
				Cipher cipher(store, c);
				Setup(cipher);
				ciphers.push(c);
				ciphercleanup = 0;

				ByteArray<64> data;
				data.CopyFrom(testData, sizeof(testData), 0, &TestError);

				success = store.StoreData(name, cipher, data, 0, &TestError);
				Assert::IsTrue(success, L"Store failed during leak test");
			}
			Logger::WriteMessage("\n");

			Logger::WriteMessage("Dispensing");
			for (int n = count - 1; n >= 0; n--)
			{
				auto name = "t" + std::to_string(n);
				Logger::WriteMessage((" " + name).c_str());

				Cipher cipher(store, ciphers.top());

				ByteArray<64> dispensed;
				success = store.DispenseData(name, cipher, dispensed, &TestError);

				Assert::IsTrue(success, L"Dispense failed during leak test");
				Assert::IsTrue(memcmp(testData, (byte*)dispensed, sizeof(testData)) == 0, L"Dispense did not return data");

				SecureStore::ReleaseDecrypted(dispensed, &TestError);

				delete[] ciphers.top().Key;
				ciphers.pop();
			}
			Logger::WriteMessage("\n");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(SecureStore_Store_Dispense_Leak_Test1)
			TEST_DESCRIPTION(L"Store all with salt then dispnese to check memory leaks.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(SecureStore_Store_Dispense_Leak_Test1)
		{
			bool success = true;

			const size_t count = 128;

			SecureStore::byte testData[64];
			for (int b = 1; b <= sizeof(testData); b++)
				testData[b - 1] = (SecureStore::byte)b;

			SecureStore store;
			success = store.Initialize(count, sizeof(testData) * 2, &TestError);
			Assert::IsTrue(success, L"Initialization failed");

			std::stack<OSPCipher> ciphers;

			Logger::WriteMessage("Storing");
			for (int n = 0; n < count; n++)
			{
				auto name = "t" + std::to_string(n);
				Logger::WriteMessage((" " + name).c_str());

				DECLARE_OSPCipher(c);
				Cipher cipher(store, c);
				Setup(cipher);

				ciphers.push(c);
				ciphercleanup = 0;

				ByteArray<64> data;
				data.CopyFrom(testData, sizeof(testData), 0, &TestError);

				success = store.StoreData(name, cipher, data, 0, &TestError);
				Assert::IsTrue(success, L"Store failed during leak test");
			}
			Logger::WriteMessage("\n");

			Logger::WriteMessage("Dispensing");
			for (int n = count - 1; n >= 0; n--)
			{
				auto name = "t" + std::to_string(n);
				Logger::WriteMessage((" " + name).c_str());

				Cipher cipher(store, ciphers.top());
				ByteArray<_countof(testData)> dispensed;
				success = store.DispenseData(name, cipher, dispensed, &TestError);

				Assert::IsTrue(success, L"Dispense failed during leak test");
				Assert::IsTrue(memcmp(testData, (byte*)dispensed, sizeof(testData)) == 0, L"Dispense did not return data");

				SecureStore::ReleaseDecrypted(dispensed, &TestError);

				delete[] ciphers.top().Key;
				ciphers.pop();
			}
			Logger::WriteMessage("\n");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(SecureStore_Store_Dispense_Leak_Test2)
			TEST_DESCRIPTION(L"Store and dispense to check memory leaks.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(SecureStore_Store_Dispense_Leak_Test2)
		{
			bool success = true;

			const size_t count = 128;

			SecureStore::byte testData[64];
			for (int b = 1; b <= sizeof(testData); b++)
				testData[b - 1] = (SecureStore::byte)b;

			SecureStore store;
			success = store.Initialize(0, sizeof(testData), &TestError);
			Assert::IsTrue(success, L"Initialization failed");

			Logger::WriteMessage("Storing/Dispensing");
			for (int n = 0; n < count; n++)
			{
				auto name = "t" + std::to_string(n);
				Logger::WriteMessage((" " + name).c_str());

				DECLARE_OSPCipher(c);
				Cipher cipher(store, c);
				Setup(cipher);

				ByteArray<64> data;
				data.CopyFrom(testData, sizeof(testData), 0, &TestError);

				success = store.StoreData(name, cipher, data, 0, &TestError);
				Assert::IsTrue(success, L"Store failed during leak test");

				ByteArray<_countof(testData)> dispensed;
				success = store.DispenseData(name, cipher, dispensed, &TestError);

				Assert::IsTrue(success, L"Dispense failed during leak test");
				Assert::IsTrue(memcmp(testData, (byte*)dispensed, sizeof(testData)) == 0, L"Dispense did not return data");

				SecureStore::ReleaseDecrypted(dispensed, &TestError);
				
				delete[] cipher.Key();
				ciphercleanup = 0;
			}
			Logger::WriteMessage("\n");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(SecureStore_Store_Dispense_Leak_Test3)
			TEST_DESCRIPTION(L"Store and dispense with salt to check memory leaks.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(SecureStore_Store_Dispense_Leak_Test3)
		{
			bool success = true;

			const size_t count = 128;

			SecureStore::byte testData[64];
			for (int b = 1; b <= sizeof(testData); b++)
				testData[b - 1] = (SecureStore::byte)b;

			SecureStore store;
			success = store.Initialize(0, sizeof(testData) * 2, &TestError);
			Assert::IsTrue(success, L"Initialization failed");

			Logger::WriteMessage("Storing/Dispensing");
			for (int n = 0; n < count; n++)
			{
				auto name = "t" + std::to_string(n);
				Logger::WriteMessage((" " + name).c_str());

				DECLARE_OSPCipher(c);
				Cipher cipher(store, c);
				Setup(cipher);

				ByteArray<64> data;
				data.CopyFrom(testData, sizeof(testData), 0, &TestError);

				success = store.StoreData(name, cipher, data, 0, &TestError);
				Assert::IsTrue(success, L"Store failed during leak test");

				ByteArray<_countof(testData)> dispensed;
				success = store.DispenseData(name, cipher, dispensed, &TestError);

				Assert::IsTrue(success, L"Dispense failed during leak test");
				Assert::IsTrue(memcmp(testData, (byte*)dispensed, sizeof(testData)) == 0, L"Dispense did not return data");

				SecureStore::ReleaseDecrypted(dispensed, &TestError);

				delete[] cipher.Key();
				ciphercleanup = 0;
			}
			Logger::WriteMessage("\n");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(SecureStore_Store_Destroy_Test0)
			TEST_DESCRIPTION(L"Store data and destroy.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(SecureStore_Store_Destroy_Test0)
		{
			bool success = true;

			string name = "test";

			SecureStore store(1, BLOCK_SIZE, &TestError);

			DECLARE_OSPCipher(c);
			Cipher cipher(store, c);
			Setup(cipher);

			{
				ByteArray<DATA_SIZE> data;
				data.CopyFrom(TestDataA, &TestError);

				success = store.StoreData(name, cipher, data, 0, &TestError);

				Assert::IsTrue(success, L"Store failed");
				Assert::IsTrue(data.Zeroed(), L"Data not cleared");
				Assert::AreEqual(store.DataSize(name), data.Size(), L"Size not stored");
			}

			Assert::IsTrue(cipher.Completed(), L"Store changed cipher");

			success = store.DestroyData(name, &TestError);

			Assert::IsTrue(success, L"Destroy failed");
			Assert::IsTrue(store.DataSize(name) == 0, L"Size not cleared");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(SecureStore_Store_Destroy_Leak_Test0)
			TEST_DESCRIPTION(L"Store all then destroy to check memory leaks.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(SecureStore_Store_Destroy_Leak_Test0)
		{
			bool success = true;

			const size_t count = 128;

			ByteArray<64> testData;
			for (size_t b = 1; b <= testData.Size(); b++)
				testData[b - 1] = (SecureStore::byte)b;

			SecureStore store;
			success = store.Initialize(count, testData.Size(), &TestError);
			Assert::IsTrue(success, L"Initialization failed");

			Logger::WriteMessage("Storing");
			for (int n = 0; n < count; n++)
			{
				auto name = "t" + std::to_string(n);
				Logger::WriteMessage((" " + name).c_str());

				DECLARE_OSPCipher(c);
				Cipher cipher(store, c);
				Setup(cipher);
				ciphercleanup = 0;

				ByteArray<64> data;
				data.CopyFrom(testData, &TestError);

				success = store.StoreData(name, cipher, data, 0, &TestError);
				Assert::IsTrue(success, L"Store failed during leak test");

				//cipher.Zero();
				delete[] cipher.Key();
			}
			Logger::WriteMessage("\n");

			Logger::WriteMessage("Destroying");
			for (int n = count - 1; n >= 0; n--)
			{
				auto name = "t" + std::to_string(n);
				Logger::WriteMessage((" " + name).c_str());
				success = store.DestroyData(name, &TestError);
				Assert::IsTrue(success, L"Dispense failed during leak test");
			}
			Logger::WriteMessage("\n");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(SecureStore_Store_Destroy_Leak_Test1)
			TEST_DESCRIPTION(L"Store all with salt then destroy to check memory leaks.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(SecureStore_Store_Destroy_Leak_Test1)
		{
			bool success = true;

			const size_t count = 128;

			ByteArray<64> testData;
			for (size_t b = 1; b <= testData.Size(); b++)
				testData[b - 1] = (SecureStore::byte)b;

			SecureStore store;
			success = store.Initialize(count, testData.Size() * 2, &TestError);
			Assert::IsTrue(success, L"Initialization failed");

			Logger::WriteMessage("Storing");
			for (int n = 0; n < count; n++)
			{
				auto name = "t" + std::to_string(n);
				Logger::WriteMessage((" " + name).c_str());

				DECLARE_OSPCipher(c);
				Cipher cipher(store, c);
				Setup(cipher);

				ciphercleanup = 0;

				ByteArray<64> data;
				data.CopyFrom(testData, &TestError);

				success = store.StoreData(name, cipher, data, 0, &TestError);
				Assert::IsTrue(success, L"Store failed during leak test");

				//cipher.Zero();
				delete[] cipher.Key();
			}
			Logger::WriteMessage("\n");

			Logger::WriteMessage("Destroying");
			for (int n = count - 1; n >= 0; n--)
			{
				auto name = "t" + std::to_string(n);
				Logger::WriteMessage((" " + name).c_str());
				success = store.DestroyData(name, &TestError);
				Assert::IsTrue(success, L"Destroy failed during leak test");
			}
			Logger::WriteMessage("\n");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(SecureStore_Store_Destroy_Leak_Test2)
			TEST_DESCRIPTION(L"Store and destroy to check memory leaks.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(SecureStore_Store_Destroy_Leak_Test2)
		{
			bool success = true;

			const size_t count = 128;

			ByteArray<64> testData;
			for (size_t b = 1; b <= testData.Size(); b++)
				testData[b - 1] = (SecureStore::byte)b;

			SecureStore store;
			success = store.Initialize(0, testData.Size(), &TestError);
			Assert::IsTrue(success, L"Initialization failed");

			Logger::WriteMessage("Storing/Destroying");
			for (int n = 0; n < count; n++)
			{
				auto name = "t" + std::to_string(n);
				Logger::WriteMessage((" " + name).c_str());

				DECLARE_OSPCipher(c);
				Cipher cipher(store, c);
				Setup(cipher);

				ByteArray<64> data;
				data.CopyFrom(testData, &TestError);

				success = store.StoreData(name, cipher, data, 0, &TestError);
				Assert::IsTrue(success, L"Store failed during leak test");

				success = store.DestroyData(name, &TestError);

				Assert::IsTrue(success, L"Destroy failed during leak test");

				delete[] cipher.Key();
				ciphercleanup = 0;
			}
			Logger::WriteMessage("\n");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(SecureStore_Store_Destroy_Leak_Test3)
			TEST_DESCRIPTION(L"Store and destroy with salt to check memory leaks.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(SecureStore_Store_Destroy_Leak_Test3)
		{
			bool success = true;

			const size_t count = 128;

			ByteArray<64> testData;
			for (size_t b = 1; b <= testData.Size(); b++)
				testData[b - 1] = (SecureStore::byte)b;

			SecureStore store;
			success = store.Initialize(0, testData.Size() * 2, &TestError);
			Assert::IsTrue(success, L"Initialization failed");

			Logger::WriteMessage("Storing/Destroying");
			for (int n = 0; n < count; n++)
			{
				auto name = "t" + std::to_string(n);
				Logger::WriteMessage((" " + name).c_str());

				DECLARE_OSPCipher(c);
				Cipher cipher(store, c);
				Setup(cipher);

				ByteArray<64> data;
				data.CopyFrom(testData, &TestError);

				success = store.StoreData(name, cipher, data, 0, &TestError);
				Assert::IsTrue(success, L"Store failed during leak test");

				success = store.DestroyData(name, &TestError);

				Assert::IsTrue(success, L"Destroy failed during leak test");

				delete[] cipher.Key();
				ciphercleanup = 0;
			}
			Logger::WriteMessage("\n");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(SecureStore_StrongHash_Test0)
			TEST_DESCRIPTION(L"StrongHash takes enough time.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(SecureStore_StrongHash_Test0)
		{
			bool success = true;

			ByteArray<64> test;
			for (size_t b = 1; b <= test.Size(); b++)
				test[b - 1] = (Cryptography::byte)b;

			SecureStore store;
			success = store.Initialize(1, test.Size(), &TestError);
			Assert::IsTrue(success, L"Initialization failed");

			ByteArray<64> hash;

			auto t0 = GetTickCount();
			success = store.StrongHash(test, hash, &TestError);
			auto t1 = GetTickCount();

			Assert::IsTrue(success, L"Strong Hash failed");
			Assert::IsFalse(hash.Zeroed(), L"Strong Hash not created");
			Assert::AreNotEqual(t0, t1, L"Strong Hash went to fast");
		}

		static const size_t stronghash_size = 4;

		void StrongHashCheck(SecureStore& store, const byte input[stronghash_size], const byte expected[stronghash_size])
		{
			ByteArray<stronghash_size> test;
			ByteArray<stronghash_size> hash;

			test.CopyFrom(input, 4, 0, &TestError);

			bool success = store.StrongHash(test, hash, &TestError);

			Assert::IsTrue(success, L"Strong Hash failed");
			Assert::IsFalse(hash.Zeroed(), L"Strong Hash not created");
			Assert::IsTrue(0 == memcmp(hash, expected, hash.Size()), L"Strong Hash has changed");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(SecureStore_StrongHash_Test1)
			TEST_DESCRIPTION(L"StrongHash results did not change.")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(SecureStore_StrongHash_Test1)
		{
			bool success = true;

			SecureStore store;
			success = store.Initialize(1, stronghash_size, &TestError);
			Assert::IsTrue(success, L"Initialization failed");

			{
				const byte input[stronghash_size] = { 0, 0, 0, 1 };
				const byte expected[stronghash_size] = { 147, 1, 186, 68 };
				StrongHashCheck(store, input, expected);
			}

			{
				const byte input[stronghash_size] = { 0, 0, 2, 1 };
				const byte expected[stronghash_size] = { 166, 71, 147, 91 };
				StrongHashCheck(store, input, expected);
			}

			{
				const byte input[stronghash_size] = { 0, 3, 2, 2 };
				const byte expected[stronghash_size] = { 90, 209, 113, 128 };
				StrongHashCheck(store, input, expected);
			}

			{
				const byte input[stronghash_size] = { 4, 3, 2, 2 };
				const byte expected[stronghash_size] = { 202, 155, 139, 210 };
				StrongHashCheck(store, input, expected);
			}
		}

	};
}