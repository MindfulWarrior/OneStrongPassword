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

#include "../osp/strongpassword.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace OneStrongPassword
{
	TEST_CLASS(Recipe_Test)
	{
		static const size_t size0 = 48;

		const char* strong0 = "This is a password. Just a stinkin password.";

		OSPError TestError;

		void* ciphercleanup;

		void Generate(const std::string& mnemonic, char* const gen, size_t size, const Recipe& recipe)
		{
			SecureStore store;
			bool success = store.Initialize(1);
			Assert::IsTrue(success, L"Setting up store failed");

			DECLARE_OSPCipher(ospcipher);
			Cipher cipher(store, ospcipher);

			success = cipher.Prepare();
			if (success)
			{
				ciphercleanup = cipher.Key() = new Cipher::byte[cipher.Size()];
				success = cipher.Complete();
			}
			Assert::IsTrue(success, L"Setting up cipher failed");

			PasswordArray<size0> strong;
			strong.CopyFrom(strong0);
			  
			StrongPassword strongPassword(store, "recipe_test");
			strongPassword.Store(cipher, strong);

			PasswordVector generated(nullptr, gen, size);
			success = strongPassword.GeneratePassword(mnemonic, cipher, generated, generated.Size() - 1, recipe);
			Assert::IsTrue(success, L"GeneratePassword failed");
			generated.Release();
		 }

		TEST_METHOD_CLEANUP(MethodCleanup)
		{
			if (ciphercleanup)
				delete[] ciphercleanup;
			Assert::IsTrue(EXPOSED(0), L"Something is exposed");
			Assert::AreEqual(TestError.Code, OSP_NO_ERROR, L"There was an undected error");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(Recipe_CharSet_Test0)
			TEST_DESCRIPTION("Add flags and set specials")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(Recipe_CharSet_Test0)
		{
			Recipe recipe;

			Assert::IsTrue(recipe.Cleared(), L"Not empty");

			recipe.AddFlags(OSP_RECIPE_NUMERIC);

			Assert::IsFalse(recipe.Cleared(), L"Char set not set");
			for (char ch = '0'; ch < '9'; ch++)
				Assert::IsTrue(recipe.HasChar(ch), L"Missing numeric");

			recipe.Clear();
			recipe.AddFlags(OSP_RECIPE_LOWERCASE);

			Assert::IsFalse(recipe.Cleared(), L"Char set not set");
			for (char ch = 'a'; ch < 'z'; ch++)
				Assert::IsTrue(recipe.HasChar(ch), L"Missing lower case");

			recipe.Clear();
			recipe.AddFlags(OSP_RECIPE_UPPERCASE);

			Assert::IsFalse(recipe.Cleared(), L"Char set not set");
			for (char ch = 'A'; ch < 'Z'; ch++)
				Assert::IsTrue(recipe.HasChar(ch), L"Missing upper case");

			size_t length = (size_t)strnlen(OSP_RECIPE_ALL_SUPPORTED_SPECIALS, 32);

			recipe.Clear();
			recipe.SetSpecials(OSP_RECIPE_ALL_SUPPORTED_SPECIALS, length);

			Assert::IsFalse(recipe.Cleared(), L"Char set not set");
			Assert::IsFalse(recipe.HasChar(' '), L"Has ' ");
			for (size_t n = 0; n < length; n++)
				Assert::IsTrue(
					recipe.HasChar(OSP_RECIPE_ALL_SUPPORTED_SPECIALS[n]),
					L"Missing supported special"
				);

			recipe.Clear();
			recipe.SetSpecials("!", 1);

			Assert::IsFalse(recipe.Cleared(), L"Char set not set");
			Assert::IsTrue(recipe.HasChar('!'), L"Missing '!");
			Assert::IsFalse(recipe.HasChar('?'), L"Has char it should not");

			recipe.Reset({ OSP_RECIPE_ALL_SUPPORTED_SPECIALS, length, OSP_RECIPE_SPACE_ALLOWED });

			Assert::IsFalse(recipe.Cleared(), L"Char set not set");
			Assert::IsTrue(recipe.HasChar(' '), L"Missing ' ");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(Recipe_CharSet_Test1)
			TEST_DESCRIPTION("Space allowed flags")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(Recipe_CharSet_Test1)
		{
			Recipe recipe;

			Assert::IsTrue(recipe.Cleared(), L"Not empty");

			recipe.Clear();
			recipe.AddFlags(OSP_RECIPE_SPACE_ALLOWED);

			Assert::IsFalse(recipe.Cleared(), L"Char set not set");
			Assert::IsTrue(recipe.HasChar(' '), L"Space not added");

			recipe.Clear();
			recipe.SetSpecials(" ", 1);

			Assert::IsTrue(recipe.Cleared(), L"Something was added");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(Recipe_Required_Test0)
			TEST_DESCRIPTION("Required flags")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(Recipe_Required_Test0)
		{
			Recipe recipe;

			recipe.Clear();
			recipe.AddFlags(OSP_RECIPE_NUMERIC|OSP_RECIPE_NUMERIC_REQUIRED);

			Assert::IsFalse(recipe.Verified("abc", 3), L"Lack of numeric missed");
			Assert::IsTrue(recipe.Verified("a3c", 3), L"Numeric not found");

			recipe.Clear();
			recipe.AddFlags(OSP_RECIPE_LOWERCASE|OSP_RECIPE_LOWERCASE_REQUIRED);

			Assert::IsFalse(recipe.Verified("ABC", 3), L"Lack of lower case missed");
			Assert::IsTrue(recipe.Verified("AbC", 3), L"Lower case not found");

			recipe.Clear();
			recipe.AddFlags(OSP_RECIPE_UPPERCASE|OSP_RECIPE_UPPERCASE_REQUIRED);

			Assert::IsFalse(recipe.Verified("abc", 3), L"Lack of upper case missed");
			Assert::IsTrue(recipe.Verified("aBc", 3), L"Upper case not found");

			recipe.Reset({ "!?", 2, OSP_RECIPE_SPECIAL_REQUIRED });

			Assert::IsFalse(recipe.Verified("@bc", 3), L"Lack of special missed");
			Assert::IsTrue(recipe.Verified("ab?", 3), L"Special not found");

			recipe.Reset({
				"!?",
				2,
				OSP_RECIPE_NUMERIC|OSP_RECIPE_NUMERIC_REQUIRED |
				OSP_RECIPE_LOWERCASE|OSP_RECIPE_LOWERCASE_REQUIRED |
				OSP_RECIPE_UPPERCASE|OSP_RECIPE_UPPERCASE_REQUIRED |
				OSP_RECIPE_SPECIAL_REQUIRED
			});

			Assert::IsFalse(recipe.Verified("ab?", 3), L"Required characters missed");
			Assert::IsTrue(recipe.Verified("a3?D", 4), L"Requred not found");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(Recipe_Seperator_Test0)
			TEST_DESCRIPTION("Add seperator")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(Recipe_Seperator_Test0)
		{
			Recipe recipe;

			Assert::IsTrue(recipe.Cleared(), L"Not empty");

			size_t length = (size_t)strnlen(OSP_RECIPE_ALL_SUPPORTED_SPECIALS, 32);

			recipe.Clear();
			recipe.SetSpecials(OSP_RECIPE_ALL_SUPPORTED_SPECIALS, length);
			recipe.SetSeperator(' ');

			Assert::IsFalse(recipe.Cleared(), L"Char set not set");
			Assert::IsFalse(recipe.HasChar(' '), L"Has ' ");
			for (size_t n = 0; n < length; n++)
				Assert::IsTrue(
					recipe.HasChar(OSP_RECIPE_ALL_SUPPORTED_SPECIALS[n]),
					L"Missing supported special"
				);

			recipe.Clear();
			recipe.SetSpecials(OSP_RECIPE_ALL_SUPPORTED_SPECIALS, length);
			recipe.SetSeperator('-');

			Assert::IsFalse(recipe.Cleared(), L"Char set not set");
			Assert::IsTrue(recipe.HasChar('-'), L"Has '-");

			recipe.Clear();
			recipe.SetSeperator(' ');
			recipe.AddFlags(OSP_RECIPE_SPACE_ALLOWED);

			Assert::IsTrue(recipe.GetSeperator() == 0, L"Seperator not removed when part of charset");

			recipe.Clear();
			recipe.AddFlags(OSP_RECIPE_SPACE_ALLOWED);
			recipe.SetSeperator(' ');

			Assert::IsTrue(recipe.GetSeperator() == 0, L"Seperator not removed when part of charset");
		}
	};
}