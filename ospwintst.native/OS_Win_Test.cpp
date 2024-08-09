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

#include "../osp/os.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace OneStrongPassword
{		
	TEST_CLASS(OS_Win_Test)
	{
	public:
		OSPError TestError;

		TEST_METHOD_CLEANUP(MethodCleanup)
		{
			Assert::AreEqual(TestError.Code, OSP_NO_ERROR, L"There was an undected error");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(OS_Clipboard_Test0)
			TEST_DESCRIPTION(L"Copy to and Paste from clipboard")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(OS_Clipboard_Test0)
		{
			bool success;

			char test[] = "test";

			success = OS::CopyToClipboard(test, sizeof(test), &TestError);

			Assert::IsTrue(success, L"Copy to clipboard failed");
			Assert::IsTrue(OS::Zeroed((OS::byte* const)test, sizeof(test)), L"Data not zeroed");

			char pasted[sizeof(test)];

			success = OS::PasteFromClipboard(pasted, sizeof(pasted), &TestError);

			Assert::IsTrue(success, L"Paste clipboard failed");
			Assert::IsFalse(OS::Zeroed((OS::byte* const)pasted, sizeof(test)), L"No data returned");
			Assert::IsTrue(strncmp("test", pasted, sizeof(pasted)) == 0, L"Wrong data returned");
		}
	};
}