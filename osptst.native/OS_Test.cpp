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
	TEST_CLASS(OS_Test)
	{
	public:
		OSPError TestError;

		TEST_METHOD_CLEANUP(MethodCleanup)
		{
			Assert::AreEqual(TestError.Code, OSP_NO_ERROR, L"There was an undected error");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(OS_Zero_Test0)
			TEST_DESCRIPTION(L"Zero then Zeroed")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(OS_Zero_Test0)
		{
			OS::byte data[] = { 1, 2, 3, 4, 5, 6, 7, 9 };

			Assert::IsFalse(OS::Zeroed(data, sizeof(data)), L"Non-zeroed array tested as zeroed");

			OS::Zero(data, sizeof(data));

			for (int n = 0; n < sizeof(data); n++)
				Assert::AreEqual(OS::byte(0), data[n], L"Datat not cleared");

			Assert::IsTrue(OS::Zeroed(data, sizeof(data)), L"Array not as zeroed");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(OS_Intialize_Destroy_Test0)
			TEST_DESCRIPTION(L"Initialize then Destroy")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(OS_Intialize_Destroy_Test0)
		{
			const size_t count = 2;
			const size_t maxsize = 8;

			OS os;

			Assert::AreEqual(size_t(0), os.MaxDataSize(), L"Wrong maxsize");
			Assert::AreEqual(size_t(0), os.AvailableMemory(), L"Wrong available memory");

			bool success = os.Initialize(count, maxsize, &TestError);

			Assert::IsTrue(success, L"Initialize failed");
			Assert::AreEqual(maxsize, os.MaxDataSize(), L"Wrong maxsize");
			Assert::AreEqual(count*maxsize, os.AvailableMemory(), L"Wrong available memory");

			for (int n = 0; n < count*2; n++)
			{
				os.Alloc(maxsize / 2, &TestError);
				Assert::AreEqual((count*maxsize - (n + 1)*maxsize/2), os.AvailableMemory(), L"Memory not allocated");
			}

			success = os.Destroy(&TestError);

			Assert::IsTrue(success, L"Destroy() failed");
			Assert::AreEqual(size_t(0), os.AvailableMemory(), L"Wrong available memory");
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(OS_Reset_Test0)
			TEST_DESCRIPTION(L"Reset and Alloc")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(OS_Reset_Test0)
		{
			const size_t count = 2;
			const size_t maxsize = 8;

			OS os;

			bool success = os.Reset(count, maxsize, &TestError);

			Assert::IsTrue(success, L"Reset failed");
			Assert::AreEqual(maxsize, os.MaxDataSize(), L"Wrong maxsize");
			Assert::AreEqual(count*maxsize, os.AvailableMemory(), L"Wrong available memory");

			for (int n = 0; n < count*2; n++)
			{
				os.Alloc(maxsize / 2, &TestError);
				Assert::AreEqual((count*maxsize - (n + 1)*maxsize/2), os.AvailableMemory(), L"Memory not allocated");
			}
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(OS_Reset_Test1)
			TEST_DESCRIPTION(L"Initialize, Reset and Alloc")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(OS_Reset_Test1)
		{
			const size_t count = 2;
			const size_t maxsize = 8;

			OS os;
			os.Initialize(count, maxsize, &TestError);

			bool success = os.Reset(count *2, maxsize*2, &TestError);

			Assert::IsTrue(success, L"Reset failed");
			Assert::AreEqual(maxsize*2, os.MaxDataSize(), L"Wrong maxsize");
			Assert::AreEqual(count*maxsize*4, os.AvailableMemory(), L"Wrong available memory");

			for (int n = 0; n < count*4; n++)
			{ 
				os.Alloc(maxsize / 2, &TestError);
				Assert::AreEqual((count*maxsize*4 - (n + 1)*maxsize/2), os.AvailableMemory(), L"Memory not allocated");
			}
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(OS_Alloc_Destroy_Test0)
			TEST_DESCRIPTION(L"Alloc and Destroy in a loop")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(OS_Alloc_Destroy_Test0)
		{
			const size_t count = 2;
			const size_t maxsize = 8;

			OS os;
			os.Initialize(count, maxsize, &TestError);

			size_t alloc = maxsize / 2;
			for (int n = 0; n < 100; n++)
			{
				OS::byte* ptr = os.Alloc(alloc, &TestError);
				Assert::AreEqual(count*maxsize - alloc, os.AvailableMemory(), L"Memory not allocated");

				os.Destroy(ptr, alloc, &TestError);
				Assert::AreEqual(count*maxsize, os.AvailableMemory(), L"Memory not freed");
			}
		}

		BEGIN_TEST_METHOD_ATTRIBUTE(OS_Alloc_Destroy_Test1)
			TEST_DESCRIPTION(L"Alloc in a loop and Destroy in a loop")
		END_TEST_METHOD_ATTRIBUTE()

		TEST_METHOD(OS_Alloc_Destroy_Test1)
		{
			const size_t maxsize = 512;
			const size_t count = 128; // OS::MAX_HEAP_SIZE / maxsize;

			OS os;
			bool success = os.Initialize(count, maxsize, &TestError);
			Assert::IsTrue(success, L"Initialize failed");

			std::stack<OS::byte*> ptrs;

			Logger::WriteMessage("Allocating");
			for (int n = 1; n <= count; n++)
			{
				Logger::WriteMessage((" " + std::to_string(n)).c_str());
				OS::byte* ptr = os.Alloc(maxsize, &TestError);
				Assert::AreEqual((count - n)*maxsize, os.AvailableMemory(), L"Memory not allocated");
				ptrs.push(ptr);
			}
			Logger::WriteMessage("\n");

			Logger::WriteMessage("Destroying");
			for (int n = 1; n <= count; n++)
			{
				Logger::WriteMessage((" " + std::to_string(n)).c_str());
				os.Destroy(ptrs.top(), maxsize, &TestError);
				Assert::AreEqual(n*maxsize, os.AvailableMemory(), L"Memory not freed");
				ptrs.pop();
			}
			Logger::WriteMessage("\n");
		}
	};
}