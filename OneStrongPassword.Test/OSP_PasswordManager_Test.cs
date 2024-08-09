/*
One Strong Password

Copyright(c) Robert Richard Flores. (MIT License)

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files(the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions :
-The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.
- The Software is provided "as is", without warranty of any kind, express or
implied, including but not limited to the warranties of merchantability,
fitness for a particular purpose and noninfringement.In no event shall the
authors or copyright holders be liable for any claim, damages or other
liability, whether in an action of contract, tort or otherwise, arising from,
out of or in connection with the Software or the use or other dealings in the
Software.
*/

using Microsoft.VisualStudio.TestTools.UnitTesting;
using OneStrongPassword.API.Standard;

namespace OneStrongPassword.Test.Standard
{
    [TestClass]
    public class OSP_PasswordManager_Test
    {
        Result TestResult;

        [TestCleanup]
        public void TestCleanup()
        {
            Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "Error occurred");
        }

        [TestMethod]
        [Description("Open then close.")]
        public void OSP_PasswordManager_Open_Close_Test0()
        {
            uint count = 2;
            uint maxlength = PasswordManager.MinLength;

            Assert.IsTrue(maxlength > 0, "Unable to get minimum length");

            var manager = PasswordManager.Open(count, maxlength, out TestResult);

            Assert.IsNotNull(manager, "Open failed");
            Assert.AreEqual(maxlength, manager.MaxLength, "Wrong max length");
            Assert.IsFalse(manager.Closed, "Open showing as clossed");

            TestResult = manager.Close();

            Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "Close failed");
            Assert.IsTrue(manager.Closed, "Closed showing as opened");
        }

        [TestMethod]
        [Description("Open and close with using.")]
        public void OSP_PasswordManager_Open_Close_Test1()
        {
            uint count = 2;
            uint maxlength = PasswordManager.MinLength;

            using (var manager = PasswordManager.Open(count, maxlength, out TestResult))
            {
                Assert.IsNotNull(manager, "Open failed");
                Assert.AreEqual(maxlength, manager.MaxLength, "Wrong max length");
                Assert.IsFalse(manager.Closed, "Open showing as clossed");

                TestResult = manager.Close();

                Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "Close failed");
                Assert.IsTrue(manager.Closed, "Closed showing as opened");
            }
        }

        [TestMethod]
        [Description("Open and implicit close from using.")]
        public void OSP_PasswordManager_Open_Close_Test2()
        {
            uint count = 2;
            uint maxlength = PasswordManager.MinLength;

            PasswordManager manager;

            using (manager = PasswordManager.Open(count, maxlength, out TestResult))
            {
                Assert.IsNotNull(manager, "Open failed");
                Assert.AreEqual(maxlength, manager.MaxLength, "Wrong max length");
                Assert.IsFalse(manager.Closed, "Open showing as clossed");
            }

            Assert.IsTrue(manager.Closed, "Closed showing as opened");
        }

        [TestMethod]
        [Description("Open twice, close, open, close.")]
        public void OSP_PasswordManager_Open_Close_Test3()
        {
            uint count = 2;
            uint maxlength = PasswordManager.MinLength;

            var manager0 = PasswordManager.Open(count, maxlength, out TestResult);
            Assert.IsNotNull(manager0, "1st Open failed");

            var manager1 = PasswordManager.Open(count, maxlength, out TestResult);
            Assert.IsNull(manager1, "2nd Open should have failed failed");
            Assert.AreNotEqual(OSP.NO_ERROR, TestResult.ErrorCode, "Error never returned");

            TestResult = manager0.Close();
            Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "Close failed");

            manager1 = PasswordManager.Open(count, maxlength, out TestResult);
            Assert.IsNotNull(manager0, "Open after Close failed");

            TestResult = manager1.Close();
            Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "Close failed");
        }

        [TestMethod]
        [Description("Open, reopen, close")]
        public void OSP_Reopen_Test0()
        {
            uint count = 2;
            uint maxlength = PasswordManager.MinLength;

            using (var manager = PasswordManager.Open(count, maxlength, out TestResult))
            {
                Assert.IsNotNull(manager, "Open failed");

                TestResult = manager.Reopen(count, maxlength * 2);

                Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "Reset failed");
                Assert.AreEqual(maxlength * 2, manager.MaxLength, "Wrong max length");
            }
        }
    }
}
