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
    public class OSP_Cipher_Test
    {
        Result TestResult;

        [TestCleanup]
        public void TestCleanup()
        {
            Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "Error occurred");
        }

        [TestMethod]
        [Description("Create and Destroy Cipher")]
        public void OSP_Cipher_Test0()
        {
            using (var manager = PasswordManager.Open(0, 0, out TestResult))
            {
                var cipher = manager.Cipher(out TestResult);

                Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "CreateCipher failed");
                Assert.IsNotNull(cipher, "CreateCipher failed");
                Assert.IsFalse(cipher.Detroyed(), "Cipher is destroyed");
                Assert.IsTrue(cipher.Completed(), "Cipher not completed");

                TestResult = cipher.Destroy();

                Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "Zero cipher failed");
                Assert.IsTrue(cipher.Detroyed(), "Cipher not destroyed");
                Assert.IsFalse(cipher.Completed(), "Cipher still complete");
            }
        }

        [TestMethod]
        [Description("Create and Destroy Cipher with using")]
        public void OSP_Cipher_Test1()
        {
            using (var manager = PasswordManager.Open(0, 0, out TestResult))
            {
                using (var cipher = manager.Cipher(out TestResult))
                {
                    Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "CreateCipher failed");
                    Assert.IsNotNull(cipher, "CreateCipher failed");
                    Assert.IsFalse(cipher.Detroyed(), "Cipher is destroyed");
                    Assert.IsTrue(cipher.Completed(), "Cipher not completed");

                    TestResult = cipher.Destroy();

                    Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "Zero cipher failed");
                    Assert.IsTrue(cipher.Detroyed(), "Cipher not destroyed");
                    Assert.IsFalse(cipher.Completed(), "Cipher still complete");
                }
            }
        }

        [TestMethod]
        [Description("Create Cipher and implicit Destroy with using")]
        public void OSP_Cipher_Test2()
        {
            using (var manager = PasswordManager.Open(0, 0, out TestResult))
            {
                Cipher cipher;

                using (cipher = manager.Cipher(out TestResult))
                {
                    Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "CreateCipher failed");
                    Assert.IsNotNull(cipher, "CreateCipher failed");
                    Assert.IsFalse(cipher.Detroyed(), "Cipher is destroyed");
                    Assert.IsTrue(cipher.Completed(), "Cipher not completed");
                }

                Assert.IsTrue(cipher.Detroyed(), "Cipher not destroyed");
                Assert.IsFalse(cipher.Completed(), "Cipher still complete");
            }
        }
    }
}
