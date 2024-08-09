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

using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Windows.Forms;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using OneStrongPassword.API.Standard;

namespace OneStrongPassword.Test.Standard
{
    [TestClass]
    public class OSP_StrongPassword_Test
    {
        const string pwd = "This is password. Just a stinkin password";

        readonly byte[] PasswordBytes = Encoding.Convert(
             Encoding.Unicode,
             Encoding.ASCII,
             Encoding.Unicode.GetBytes("This is password. Just a stinkin password")
        );

        SecureString Password = new SecureString();

        OSP.Error TestError;
        Result TestResult;

        public OSP_StrongPassword_Test()
        {
            foreach (var ch in pwd)
                Password.AppendChar(ch);
        }

        void TestPassword(SecureString password)
        {
            Assert.IsTrue(Password.Length <= password.Length, "Wrong Length");

            var ptr = Marshal.SecureStringToGlobalAllocAnsi(password);
            var bytes = new byte[password.Length];
            Marshal.Copy(ptr, bytes, 0, bytes.Length);
            Marshal.ZeroFreeGlobalAllocAnsi(ptr);

            for (int n = 0; n < PasswordBytes.Length; n++)
                Assert.AreEqual(PasswordBytes[n], bytes[n]);

            for (int n = PasswordBytes.Length; n < bytes.Length; n++)
                Assert.AreEqual(0, bytes[n], "Password is wrong");
        }

        [TestInitialize]
        public void TestInitialize()
        {
            TestError.Code = 0;
            TestError.Type = (int)OSP.ErrorType.OSP_No_Error;
        }

        [TestCleanup]
        public void TestCleanup()
        {
            Assert.AreEqual((UInt32)0, TestError.Code, "Error occured");
            Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "Error occurred");
        }

        [TestMethod]
        [Description("Store password and destroy.")]
        public void OSP_StrongPassword_Store_Destroy_Test0()
        {
            const string name = "test";

            using (var manager = PasswordManager.Open(1, PasswordManager.MinLength, out TestResult))
            {
                var password = Password.Copy();
                var strong = manager.StrongPassword(name);

                TestResult = strong.Store(ref password);

                Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "Store failed");
                Assert.AreEqual(0, password.Length, "Data not cleared");
                Assert.AreEqual((uint)Password.Length, strong.Length, "Size not stored");

                TestResult = strong.Destroy();

                Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "Destroy failed");
                Assert.AreEqual((uint)(0), strong.Length, "Size not cleared");
            }
        }

        [TestMethod]
        [Description("Store password and destroy with using.")]
        public void OSP_StrongPassword_Store_Destroy_Test1()
        {
            const string name = "test";

            using (var manager = PasswordManager.Open(1, PasswordManager.MinLength, out TestResult))
            {
                using (var strong = manager.StrongPassword(name))
                {
                    var password = Password.Copy();

                    TestResult = strong.Store(ref password);

                    Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "Store failed");
                    Assert.AreEqual(0, password.Length, "Data not cleared");
                    Assert.AreEqual((uint)Password.Length, strong.Length, "Size not stored");

                    TestResult = strong.Destroy();

                    Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "Destroy failed");
                    Assert.AreEqual((uint)(0), strong.Length, "Size not cleared");
                }
            }
        }

        [TestMethod]
        [Description("Store password and implicit destroy with using.")]
        public void OSP_StrongPassword_Store_Destroy_Test2()
        {
            const string name = "test";

            using (var manager = PasswordManager.Open(1, PasswordManager.MinLength, out TestResult))
            {
                StrongPassword strong;

                using (strong = manager.StrongPassword(name))
                {
                    var password = Password.Copy();

                    TestResult = strong.Store(ref password);

                    Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "Store failed");
                    Assert.AreEqual(0, password.Length, "Data not cleared");
                    Assert.AreEqual((uint)Password.Length, strong.Length, "Size not stored");
                }

                Assert.AreEqual((uint)(0), strong.Length, "Size not cleared");
            }
        }

        [TestMethod]
        [Description("Store data and dispense.")]
        public void OSP_StrongPassword_Store_Dispense_Test0()
        {
            const string name = "test";

            using (var manager = PasswordManager.Open(1, PasswordManager.MinLength, out TestResult))
            {
                using (var strong = manager.StrongPassword(name))
                {
                    SecureString password;

                    password = Password.Copy();
                    TestResult = strong.Store(ref password);
                    Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "Store failed");

                    password = strong.Dispense(out TestResult);
                    Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "Dispense failed");

                    TestPassword(password);
                }
            }
        }

        [TestMethod]
        [Description("Add strong password one key at a time.")]
        public void OSP_StrongPassword_Start_Finish_Test0()
        {
            const string name = "test";

            using (var manager = PasswordManager.Open(1, PasswordManager.MinLength, out TestResult))
            {
                using (var strong = manager.StrongPassword(name))
                {
                    TestResult = strong.StartInput((uint)Password.Length);
                    Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "Could not start strong password.");

                    foreach (var ch in PasswordBytes)
                    {
                        TestResult = strong.Put(ch);
                        Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "Failure adding to strong password.");
                    }

                    TestResult = strong.FinishInput();
                    Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "Could not finish strong password.");

                    var password = strong.Dispense(out TestResult);
                    Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "Dispense failed");

                    TestPassword(password);
                }
            }
        }

        [TestMethod]
        [Description("Abort adding strong password.")]
        public void OSP_StrongPassword_Start_Abort_Test0()
        {
            const string name = "test";

            using (var manager = PasswordManager.Open(1, PasswordManager.MinLength, out TestResult))
            {
                using (var strong = manager.StrongPassword(name))
                {
                    TestResult = strong.StartInput((uint)Password.Length);
                    for (uint n = 0; TestResult.Success && n < PasswordBytes.Length; n++)
                        TestResult = strong.Put(PasswordBytes[n]);
                    Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "Error entering password.");

                    TestResult = strong.AbortInput();
                    Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "Could not finish strong password.");

                    var password = strong.Dispense(out TestResult);
                    Assert.AreEqual(OSP.ERROR_NO_STRONG_PASSWORD_STORED, TestResult.ErrorCode, "Dispense failed");
                    Assert.IsNull(password, "Password should not have been stored");

                    TestResult = new Result();
                }
            }
        }

        [TestMethod]
        [Description("Generate small password with mnemonic.")]
        public void OSP_StrongPassword_Generate_Test0()
        {
            const string name = "test";

            var osp = new PrivateType(typeof(OSP));

            var receipe = new Recipe()
            {
                Specials = Recipe.AllSupportedSpecials,
                Flags = (UInt32)Recipe.RecipeFlag.Alphanumeric,
                Seperator = 0
            };

            const string mnemonic = "stinkin";

            using (var manager = PasswordManager.Open(1, PasswordManager.MinLength, out TestResult))
            {
                using (var strong = manager.StrongPassword(name))
                {
                    TestResult = strong.StartInput((uint)Password.Length);
                    for (uint n = 0; TestResult.Success && n < PasswordBytes.Length; n++)
                        TestResult = strong.Put(PasswordBytes[n]);
                    Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "Error entering password.");

                    if (TestResult.Success)
                        TestResult = strong.FinishInput();
                    else
                        strong.AbortInput();

                    Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "Could not finish strong password.");

                    var gen = strong.GeneratePassword(mnemonic, 8, receipe, out TestResult);
                    Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "GeneratePassword failed");
                    Assert.IsNotNull(gen, "GeneratePassword failed");
                    Assert.IsTrue(gen.Length == 8, "Password not the right length");
                }
            }
        }

        [TestMethod]
        [Description("Generate password to clipboard.")]
        public void OSP_StrongPassword_Clipboard_Test0()
        {
            const string name = "test";

            var receipe = new Recipe()
            {
                Specials = Recipe.AllSupportedSpecials,
                Flags = (UInt32)Recipe.RecipeFlag.Alphanumeric,
                Seperator = 0
            };

            const string mnemonic = "stinkin";

            using (var manager = PasswordManager.Open(1, PasswordManager.MinLength, out TestResult))
            {
                using (var strong = manager.StrongPassword(name))
                {
                    TestResult = strong.StartInput((uint)Password.Length);
                    for (uint n = 0; TestResult.Success && n < PasswordBytes.Length; n++)
                        TestResult = strong.Put(PasswordBytes[n]);
                    Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "Error entering password.");

                    if (TestResult.Success)
                        TestResult = strong.FinishInput();
                    else
                        strong.AbortInput();

                    Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "Could not finish strong password.");

                    TestResult = strong.PasswordToClipboard(mnemonic, 8, receipe);
                    Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "PasswordToClipboard failed");
                    Assert.IsTrue(Clipboard.ContainsText(TextDataFormat.Text), "Text not in clipboard");

                    var gen0 = Clipboard.GetText(TextDataFormat.Text);
                    Assert.IsTrue(gen0.Length == 8, "Password not the right length");

                    Clipboard.Clear();

                    TestResult = strong.PasswordToClipboard(mnemonic, 8, receipe);
                    Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "PasswordToClipboard failed");
                    Assert.IsTrue(Clipboard.ContainsText(TextDataFormat.Text), "Text not in clipboard");

                    var gen1 = Clipboard.GetText(TextDataFormat.Text);
                    Assert.IsTrue(gen1.Length == 8, "Password not the right length");

                    Assert.IsTrue(gen0.CompareTo(gen1) == 0, "Passwords are different");
                }
            }
        }
    }
}
