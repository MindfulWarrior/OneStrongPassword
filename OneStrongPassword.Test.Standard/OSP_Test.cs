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
    public class OSP_Test
    {
        const string pwd = "This is password. Just a stinkin password";
        readonly byte[] PasswordBytesA = Encoding.Convert(Encoding.Unicode, Encoding.ASCII, Encoding.Unicode.GetBytes(pwd));

        SecureString PasswordStringA = new SecureString();

        OSP.Error TestError;
        Result TestResult;

        public OSP_Test()
        {
            foreach (var ch in pwd)
                PasswordStringA.AppendChar(ch);
        }

        void Setup(out Cipher cipher)
        {
            var osp = new PrivateType(typeof(OSP));

            if ((bool)osp.InvokeStatic("Destroyed"))
            {
                uint count = 2;
                uint maxlength = (uint)osp.InvokeStatic("MinLength");

                TestResult = (Result)osp.InvokeStatic("Init", count, maxlength);
                Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "Initialize failed, see OSPDLL_Initialize_Test0");
            }

            var args = new object[] { null };
            cipher = (Cipher)osp.InvokeStatic("CreateCipher", args);

            Assert.AreEqual(OSP.NO_ERROR, ((Result)args[0]).ErrorCode, "Creating a cipher failed, see OSPDLL_Cipher_Test0");
            Assert.IsNotNull(cipher, "Creating a cipher failed, see OSPDLL_Cipher_Test0");
        }

        void SetupAndStore(string name, out Cipher cipher)
        {
            Setup(out cipher);

            var osp = new PrivateType(typeof(OSP));

            var password = PasswordStringA.Copy();
            var storeTypes = new Type[] { typeof(string), typeof(Cipher), typeof(SecureString).MakeByRefType() };
            var storeArgs = new object[] { name, cipher, password };
            var result = (Result)osp.InvokeStatic("StoreStrongPassword", storeTypes, storeArgs);
            Assert.AreEqual(OSP.NO_ERROR, result.ErrorCode, "Store failed");
        }

        void TestPassword(SecureString password)
        {
            Assert.IsTrue(PasswordBytesA.Length <= password.Length, "Wrong Length");

            var ptr = Marshal.SecureStringToGlobalAllocAnsi(password);
            var bytes = new byte[password.Length];
            Marshal.Copy(ptr, bytes, 0, bytes.Length);
            Marshal.ZeroFreeGlobalAllocAnsi(ptr);

            for (int n = 0; n < PasswordBytesA.Length; n++)
                Assert.AreEqual(PasswordBytesA[n], bytes[n]);

            for (int n = PasswordBytesA.Length; n < bytes.Length; n++)
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
            var osp = new PrivateType(typeof(OSP));
            Assert.AreEqual(OSP.NO_ERROR, ((Result)osp.InvokeStatic("Destroy")).ErrorCode, "Failure cleaning up");
            Assert.AreEqual(OSP.NO_ERROR, TestError.Code, "Error occured");
            Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "Error occurred");
        }

        [TestMethod]
        [Description("Confirm error is returned.")]
        public void OSP_Error_Test0()
        {
            TestResult = OSP.SetError(OSP.ErrorType.OSP_API_Error, OSP.ERROR_UNKNOWN, IntPtr.Zero);

            Assert.IsFalse(TestResult.Success, "Should have failed even with null");
            Assert.AreEqual(OSP.ERROR_UNKNOWN, TestResult.ErrorCode, "No error returned");
            Assert.AreEqual(OSP.ErrorType.OSP_API_Error, TestResult.ErrorType, "Wrong type");

            TestResult = OSP.SetError(OSP.ErrorType.OSP_API_Error, OSP.ERROR_UNKNOWN);

            Assert.IsFalse(TestResult.Success, "Should have failed");
            Assert.AreEqual(OSP.ERROR_UNKNOWN, TestResult.ErrorCode, "No error returned");
            Assert.AreEqual(OSP.ErrorType.OSP_API_Error, TestResult.ErrorType, "Wrong type");

            TestResult = OSP.SetError(OSP.ErrorType.OSP_System_Error, 100);

            Assert.IsFalse(TestResult.Success, "Should have failed");
            Assert.AreEqual((UInt32)100, TestResult.ErrorCode, "No error returned");
            Assert.AreEqual(OSP.ErrorType.OSP_System_Error, TestResult.ErrorType, "Wrong type");

            TestResult = OSP.SetError(OSP.ErrorType.OSP_No_Error, OSP.NO_ERROR);

            Assert.IsTrue(TestResult.Success, "Should not have failed");
            Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "Error not reset");
            Assert.AreEqual(OSP.ErrorType.OSP_No_Error, TestResult.ErrorType, "Wrong type");

            TestResult = new Result();
        }

        [TestMethod]
        [Description("Initialize then destroy.")]
        public void OSP_Initialize_Test0()
        {
            var osp = new PrivateType(typeof(OSP));

            uint count = 2;
            uint maxlength = (uint)osp.InvokeStatic("MinLength");

            Assert.IsTrue(maxlength > 0, "Unable to get minimum length");

            TestResult = (Result)osp.InvokeStatic("Init", count, maxlength);

            Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "Initialize failed");
            Assert.AreEqual((UInt32)0, TestError.Code, "Error occured");
            Assert.AreEqual(maxlength, (uint)osp.InvokeStatic("MaxLength"), "Wrong max length");

            TestResult = (Result)osp.InvokeStatic("Destroy");

            Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "Destroy failed");
        }

        [TestMethod]
        [Description("")]
        public void OSP_Reset_Test0()
        {
            var osp = new PrivateType(typeof(OSP));

            uint count = 2;
            uint maxlength = (uint)osp.InvokeStatic("MinLength");

            TestResult = (Result)osp.InvokeStatic("Init", count, maxlength);

            Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "Initialize failed");
            Assert.AreEqual(maxlength, (uint)osp.InvokeStatic("MaxLength"), "Wrong max length");

            TestResult = (Result)osp.InvokeStatic("Reset", count, maxlength * 2);

            Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "Reset failed");
            Assert.AreEqual(maxlength * 2, (uint)osp.InvokeStatic("MaxLength"), "Wrong max length");
        }

        [TestMethod]
        [Description("Store password and destroy.")]
        public void OSP_Store_Destroy_Test0()
        {
            const string name = "test";
            uint length;

            var osp = new PrivateType(typeof(OSP));

            Setup(out Cipher cipher);

            {
                var password = PasswordStringA.Copy();

                var types = new Type[] { typeof(string), typeof(Cipher), typeof(SecureString).MakeByRefType()};
                var objects = new object[] { name, cipher, password };

                TestResult = (Result)osp.InvokeStatic("StoreStrongPassword", types, objects);

                Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "Store failed");
                Assert.AreEqual(0, password.Length, "Data not cleared");
            }

            length = (uint)osp.InvokeStatic("StrongPasswordSize", name);
            Assert.AreEqual((uint)PasswordBytesA.Length, length, "Size not stored");

            TestResult = (Result)osp.InvokeStatic("DestroyStrongPassword", name);
            Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "Destroy failed");

            length = (uint)osp.InvokeStatic("StrongPasswordSize", name);
            Assert.AreEqual((uint)(0), length, "Size not cleared");
        }

        [TestMethod]
        [Description("Store data and dispense.")]
        public void OSP_Store_Dispense_Test0()
        {
            const string name = "test";

            var osp = new PrivateType(typeof(OSP));

            SetupAndStore(name, out Cipher cipher);

            var dispenseArgs = new object[] { name, cipher, null };
            var password = (SecureString)osp.InvokeStatic("DispenseStrongPassword", dispenseArgs);

            TestResult = (Result)dispenseArgs[2];
            Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "Dispense failed");

            TestPassword(password);
        }

        [TestMethod]
        [Description("Add strong password one key at a time.")]
        public void OSP_Start_Finish_Test0()
        {
            const string name = "test";

            var osp = new PrivateType(typeof(OSP));

            Setup(out Cipher cipher);

            TestResult = (Result)osp.InvokeStatic("StrongPasswordStart", (uint)PasswordBytesA.Length);
            Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "Could not start strong password.");

            for (uint n = 0; TestResult.Success && n < PasswordBytesA.Length; n++)
            {
                TestResult = (Result)osp.InvokeStatic("StrongPasswordPut", PasswordBytesA[n]);
                Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "Failure adding to strong password.");
            }

            var finishTypes = new Type[] { typeof(string), typeof(Cipher).MakeByRefType() };
            var finishArgs = new object[] { name, cipher };

            TestResult = (Result)osp.InvokeStatic("StrongPasswordFinish", finishTypes, finishArgs);
            Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "Could not finish strong password.");

            var dispenseArgs = new object[] { name, cipher, null };
            var password = (SecureString)osp.InvokeStatic("DispenseStrongPassword", dispenseArgs);

            TestResult = (Result)dispenseArgs[2];
            Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "Dispense failed");

            TestPassword(password);
        }

        [TestMethod]
        [Description("Abort adding strong password.")]
        public void OSP_Start_Abort_Test0()
        {
            const string name = "test";

            var osp = new PrivateType(typeof(OSP));

            Setup(out Cipher cipher);

            TestResult = (Result)osp.InvokeStatic("StrongPasswordStart", (uint)PasswordBytesA.Length);
            Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "Could not start strong password.");
            for (uint n = 0; TestResult.Success && n < PasswordBytesA.Length; n++)

            {
                TestResult = (Result)osp.InvokeStatic("StrongPasswordPut", PasswordBytesA[n]);
                Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "Failure adding to strong password.");
            }

            TestResult = (Result)osp.InvokeStatic("StrongPasswordAbort");
            Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "Could not abort strong password.");

            var dispenseArgs = new object[] { name, cipher, null };
            var password = osp.InvokeStatic("DispenseStrongPassword", dispenseArgs);

            TestResult = (Result)dispenseArgs[2];
            Assert.AreEqual(OSP.ERROR_NO_STRONG_PASSWORD_STORED, TestResult.ErrorCode, "Dispense failed");
            Assert.IsNull(password, "Password should not have been stored");

            TestResult = new Result();
        }

        [TestMethod]
        [Description("Generate small password with mnemonic.")]
        //[Ignore]
        public void OSP_Generate_Test0()
        {
            const string name = "test";

            var osp = new PrivateType(typeof(OSP));

            SetupAndStore(name, out Cipher cipher);

            var receipe = new Recipe()
            {
                Specials = Recipe.AllSupportedSpecials,
                Flags = (UInt32)Recipe.RecipeFlag.Alphanumeric,
                Seperator = 0
            };

            const string mnemonic = "stinkin";

            var genArgs = new object[] { name, mnemonic, cipher, (uint)8, receipe, null };
            var gen = (SecureString)osp.InvokeStatic("GeneratePassword", genArgs);

            TestResult = (Result)genArgs[5];
            Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "GeneratePassword failed");
            Assert.IsNotNull(gen, "GeneratePassword failed");
            Assert.IsTrue(gen.Length == 8, "Password not the right length");
        }

        [TestMethod]
        [Description("Generate password to clipboard.")]
        public void OSP_Clipboard_Test0()
        {
            bool success = true;

            const string name = "test";

            var osp = new PrivateType(typeof(OSP));

            SetupAndStore(name, out Cipher cipher);

            var receipe = new Recipe()
            {
                Specials = Recipe.AllSupportedSpecials,
                Flags = (UInt32)Recipe.RecipeFlag.Alphanumeric,
                Seperator = 0
            };

            const string mnemonic = "stinkin";

            var genTypes = new Type[] {
                typeof(string),
                typeof(string),
                typeof(Cipher).MakeByRefType(),
                typeof(uint),
                typeof(Recipe)
            };

            var genArgs = new object[] { name, mnemonic, cipher, (uint)8, receipe };

            TestResult = (Result)osp.InvokeStatic("PasswordToClipboard", genTypes, genArgs);
            Assert.AreEqual(OSP.NO_ERROR, TestResult.ErrorCode, "PasswordToClipboard failed");
            Assert.IsTrue(success, "PasswordToClipboard failed");

            var gen = Clipboard.GetText();

            Assert.IsTrue(gen.Length == 8, "Password not the right length");
        }
    }
}
