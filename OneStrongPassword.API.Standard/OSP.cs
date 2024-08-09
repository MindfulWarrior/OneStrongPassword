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

namespace OneStrongPassword.API.Standard
{
    public class OSP
    {
        #region Public Constants, Enums, ans Structures

        public const UInt32 NO_ERROR = 0x00;
        public const UInt32 ERROR_UNKNOWN = 0x01;
        public const UInt32 ERROR_ALREADY_INITIALIZED = 0x02;
        public const UInt32 ERROR_NO_STRONG_PASSWORD_STORED = 0x0C;

        public enum ErrorType
        {
            OSP_No_Error = 0,
            OSP_API_Error = 1,
            OSP_System_Error = 2,
            OSP_NT_Error = 3
        }

        public enum ShowResponse
        {
            Error = 0,
            OK = 1,
            Cancel = 2,
            Abort = 3,
            Retry = 4,
            Ignore = 5,
            Yes = 6,
            No = 7
        }

        public enum ShowType
        {
            OK = 0,
            OKCancel = 1,
            AbortRetryIgnore = 2,
            YesNoCancel = 3,
            YesNo = 4,
            RetryCancel = 5,
            CancelTryContinue = 6
        }

        public struct Error
        {
            public UInt32 Code;
            public ErrorType Type;
        }

        #endregion

        #region Static Private Methods and Structures

        private struct CipherStruct
        {
            public IntPtr Handle;
            public IntPtr Key;
            public uint Size;
        }

        private struct RecipeStruct
        {
            public IntPtr Specials;
            public uint SpecialsLength;
            public UInt32 Flags;
            public byte Seperator;
        }

        private static unsafe void PtrToSecureString(IntPtr buffer, int size, out SecureString str)
        {
            str = new SecureString();
            var ptr = (byte*)buffer.ToPointer();
            for (int n = 0; n < size; n++)
            {
                str.AppendChar((char)*ptr);
                *ptr++ = 0;
            }
            str.MakeReadOnly();
        }

        private static IntPtr ErrorPtr(out Error error)
        {
            error = new OSP.Error
            {
                Code = 0,
                Type = (int)OSP.ErrorType.OSP_No_Error
            };

            var size = Marshal.SizeOf(error);
            var ptr = Marshal.AllocHGlobal(size);
            Marshal.StructureToPtr(error, ptr, false);

            return ptr;
        }

        private static Result ErrorResult(bool success, IntPtr ptr, Error error)
        {
            if (!success && ptr != IntPtr.Zero)
            {
                var structure = (OSP.Error)Marshal.PtrToStructure(ptr, typeof(OSP.Error));
                error.Code = structure.Code;
                error.Type = structure.Type;
            }
            Marshal.FreeHGlobal(ptr);
            return new Result(error);
        }

        private static void CipherToStruct(Cipher cipher, out CipherStruct cipherStruct)
        {
            cipherStruct = new CipherStruct() { Handle = IntPtr.Zero, Key = IntPtr.Zero, Size = 0 };
            if (cipher != null && cipher.Key != null && cipher.Key.Length > 0)
            {
                cipherStruct.Key = Marshal.AllocHGlobal(cipher.Key.Length);
                cipherStruct.Size = (uint)cipher.Key.Length;
                Marshal.Copy(cipher.Key, 0, cipherStruct.Key, cipher.Key.Length);
            }
        }

        private static bool StructToCipher(bool success, ref CipherStruct cipherStruct, ref Cipher cipher)
        {
            if (cipherStruct.Size > 0)
            {
                cipher.Key = new byte[cipherStruct.Size];
                if (cipherStruct.Key != IntPtr.Zero)
                {
                    if (success)
                        Marshal.Copy(cipherStruct.Key, cipher.Key, 0, cipher.Key.Length);
                    Marshal.FreeHGlobal(cipherStruct.Key);
                }
            }
            return success;
        }

        #endregion

        #region Not Used
        [DllImport("ospapi.dll")]
        private static extern uint OSPBlockLength(IntPtr error);

        [DllImport("ospapi.dll")]
        private static extern Int32 OSPCipherPrepared(ref CipherStruct cipher);

        [DllImport("ospapi.dll")]
        private static extern Int32 OSPCipherReady(ref CipherStruct cipher);
        #endregion

        #region Global

        #region SetError
        [DllImport("ospapi.dll")]
        private static extern Int32 OSPSetError(ErrorType type, UInt32 code, IntPtr error);

        public static Result SetError(ErrorType type, UInt32 code, IntPtr error)
        {
            var success = OSPSetError(type, code, error) != 0;
            var result = ErrorResult(success, error, new Error());
            if (error == IntPtr.Zero)
                result = new Result(type, code);
            return result;
        }

        public static Result SetError(ErrorType type, UInt32 code)
        {
            var ptr = ErrorPtr(out OSP.Error error);
            return OSP.SetError(type, code, ptr);
        }
#endregion

        #region Init
        [DllImport("ospapi.dll")]
        private static extern Int32 OSPInit(uint count, uint length, IntPtr error);

        internal static Result Init(uint count, uint length)
        {
            var ptr = ErrorPtr(out Error error);
            var success = OSPInit(count, length, ptr) != 0;
            return ErrorResult(success, ptr, error);
        }
        #endregion

        #region Reset
        [DllImport("ospapi.dll")]
        private static extern Int32 OSPReset(uint count, uint length, IntPtr error);

        internal static Result Reset(uint count, uint length)
        {
            var ptr = ErrorPtr(out OSP.Error error);
            var success = OSPReset(count, length, ptr) != 0;
            return ErrorResult(success, ptr, error);
        }
#endregion

        #region Destroy
        [DllImport("ospapi.dll")]
        private static extern Int32 OSPDestroy(IntPtr error);

        internal static Result Destroy()
        {
            var ptr = ErrorPtr(out OSP.Error error);
            var success = OSPDestroy(ptr) != 0;
            return ErrorResult(success, ptr, error);
        }
#endregion

        #region Destroyed
        [DllImport("ospapi.dll")]
        private static extern Int32 OSPDestroyed();

        internal static bool Destroyed() => OSPDestroyed() != 0;
        #endregion

        #region MinLength
        [DllImport("ospapi.dll")]
        private static extern uint OSPMinLength();

        internal static uint MinLength() => OSPMinLength();
#endregion

        #region MaxLength
        [DllImport("ospapi.dll")]
        private static extern uint OSPMaxLength();

        internal static uint MaxLength() => OSPMaxLength();
#endregion

        #endregion

        #region Cipher

        #region CreateCipher (PrepareCipher, CompleteCipher)
        [DllImport("ospapi.dll")]
        private static extern Int32 OSPPrepareCipher(ref CipherStruct cipher, IntPtr error);

        [DllImport("ospapi.dll")]
        private static extern Int32 OSPCompleteCipher(ref CipherStruct cipher, IntPtr error);

        internal static Cipher CreateCipher(out Result result)
        {
            Cipher cipher = null;
            CipherToStruct(cipher, out CipherStruct cipherStruct);

            var success = false;
            var ptr = ErrorPtr(out OSP.Error error);
            if (OSPPrepareCipher(ref cipherStruct, ptr) != 0)
            {
                cipherStruct.Key = Marshal.AllocHGlobal((int)cipherStruct.Size);
                if (OSPCompleteCipher(ref cipherStruct, ptr) != 0)
                {
                    cipher = new Cipher();
                    success =StructToCipher(true, ref cipherStruct, ref cipher);
                }
            }

            result = ErrorResult(success, ptr, error);
            return cipher;
        }
#endregion

        #region ZeroCipher
        [DllImport("ospapi.dll")]
        private static extern Int32 OSPZeroCipher(ref CipherStruct cipher, IntPtr error);

        internal static Result ZeroCipher(Cipher cipher)
        {
            CipherToStruct(cipher, out CipherStruct cipherStruct);
            var ptr = ErrorPtr(out OSP.Error error);
            var success = OSPZeroCipher(ref cipherStruct, ptr) != 0;
            if (cipherStruct.Key != IntPtr.Zero)
                Marshal.FreeHGlobal(cipherStruct.Key);
            return ErrorResult(success, ptr, error);
        }
#endregion

        #region CipherCompleted
        [DllImport("ospapi.dll")]
        private static extern Int32 OSPCipherCompleted(ref CipherStruct cipher);

        internal static bool CipherCompleted(Cipher cipher)
        {
            CipherToStruct(cipher, out CipherStruct cipherStruct);
            var completed = OSPCipherCompleted(ref cipherStruct) != 0;
            if (cipherStruct.Key != IntPtr.Zero)
                Marshal.FreeHGlobal(cipherStruct.Key);
            return completed;
        }
#endregion

        #region CipherZeroed
        [DllImport("ospapi.dll")]
        private static extern Int32 OSPCipherZeroed(ref CipherStruct cipher);

        internal static bool CipherZeroed(Cipher cipher)
        {
            CipherToStruct(cipher, out CipherStruct cipherStruct);
            var released = OSPCipherZeroed(ref cipherStruct) != 0;
            if (cipherStruct.Key != IntPtr.Zero)
                Marshal.FreeHGlobal(cipherStruct.Key);
            return released;
        }
#endregion

        #endregion

        #region Strong Password

        #region StoreStrongPassword
        [DllImport("ospapi.dll", CharSet = CharSet.Ansi)]
        private static extern Int32 OSPStoreStrongPassword(
	        StringBuilder name, uint nlen, ref CipherStruct cipher, IntPtr password, uint length, IntPtr error
        );

        private static Result StoreStrongPassword(StringBuilder name, Cipher cipher, ref SecureString password)
        {
            CipherToStruct(cipher, out CipherStruct cipherStruct);

            var ptr = ErrorPtr(out OSP.Error error);
            var buffer = Marshal.SecureStringToGlobalAllocAnsi(password);
            var success = OSPStoreStrongPassword(
                name,
                (uint)name.Length,
                ref cipherStruct,
                buffer,
                (uint)password.Length,
                ptr
            ) != 0;

            Marshal.ZeroFreeGlobalAllocAnsi(buffer);
            if (success)
                password.Clear();

            StructToCipher(success, ref cipherStruct, ref cipher);
            return ErrorResult(success, ptr, error);
        }

        internal static Result StoreStrongPassword(string name, Cipher cipher, ref SecureString password)
            => StoreStrongPassword(new StringBuilder(name), cipher, ref password);
#endregion

        #region DispenseStrongPassord
        [DllImport("ospapi.dll", CharSet = CharSet.Ansi)]
        private static extern Int32 OSPDispenseStrongPassword(
	        StringBuilder name, uint nlen, ref CipherStruct cipher, IntPtr password, uint length, IntPtr error
        );

        private static SecureString DispenseStrongPassword(StringBuilder name, ref Cipher cipher, out Result result)
        {
            var size = StrongPasswordSize(name);
            if (size == 0)
            {
                result = new Result(ErrorType.OSP_API_Error, ERROR_NO_STRONG_PASSWORD_STORED);
                return null;
            }

            CipherToStruct(cipher, out CipherStruct cipherStruct);

            var ptr = ErrorPtr(out OSP.Error error);
            var buffer = Marshal.AllocHGlobal((int)size);
            var success = OSPDispenseStrongPassword(name, (uint)name.Length, ref cipherStruct, buffer, size, ptr) != 0;

            SecureString password = null;
            if (success)
                PtrToSecureString(buffer, (int)size, out password);
            Marshal.FreeHGlobal(buffer);
            StructToCipher(success, ref cipherStruct, ref cipher);

            result = ErrorResult(success, ptr, error);
            return password;
        }

        internal static SecureString DispenseStrongPassword(string name, ref Cipher cipher, out Result result)
            => DispenseStrongPassword(new StringBuilder(name), ref cipher, out result);
#endregion

        #region DestroyStrongPassword
        [DllImport("ospapi.dll", CharSet = CharSet.Ansi)]
        private static extern Int32 OSPDestroyStrongPassword(StringBuilder name, uint nlen, IntPtr error);

        private static Result DestroyStrongPassword(StringBuilder name)
        {
            var ptr = ErrorPtr(out OSP.Error error);
            var success = OSPDestroyStrongPassword(name, (uint)name.Length, ptr) != 0;
            return ErrorResult(success, ptr, error);
        }

        internal static Result DestroyStrongPassword(string name)
            => DestroyStrongPassword(new StringBuilder(name));
#endregion

        #region StrongPasswordStart
        [DllImport("ospapi.dll")]
        private static extern Int32 OSPStrongPasswordStart(uint length, IntPtr error);

        internal static Result StrongPasswordStart(uint length)
        {
            var ptr = ErrorPtr(out OSP.Error error);
            var success = OSPStrongPasswordStart(length, ptr) != 0;
            return ErrorResult(success, ptr, error);
        }
#endregion

        #region StrongPasswordPut
        [DllImport("ospapi.dll", CharSet = CharSet.Ansi)]
        private static extern Int32 OSPStrongPasswordPut(byte ch, IntPtr error);

        internal static Result StrongPasswordPut(byte ch)
        {
            var ptr = ErrorPtr(out OSP.Error error);
            var success = OSPStrongPasswordPut(ch, ptr) != 0;
            return ErrorResult(success, ptr, error);
        }
        #endregion

        #region StrongPasswordFinish
        [DllImport("ospapi.dll", CharSet = CharSet.Ansi)]
        private static extern Int32 OSPStrongPasswordFinish(
	        StringBuilder name, uint length, ref CipherStruct cipher, IntPtr error
        );

        private static Result StrongPasswordFinish(StringBuilder name, ref Cipher cipher)
        {
            CipherToStruct(cipher, out CipherStruct cipherStruct);
            var ptr = ErrorPtr(out OSP.Error error);
            var success = OSPStrongPasswordFinish(name, (uint)name.Length, ref cipherStruct, ptr) != 0;
            StructToCipher(success, ref cipherStruct, ref cipher);
            return ErrorResult(success, ptr, error);
        }

        internal static Result StrongPasswordFinish(string name, ref Cipher cipher)
            => StrongPasswordFinish(new StringBuilder(name), ref cipher);
        #endregion

        #region StrongPasswordAbort
        [DllImport("ospapi.dll")]
        private static extern Int32 OSPStrongPasswordAbort(IntPtr error);

        internal static Result StrongPasswordAbort()
        {
            var ptr = ErrorPtr(out OSP.Error error);
            var success = OSPStrongPasswordAbort(ptr) != 0;
            return ErrorResult(success, ptr, error);
        }
        #endregion

        #region ShowStrongPassword
        [DllImport("ospapi.dll", CharSet = CharSet.Ansi)]
        private static extern Int32 OSPShowStrongPassword(
	        StringBuilder name,
            uint nlen,
            ref CipherStruct Cipher,
            uint width,
            StringBuilder title,
            uint tlen,
            UInt32 type,
            IntPtr error
        );

        private static ShowResponse ShowStrongPassword(
            StringBuilder name, ref Cipher cipher, uint width, StringBuilder title, ShowType type, out Result result
        ) {
            CipherToStruct(cipher, out CipherStruct cipherStruct);
            var ptr = ErrorPtr(out OSP.Error error);
            var response = OSPShowStrongPassword(
                name,
                (uint)name.Length,
                ref cipherStruct, 
                width,
                title,
                (uint)title.Length,
                (UInt32)type,
                ptr
            );
            StructToCipher(response != 0, ref cipherStruct, ref cipher);
            result = ErrorResult(response != 0, ptr, error);
            return (ShowResponse)response;
        }

        internal static ShowResponse ShowStrongPassword(
          string name, ref Cipher cipher, uint width, string title, ShowType type, out Result result
        ) => ShowStrongPassword(
            new StringBuilder(name), ref cipher, width, new StringBuilder(title), type, out result
        );
        #endregion

        #region StrongPasswordSize
        [DllImport("ospapi.dll", CharSet = CharSet.Ansi)]
        private static extern uint OSPStrongPasswordSize(StringBuilder name, uint nlen);

        private static uint StrongPasswordSize(StringBuilder name) => OSPStrongPasswordSize(name, (uint)name.Length);

        internal static uint StrongPasswordSize(string name) => StrongPasswordSize(new StringBuilder(name));
        #endregion

        #endregion

        #region Generate Password

        #region GeneratePassword
        [DllImport("ospapi.dll", CharSet = CharSet.Ansi)]
        private static extern Int32 OSPGeneratePassword(
	        StringBuilder name,
	        uint nlen,
	        StringBuilder mnemonic,
	        uint mlen,
	        ref CipherStruct cipher,
	        IntPtr password,
	        uint length,
	        ref RecipeStruct recipe,
	        IntPtr error
        );

        private static SecureString GeneratePassword(
            StringBuilder name,
            StringBuilder mnemonic,
            ref Cipher cipher,
            uint length,
            Recipe recipe,
            out Result result
        ) {
            CipherToStruct(cipher, out CipherStruct cipherStruct);

            var recipeStruct = new RecipeStruct()
            {
                Specials = Marshal.StringToHGlobalAnsi(recipe.Specials),
                SpecialsLength = (uint)recipe.Specials.Length,
                Seperator = recipe.Seperator,
                Flags = recipe.Flags
            };

            var ptr = ErrorPtr(out OSP.Error error);
            var buffer = Marshal.AllocHGlobal((int)length + 1);
            var success = OSPGeneratePassword(
                name,
                (uint)name.Length,
                mnemonic,
                (uint)mnemonic.Length,
                ref cipherStruct,
                buffer,
                length,
                ref recipeStruct,
                ptr
            ) != 0;

            SecureString password = null;
            if (success)
                PtrToSecureString(buffer, (int)length, out password);
            Marshal.FreeHGlobal(recipeStruct.Specials);
            Marshal.FreeHGlobal(buffer);
            StructToCipher(success, ref cipherStruct, ref cipher);

            result = ErrorResult(success, ptr, error);
            return password;
        }

        internal static SecureString GeneratePassword(
            string name, string mnemonic, ref Cipher cipher, uint length, Recipe recipe, out Result result
        ) => GeneratePassword(
            new StringBuilder(name), new StringBuilder(mnemonic), ref cipher, length, recipe, out result
        );
        #endregion

        #region PasswordToClipboard
        [DllImport("ospapi.dll", CharSet = CharSet.Ansi)]
        private static extern Int32 OSPPasswordToClipboard(
	        StringBuilder name,
	        uint nlen,
	        StringBuilder mnemonic,
	        uint mlen,
	        ref CipherStruct cipher,
	        uint length,
	        ref RecipeStruct recipe,
	        IntPtr error
        );

        private static Result PasswordToClipboard(
            StringBuilder name, StringBuilder mnemonic, ref Cipher cipher, uint length, Recipe recipe
        ) {
            CipherToStruct(cipher, out CipherStruct cipherStruct);

            var recipeStruct = new RecipeStruct()
            {
                SpecialsLength = 0,
                Seperator = recipe.Seperator,
                Flags = recipe.Flags
            };

            if (!String.IsNullOrWhiteSpace(recipe.Specials))
            {
                recipeStruct.Specials = Marshal.StringToHGlobalAnsi(recipe.Specials);
                recipeStruct.SpecialsLength = (uint)recipe.Specials.Length;
            }

            var ptr = ErrorPtr(out OSP.Error error);
            var success = OSPPasswordToClipboard(
                name,
                (uint)name.Length,
                mnemonic,
                (uint)mnemonic.Length,
                ref cipherStruct,
                length,
                ref recipeStruct,
                ptr
            ) != 0;

            Marshal.FreeHGlobal(recipeStruct.Specials);

            StructToCipher(success, ref cipherStruct, ref cipher);
            return ErrorResult(success, ptr, error);
        }

        internal static Result PasswordToClipboard(
            string name, string mnemonic, ref Cipher cipher, uint length, Recipe recipe
        ) => PasswordToClipboard(new StringBuilder(name), new StringBuilder(mnemonic), ref cipher, length, recipe);
        #endregion

        #region ShowPassword
        [DllImport("ospapi.dll")]
        private static extern Int32 OSPShowPassword(
	        StringBuilder name,
	        uint nlen,
	        StringBuilder mnemonic,
	        uint mlen,
	        ref CipherStruct cipher,
	        uint length,
	        ref RecipeStruct recipe,
            uint width,
            StringBuilder title,
            uint tlen,
                    UInt32 type,
            IntPtr error
        );

        private static ShowResponse ShowPassword(
            StringBuilder name,
            StringBuilder mnemonic,
            ref Cipher cipher,
            uint length,
            Recipe recipe,
            uint width,
            StringBuilder title,
            ShowType type,
            out Result result
        ) {
            CipherToStruct(cipher, out CipherStruct cipherStruct);

            var recipeStruct = new RecipeStruct()
            {
                Specials = Marshal.StringToHGlobalAnsi(recipe.Specials),
                SpecialsLength = String.IsNullOrEmpty(recipe.Specials) ? 0 : (uint)recipe.Specials.Length,
                Seperator = recipe.Seperator,
                Flags = recipe.Flags
            };

            var ptr = ErrorPtr(out OSP.Error error);
            var response = OSPShowPassword(
                name,
                (uint)name.Length,
                mnemonic,
                (uint)mnemonic.Length,
                ref cipherStruct,
                length,
                ref recipeStruct,
                width,
                title,
                (uint)title.Length,
                (UInt32)type,
                ptr
            );

            Marshal.FreeHGlobal(recipeStruct.Specials);

            StructToCipher(response != 0, ref cipherStruct, ref cipher);
            result = ErrorResult(response != 0, ptr, error);
            return (ShowResponse)response;
        }

        internal static ShowResponse ShowPassword(
            string name,
            string mnemonic,
            ref Cipher cipher,
            uint length,
            Recipe recipe,
            uint width,
            string title,
            ShowType type,
            out Result result
        ) => ShowPassword(
            new StringBuilder(name),
            new StringBuilder(mnemonic),
            ref cipher,
            length,
            recipe,
            width,
            new StringBuilder(title),
            type,
            out result
        );
        #endregion

        #endregion

    }
}
