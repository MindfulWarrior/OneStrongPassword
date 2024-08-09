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
using System.Security;

namespace OneStrongPassword.API.Standard
{
    public class StrongPassword : IDisposable
    {
        internal StrongPassword(string name)
        {
            Name = name;
            Started = false;
        }

        internal Cipher Cipher;

        public string Name { get; set; }
        public uint Length => OSP.StrongPasswordSize(Name);
        public uint MaxLength => OSP.MaxLength();

        public bool Started { get; private set; }

        public Result Store(ref SecureString password) => OSP.StoreStrongPassword(Name, Cipher, ref password);

        public SecureString Dispense()
            => OSP.DispenseStrongPassword(Name, ref Cipher, out Result result);
        public SecureString Dispense(out Result result)
            => OSP.DispenseStrongPassword(Name, ref Cipher, out result);

        public OSP.ShowResponse ShowStrongPassword(uint width, string title = null, OSP.ShowType type = OSP.ShowType.OK)
            => OSP.ShowStrongPassword(Name, ref Cipher, width, title, type, out Result result);
        public OSP.ShowResponse ShowStrongPassword(uint width, string title, OSP.ShowType type, out Result result)
            => OSP.ShowStrongPassword(Name, ref Cipher, width, title, type, out result);

        public Result Destroy()
        {
            var result0 = OSP.DestroyStrongPassword(Name);
            var result1 = Cipher.Destroy();
            return result0.Success ? result1 : result0;
        }

        public void Dispose() => Destroy();

        public Result StartInput(uint length)
        {
            var result = OSP.StrongPasswordStart(length);
            Started = result.Success;
            return result;
        }

        public Result Put(byte ch) => OSP.StrongPasswordPut(ch);

        public Result FinishInput()
        {
            var result = OSP.StrongPasswordFinish(Name, ref Cipher);
            Started = !result.Success;
            return result;
        }

        public Result AbortInput()
        {
            var result = OSP.StrongPasswordAbort();
            Started = !result.Success;
            return result;
        }

        public SecureString GeneratePassword(string mnemonic, uint length, Recipe recipe)
            => OSP.GeneratePassword(Name, mnemonic, ref Cipher, length, recipe, out Result result);

        public SecureString GeneratePassword(string mnemonic, uint length, Recipe recipe, out Result result)
            => OSP.GeneratePassword(Name, mnemonic, ref Cipher, length, recipe, out result);

        public Result PasswordToClipboard(string mnemonic, uint length, Recipe recipe)
            => OSP.PasswordToClipboard(Name, mnemonic, ref Cipher, length, recipe);

        public OSP.ShowResponse ShowPassword(
            string mnemonic,
            uint length,
            Recipe recipe,
            uint width,
            string title = null,
            OSP.ShowType type = OSP.ShowType.OK
        ) => OSP.ShowPassword(Name, mnemonic, ref Cipher, length, recipe, width, title, type, out Result result);

        public OSP.ShowResponse ShowPassword(
            string mnemonic, uint length, Recipe recipe, uint width, string title, OSP.ShowType type, out Result result
        ) => OSP.ShowPassword(Name, mnemonic, ref Cipher, length, recipe, width, title, type, out result);

        public bool PutKey(int key)
        {
            if (key > 127)
                return false;

            char ch = (char)key;

            if (
                   Char.IsLetterOrDigit(ch)
                || Char.IsSymbol(ch)
                || Char.IsPunctuation(ch)
                || Char.IsSeparator(ch)
            )
                return true;

            return ch == '\b';
        }

        public int KeyPress(int key, out Result result)
        {
            result = new Result();
            if (PutKey(key))
            {
                if (!Started)
                    result = StartInput(MaxLength);

                if (result.Success && Put((byte)key).Success)
                    return key == '\b' ? -1 : 1;
            }
            return 0;
        }
    }
}
