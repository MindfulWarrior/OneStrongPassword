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

namespace OneStrongPassword.API.Standard
{
    public class PasswordManager : IDisposable
    {
        private static PasswordManager theManager = new PasswordManager();

        public static uint MinLength => OSP.MinLength();

        public static PasswordManager Open(uint count, uint length)
        {
            if (theManager.Closed)
            {
                if (OSP.Init(count, length).Success)
                    return theManager;
                return null;
            }
            return null;
        }

        public static PasswordManager Open(uint count, uint length, out Result result)
        {
            if (theManager.Closed)
            {
                result = OSP.Init(count, length);
                if (result.Success)
                    return theManager;
                return null;
            }

            result = new Result(OSP.ErrorType.OSP_API_Error, OSP.ERROR_ALREADY_INITIALIZED);
            return null;
        }

        private PasswordManager() { }

        public uint MaxLength => OSP.MaxLength();

        public bool Closed => OSP.Destroyed();

        public Result Close() => OSP.Destroy();
        public Result Reopen(uint count, uint maxLength) => OSP.Reset(count, maxLength);

        public Cipher Cipher() => OSP.CreateCipher(out Result result);
        public Cipher Cipher(out Result result) => OSP.CreateCipher(out result);

        public StrongPassword StrongPassword(string name)
        {
            var strong = new StrongPassword(name);
            strong.Cipher = Cipher();
            return strong;
        }

        public StrongPassword StrongPassword(string name, out Result result)
        {
            var strong = new StrongPassword(name);
            strong.Cipher = Cipher(out result);
            return strong;
        }

        public void Dispose() => Close();
    }
}
