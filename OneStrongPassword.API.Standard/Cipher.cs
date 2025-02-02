﻿/*
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
    public class Cipher : IDisposable
    {
        internal Cipher() { Key = null; }

        internal byte[] Key { get; set; }

        private void DestroyKey()
        {
            if (Key != null)
            {
                for (int n = 0; n < Key.Length; n++)
                    Key[n] = 0;
                Key = null;
            }
        }

        public bool Completed() => OSP.CipherCompleted(this);
        public bool Detroyed() => Key == null && OSP.CipherZeroed(this);

        public Result Destroy()
        {
            var result = OSP.ZeroCipher(this);
            if (result.Success)
                DestroyKey();
            return result;
        }

        public void Dispose() => Destroy();
    }
}
