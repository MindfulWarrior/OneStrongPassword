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
    public class Result
    {
        public class Exception : System.Exception
        {
            public Exception(Result result) => Result = result;
            public Result Result { get; private set; }
        }

        private readonly OSP.Error error;

        public Result() => error = new OSP.Error() { Code = OSP.NO_ERROR, Type = OSP.ErrorType.OSP_No_Error };
        public Result(OSP.Error error) => this.error = new OSP.Error() { Code = error.Code, Type = error.Type };
        public Result(OSP.ErrorType type, UInt32 code) => error = new OSP.Error() { Code = code, Type = type };

        public OSP.ErrorType ErrorType => error.Type;
        public UInt32 ErrorCode => error.Code;
        public bool Success => (ErrorCode == OSP.NO_ERROR && ErrorType == OSP.ErrorType.OSP_No_Error);
        public Exception FailedException() => new Exception(this);
    }
}
