/*
One Strong Password Generator

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

#pragma once

#include "osp.h"
#include "icryptography.h"
#include "os.h"

/*
S H  K
New/Destroyed 0 0  0
Zeroed        0 0 0|Z
Prepared      # # 0|Z
Ready         # # Z|#
Completed     # 0  #
Invalid       0 0  #
0 #  *
*/

namespace OneStrongPassword
{

	class Cipher
	{
	public:
		typedef OS::byte byte;

		Cipher(const ICryptography& cryptography, OSPCipher& cipher) : cryptography(cryptography), cipher(cipher) { }
		Cipher(Cipher& cipher) : Cipher(cipher.cryptography, cipher.cipher) { }

		virtual ~Cipher() { /*Zero();*/ }

		void*& Handle()       { return cipher.Handle; }
		void*  Handle() const { return cipher.Handle; }

		      byte*& Key()       { return (byte*&)cipher.Key; }
		const byte*  Key() const { return (const byte*)cipher.Key; }

		size_t& Size()       { return cipher.Size; }
		size_t  Size() const { return cipher.Size; }

		bool Prepared()  const { return Size() && Handle() && NoKey(); }
		bool Ready()     const { return Size() && Handle() && Key(); }
		bool Completed() const { return Size() && !Handle() && !NoKey(); }
		bool Zeroed()    const { return !Handle() && NoKey(); }
		bool Invalid()   const { return !Size() && (!Handle() || !Key()); }

		bool Prepare(OSPError* error = nullptr);
		bool Prepare(const ByteVector& secret, OSPError* error = nullptr);

		bool Complete(OSPError* error = nullptr) { return cryptography.CompleteCipher(*this, error); }
		bool Zero(OSPError* error = nullptr) { return cryptography.ZeroCipher(*this, error);  }

	protected:
		bool NoKey() const { return !cipher.Key || OS::Zeroed(Key(), Size()); }

	private:
		const ICryptography& cryptography;
		OSPCipher& cipher;
	};

}
