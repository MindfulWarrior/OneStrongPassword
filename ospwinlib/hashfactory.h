#pragma once
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

#include <windows.h>

namespace OneStrongPassword
{
	class HashFactory
	{
	public:
		class Hash
		{
		public:
			Hash();
			virtual ~Hash();

			BCRYPT_HASH_HANDLE Handle() const { return handle; }

			bool Initialize(BCRYPT_ALG_HANDLE algorithm, ULONG flags, OSPError* error = NULL);
			bool Destroy(OSPError* error = NULL);

		private:
			BCRYPT_HASH_HANDLE handle = NULL;
			PUCHAR hashobj = NULL;
			size_t obj_size = 0;
		};

		HashFactory();
		virtual ~HashFactory();

		BCRYPT_ALG_HANDLE Algorithm(OSPError* error = NULL) const;
		size_t Size(OSPError* error = NULL) const;

		bool Destroy(OSPError* error = NULL);

		bool Start(Hash& hfhash, ULONG flags, OSPError* error) const;
		bool Update(
			Hash& hfhash, const byte* const data, size_t dsize, byte* const hash, OSPError* error
		) const;
		bool Finish(Hash& hfhash, OSPError* error) const;


	private:
		mutable BCRYPT_ALG_HANDLE algorithm = NULL;
		mutable size_t size = 0;
	};
}

