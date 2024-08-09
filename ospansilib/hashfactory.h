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

#include <array>
#include "../osp/os.h"
#include "../osp/bytevector.h"

namespace OneStrongPassword
{
	class HashFactory
	{
	public:
		typedef OS::byte byte;

		static const size_t BLOCK_SIZE = (1024 / 8);

		class Hash
		{
		public:
			Hash() : block() { }
			virtual ~Hash() { Destroy(); }

			void Initialize(OSPError* error = nullptr);
			void Update(const byte* const data, size_t dsize, OSPError* error = nullptr);
			void Finialize(byte* const hash, OSPError* error = nullptr);

			void Transform(const byte* const dpart, size_t blocks, OSPError* error = nullptr);

			bool Destroy(OSPError* error = nullptr);

		private:
			friend HashFactory;

			ByteArray<BLOCK_SIZE * 2> block;

			size_t length = 0;
			size_t total_length = 0;
			std::array<uint64_t, 8> part;
		};

		HashFactory();
		virtual ~HashFactory();

		size_t Size(OSPError* error = nullptr) const;

		bool Start(Hash& hfhash, OSPError* error = nullptr) const;
		bool Update(
			Hash& hfhash,
			const byte* const data,
			size_t dsize,
			byte* const hash,
			OSPError* error = nullptr
		) const;
		bool Finish(Hash& hfhash, OSPError* error = nullptr) const;

	private:
		const static uint64_t sha512_k[];
	};
}
