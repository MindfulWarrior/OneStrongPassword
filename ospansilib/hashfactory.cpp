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

#include <algorithm>
#include "hashfactory.h"

using namespace std;
using namespace OneStrongPassword;

template<typename T> constexpr T shiftRight(T x, int n)  { return x >> n; }
template<typename T> constexpr T rotateRight(T x, int n) { return (x >> n) | (x << ((sizeof(x) << 3) - n)); }

template<typename T> constexpr T sha2_ch(T x, T y, T z)  { return (x & y) ^ (~x & z); }
template<typename T> constexpr T sha2_maj(T x, T y, T z) { return (x & y) ^ (x & z) ^ (y & z); }
template<typename T> constexpr T sha512_f1(T x) { return rotateRight(x, 28) ^ rotateRight(x, 34) ^ rotateRight(x, 39); }
template<typename T> constexpr T sha512_f2(T x) { return rotateRight(x, 14) ^ rotateRight(x, 18) ^ rotateRight(x, 41); }
template<typename T> constexpr T sha512_f3(T x) { return rotateRight(x, 1)  ^ rotateRight(x, 8)  ^ shiftRight(x, 7); }
template<typename T> constexpr T sha512_f4(T x) { return rotateRight(x, 19) ^ rotateRight(x, 61) ^ shiftRight(x, 6); }

inline void unpack32(uint64_t x, HashFactory::byte* const bytes)
{
    *((bytes) + 3) = (HashFactory::byte) ((x)      );
    *((bytes) + 2) = (HashFactory::byte) ((x) >>  8);
    *((bytes) + 1) = (HashFactory::byte) ((x) >> 16);
    *((bytes) + 0) = (HashFactory::byte) ((x) >> 24);
}

inline void unpack64(uint64_t x, HashFactory::byte* const bytes)
{
    *((bytes) + 7) = (HashFactory::byte) ((x)      );
    *((bytes) + 6) = (HashFactory::byte) ((x) >>  8);
    *((bytes) + 5) = (HashFactory::byte) ((x) >> 16);
    *((bytes) + 4) = (HashFactory::byte) ((x) >> 24);
    *((bytes) + 3) = (HashFactory::byte) ((x) >> 32);
    *((bytes) + 2) = (HashFactory::byte) ((x) >> 40);
    *((bytes) + 1) = (HashFactory::byte) ((x) >> 48);
    *((bytes) + 0) = (HashFactory::byte) ((x) >> 56);
}

inline uint64_t pack64(const HashFactory::byte* bytes)
{
	return ((uint64_t) *((bytes)+7))
		| ((uint64_t) *((bytes)+6) << 8)
		| ((uint64_t) *((bytes)+5) << 16)
		| ((uint64_t) *((bytes)+4) << 24)
		| ((uint64_t) *((bytes)+3) << 32)
		| ((uint64_t) *((bytes)+2) << 40)
		| ((uint64_t) *((bytes)+1) << 48)
		| ((uint64_t) *((bytes)+0) << 56)
		;
}

const uint64_t HashFactory::sha512_k[] =
{
	0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
	0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
	0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
	0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
	0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
	0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
	0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
	0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
	0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
	0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
	0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
	0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
	0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
	0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
	0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
	0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
	0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
	0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
	0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
	0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
	0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
	0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
	0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
	0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
	0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
	0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
	0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
	0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
	0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
	0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
	0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
	0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
	0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
	0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
	0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
	0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
	0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
	0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
	0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
	0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

HashFactory::HashFactory()
{
}

HashFactory::~HashFactory()
{
}

size_t HashFactory::Size(OSPError* error) const
{
	return 64;
}

bool HashFactory::Start(Hash& hfhash, OSPError* error) const
{
	hfhash.Initialize(error);
	return true;
}

bool HashFactory::Update(Hash& hfhash, const byte* const data, size_t dsize, byte* const hash, OSPError* error) const
{
	hfhash.Update(data, dsize, error);
	hfhash.Finialize(hash, error);
	return true;
}

bool HashFactory::Finish(Hash& hfhash, OSPError* error) const
{
	return hfhash.Destroy(error);
}

void HashFactory::Hash::Initialize(OSPError * error)
{
	Destroy(error);

	part[0] = 0x6a09e667f3bcc908ULL;
	part[1] = 0xbb67ae8584caa73bULL;
	part[2] = 0x3c6ef372fe94f82bULL;
	part[3] = 0xa54ff53a5f1d36f1ULL;
	part[4] = 0x510e527fade682d1ULL;
	part[5] = 0x9b05688c2b3e6c1fULL;
	part[6] = 0x1f83d9abfb41bd6bULL;
	part[7] = 0x5be0cd19137e2179ULL;
}

void OneStrongPassword::HashFactory::Hash::Update(const byte * const data, size_t dsize, OSPError * error)
{
	auto remaining = min(dsize, BLOCK_SIZE - length);
	block.CopyFrom(data, remaining, length);

	if (remaining == dsize)
		length += dsize;
	else
	{
		Transform(block, 1);

		auto dpart = data + remaining;
		dsize -= remaining;
		remaining = dsize % BLOCK_SIZE;

		auto blocks = dsize / BLOCK_SIZE;
		Transform(dpart, blocks);
		block.CopyFrom(&dpart[blocks << 7], remaining);

		length = remaining;
		total_length += (blocks + 1) << 7;
	}
}

void OneStrongPassword::HashFactory::Hash::Finialize(byte * const hash, OSPError * error)
{
	const auto block_nb = 1 + ((BLOCK_SIZE - 17) < (length % BLOCK_SIZE));
	const size_t pm_len = block_nb << 7;

	memset(&block[length], 0, pm_len - length);
	block[length] = 0x80;
	unpack32((total_length + length) << 3, &block[pm_len] - 4);
	
	Transform(block, block_nb);
	for (size_t i = 0; i < 8; i++)
		unpack64(part[i], &hash[i << 3]);
}

void HashFactory::Hash::Transform(const byte* const dpart, size_t blocks, OSPError* error)
{
	array<uint64_t, 80> w;
	for (size_t i = 0; i < blocks; i++)
	{
		const byte* sub_block = dpart + (i << 7);

		for (size_t j = 0; j < 16; j++)
			w[j] = pack64(&sub_block[j << 3]);

		for (size_t j = 16; j < 80; j++)
			w[j] = sha512_f4(w[j - 2]) + w[j - 7] + sha512_f3(w[j - 15]) + w[j - 16];

		array<uint64_t, 8> wv(part);

		for (size_t j = 0; j < 80; j++)
		{
			uint64_t t1 = wv[7] + sha512_f2(wv[4]) + sha2_ch(wv[4], wv[5], wv[6]) + sha512_k[j] + w[j];
			uint64_t t2 = sha512_f1(wv[0]) + sha2_maj(wv[0], wv[1], wv[2]);
			wv[7] = wv[6];
			wv[6] = wv[5];
			wv[5] = wv[4];
			wv[4] = wv[3] + t1;
			wv[3] = wv[2];
			wv[2] = wv[1];
			wv[1] = wv[0];
			wv[0] = t1 + t2;
		}

		for (size_t j = 0; j < 8; j++)
			part[j] += wv[j];
	}
}

bool HashFactory::Hash::Destroy(OSPError * error)
{
	block.Destroy(error);
	length = 0;
	total_length = 0;

	OS::Zero((byte*)part.data(), part.size() * sizeof(part[0]));
	return true;
}
