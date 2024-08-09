#pragma once
/*
One Strong Password Generator Windows library

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

#include <map>
#include "../osp/os.h"

class Heap
{
public:
	typedef OneStrongPassword::OS::byte* byte_ptr;
	typedef std::multimap<size_t, byte_ptr> map_type;
	typedef map_type::key_type size_type;
	typedef map_type::mapped_type mem_type;

	Heap(size_t sz);
	virtual ~Heap();

	byte_ptr alloc(size_t& sz, OSPError* error);
	bool dealloc(byte_ptr data, size_t& sz, OSPError* error);

private:
	byte_ptr front;
	byte_ptr back;

	map_type used;
	map_type freed;

	size_t size;
	size_t largest;
};

