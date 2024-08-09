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

#include <algorithm>
#include "heap.h"

using namespace std;
using namespace OneStrongPassword;

Heap::Heap(size_t sz) : used(), freed(), size(sz), largest(0)
{
	back = front = new OS::byte[size];
}

Heap::~Heap()
{
	used.clear();
	freed.clear();

	OS::Zero(front, size);
	delete[] front;
	front = back = 0;
}

OS::byte* Heap::alloc(size_t& sz, OSPError* error)
{
	OS::byte* data = nullptr;

	size_t usedsz = sz;

	if (size - (back - front) >= usedsz) {
		data = back;
		back += usedsz;
		largest = max(largest, usedsz);
	}
	else if (!freed.empty()) {
		while (!data && usedsz <= largest) {
			auto free = freed.find(usedsz);
			if (free == freed.end())
				usedsz++;
			else {
				data = free->second;
				freed.erase(free);
			}
		}
	}

	if (data)
		used.insert(pair<size_type, mem_type>((sz = usedsz), data));
	else
		OS::SetOSPError(error, OSP_API_Error, OSP_ERROR_NO_AVAILABLE_HEAP_MEMORY);
	return data;
}

bool Heap::dealloc(byte_ptr data, size_t& sz, OSPError* error)
{
	if (!data)
		return true;

	size_t freedsz = sz;
	while (freedsz <= largest) {
		auto range = used.equal_range(freedsz);
		map_type::iterator match;
		for (map_type::iterator itr = range.first; itr != range.second; itr++) {
			if (itr->second == data) {
				freed.insert(pair<size_type, mem_type>(freedsz, data));
				used.erase(itr);
				sz = freedsz;
				return true;
			}
		}
	}
	return OS::SetOSPError(error, OSP_API_Error, OSP_ERROR_BAD_POINTER);
}