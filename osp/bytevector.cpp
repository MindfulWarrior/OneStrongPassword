#include "bytevector.h"
#include <algorithm>

using namespace OneStrongPassword;
using namespace std;

bool ByteVector::Alloc(size_t sz, OSPError* error)
{
	if (bytes || !cryptography)
		return OS::SetOSPError(error, OSP_API_Error, OSP_ERROR_NOT_INITIALIZED);
	bytes = cryptography->Alloc(size = sz, error);
	return 0 != bytes;
}

bool ByteVector::Realloc(size_t sz, OSPError* error)
{
	if (fixed)
		return OS::SetOSPError(error, OSP_API_Error, OSP_ERROR_MEMORY_IS_FIXED);

	if (!sz)
		return OS::SetOSPError(error, OSP_API_Error, OSP_ERROR_SIZE_IS_0);

	return Destroy(error) && Alloc(sz, error);
}

bool ByteVector::Release(OSPError* error)
{
	if (!fixed)
		return OS::SetOSPError(error, OSP_API_Error, OSP_ERROR_DATA_STILL_EXPOSED);

	bytes = 0;
	size = 0;
	fixed = false;

	return true;
}

void ByteVector::Zero()
{
	OS::Zero(bytes, Size());
}

bool ByteVector::Destroy(OSPError* error)
{
	if (fixed)
		return OS::Zero(bytes, Size());

	if (!cryptography)
		return OS::SetOSPError(error, OSP_API_Error, OSP_ERROR_NOT_INITIALIZED);

	bool success = cryptography->Destroy(bytes, Size(), error);
	
	size = 0;

	return success;
}

bool ByteVector::CopyTo(byte * const dst, size_t sz, OSPError* error) const
{
	if (!bytes || !dst)
		return OS::SetOSPError(error, OSP_API_Error, OSP_ERROR_NULL_POINTER);
	memcpy(dst, bytes, min(Size(), sz));
	return true;
}

bool ByteVector::CopyFrom(const byte * const src, size_t sz, size_t pos, OSPError* error)
{
	if (!bytes || !src || pos >= Size())
		return OS::SetOSPError(error, OSP_API_Error, OSP_ERROR_BAD_POINTER);
	memcpy(bytes + pos, src, min(Size(), sz));
	return true;
}

bool ByteVector::CopyFrom(const ByteVector& v, OSPError* error)
{
	return CopyFrom(v.bytes, v.Size(), 0, error);
}

bool ByteVector::CopyFrom(const string& str, OSPError* error)
{
	return CopyFrom((const byte* const)str.c_str(), str.size() * sizeof(char), 0, error);
}

bool ByteVector::MoveTo(byte*& dst, size_t& sz, OSPError* error)
{
	if (fixed || !bytes || dst)
		return OS::SetOSPError(error, OSP_API_Error, OSP_ERROR_BAD_POINTER);

	dst = bytes;
	sz = size;

	fixed = true; // Make OK for release
	Release(error);

	return true;
}

bool ByteVector::MoveTo(ByteVector & v, OSPError* error)
{
	return MoveTo(v.bytes, v.size, error);
}
