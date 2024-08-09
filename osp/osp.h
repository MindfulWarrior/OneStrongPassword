/*
One Strong Password

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
#include <stdint.h>
#include <assert.h>

#ifdef _DEBUG

extern int EXPOSURE_COUNT;

#define INCREASE_EXPOSURE (++EXPOSURE_COUNT)
#define DECREASE_EXPOSURE (EXPOSURE_COUNT--)

#define CLEAR_EXPOSURE (EXPOSURE_COUNT = 0)

#define BEGIN_MEMORY_CHECK(size) size_t _MEMORY_CHECK_ = (size);
#define END_MEMORY_CHECK(size) assert(_MEMORY_CHECK_ == (size));

#else

#define EXPOSURE_COUNT (0)

#define INCREASE_EXPOSURE
#define DECREASE_EXPOSURE

#define CLEAR_EXPOSURE

#define BEGIN_MEMORY_CHECK(size)
#define END_MEMORY_CHECK(size)

#endif

#define EXPOSED(cnt) (EXPOSURE_COUNT == cnt)

typedef enum OSPErrorType {
	OSP_No_Error = 0,
	OSP_API_Error = 1,
	OSP_System_Error = 2,
	OSP_NT_Error = 3
} OSPErrorType;

typedef struct OSPError {
	uint32_t Code;
	OSPErrorType Type;
} OSPError;

#define CLEAR_OSPError(error) \
error.Code = 0;\
error.Type = OSP_No_Error;

#define DECLARE_OSPError(error) \
OSPError error;\
CLEAR_OSPError(error)

#define OSP_NO_ERROR                                     (uint32_t(0x00))
#define OSP_ERROR_UNKNOWN                                (uint32_t(0x01))
#define OSP_ERROR_ALREADY_INITIALIZED                    (uint32_t(0x02))
#define OSP_ERROR_NOT_INITIALIZED                        (uint32_t(0x03))
#define OSP_ERROR_NO_AVAILABLE_HEAP_MEMORY               (uint32_t(0x04))
#define OSP_ERROR_MEMORY_IS_FIXED                        (uint32_t(0x05))
#define OSP_ERROR_DATA_STILL_EXPOSED                     (uint32_t(0x06))
#define OSP_ERROR_NULL_POINTER                           (uint32_t(0x07))
#define OSP_ERROR_BAD_POINTER                            (uint32_t(0x08))
#define OSP_ERROR_SIZE_IS_0                              (uint32_t(0x09))
#define OSP_ERROR_DATA_NOT_FOUND                         (uint32_t(0x0A))
#define OSP_ERROR_BUFFER_TOO_SMALL                       (uint32_t(0x0B))
#define OSP_ERROR_NO_STRONG_PASSWORD_STORED              (uint32_t(0x0C))
#define OSP_ERROR_CIPHER_NOT_IN_THE_RIGHT_STATE          (uint32_t(0x0D))
#define OSP_ERROR_STRONG_PASSWORD_ENTRY_ALREADY_STARTED  (uint32_t(0x0E))
#define OSP_ERROR_STRONG_PASSWORD_ENTRY_NOT_STARTED      (uint32_t(0x0F))
#define OSP_ERROR_STRONG_PASSWORD_ENTRY_FULL             (uint32_t(0x10))
#define OSP_ERROR_UNABLE_TO_MEET_PASSWORD_REQUIREMENTS   (uint32_t(0x11))
#define OSP_ERROR_PASSWORD_EXCEEDS_SUPPORTED_LENGTH      (uint32_t(0x12))
#define OSP_ERROR_TIMEOUT                                (uint32_t(0x13))
#define OSP_ERROR_NOT_SUPPORTED                          (uint32_t(0x14))

typedef struct OSPCipher {
	void* Handle;
	volatile void* volatile Key;
	size_t Size;
} OSPCipher;

#define DECLARE_OSPCipher(cipher) \
OSPCipher cipher;\
cipher.Handle = nullptr;\
cipher.Key = nullptr;\
cipher.Size = 0;

typedef struct OSPRecipe
{
	const char* Specials;
	size_t SpecialsLength;
	uint32_t Flags;
	char Seperator;
} OSPRecipe;

#define CLEAR_OSPRecipe(recipe) \
recipe.Specials = nullptr;\
recipe.SpecialsLength = recipe.Flags = recipe.Seperator = 0;

#define DECLARE_OSPRecipe(recipe) \
OSPRecipe recipe;\
CLEAR_OSPRecipe(recipe)

#define IS_UNDEFINED_OSPRecipe(recipe) ((recipe.Specials == nullptr || recipe.SpecialsLength == 0) && recipe.Flags == 0)

#define OSP_RECIPE_NUMERIC       (uint32_t(0x0001))
#define OSP_RECIPE_LOWERCASE     (uint32_t(0x0002))
#define OSP_RECIPE_UPPERCASE     (uint32_t(0x0004))
#define OSP_RECIPE_SPACE_ALLOWED (uint32_t(0x0008))

#define OSP_RECIPE_ALPHANUMERIC (OSP_RECIPE_LOWERCASE|OSP_RECIPE_UPPERCASE|OSP_RECIPE_NUMERIC)

#define OSP_RECIPE_NUMERIC_REQUIRED   (uint32_t(0x0010))
#define OSP_RECIPE_LOWERCASE_REQUIRED (uint32_t(0x0020))
#define OSP_RECIPE_UPPERCASE_REQUIRED (uint32_t(0x0040))
#define OSP_RECIPE_SPECIAL_REQUIRED   (uint32_t(0x0080))

#define OSP_RECIPE_ALL_SUPPORTED_SPECIALS ("!@#$%^&*()_-+=[]{};:,.<>/?`~\\\'\"")
