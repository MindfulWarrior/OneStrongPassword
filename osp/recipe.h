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
#include "osp.h"

#include <string>

#include "os.h"
#include "password.h"

namespace OneStrongPassword
{
	class Recipe : OSPRecipe
	{
	public:
		typedef OS::byte byte;

		Recipe() { Clear(); }
		Recipe(const OSPRecipe& recipe) { Reset(recipe); }
		virtual ~Recipe() { }

		bool NumericAllowed() const { return Flags & OSP_RECIPE_NUMERIC; };
		bool LowerCaseAllowed() const { return Flags & OSP_RECIPE_LOWERCASE; };
		bool UpperCaseAllowed() const { return Flags & OSP_RECIPE_UPPERCASE; };
		bool SpaceAllowed() const { return Flags & OSP_RECIPE_SPACE_ALLOWED; }

		bool NumericRequired() const { return Flags & OSP_RECIPE_NUMERIC_REQUIRED; };
		bool LowerCaseRequired() const { return Flags & OSP_RECIPE_LOWERCASE_REQUIRED; };
		bool UpperCaseRequired() const { return Flags & OSP_RECIPE_UPPERCASE_REQUIRED; };
		bool SpecialRequired() const { return Flags & OSP_RECIPE_SPECIAL_REQUIRED; };

		bool Cleared() const { return OS::Zeroed((byte*)charSet, sizeof(charSet)); }
		bool HasChar(char ch) const;

		bool Verified(const char* password, size_t length) const;

		char GetSeperator() const { return Seperator; }

		void Clear() {
			Specials = 0; 
			SpecialsLength = Flags = Seperator = 0;
			OS::Zero((byte*)charSet, sizeof(charSet));
		}

		void AddFlags(uint32_t flags);
		void SetSpecials(const char* specials, size_t length);
		void SetSeperator(char ch);
		void Reset(const OSPRecipe& recipe);

	private:
		typedef uint32_t CharSet[3];
		CharSet charSet = { 0, 0, 0 };

		void setCharBitOn(char ch);
		void setCharBitOff(char ch);
	};
}
