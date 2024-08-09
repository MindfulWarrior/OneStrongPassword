#include "recipe.h"

using namespace OneStrongPassword;
using namespace std;

bool Recipe::HasChar(char ch) const
{
	if (ch == 0)
		return false;

	char position = ch - ' '; // ignore non-printable
	if (position < 0)
		return false;

	short block = position / 32;
	position -= block * 32;
	return charSet[block] & 1 << position;
}

bool Recipe::Verified(const char* password, size_t length) const
{
	bool numeric = !NumericRequired();
	bool lowerCase = !LowerCaseRequired();
	bool upperCase = !UpperCaseRequired();
	bool special = !SpecialRequired();

	string specials;
	if (Specials)
		specials = Specials;

	bool verified = numeric && lowerCase && upperCase && special;

	for (size_t n = 0; !verified && n < length; n++)
	{
		char ch = password[n];

		numeric = numeric || (ch >= '0' && ch <= '9');
		lowerCase = lowerCase || (ch >= 'a' && ch <= 'z');
		upperCase = upperCase || (ch >= 'A' && ch <= 'Z');
		special = special || (specials.find(ch) < specials.size());

		verified = numeric && lowerCase && upperCase && special;
	}

	return verified;
}

void Recipe::AddFlags(uint32_t flags)
{
	Flags |= flags;

	if ((Flags & OSP_RECIPE_SPACE_ALLOWED))
		setCharBitOn(' ');
	else
		setCharBitOff(' ');

	if (Flags & OSP_RECIPE_NUMERIC)
	{
		for (char ch = '0'; ch <= '9'; ch++)
			setCharBitOn(ch);
	}
	else
		Flags &= ~OSP_RECIPE_NUMERIC_REQUIRED;

	if (Flags & OSP_RECIPE_LOWERCASE)
	{
		for (char ch = 'a'; ch <= 'z'; ch++)
			setCharBitOn(ch);
	}
	else
		Flags &= ~OSP_RECIPE_LOWERCASE_REQUIRED;

	if (Flags & OSP_RECIPE_UPPERCASE)
	{
		for (char ch = 'A'; ch <= 'Z'; ch++)
			setCharBitOn(ch);
	}
	else
		Flags &= ~OSP_RECIPE_UPPERCASE_REQUIRED;

	if (HasChar(Seperator))
		Seperator = 0;
}

void Recipe::SetSpecials(const char * specials, size_t length)
{
	Reset({specials, length, Flags, Seperator});
}

void Recipe::SetSeperator(char ch)
{
	Reset({ Specials, SpecialsLength, Flags, ch });
}

void Recipe::Reset(const OSPRecipe & recipe)
{
	Clear();
	Specials = recipe.Specials;
	SpecialsLength = recipe.SpecialsLength;
	Seperator = recipe.Seperator;
	for (size_t n = 0; n < SpecialsLength; n++)
		setCharBitOn(Specials[n]);
	AddFlags(recipe.Flags);
}

void Recipe::setCharBitOn(char ch)
{
	char position = ch - ' '; // ignore non-printable
	if (position < 0)
		return;
	short block = position / 32;
	position -= block * 32;
	charSet[block] |= 1 << position;
}

void Recipe::setCharBitOff(char ch)
{
	char position = ch - ' '; // ignore non-printable
	if (position < 0)
		return;
	short block = position / 32;
	position -= block * 32;
	charSet[block] &= ~(1 << position);
}
