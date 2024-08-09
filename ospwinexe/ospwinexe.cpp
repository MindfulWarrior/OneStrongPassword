/*
One Strong Password

Copyright(c) Robert Richard Flores. (MIT License)

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files(the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions :
-The above copyright notice and this permission notice shall be included in
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
#include "../ospwindll/ospapi.h"

#include <conio.h>
#include <iostream>
#include "commandline.h"

using namespace std;

typedef unsigned char byte;

const string StrongName = "main";

int main(int argc, char* argv[])
{
	CommandLine cmdln;
	if (!cmdln.Parse(argc, argv))
	{
		cmdln.ShowUsage();
		return 0;
	}

	int retval = 0;

	bool needStrongPassword = true;

	DECLARE_OSPError(error);

	DECLARE_OSPCipher(cipher);

	if (!OSPInit(1, 64, &error))
		goto exit;

	if (!OSPPrepareCipher(&cipher, &error))
		goto exit;

	cipher.Key = new byte[cipher.Size];

	if (!OSPCompleteCipher(&cipher, &error))
		goto exit;

	do
	{
		if (!OSPStrongPasswordStart(64, &error))
			goto exit;

		cout << "Enter strong password: ";

		for (int n = 0; n < 64; n++)
		{
			char ch = _getch();
			if (ch == '\r')
				break;
			putchar('*');
			if (!OSPStrongPasswordPut(ch, &error))
				goto exit;
		}
		cout << endl;

		if (!OSPStrongPasswordFinish(StrongName.c_str(), StrongName.size(), &cipher, &error))
			goto exit;

		if (needStrongPassword = cmdln.ShowStrongPassword)
		{
			auto response = OSPShowStrongPassword(
				StrongName.c_str(),
				StrongName.size(),
				&cipher,
				0,
				"Is Strong Password Correct?",
				27,
				MB_YESNO,
				&error
			);

			if (response == 0)
				goto exit;

			needStrongPassword = (IDNO == response);
		}
	}
	while (needStrongPassword);

	do
	{
		if (cmdln.Mnemonic.empty())
		{
			cout << "Enter mnemonic: ";
			cin >> cmdln.Mnemonic;
		}

		if (cmdln.Length == 0)
		{
			cout << "Enter length: ";
			cin >> cmdln.Length;
		}

		if (IS_UNDEFINED_OSPRecipe(cmdln.Recipe))
		{
			char ch;

			cmdln.Recipe.Specials = OSP_RECIPE_ALL_SUPPORTED_SPECIALS;
			cmdln.Recipe.SpecialsLength = strlen(OSP_RECIPE_ALL_SUPPORTED_SPECIALS);

			cout << "Enter Seperator, Hit <Return> for none:";
			ch = _getch();
			if (ch != '\r')
				cmdln.Recipe.Seperator = ch;
			cout << endl;

			bool done = false;
			while (!done)
			{
				if (!(cmdln.Recipe.Flags & OSP_RECIPE_ALPHANUMERIC))
					cout << "  1) Alphanumeric" << endl;
				if (!(cmdln.Recipe.Flags & OSP_RECIPE_NUMERIC))
					cout << "  2) Numeric" << endl;
				if (!(cmdln.Recipe.Flags & OSP_RECIPE_LOWERCASE))
					cout << "  3) Lowercase" << endl;
				if (!(cmdln.Recipe.Flags & OSP_RECIPE_UPPERCASE))
					cout << "  4) Uppercase" << endl;
				if (!(cmdln.Recipe.Flags & OSP_RECIPE_SPACE_ALLOWED))
					cout << "  5) Space" << endl;
				if (!(cmdln.Recipe.Flags & OSP_RECIPE_NUMERIC_REQUIRED))
					cout << "  6) Numeric Required" << endl;
				if (!(cmdln.Recipe.Flags & OSP_RECIPE_LOWERCASE_REQUIRED))
					cout << "  7) Lowercase Required" << endl;
				if (!(cmdln.Recipe.Flags & OSP_RECIPE_UPPERCASE_REQUIRED))
					cout << "  8) Uppercase Required" << endl;
				if (!(cmdln.Recipe.Flags & OSP_RECIPE_SPECIAL_REQUIRED))
					cout << "  9) Special Requred" << endl;

				cout << "Select Flags, (default) Alphanumeric:";
				ch = _getch();
				switch (ch)
				{
				case '1':
					cmdln.Recipe.Flags |= OSP_RECIPE_ALPHANUMERIC;
					break;
				case '2':
					cmdln.Recipe.Flags |= OSP_RECIPE_NUMERIC;
					break;
				case '3':
					cmdln.Recipe.Flags |= OSP_RECIPE_LOWERCASE;
					break;
				case '4':
					cmdln.Recipe.Flags |= OSP_RECIPE_UPPERCASE;
					break;
				case '5':
					cmdln.Recipe.Flags |= OSP_RECIPE_SPACE_ALLOWED;
					break;
				case '6':
					cmdln.Recipe.Flags |= OSP_RECIPE_NUMERIC_REQUIRED;
					break;
				case '7':
					cmdln.Recipe.Flags |= OSP_RECIPE_LOWERCASE_REQUIRED;
					break;
				case '8':
					cmdln.Recipe.Flags |= OSP_RECIPE_UPPERCASE_REQUIRED;
					break;
				case '9':
					cmdln.Recipe.Flags |= OSP_RECIPE_SPECIAL_REQUIRED;
					break;
				default:
					if (!cmdln.Recipe.Flags)
						cmdln.Recipe.Flags |= OSP_RECIPE_ALPHANUMERIC;
					done = true;
				}
				cout << endl;
			}
		}

		if (!cmdln.CopyToClipboard && !cmdln.ShowPassword)
		{
			cout << "(s)how, (c)lipboard, (b)oth: ";
			char ch = _getch();
			switch (ch)
			{
			case 's':
				cmdln.ShowPassword = true;
				break;
			case 'c':
				cmdln.CopyToClipboard = true;
				break;
			default:
				cmdln.ShowPassword = true;
				cmdln.CopyToClipboard = true;
				break;
			}
		}
		cout << endl;

		if (cmdln.ShowPassword)
		{
			if (!OSPShowPassword(
				StrongName.c_str(),
				StrongName.size(),
				cmdln.Mnemonic.c_str(),
				cmdln.Mnemonic.size(),
				&cipher,
				cmdln.Length,
				&cmdln.Recipe,
				40,
				0,
				0,
				0,
				&error
			))
				goto exit;
		}

		if (cmdln.CopyToClipboard)
		{
			if (!OSPPasswordToClipboard(
				StrongName.c_str(),
				StrongName.size(),
				cmdln.Mnemonic.c_str(),
				cmdln.Mnemonic.size(),
				&cipher,
				cmdln.Length,
				&cmdln.Recipe,
				&error
			))
				goto exit;

			cout << "Password copied to clipboard, press a key to clear...";

			_getch();

			OpenClipboard(NULL);
			EmptyClipboard();
			CloseClipboard();

			cout << " ...cleared" << endl;
		}

		if (cmdln.Continue)
		{
			cout << endl << "Continue? (y)es, (default) no: ";
			char ch = _getch();
			cout << endl;

			cmdln.Continue = (ch == 'y');
			if (cmdln.Continue)
			{
				cout << endl;

				CLEAR_OSPRecipe(cmdln.Recipe);
				cmdln.Mnemonic.clear();
				cmdln.Length = 0;
				cmdln.CopyToClipboard = false;
				cmdln.ShowPassword = false;
			}
		}

	} while (cmdln.Continue);

exit:
	OSPZeroCipher(&cipher, &error);
	if (cipher.Key)
		delete[] cipher.Key;

	OSPDestroy(&error);

	if (error.Code != OSP_NO_ERROR)
		cout << "Error: " << error.Code << ", Type: " << error.Type << endl;

    return error.Code;
}

