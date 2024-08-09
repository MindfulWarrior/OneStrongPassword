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

#include "CommandLine.h"
#include <iostream>

using namespace std;

CommandLine::CommandLine()
	: parseFunc(),
	  Length(0),
	  Help(false),
	  CopyToClipboard(false),
	  ShowPassword(false),
	  ShowStrongPassword(false)
{
	CLEAR_OSPRecipe(Recipe);

	parseFunc['c'] = copyToClipboard;
	parseFunc['s'] = showPassword;
	parseFunc['v'] = verbose;
	parseFunc['r'] = recipe;
}

bool CommandLine::Parse(int argc, char* argv[])
{
	for (int n = 1; n < argc; n++)
	{
		string arg = argv[n];
		if (!arg.empty())
		{
			if (arg[0] != '-')
				Mnemonic = arg;
			else if (arg.size() > 1)
				parseFunc[arg[1]](*this, arg);
		}
	}

	Continue = Mnemonic.empty();
	return true;
}

void CommandLine::ShowUsage() const
{
	cout << "osp <mnemonic> <-c|s|sc|v|r>" << endl;
	cout << "    -c copy to clipboard only (default)" << endl;
	cout << "    -s show generated password only" << endl;
	cout << "    -sc show generated password and copy to clipboard" << endl;
	cout << "    -v show strong password after entering" << endl;
	cout << "    -r require numeric, lowercase, uppercase, and special" << endl;
}

void CommandLine::copyToClipboard(CommandLine & cmdln, const std::string & arg)
{
	cmdln.CopyToClipboard = true;
}

void CommandLine::showPassword(CommandLine& cmdln, const std::string & arg)
{
	cmdln.ShowPassword = true;
	cmdln.CopyToClipboard = (arg.find('c') != string::npos);
}

void CommandLine::verbose(CommandLine & cmdln, const std::string & arg)
{
	cmdln.Verbose = 1;
	cmdln.ShowStrongPassword = true;
}

void CommandLine::recipe(CommandLine & cmdln, const std::string & arg)
{
	cmdln.Recipe.Specials = OSP_RECIPE_ALL_SUPPORTED_SPECIALS;
	cmdln.Recipe.SpecialsLength = strlen(OSP_RECIPE_ALL_SUPPORTED_SPECIALS);
	cmdln.Recipe.Flags = OSP_RECIPE_ALPHANUMERIC;
	cmdln.Recipe.Seperator = ' ';

	cmdln.Recipe.Flags |=
		OSP_RECIPE_NUMERIC_REQUIRED |
		OSP_RECIPE_LOWERCASE_REQUIRED |
		OSP_RECIPE_UPPERCASE_REQUIRED |
		OSP_RECIPE_SPECIAL_REQUIRED
		;
}
