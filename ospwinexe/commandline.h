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

#pragma once

#include "../osp/osp.h"
#include <map>
#include <string>

class CommandLine
{
public:
	typedef void(*ParseFunc)(CommandLine&, const std::string&);

	CommandLine();
	~CommandLine() { }

	std::string Mnemonic;

	size_t Length;

	bool Help;
	bool CopyToClipboard;
	bool ShowPassword;
	bool ShowStrongPassword;
	bool Continue;

	int Verbose;

	OSPRecipe Recipe;

	bool Parse(int argc, char* argv[]);

	void ShowUsage() const;

private:
	std::map<char, ParseFunc> parseFunc;

	static void copyToClipboard(CommandLine& cmdln, const std::string& arg);
	static void showPassword(CommandLine& cmdln, const std::string& arg);
	static void verbose(CommandLine& cmdln, const std::string& arg);
	static void recipe(CommandLine& cmdln, const std::string& arg);
};

