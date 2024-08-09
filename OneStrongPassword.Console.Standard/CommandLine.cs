using System;
using System.Collections.Generic;
using System.Linq;
using OneStrongPassword.API.Standard;

namespace OneStrongPassword.Console.Standard
{
    class CommandLine
    {
        private delegate void ParseFunc(CommandLine cmdln, string arg);

        private Dictionary<char, ParseFunc> parseFunc = new Dictionary<char, ParseFunc>();

        private static void copyToClipboard(CommandLine cmdln, string arg) => cmdln.CopyToClipboard = true;

        private static void showPassword(CommandLine cmdln, string arg)
        {
            cmdln.ShowPassword = true;
            cmdln.CopyToClipboard = arg.Contains('c');
        }

        private static void verbose(CommandLine cmdln, string arg)
        {
            cmdln.Verbose = 1;
            cmdln.ShowStrongPassword = true;
        }

        private static void receipe(CommandLine cmdln, string arg)
        {
            cmdln.Recipe.Specials = Recipe.AllSupportedSpecials;
            cmdln.Recipe.Seperator = (byte)' ';
            cmdln.Recipe.Flags |= (UInt32)(
                Recipe.RecipeFlag.Alphanumeric |
                Recipe.RecipeFlag.NumericRequired |
                Recipe.RecipeFlag.LowerCaseRequired |
                Recipe.RecipeFlag.UpperCaseRequired |
                Recipe.RecipeFlag.SpecialRequired
            );
        }

        private static void help(CommandLine cmdln, string arg) => cmdln.Help = true;

        public CommandLine()
        {
            Help = false;

            parseFunc['c'] = copyToClipboard;
            parseFunc['s'] = showPassword;
            parseFunc['v'] = verbose;
            parseFunc['r'] = receipe;
            parseFunc['h'] = help;
        }

        public string Mnemonic;

        public uint Length;

        public bool Help;
        public bool CopyToClipboard;
        public bool ShowPassword;
        public bool ShowStrongPassword;
        public bool Continue;

        public int Verbose;

        public Recipe Recipe = new Recipe();

        public bool Parse(string[] args)
        {
            foreach (var arg in args)
            {
                if (!String.IsNullOrWhiteSpace(arg))
                {
                    if (arg[0] != '-')
                        Mnemonic = arg;
                    else if (arg.Length > 1)
                        parseFunc[arg[1]](this, arg);
                }
            }
            Continue = String.IsNullOrWhiteSpace(Mnemonic);
            return true;
        }

        public void ShowUsage()
        {
            System.Console.WriteLine("osp <mnemonic> <-c|s|sc|v|r>");
            System.Console.WriteLine("    -c copy to clipboard only (default)");
            System.Console.WriteLine("    -s show generated password only");
            System.Console.WriteLine("    -sc show generated password and copy to clipboard");
            System.Console.WriteLine("    -v show strong password after entering");
            System.Console.WriteLine("    -r require numeric, lowercase, uppercase, and special");
        }
    }
}
