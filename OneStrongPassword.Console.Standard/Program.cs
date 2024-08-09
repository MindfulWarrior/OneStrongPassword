using System;
using System.Windows.Forms;
using OneStrongPassword.API.Standard;

namespace OneStrongPassword.Console.Standard
{
    class Program
    {
        const string StrongName = "main";

        [STAThread()]
        static void Main(string[] args)
        {
            var cmdln = new CommandLine();

            if (!cmdln.Parse(args) || cmdln.Help)
            {
                cmdln.ShowUsage();
                return;
            }

            try
            {
                Result result;
                bool done;

                using (var manager = PasswordManager.Open(1, PasswordManager.MinLength, out result))
                using (var strongPassword = manager.StrongPassword(StrongName, out result))
                {
                    if (manager == null || strongPassword == null)
                        throw result.FailedException();

                    done = false;
                    do
                    {
                        if (!(result = strongPassword.StartInput(manager.MaxLength)).Success)
                            throw result.FailedException();

                        System.Console.Clear();

                        System.Console.Write("Enter strong password: ");

                        for (int n = 0; result.Success && n < manager.MaxLength; n++)
                        {
                            var ch = (byte)System.Console.ReadKey(true).KeyChar;
                            if (ch == '\r')
                                break;
                            System.Console.Write('*');

                            result = strongPassword.Put(ch);
                        }
                        System.Console.WriteLine();

                        if (result.Success)
                            result = strongPassword.FinishInput();
                        else
                            strongPassword.AbortInput();

                        if (!result.Success)
                            throw result.FailedException();

                        done = !cmdln.ShowStrongPassword;
                        if (!done)
                        {
                            var response = strongPassword.ShowStrongPassword(
                                40, "Is Strong Password Correct?", OSP.ShowType.YesNo, out result
                            );

                            if (!result.Success)
                                throw result.FailedException();

                            done = (response != OSP.ShowResponse.No);
                        }
                    } while (!done);

                    do
                    {
                        if (String.IsNullOrWhiteSpace(cmdln.Mnemonic))
                        {
                            System.Console.Write("Enter mnemonic: ");
                            cmdln.Mnemonic = System.Console.ReadLine();
                        }

                        if (cmdln.Length == 0)
                        {
                            System.Console.Write("Enter length: ");
                            cmdln.Length = uint.Parse(System.Console.ReadLine());
                        }

                        if (cmdln.Recipe.Cleared())
                        {
                            cmdln.Recipe.Specials = Recipe.AllSupportedSpecials;

                            System.Console.Write("Enter Seperator, Hit <Return> for none:");

                            var ch = (byte)System.Console.ReadKey(true).KeyChar;
                            if (ch != '\r')
                                cmdln.Recipe.Seperator = (byte)ch;
                            System.Console.WriteLine();

                            done = false;
                            while (!done)
                            {
                                if ((cmdln.Recipe.Flags & (UInt32)Recipe.RecipeFlag.Alphanumeric) == 0)
                                    System.Console.WriteLine("  1) Alphanumeric");
                                if ((cmdln.Recipe.Flags & (UInt32)Recipe.RecipeFlag.NumericAllowed) == 0)
                                    System.Console.WriteLine("  2) Numeric");
                                if ((cmdln.Recipe.Flags & (UInt32)Recipe.RecipeFlag.LowerCaseAllowed) == 0)
                                    System.Console.WriteLine("  3) Lowercase");
                                if ((cmdln.Recipe.Flags & (UInt32)Recipe.RecipeFlag.UpperCaseAllowed) == 0)
                                    System.Console.WriteLine("  4) Uppercase");
                                if ((cmdln.Recipe.Flags & (UInt32)Recipe.RecipeFlag.SpaceAllowed) == 0)
                                    System.Console.WriteLine("  5) Space");
                                if ((cmdln.Recipe.Flags & (UInt32)Recipe.RecipeFlag.NumericRequired) == 0)
                                    System.Console.WriteLine("  6) Numeric Required");
                                if ((cmdln.Recipe.Flags & (UInt32)Recipe.RecipeFlag.LowerCaseRequired) == 0)
                                    System.Console.WriteLine("  7) Lowercase Required");
                                if ((cmdln.Recipe.Flags & (UInt32)Recipe.RecipeFlag.UpperCaseRequired) == 0)
                                    System.Console.WriteLine("  8) Uppercase Required");
                                if ((cmdln.Recipe.Flags & (UInt32)Recipe.RecipeFlag.SpecialRequired) == 0)
                                    System.Console.WriteLine("  9) Special Requred");

                                System.Console.Write("Select Flags, (default) Alphanumeric:");
                                ch = (byte)System.Console.ReadKey(true).KeyChar;
                                switch (ch)
                                {
                                    case (byte)'1':
                                        cmdln.Recipe.Flags |= (UInt32)Recipe.RecipeFlag.Alphanumeric;
                                        break;
                                    case (byte)'2':
                                        cmdln.Recipe.Flags |= (UInt32)Recipe.RecipeFlag.NumericAllowed;
                                        break;
                                    case (byte)'3':
                                        cmdln.Recipe.Flags |= (UInt32)Recipe.RecipeFlag.LowerCaseAllowed;
                                        break;
                                    case (byte)'4':
                                        cmdln.Recipe.Flags |= (UInt32)Recipe.RecipeFlag.UpperCaseAllowed;
                                        break;
                                    case (byte)'5':
                                        cmdln.Recipe.Flags |= (UInt32)Recipe.RecipeFlag.SpaceAllowed;
                                        break;
                                    case (byte)'6':
                                        cmdln.Recipe.Flags |= (UInt32)Recipe.RecipeFlag.NumericRequired;
                                        break;
                                    case (byte)'7':
                                        cmdln.Recipe.Flags |= (UInt32)Recipe.RecipeFlag.LowerCaseRequired;
                                        break;
                                    case (byte)'8':
                                        cmdln.Recipe.Flags |= (UInt32)Recipe.RecipeFlag.UpperCaseRequired;
                                        break;
                                    case (byte)'9':
                                        cmdln.Recipe.Flags |= (UInt32)Recipe.RecipeFlag.SpecialRequired;
                                        break;
                                    default:
                                        if (cmdln.Recipe.Flags == 0)
                                            cmdln.Recipe.Flags |= (UInt32)Recipe.RecipeFlag.Alphanumeric;
                                        done = true;
                                        break;
                                }
                                System.Console.WriteLine();
                            }
                        }

                        if (!cmdln.CopyToClipboard && !cmdln.ShowPassword)
                        {
                            System.Console.Write("(s)how, (c)lipboard, (b)oth: ");
                            var ch = (byte)System.Console.ReadKey(true).KeyChar;
                            switch (ch)
                            {
                                case (byte)'s':
                                    cmdln.ShowPassword = true;
                                    break;
                                case (byte)'c':
                                    cmdln.CopyToClipboard = true;
                                    break;
                                default:
                                    cmdln.ShowPassword = true;
                                    cmdln.CopyToClipboard = true;
                                    break;
                            }
                        }
                        System.Console.WriteLine();

                        if (cmdln.ShowPassword)
                        {
                            if (strongPassword.ShowPassword(
                                cmdln.Mnemonic,
                                cmdln.Length,
                                cmdln.Recipe,
                                40,
                                null,
                                OSP.ShowType.OK,
                                out result
                            ) == OSP.ShowResponse.Error)
                                throw result.FailedException();
                        }

                        if (cmdln.CopyToClipboard)
                        {
                            if (!(result = strongPassword.PasswordToClipboard(
                                cmdln.Mnemonic,
                                cmdln.Length,
                                cmdln.Recipe
                            )).Success)
                                throw result.FailedException();

                            System.Console.Write("Password copied to clipboard, press a key to clear...");
                            System.Console.ReadKey(true);

                            Clipboard.Clear();

                            System.Console.WriteLine(" ...cleared");
                        }

                        if (cmdln.Continue)
                        {
                            System.Console.WriteLine();
                            System.Console.Write("Continue? (y)es, (default) no: ");
                            var ch = (byte)System.Console.ReadKey(true).KeyChar;
                            System.Console.WriteLine();

                            cmdln.Continue = (ch == (byte)'y');
                            if (cmdln.Continue)
                            {
                                System.Console.WriteLine();

                                cmdln.Mnemonic = "";
                                cmdln.Length = 0;
                                cmdln.CopyToClipboard = false;
                                cmdln.ShowPassword = false;
                                cmdln.Recipe.Clear();

                                System.Console.Clear();
                            }
                        }

                    }
                    while (cmdln.Continue);
                }
            }
            catch(Result.Exception e)
            {
                if (!e.Result.Success)
                    System.Console.WriteLine("Error: {0}, Type: {1}", e.Result.ErrorCode, e.Result.ErrorType);
            }
        }
    }
}
