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

using System;

namespace OneStrongPassword.API.Standard
{
    public class Recipe
    {
        #region Public Constants, Enums, ans Structures

        public const string AllSupportedSpecials = "!@#$%^&*()_-+=[]{};:,.<>/?`~\\\'\"";

        public enum RecipeFlag
        {
            NumericAllowed = 0x0001,
            LowerCaseAllowed = 0x0002,
            UpperCaseAllowed = 0x0004,
            SpaceAllowed = 0x0008,
            NumericRequired = 0x0010,
            LowerCaseRequired = 0x0020,
            UpperCaseRequired = 0x0040,
            SpecialRequired = 0x0080,
            Alphanumeric =
                RecipeFlag.NumericAllowed |
                RecipeFlag.LowerCaseAllowed |
                RecipeFlag.UpperCaseAllowed
        }

        public static readonly Recipe Default = new Recipe()
        {
            Specials = AllSupportedSpecials,
            Seperator = (byte)' ',
            Flags = (UInt32)RecipeFlag.Alphanumeric
        };

        public static readonly Recipe DefaultWithSpaces = new Recipe()
        {
            Specials = AllSupportedSpecials,
            Flags = (UInt32)(RecipeFlag.Alphanumeric | RecipeFlag.SpaceAllowed)
        };

        public static readonly Recipe DefaultAndAllRequired = new Recipe()
        {
            Specials = AllSupportedSpecials,
            Seperator = (byte)' ',
            Flags = (UInt32)(
                RecipeFlag.Alphanumeric |
                RecipeFlag.NumericRequired |
                RecipeFlag.LowerCaseRequired |
                RecipeFlag.UpperCaseRequired |
                RecipeFlag.SpecialRequired
            )
        };

        public static readonly Recipe AlphaNumeric = new Recipe()
        {
            Flags = (UInt32)RecipeFlag.Alphanumeric
        };

        public static readonly Recipe AlphaNumericWithSpaces = new Recipe()
        {
            Seperator = (byte)' ',
            Flags = (UInt32)(RecipeFlag.Alphanumeric | RecipeFlag.SpaceAllowed)
        };

        public static readonly Recipe Pin = new Recipe()
        {
            Flags = (UInt32)RecipeFlag.NumericAllowed
        };

        #endregion

        public string Specials { get; set; }
        public byte Seperator { get; set; }
        public UInt32 Flags { get; set; }

        public bool Cleared() => String.IsNullOrEmpty(Specials) && Flags == 0;

        public void Clear()
        {
            Specials = null;
            Flags = 0;
        }
    }
}
