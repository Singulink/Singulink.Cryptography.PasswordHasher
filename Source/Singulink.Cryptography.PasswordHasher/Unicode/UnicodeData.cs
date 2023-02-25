using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;

namespace Singulink.Cryptography.Unicode;

internal static class UnicodeData
{
    private static readonly char[] ItemSeparators = new char[] { ';', ' ' };

    public static List<(int Start, int End, string Value)> Load(Stream stream)
    {
        var data = new List<(int Start, int End, string Value)>();
        using var reader = new StreamReader(stream);

        int lineNumber = 1;
        string line;

        while ((line = reader.ReadLine()?.Trim()) != null) {
            line = line.Split('#')[0].Trim();

            if (line.Length > 0) {
                string[] items = line.Split(ItemSeparators, StringSplitOptions.RemoveEmptyEntries);

                if (items.Length != 2)
                    throw new FormatException($"Unexpected number of items in data on line {lineNumber}. Data: {line}");

                string[] rangeItems = items[0].Split("..");

                int start = int.Parse(rangeItems[0], NumberStyles.HexNumber, CultureInfo.InvariantCulture);
                int end;

                if (rangeItems.Length == 1)
                    end = start;
                else if (rangeItems.Length == 2)
                    end = int.Parse(rangeItems[1], NumberStyles.HexNumber, CultureInfo.InvariantCulture);
                else
                    throw new FormatException($"Invalid code point range on line {lineNumber}. Data: {line}");

                data.Add((start, end, items[1]));
            }

            lineNumber++;
        }

        return data;
    }
}