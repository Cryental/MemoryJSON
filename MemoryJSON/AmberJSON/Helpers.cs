using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using Newtonsoft.Json.Linq;

namespace MemoryJSON.AmberJSON
{
    internal static class Helpers
    {
        internal static dynamic FindTab(dynamic source, string name)
        {
            foreach (var item in source)
            {
                if (name == (string) item.tabName)
                {
                    return item.functions;
                }
            }

            return null;
        }

        internal static List<string> GetAllTabNames(dynamic source)
        {
            var temp = new List<string>();
            foreach (var item in source)
            {
                temp.Add((string) item.tabName);
            }

            return temp;
        }

        internal static int ConvertFromHexStringToInt32(string hexCode)
        {
            try
            {
                return (int) new Int32Converter().ConvertFromString(hexCode);
            }
            catch
            {
                return -1;
            }
        }

        internal static long ConvertFromHexStringToInt64(string hexCode)
        {
            try
            {
                return (long) new Int64Converter().ConvertFromString(hexCode);
            }
            catch
            {
                return -1;
            }
        }

        internal static string GetTypeFromString(string str)
        {
            if (!str.StartsWith("{{") || !str.EndsWith("}}"))
            {
                return null;
            }

            var type = str[2].ToString();

            switch (type)
            {
                case "?":
                    return "aobScan";
                case "#":
                    return "offset";
                case "@":
                    return "local";
                case "$":
                    return "setValue";
                default:
                    return "none";
            }
        }

        internal static bool IsValidSpecialCode(string str)
        {
            return str.StartsWith("{{") && str.EndsWith("}}") && GetTypeFromString(str) != "none";
        }

        internal static string GetStringFromCode(string str)
        {
            if (str.StartsWith("{{") && str.EndsWith("}}"))
            {
                return RemoveSpecialCharacters(str.Substring(3, str.Length - 5));
            }

            return null;
        }

        private static string RemoveSpecialCharacters(string str)
        {
            var sb = new StringBuilder();
            foreach (var c in str.Where(c => (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '.' || c == '_'))
            {
                sb.Append(c);
            }
            return sb.ToString();
        }

        internal static bool IsValidJson(string strInput)
        {
            if (string.IsNullOrWhiteSpace(strInput))
            {
                return false;
            }

            if ((!strInput.StartsWith("{") || !strInput.EndsWith("}")) &&
                (!strInput.StartsWith("[") || !strInput.EndsWith("]")))
            {
                return false;
            }

            try
            {
                JToken.Parse(strInput);
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}