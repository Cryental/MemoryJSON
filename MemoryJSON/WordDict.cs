﻿using System.Collections.Generic;

namespace MemoryJSON
{
    internal static class WordDict
    {
        internal static List<string> SupportedFunctions = new List<string>
        {
            "FreezeValue",
            "UnfreezeValue",
            "WriteMemory",
            "CreateCodeCave",
            "ReadBytes",
            "ReadFloat",
            "ReadString",
            "ReadDouble",
            "ReadUIntPtr",
            "ReadInt",
            "ReadLong",
            "Read2Byte",
            "ReadBits",
            "ReadByte"
        };

        internal static List<string> SupportedTypes = new List<string>
        {
            "float",
            "int",
            "byte",
            "2bytes",
            "bytes",
            "double",
            "long",
            "string"
        };
    }
}