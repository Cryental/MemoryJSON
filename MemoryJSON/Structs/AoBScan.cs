using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MemoryJSON.Structs
{
    internal class AoBScan
    {
        internal string Name { get; set; }
        internal string Value { get; set; }
        internal string StartAddress { get; set; }
        internal string EndAddress { get; set; }
        internal bool Writable { get; set; }
        internal bool Executable { get; set; }
        internal List<string> Regions { get; set; }
    }
}
