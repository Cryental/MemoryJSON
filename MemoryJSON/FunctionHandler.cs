using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MemoryJSON
{
    public class FunctionHandler
    {
        private readonly Dictionary<string, string> _aobScannedValues;
        private readonly Dictionary<string, string> _offsets;
        private readonly Mem _sharedMemory;
        private readonly dynamic _sharedTabData;

        public FunctionHandler(Mem sharedMemory,
            Dictionary<string, string> offsets,
            Dictionary<string, string> aobScannedValues,
            dynamic sharedTabData)
        {
            _sharedMemory = sharedMemory;
            _offsets = offsets;
            _aobScannedValues = aobScannedValues;
            _sharedTabData = sharedTabData;
        }
    }
}
