using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using MemoryJSON.Structs;

namespace MemoryJSON
{
    public class FunctionHandler
    {
        private readonly Dictionary<string, string> _aobScannedValues;
        private readonly Dictionary<string, string> _offsets;
        private readonly Mem _sharedMemory;
        private readonly dynamic _sharedFunctionData;

        public FunctionHandler(Mem sharedMemory,
            Dictionary<string, string> offsets,
            Dictionary<string, string> aobScannedValues,
            dynamic sharedFunctionData)
        {
            _sharedMemory = sharedMemory;
            _offsets = offsets;
            _aobScannedValues = aobScannedValues;
            _sharedFunctionData = sharedFunctionData;
        }

        public new FunctionType GetType()
        {
            if (_sharedFunctionData.setValue != null)
            {
                return FunctionType.SetValue;
            }

            if (_sharedFunctionData.enabled != null && _sharedFunctionData.disabled != null)
            {
                return FunctionType.Toggle;
            }

            return FunctionType.Unknown;
        }
    }
}
