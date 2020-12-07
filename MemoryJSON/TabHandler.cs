using System;
using System.Collections.Generic;

namespace MemoryJSON
{
    public class TabHandler
    {
        private readonly Dictionary<string, string> _aobScannedValues;
        private readonly Dictionary<string, string> _offsets;
        private readonly Mem _sharedMemory;
        private readonly dynamic _sharedTabData;

        public TabHandler(Mem sharedMemory,
            Dictionary<string, string> offsets,
            Dictionary<string, string> aobScannedValues,
            dynamic sharedTabData)
        {
            _sharedMemory = sharedMemory;
            _offsets = offsets;
            _aobScannedValues = aobScannedValues;
            _sharedTabData = sharedTabData;
        }

        public List<string> GetAllFunctions()
        {
            var tempList = new List<string>();

            foreach (var item in _sharedTabData)
            {
                tempList.Add((string) item.name);
            }

            return tempList;
        }

        public FunctionHandler SearchFunction(string functionName)
        {
            dynamic foundFunction = null;

            foreach (var function in _sharedTabData)
            {
                if ((string) function.name == functionName)
                {
                    foundFunction = function;
                }
            }

            if (foundFunction == null)
            {
                throw new Exception("Nothing found with the specified name.");
            }

            return new FunctionHandler(_sharedMemory, _offsets, _aobScannedValues, foundFunction);
        }
    }
}