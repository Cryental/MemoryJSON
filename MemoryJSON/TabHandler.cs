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
    }
}