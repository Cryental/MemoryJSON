using System;
using System.Collections.Generic;
using MemoryJSON.Structs;
using Newtonsoft.Json.Linq;

namespace MemoryJSON
{
    public class Trainer
    {
        private readonly Dictionary<string, AoBScan> _aobScan;
        private readonly dynamic _mainData;

        private readonly Dictionary<string, string> _offsets;

        private readonly string _processName;
        private readonly string _version;
        public readonly Info Info;

        public Trainer(string jsonData)
        {
            _mainData = JObject.Parse(jsonData);

            Info = new Info {Name = (string) _mainData.name, Description = (string) _mainData.description};

            _processName = (string) _mainData.processName;
            _version = (string) _mainData.version;

            _offsets = new Dictionary<string, string>();

            foreach (var item in _mainData.offsets)
            {
                _offsets.Add((string) item.name, (string) item.value);
            }

            _aobScan = new Dictionary<string, AoBScan>();

            foreach (var item in _mainData.aobScan)
            {
                var regionList = new List<string>();

                foreach (var region in item.regions)
                {
                    regionList.Add((string) region);
                }

                _aobScan.Add((string) item.name,
                    new AoBScan
                    {
                        Name = (string) item.name,
                        Value = (string) item.value,
                        StartAddress = (string) item.startAddress,
                        EndAddress = (string) item.endAddress,
                        Writable = (bool) item.writable,
                        Executable = (bool) item.executable,
                        Regions = regionList
                    });
            }
        }
    }
}