using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Principal;
using MemoryJSON.AmberJSON;
using MemoryJSON.Structs;
using Newtonsoft.Json.Linq;

namespace MemoryJSON
{
    public class Trainer
    {
        private readonly Dictionary<string, AoBScan> _aobScan;
        private readonly Dictionary<string, string> _aobScannedValues;

        private readonly dynamic _mainData;

        private readonly Dictionary<string, string> _offsets;

        private readonly string _processName;
        private readonly string _version;

        public readonly Info Info;

        private Mem _memory;

        public Trainer(string jsonData)
        {
            _mainData = JObject.Parse(jsonData);

            Info = new Info
            {
                Name = (string) _mainData.name, Description = (string) _mainData.description,
                Author = (string) _mainData.author, Website = (string) _mainData.website
            };

            _processName = (string) _mainData.processName;
            _version = (string) _mainData.version;

            _offsets = new Dictionary<string, string>();

            foreach (var item in _mainData.offsets) _offsets.Add((string) item.name, (string) item.value);

            _aobScan = new Dictionary<string, AoBScan>();

            foreach (var item in _mainData.aobScan)
            {
                var regionList = new List<int>();

                foreach (var region in item.regions)
                    regionList.Add(Helpers.ConvertFromHexStringToInt32((string) region));

                _aobScan.Add((string) item.name,
                    new AoBScan
                    {
                        Name = (string) item.name,
                        Value = (string) item.value,
                        StartAddress = (string) item.startAddress,
                        EndAddress = (string) item.endAddress,
                        Readable = (bool) item.readable,
                        Writable = (bool) item.writable,
                        Executable = (bool) item.executable,
                        Regions = regionList.ToArray()
                    });
            }

            _aobScannedValues = new Dictionary<string, string>();
        }

        public bool Inject2Game()
        {
            // Administrator Only
            using (var identity = WindowsIdentity.GetCurrent())
            {
                var principal = new WindowsPrincipal(identity);

                if (!principal.IsInRole(WindowsBuiltInRole.Administrator)) return false;
            }

            // Search Process
            // Multiple Instances Not Allowed
            if (Process.GetProcessesByName(_processName).Length != 1) return false;

            // If value is "all" or empty, do not check the game version.
            if (string.IsNullOrEmpty(_version) || string.IsNullOrWhiteSpace(_version) || _version != "all")
            {
                var process = Process.GetProcessesByName(_processName).FirstOrDefault();
                var filePath = process.MainModule.FileName;

                var versionInfo = FileVersionInfo.GetVersionInfo(filePath);
                var version = versionInfo.FileVersion;

                if (!string.IsNullOrEmpty(version) && version != _version) return false;
            }

            _memory = new Mem();
            return _memory.OpenProcess(_processName);
        }

        public bool InitializeAoB()
        {
            if (_memory == null) return false;

            foreach (var item in _aobScan)
            {
                var name = item.Key;

                var startAddress = Helpers.ConvertFromHexStringToInt64(item.Value.StartAddress);
                var endAddress = Helpers.ConvertFromHexStringToInt64(item.Value.EndAddress);

                var scannedArray = _memory.AoBScan(startAddress, endAddress, item.Value.Value, item.Value.Readable,
                    item.Value.Writable, item.Value.Executable, "", item.Value.Regions).Result.ToArray();

                _aobScannedValues.Add(name, scannedArray.Length > 0 ? $"0x{scannedArray.FirstOrDefault():X}" : "0x0");
            }

            foreach (var item in _aobScannedValues) Console.WriteLine(item.Key + "|" + item.Value);

            return true;
        }

        public TabHandler FindTab(string tabName)
        {
            dynamic foundTab = null;

            foreach (var tab in _mainData.trainers)
                if (tab.tabName == tabName)
                    foundTab = tab.functions;

            if (foundTab == null) throw new Exception("Nothing found with the specified name.");

            return new TabHandler(_memory, _offsets, _aobScannedValues, foundTab);
        }
    }
}