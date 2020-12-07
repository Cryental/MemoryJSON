using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Principal;
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

        private Mem _memory;

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

        public bool Inject2Game()
        {
            // Administrator Only
            using (var identity = WindowsIdentity.GetCurrent())
            {
                var principal = new WindowsPrincipal(identity);

                if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
                {
                    return false;
                }
            }

            // Search Process
            // Multiple Instances Not Allowed
            if (Process.GetProcessesByName(_processName).Length != 1)
            {
                return false;
            }

            // If value is "all" or empty, do not check the game version.
            if (string.IsNullOrEmpty(_version) || string.IsNullOrWhiteSpace(_version) || _version != "all")
            {
                var process = Process.GetProcessesByName(_processName).FirstOrDefault();
                var filePath = process.MainModule.FileName;

                var versionInfo = FileVersionInfo.GetVersionInfo(filePath);
                var version = versionInfo.FileVersion;

                if (!string.IsNullOrEmpty(version) && version != _version)
                {
                    return false;
                }
            }

            _memory = new Mem();
            return _memory.OpenProcess(_processName);
        }
    }
}