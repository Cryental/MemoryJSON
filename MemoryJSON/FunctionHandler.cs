using System;
using System.Collections.Generic;
using MemoryJSON.AmberJSON;
using MemoryJSON.Structs;

namespace MemoryJSON
{
    public class FunctionHandler
    {
        private readonly Dictionary<string, string> _aobScannedValues;
        private readonly Dictionary<string, string> _offsets;
        private readonly dynamic _sharedFunctionData;
        private readonly Mem _sharedMemory;

        private readonly Dictionary<string, dynamic> _dynamicDefinedValues;

        public FunctionHandler(Mem sharedMemory,
            Dictionary<string, string> offsets,
            Dictionary<string, string> aobScannedValues,
            dynamic sharedFunctionData)
        {
            _sharedMemory = sharedMemory;
            _offsets = offsets;
            _aobScannedValues = aobScannedValues;
            _sharedFunctionData = sharedFunctionData;

            foreach (var item in _offsets)
            {
                Console.WriteLine(item.Key);
            }
            _dynamicDefinedValues = new Dictionary<string, dynamic>();
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

        public bool Enable()
        {
            if (_sharedFunctionData.enabled == null)
            {
                return false;
            }

            foreach (var procedure in _sharedFunctionData.enabled.procedures)
            {
                try
                {
                    ProcedureHandler(procedure);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }
            }

            return true;
        }

        public bool Disable()
        {
            if (_sharedFunctionData.disabled == null)
            {
                return false;
            }

            foreach (var procedure in _sharedFunctionData.disabled.procedures)
            {
                try
                {
                    ProcedureHandler(procedure);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }
            }

            return true;
        }

        private void ProcedureHandler(dynamic procedureItem, string setValue = "")
        {
            var functionName = (string) procedureItem.function;

            if (!WordDict.SupportedFunctions.Contains(functionName))
            {
                return;
            }

            switch (functionName)
            {
                case "WriteMemory":
                    if (procedureItem.address != null && procedureItem.type != null && procedureItem.value != null &&
                        WordDict.SupportedTypes.Contains((string) procedureItem.type))
                    {
                        var address = ParseSpecificCodes((string) procedureItem.address, setValue);
                        var type = ParseSpecificCodes((string) procedureItem.type, setValue);
                        var value = ParseSpecificCodes((string) procedureItem.value, setValue);

                        _sharedMemory.WriteMemory(address, type, value);
                    }

                    break;
                case "CreateCodeCave":
                    if (procedureItem.address != null && procedureItem.newBytes != null && procedureItem.replaceCount != null && procedureItem.size != null)
                    {
                        var address = ParseSpecificCodes((string)procedureItem.address);
                        var newBytes = ParseSpecificCodes((string)procedureItem.newBytes);
                        var replaceCount = (int)procedureItem.replaceCount;
                        var size = (int)procedureItem.size;

                        _sharedMemory.CreateCodeCave(address, newBytes, replaceCount, size);
                    }

                    break;
            }
        }

        private string ParseSpecificCodes(string target, string setValue = "")
        {
            var addressType = Helpers.GetTypeFromString(target);
            var outputString = target;

            switch (addressType)
            {
                case "aobScan":
                {
                    var variableName = Helpers.GetStringFromCode(target);

                    outputString = _aobScannedValues.ContainsKey(variableName) ? _aobScannedValues[variableName] : "";

                    break;
                }
                case "offset":
                {
                    var variableName = Helpers.GetStringFromCode(target);

                    outputString = _offsets.ContainsKey(variableName) ? _offsets[variableName] : "";

                    break;
                }
                case "local":
                {
                    var variableName = Helpers.GetStringFromCode(target);

                    outputString = _dynamicDefinedValues.ContainsKey(target) ? (string) _dynamicDefinedValues[variableName] : "";

                    break;
                }
                case "setValue":
                {
                    outputString = target == "{{$value}}" ? setValue : "";

                    break;
                }
            }

            return outputString;
        }
    }
}