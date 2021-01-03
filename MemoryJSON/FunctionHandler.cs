using System;
using System.Collections.Generic;
using MemoryJSON;
using MemoryJSON.Structs;

namespace MemoryJSON
{
    public class FunctionHandler
    {
        private readonly Dictionary<string, string> _aobScannedValues;

        private readonly Dictionary<string, dynamic> _dynamicDefinedValues;
        private readonly Dictionary<string, string> _offsets;
        private readonly dynamic _sharedFunctionData;
        private readonly Mem _sharedMemory;

        public FunctionHandler(Mem sharedMemory,
            Dictionary<string, string> offsets,
            Dictionary<string, string> aobScannedValues,
            dynamic sharedFunctionData)
        {
            _sharedMemory = sharedMemory;
            _offsets = offsets;
            _aobScannedValues = aobScannedValues;
            _sharedFunctionData = sharedFunctionData;

            foreach (var item in _offsets) Console.WriteLine(item.Key);

            _dynamicDefinedValues = new Dictionary<string, dynamic>();
        }

        public new FunctionType GetType()
        {
            if (_sharedFunctionData.setValue != null) return FunctionType.SetValue;

            if (_sharedFunctionData.enabled != null && _sharedFunctionData.disabled != null) return FunctionType.Toggle;

            return FunctionType.Unknown;
        }

        public bool SetValue(string value)
        {
            if (_sharedMemory == null) return false;

            if (_sharedFunctionData.setValue == null) return false;

            if (GetType() != FunctionType.SetValue) return false;

            foreach (var procedure in _sharedFunctionData.setValue.procedures)
                try
                {
                    ProcedureHandler(procedure, value);
                }
                catch (Exception e)
                {
                    return false;
                }

            return true;
        }

        public bool Enable()
        {
            if (_sharedMemory == null) return false;

            if (_sharedFunctionData.enabled == null) return false;

            if (GetType() != FunctionType.Toggle) return false;

            foreach (var procedure in _sharedFunctionData.enabled.procedures)
                try
                {
                    ProcedureHandler(procedure);
                }
                catch
                {
                    return false;
                }

            return true;
        }

        public bool Disable()
        {
            if (_sharedMemory == null) return false;

            if (_sharedFunctionData.disabled == null) return false;

            if (GetType() != FunctionType.Toggle) return false;

            foreach (var procedure in _sharedFunctionData.disabled.procedures)
                try
                {
                    ProcedureHandler(procedure);
                }
                catch
                {
                    return false;
                }

            return true;
        }

        private void ProcedureHandler(dynamic procedureItem, string setValue = "")
        {
            if (_sharedMemory == null) return;

            var functionName = (string) procedureItem.function;

            if (!WordDict.SupportedFunctions.Contains(functionName)) return;

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
                    if (procedureItem.address != null && procedureItem.newBytes != null &&
                        procedureItem.replaceCount != null && procedureItem.size != null)
                    {
                        var address = ParseSpecificCodes((string) procedureItem.address);
                        var newBytes = ParseSpecificCodes((string) procedureItem.newBytes);
                        var replaceCount = (int) procedureItem.replaceCount;
                        var size = (int) procedureItem.size;

                        _sharedMemory.CreateCodeCave(address, newBytes, replaceCount, size);
                    }

                    break;
                case "FreezeValue":
                    if (procedureItem.address != null && procedureItem.type != null && procedureItem.value != null &&
                        WordDict.SupportedTypes.Contains((string) procedureItem.type))
                    {
                        var address = ParseSpecificCodes((string) procedureItem.address, setValue);
                        var type = ParseSpecificCodes((string) procedureItem.type, setValue);
                        var value = ParseSpecificCodes((string) procedureItem.value, setValue);

                        _sharedMemory.FreezeValue(address, type, value);
                    }

                    break;
                case "UnfreezeValue":
                    if (procedureItem.address != null)
                    {
                        var address = ParseSpecificCodes((string) procedureItem.address, setValue);

                        _sharedMemory.UnfreezeValue(address);
                    }

                    break;
                case "ReadBytes":
                    if (procedureItem.defineName != null && procedureItem.address != null &&
                        procedureItem.length != null)
                    {
                        var searchedValue = _sharedMemory.ReadBytes(procedureItem.address, procedureItem.length);

                        _dynamicDefinedValues.Add(procedureItem.defineName, searchedValue);
                    }

                    break;
                case "ReadFloat":
                    if (procedureItem.defineName != null && procedureItem.address != null)
                    {
                        var searchedValue = _sharedMemory.ReadFloat(procedureItem.address);

                        _dynamicDefinedValues.Add(procedureItem.defineName, searchedValue);
                    }

                    break;
                case "ReadString":
                    if (procedureItem.defineName != null && procedureItem.address != null &&
                        procedureItem.length != null)
                    {
                        var searchedValue = _sharedMemory.ReadString(procedureItem.address, "", procedureItem.length);

                        _dynamicDefinedValues.Add(procedureItem.defineName, searchedValue);
                    }

                    break;
                case "ReadDouble":
                    if (procedureItem.defineName != null && procedureItem.address != null)
                    {
                        var searchedValue = _sharedMemory.ReadDouble(procedureItem.address);

                        _dynamicDefinedValues.Add(procedureItem.defineName, searchedValue);
                    }

                    break;
                case "ReadUIntPtr":
                    if (procedureItem.defineName != null && procedureItem.address != null)
                    {
                        var searchedValue = _sharedMemory.ReadUIntPtr(procedureItem.address);

                        _dynamicDefinedValues.Add(procedureItem.defineName, searchedValue);
                    }

                    break;
                case "ReadInt":
                    if (procedureItem.defineName != null && procedureItem.address != null)
                    {
                        var searchedValue = _sharedMemory.ReadInt(procedureItem.address);

                        _dynamicDefinedValues.Add(procedureItem.defineName, searchedValue);
                    }

                    break;
                case "ReadLong":
                    if (procedureItem.defineName != null && procedureItem.address != null)
                    {
                        var searchedValue = _sharedMemory.ReadLong(procedureItem.address);

                        _dynamicDefinedValues.Add(procedureItem.defineName, searchedValue);
                    }

                    break;
                case "Read2Byte":
                    if (procedureItem.defineName != null && procedureItem.address != null)
                    {
                        var searchedValue = _sharedMemory.Read2Byte(procedureItem.address);

                        _dynamicDefinedValues.Add(procedureItem.defineName, searchedValue);
                    }

                    break;
                case "ReadBits":
                    if (procedureItem.defineName != null && procedureItem.address != null)
                    {
                        var searchedValue = _sharedMemory.ReadBits(procedureItem.address);

                        _dynamicDefinedValues.Add(procedureItem.defineName, searchedValue);
                    }

                    break;
                case "ReadByte":
                    if (procedureItem.defineName != null && procedureItem.address != null)
                    {
                        var searchedValue = _sharedMemory.ReadByte(procedureItem.address);

                        _dynamicDefinedValues.Add(procedureItem.defineName, searchedValue);
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

                    outputString = _dynamicDefinedValues.ContainsKey(target)
                        ? (string) _dynamicDefinedValues[variableName]
                        : "";

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