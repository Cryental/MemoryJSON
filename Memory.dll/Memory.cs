using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

public struct MemoryRegionResult
{
    public UIntPtr CurrentBaseAddress { get; set; }
    public long RegionSize { get; set; }
    public UIntPtr RegionBase { get; set; }
}

public class Mem
{
    #region DllImports

    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

#if WINXP
#else
    [DllImport("kernel32.dll", EntryPoint = "VirtualQueryEx")]
    public static extern UIntPtr Native_VirtualQueryEx(IntPtr hProcess,
        UIntPtr lpAddress,
        out MEMORY_BASIC_INFORMATION32 lpBuffer,
        UIntPtr dwLength);

    [DllImport("kernel32.dll", EntryPoint = "VirtualQueryEx")]
    public static extern UIntPtr Native_VirtualQueryEx(IntPtr hProcess,
        UIntPtr lpAddress,
        out MEMORY_BASIC_INFORMATION64 lpBuffer,
        UIntPtr dwLength);

    [DllImport("kernel32.dll")]
    private static extern uint GetLastError();

    [DllImport("kernel32.dll")]
    private static extern int VirtualQueryEx(int hProcess,
        long lpAddress,
        out MemoryBasicInformation64 lpBuffer,
        uint dwLength);

    public UIntPtr VirtualQueryEx(IntPtr hProcess, UIntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer)
    {
        UIntPtr retVal;

        if (Is64Bit || IntPtr.Size == 8)
        {
            var tmp64 = new MEMORY_BASIC_INFORMATION64();
            retVal = Native_VirtualQueryEx(hProcess, lpAddress, out tmp64,
                new UIntPtr((uint)Marshal.SizeOf(tmp64)));

            lpBuffer.BaseAddress = tmp64.BaseAddress;
            lpBuffer.AllocationBase = tmp64.AllocationBase;
            lpBuffer.AllocationProtect = tmp64.AllocationProtect;
            lpBuffer.RegionSize = (long)tmp64.RegionSize;
            lpBuffer.State = tmp64.State;
            lpBuffer.Protect = tmp64.Protect;
            lpBuffer.Type = tmp64.Type;

            return retVal;
        }

        var tmp32 = new MEMORY_BASIC_INFORMATION32();

        retVal = Native_VirtualQueryEx(hProcess, lpAddress, out tmp32, new UIntPtr((uint)Marshal.SizeOf(tmp32)));

        lpBuffer.BaseAddress = tmp32.BaseAddress;
        lpBuffer.AllocationBase = tmp32.AllocationBase;
        lpBuffer.AllocationProtect = tmp32.AllocationProtect;
        lpBuffer.RegionSize = tmp32.RegionSize;
        lpBuffer.State = tmp32.State;
        lpBuffer.Protect = tmp32.Protect;
        lpBuffer.Type = tmp32.Type;

        return retVal;
    }

    [DllImport("kernel32.dll")]
    private static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);
#endif

    [DllImport("kernel32.dll")]
    private static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

    [DllImport("kernel32.dll")]
    private static extern uint SuspendThread(IntPtr hThread);

    [DllImport("kernel32.dll")]
    private static extern int ResumeThread(IntPtr hThread);

    [DllImport("dbghelp.dll")]
    private static extern bool MiniDumpWriteDump(IntPtr hProcess,
        int ProcessId,
        IntPtr hFile,
        MINIDUMP_TYPE DumpType,
        IntPtr ExceptionParam,
        IntPtr UserStreamParam,
        IntPtr CallackParam);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern int GetWindowLong(IntPtr hWnd, int nIndex);

    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = false)]
    public static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr w, IntPtr l);

    [DllImport("kernel32.dll")]
    private static extern bool WriteProcessMemory(IntPtr hProcess,
        UIntPtr lpBaseAddress,
        string lpBuffer,
        UIntPtr nSize,
        out IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    private static extern int GetProcessId(IntPtr handle);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern uint GetPrivateProfileString(string lpAppName,
        string lpKeyName,
        string lpDefault,
        StringBuilder lpReturnedString,
        uint nSize,
        string lpFileName);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    private static extern bool VirtualFreeEx(IntPtr hProcess, UIntPtr lpAddress, UIntPtr dwSize, uint dwFreeType);

    [DllImport("kernel32.dll")]
    private static extern bool ReadProcessMemory(IntPtr hProcess,
        UIntPtr lpBaseAddress,
        [Out] byte[] lpBuffer,
        UIntPtr nSize,
        IntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll")]
    private static extern bool ReadProcessMemory(IntPtr hProcess,
        UIntPtr lpBaseAddress,
        [Out] byte[] lpBuffer,
        UIntPtr nSize,
        out ulong lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadProcessMemory(IntPtr hProcess,
        long lpBaseAddress,
        [In][Out] byte[] lpBuffer,
        ulong dwSize,
        out IntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll")]
    private static extern bool ReadProcessMemory(IntPtr hProcess,
        UIntPtr lpBaseAddress,
        [Out] IntPtr lpBuffer,
        UIntPtr nSize,
        out ulong lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    private static extern UIntPtr VirtualAllocEx(IntPtr hProcess,
        UIntPtr lpAddress,
        uint dwSize,
        uint flAllocationType,
        uint flProtect);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true)]
    public static extern UIntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll", EntryPoint = "CloseHandle")]
    private static extern bool _CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll")]
    public static extern int CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32", SetLastError = true, ExactSpelling = true)]
    public static extern int WaitForSingleObject(IntPtr handle, int milliseconds);

    [DllImport("kernel32.dll")]
    private static extern bool VirtualProtectEx(IntPtr hProcess,
        IntPtr lpAddress,
        UIntPtr dwSize,
        uint flNewProtect,
        out uint lpflOldProtect);


    [DllImport("kernel32.dll")]
    private static extern bool WriteProcessMemory(IntPtr hProcess,
        UIntPtr lpBaseAddress,
        byte[] lpBuffer,
        UIntPtr nSize,
        IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    private static extern bool WriteProcessMemory(IntPtr hProcess,
        UIntPtr lpBaseAddress,
        byte[] lpBuffer,
        UIntPtr nSize,
        out IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32")]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess,
        IntPtr lpThreadAttributes,
        uint dwStackSize,
        UIntPtr lpStartAddress,
        UIntPtr lpParameter,
        uint dwCreationFlags,
        out IntPtr lpThreadId);

    [DllImport("kernel32")]
    public static extern bool IsWow64Process(IntPtr hProcess, out bool lpSystemInfo);

    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    private int _bufSize = 0x1000;
    private uint _mbiSize;

    private const int PROCESS_CREATE_THREAD = 0x0002;
    private const int PROCESS_QUERY_INFORMATION = 0x0400;
    private const int PROCESS_VM_OPERATION = 0x0008;
    private const int PROCESS_VM_WRITE = 0x0020;
    private const int PROCESS_VM_READ = 0x0010;

    private const uint MEM_FREE = 0x10000;
    private const uint MEM_COMMIT = 0x00001000;
    private const uint MEM_RESERVE = 0x00002000;

    private const uint PAGE_READONLY = 0x02;
    private const uint PAGE_READWRITE = 0x04;
    private const uint PAGE_WRITECOPY = 0x08;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint PAGE_EXECUTE_WRITECOPY = 0x80;
    private const uint PAGE_EXECUTE = 0x10;
    private const uint PAGE_EXECUTE_READ = 0x20;

    private const uint PAGE_GUARD = 0x100;
    private const uint PAGE_NOACCESS = 0x01;

    private readonly uint MEM_PRIVATE = 0x20000;
    private readonly uint MEM_IMAGE = 0x1000000;
    private readonly uint MEM_MAPPED = 0x40000;

    #endregion

    public IntPtr pHandle;

    private readonly Dictionary<string, CancellationTokenSource> FreezeTokenSrcs =
        new Dictionary<string, CancellationTokenSource>();

    public Process theProc;

    public enum MINIDUMP_TYPE
    {
        MiniDumpNormal = 0x00000000, MiniDumpWithDataSegs = 0x00000001, MiniDumpWithFullMemory = 0x00000002,
        MiniDumpWithHandleData = 0x00000004, MiniDumpFilterMemory = 0x00000008, MiniDumpScanMemory = 0x00000010,
        MiniDumpWithUnloadedModules = 0x00000020, MiniDumpWithIndirectlyReferencedMemory = 0x00000040,
        MiniDumpFilterModulePaths = 0x00000080, MiniDumpWithProcessThreadData = 0x00000100,
        MiniDumpWithPrivateReadWriteMemory = 0x00000200, MiniDumpWithoutOptionalData = 0x00000400,
        MiniDumpWithFullMemoryInfo = 0x00000800, MiniDumpWithThreadInfo = 0x00001000, MiniDumpWithCodeSegs = 0x00002000
    }

    private bool IsDigitsOnly(string str)
    {
        foreach (var c in str)
        {
            if (c < '0' || c > '9')
            {
                return false;
            }
        }

        return true;
    }

    public void FreezeValue(string address, string type, string value, string file = "")
    {
        var cts = new CancellationTokenSource();

        if (FreezeTokenSrcs.ContainsKey(address))
        {
            Debug.WriteLine("Changing Freezing Address " + address + " Value " + value);
            try
            {
                FreezeTokenSrcs[address].Cancel();
                FreezeTokenSrcs.Remove(address);
            }
            catch
            {
                Debug.WriteLine("ERROR: Avoided a crash. Address " + address + " was not frozen.");
            }
        }
        else
        {
            Debug.WriteLine("Adding Freezing Address " + address + " Value " + value);
        }

        FreezeTokenSrcs.Add(address, cts);

        Task.Factory.StartNew(() =>
        {
            while (!cts.Token.IsCancellationRequested)
            {
                WriteMemory(address, type, value, file);
                Thread.Sleep(25);
            }
        }, cts.Token);
    }

    public void UnfreezeValue(string address)
    {
        Debug.WriteLine("Un-Freezing Address " + address);
        try
        {
            FreezeTokenSrcs[address].Cancel();
            FreezeTokenSrcs.Remove(address);
        }
        catch
        {
            Debug.WriteLine("ERROR: Address " + address + " was not frozen.");
        }
    }

    public bool OpenProcess(int pid)
    {
        try
        {
            if (theProc != null && theProc.Id == pid)
            {
                return true;
            }

            if (pid <= 0)
            {
                Debug.WriteLine("ERROR: OpenProcess given proc ID 0.");
                return false;
            }

            theProc = Process.GetProcessById(pid);

            if (theProc != null && !theProc.Responding)
            {
                Debug.WriteLine("ERROR: OpenProcess: Process is not responding or null.");
                return false;
            }

            pHandle = OpenProcess(0x1F0FFF, true, pid);
            Process.EnterDebugMode();

            if (pHandle == IntPtr.Zero)
            {
                var eCode = Marshal.GetLastWin32Error();
            }

            mainModule = theProc.MainModule;

            GetModules();

            Is64Bit = Environment.Is64BitOperatingSystem && IsWow64Process(pHandle, out var retVal) && !retVal;

            _mbiSize = (uint)Marshal.SizeOf<MemoryBasicInformation64>();

            Debug.WriteLine("Program is operating at Administrative level. Process #" + theProc +
                            " is open and modules are stored.");

            return true;
        }
        catch
        {
            Debug.WriteLine(
                "ERROR: OpenProcess has crashed. Are you trying to hack a x64 game? https://github.com/erfg12/memory.dll/wiki/64bit-Games");
            return false;
        }
    }

    public long FindPattern(byte[] buffer, byte[] pattern, string mask)
    {
        var length = mask.Length;
        var num2 = 0;
        while (num2 < buffer.Length - length)
        {
            var flag = true;
            var index = 0;
            while (true)
            {
                if (index < length)
                {
                    if (mask[index] == '?' || pattern[index] == buffer[num2 + index])
                    {
                        index++;
                        continue;
                    }

                    flag = false;
                }

                if (flag)
                {
                    return num2;
                }

                num2++;
                break;
            }
        }

        return -1L;
    }

    public T ReadMemory<T>(long address, int size, bool unicode = false)
    {
        var lpBuffer = typeof(T) != typeof(string) ? !(typeof(T) == typeof(byte[]))
                ? new byte[Marshal.SizeOf(typeof(T))]
                : new byte[size] :
            !unicode ? new byte[size] : new byte[size * 2 + 1];

        if (!ReadProcessMemory(pHandle, (UIntPtr)address, lpBuffer, (UIntPtr)size, out _))
        {
            return default;
        }

        if (typeof(T) == typeof(byte[]))
        {
            return (T)Convert.ChangeType(lpBuffer, typeof(byte[]));
        }

        if (typeof(T) == typeof(string))
        {
            return !unicode
                ? (T)Convert.ChangeType(Encoding.ASCII.GetString(lpBuffer), typeof(string))
                : (T)Convert.ChangeType(Encoding.Unicode.GetString(lpBuffer), typeof(string));
        }

        var handle = GCHandle.Alloc(lpBuffer, GCHandleType.Pinned);
        var ss = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
        handle.Free();
        return ss;
    }

    public long[] FindPatterns(byte[] buffer, string stringPattern, out long time)
    {
        var pattern = ConvertPattern(stringPattern);
        var mask = string.Empty;

        var stringByteArray = stringPattern.Split(' ');

        foreach (var t in stringByteArray)
        {
            if (t == "??")
            {
                mask += "?";
            }
            else
            {
                mask += "x";
            }
        }

        var w = Stopwatch.StartNew();
        var list = new List<long>();
        var length = mask.Length;
        var num2 = 0;
        while (num2 < buffer.Length - length)
        {
            var flag = true;
            var index = 0;
            while (true)
            {
                if (index < length)
                {
                    if (mask[index] == '?' || pattern[index] == buffer[num2 + index])
                    {
                        index++;
                        continue;
                    }

                    flag = false;
                }

                if (flag)
                {
                    list.Add(num2);
                }

                num2++;
                break;
            }
        }

        w.Stop();
        time = w.ElapsedMilliseconds;
        return list.ToArray();
    }

    private long[] FindPatternEx(long start, long end, byte[] pattern, string mask, int[] size)
    {
        var lpBaseAddress = start;
        var source = new List<long>();

        foreach (var f in size)
        {
            if (end - lpBaseAddress > f && f != 0 || end - lpBaseAddress < f && f != 0)
            {
                return source.ToArray<long>();
            }

            while (lpBaseAddress < end)
            {
                _bufSize = (int)(end - start);
                var lpBuffer = new byte[_bufSize];
                if (!ReadProcessMemory(pHandle, (UIntPtr)lpBaseAddress, lpBuffer, (UIntPtr)_bufSize, out _))
                {
                    lpBaseAddress += _bufSize;
                    continue;
                }

                var num3 = FindPattern(lpBuffer, pattern, mask);
                if (num3 != -1L)
                {
                    source.Add(lpBaseAddress + num3);
                }

                lpBaseAddress += _bufSize;
            }

            return source.ToArray<long>();
        }

        return source.ToArray<long>();
    }

    public MemoryBasicInformation64[] MemoryBasicInformation;

    public long AobScan(string stringPattern, out long time, int size = 0, bool region = false)
    {
        int[] sizeT = { size };

        return AobScan(stringPattern, out time, sizeT, region);
    }

    public long AobScan(string stringPattern, out long time, int[] size, bool region = false)
    {
        UpdateMemReg();
        Array.Reverse(MemoryBasicInformation);

        var w = Stopwatch.StartNew();

        var pattern = ConvertPattern(stringPattern);
        var mask = string.Empty;

        var stringByteArray = stringPattern.Split(' ');

        foreach (var t in stringByteArray)
        {
            if (t == "??")
            {
                mask += "?";
            }
            else
            {
                mask += "x";
            }
        }

        foreach (var mbi in MemoryBasicInformation)
        {
            var numArray = FindPatternEx((long)mbi.BaseAddress, (long)(mbi.RegionSize + mbi.BaseAddress), pattern,
                mask, size);

            if (numArray.Length == 0)
            {
                continue;
            }

            if (region)
            {
                Console.WriteLine("Found => 0x" + mbi.RegionSize.ToString("X"));
            }

            w.Stop();
            time = w.ElapsedMilliseconds;

            return numArray[0];
        }

        time = w.ElapsedMilliseconds;
        return 0;
    }

    public long[] AoBScanEx(string stringPattern, out long time, int size = 0, bool region = false)
    {
        int[] sizeT = { size };

        return AoBScanEx(stringPattern, out time, sizeT, region);
    }

    public long[] AoBScanEx(string stringPattern, out long time, int[] size, bool region = false)
    {
        var temp = new List<long>();

        var pattern = ConvertPattern(stringPattern);
        var mask = string.Empty;

        var stringByteArray = stringPattern.Split(' ');

        foreach (var t in stringByteArray)
        {
            if (t == "??")
            {
                mask += "?";
            }
            else
            {
                mask += "x";
            }
        }

        UpdateMemReg();

        foreach (var mbi in MemoryBasicInformation)
        {
            var numArray = FindPatternEx((long)mbi.BaseAddress, (long)(mbi.RegionSize + mbi.BaseAddress), pattern,
                mask, size);

            if (numArray.Length == 0)
            {
                continue;
            }

            if (region)
            {
                foreach (var f in numArray)
                {
                    Console.WriteLine("Found => " + f.ToString("X") + "(0x" + mbi.RegionSize.ToString("X") + ")");
                }
            }

            temp.AddRange(numArray);
        }

        time = 0;
        return temp.ToArray();
    }

    private byte[] ConvertPattern(string pattern)
    {
        var convertertedArray = new List<byte>();
        foreach (var each in pattern.Split(' '))
        {
            if (each == "??")
            {
                convertertedArray.Add(Convert.ToByte("0", 16));
            }
            else
            {
                convertertedArray.Add(Convert.ToByte(each, 16));
            }
        }

        return convertertedArray.ToArray();
    }

    private void UpdateMemReg()
    {
        GetSystemInfo(out var sys_info);

        var lpAddress = (long)sys_info.minimumApplicationAddress.ToUInt64();
        var source = new List<MemoryBasicInformation64>();

        while (VirtualQueryEx((int)pHandle, lpAddress, out var memoryBasicInformation, _mbiSize) != 0)
        {
            if ((memoryBasicInformation.State & 0x1000) != 0)
            {
                source.Add(memoryBasicInformation);
            }

            lpAddress = (long)(memoryBasicInformation.BaseAddress + memoryBasicInformation.RegionSize);
        }

        MemoryBasicInformation = source.ToArray<MemoryBasicInformation64>();
    }

    public bool OpenProcess(string proc)
    {
        return OpenProcess(GetProcIdFromName(proc));
    }

    public bool IsAdmin()
    {
        using (var identity = WindowsIdentity.GetCurrent())
        {
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
    }

    public bool Is64Bit { get; private set; }


    public void GetModules()
    {
        if (theProc == null)
        {
            return;
        }

        modules.Clear();
        foreach (ProcessModule Module in theProc.Modules)
        {
            if (!string.IsNullOrEmpty(Module.ModuleName) && !modules.ContainsKey(Module.ModuleName))
            {
                modules.Add(Module.ModuleName, Module.BaseAddress);
            }
        }
    }

    public void SetFocus()
    {
        SetForegroundWindow(theProc.MainWindowHandle);
    }

    public int GetProcIdFromName(string name)
    {
        var processlist = Process.GetProcesses();

        if (name.ToLower().Contains(".exe"))
        {
            name = name.Replace(".exe", "");
        }

        if (name.ToLower().Contains(".bin"))
        {
            name = name.Replace(".bin", "");
        }

        foreach (var theprocess in processlist)
        {
            if (theprocess.ProcessName.Equals(name, StringComparison.CurrentCultureIgnoreCase))
            {
                return theprocess.Id;
            }
        }

        return 0;
    }


    public string LoadCode(string name, string file)
    {
        var returnCode = new StringBuilder(1024);
        uint read_ini_result;

        if (file != "")
        {
            read_ini_result =
                GetPrivateProfileString("codes", name, "", returnCode, (uint)returnCode.Capacity, file);
        }
        else
        {
            returnCode.Append(name);
        }

        return returnCode.ToString();
    }

    private int LoadIntCode(string name, string path)
    {
        try
        {
            var intValue = Convert.ToInt32(LoadCode(name, path), 16);
            if (intValue >= 0)
            {
                return intValue;
            }

            return 0;
        }
        catch
        {
            Debug.WriteLine("ERROR: LoadIntCode function crashed!");
            return 0;
        }
    }

    public Dictionary<string, IntPtr> modules = new Dictionary<string, IntPtr>();

    public void ThreadStartClient(string func, string name)
    {
        using (var pipeStream = new NamedPipeClientStream(name))
        {
            if (!pipeStream.IsConnected)
            {
                pipeStream.Connect();
            }

            using (var sw = new StreamWriter(pipeStream))
            {
                if (!sw.AutoFlush)
                {
                    sw.AutoFlush = true;
                }

                sw.WriteLine(func);
            }
        }
    }

    private ProcessModule mainModule;

    public string CutString(string str)
    {
        var sb = new StringBuilder();
        foreach (var c in str)
        {
            if (c >= ' ' && c <= '~')
            {
                sb.Append(c);
            }
            else
            {
                break;
            }
        }

        return sb.ToString();
    }

    public string SanitizeString(string str)
    {
        var sb = new StringBuilder();
        foreach (var c in str)
        {
            if (c >= ' ' && c <= '~')
            {
                sb.Append(c);
            }
        }

        return sb.ToString();
    }

    #region readMemory

    public byte[] ReadBytes(string code, long length, string file = "")
    {
        var memory = new byte[length];
        var theCode = GetCode(code, file);

        if (!ReadProcessMemory(pHandle, theCode, memory, (UIntPtr)length, IntPtr.Zero))
        {
            return null;
        }

        return memory;
    }

    public byte[] ReadBytes(long address, int length)
    {
        var lpBuffer = new byte[length];
        ReadProcessMemory(pHandle, (UIntPtr)address, lpBuffer, (UIntPtr)length, out _);

        return lpBuffer;
    }

    public float ReadFloat(string code, string file = "", bool round = true)
    {
        var memory = new byte[4];

        UIntPtr theCode;
        theCode = GetCode(code, file);
        try
        {
            if (ReadProcessMemory(pHandle, theCode, memory, (UIntPtr)4, IntPtr.Zero))
            {
                var address = BitConverter.ToSingle(memory, 0);
                var returnValue = address;
                if (round)
                {
                    returnValue = (float)Math.Round(address, 2);
                }

                return returnValue;
            }

            return 0;
        }
        catch
        {
            return 0;
        }
    }

    public string ReadString(string code, string file = "", int length = 32, bool zeroTerminated = true)
    {
        var memoryNormal = new byte[length];
        UIntPtr theCode;
        theCode = GetCode(code, file);
        if (ReadProcessMemory(pHandle, theCode, memoryNormal, (UIntPtr)length, IntPtr.Zero))
        {
            return zeroTerminated
                ? Encoding.UTF8.GetString(memoryNormal).Split('\0')[0]
                : Encoding.UTF8.GetString(memoryNormal);
        }

        return "";
    }

    public T Read<T>(long address)
    {
        var Buffer = new byte[Marshal.SizeOf(typeof(T))];
        IntPtr ByteRead;
        ReadProcessMemory(pHandle, address, Buffer, (uint)Buffer.Length, out ByteRead);

        var handle = GCHandle.Alloc(Buffer, GCHandleType.Pinned);
        var stuff = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
        handle.Free();
        return stuff;
    }

    public double ReadDouble(string code, string file = "", bool round = true)
    {
        var memory = new byte[8];

        UIntPtr theCode;
        theCode = GetCode(code, file);
        try
        {
            if (ReadProcessMemory(pHandle, theCode, memory, (UIntPtr)8, IntPtr.Zero))
            {
                var address = BitConverter.ToDouble(memory, 0);
                var returnValue = address;
                if (round)
                {
                    returnValue = Math.Round(address, 2);
                }

                return returnValue;
            }

            return 0;
        }
        catch
        {
            return 0;
        }
    }

    public int ReadUIntPtr(UIntPtr code)
    {
        var memory = new byte[4];
        if (ReadProcessMemory(pHandle, code, memory, (UIntPtr)4, IntPtr.Zero))
        {
            return BitConverter.ToInt32(memory, 0);
        }

        return 0;
    }

    public int ReadInt(string code, string file = "")
    {
        var memory = new byte[4];
        UIntPtr theCode;
        theCode = GetCode(code, file);
        if (ReadProcessMemory(pHandle, theCode, memory, (UIntPtr)4, IntPtr.Zero))
        {
            return BitConverter.ToInt32(memory, 0);
        }

        return 0;
    }

    public long ReadLong(string code, string file = "")
    {
        var memory = new byte[16];
        UIntPtr theCode;

        theCode = GetCode(code, file);

        if (ReadProcessMemory(pHandle, theCode, memory, (UIntPtr)16, IntPtr.Zero))
        {
            return BitConverter.ToInt64(memory, 0);
        }

        return 0;
    }

    public ulong ReadUInt(string code, string file = "")
    {
        var memory = new byte[4];
        UIntPtr theCode;
        theCode = GetCode(code, file);

        if (ReadProcessMemory(pHandle, theCode, memory, (UIntPtr)4, IntPtr.Zero))
        {
            return BitConverter.ToUInt64(memory, 0);
        }

        return 0;
    }

    public int Read2ByteMove(string code, int moveQty, string file = "")
    {
        var memory = new byte[4];
        UIntPtr theCode;
        theCode = GetCode(code, file);

        var newCode = UIntPtr.Add(theCode, moveQty);

        if (ReadProcessMemory(pHandle, newCode, memory, (UIntPtr)2, IntPtr.Zero))
        {
            return BitConverter.ToInt32(memory, 0);
        }

        return 0;
    }

    public int ReadIntMove(string code, int moveQty, string file = "")
    {
        var memory = new byte[4];
        UIntPtr theCode;
        theCode = GetCode(code, file);

        var newCode = UIntPtr.Add(theCode, moveQty);

        if (ReadProcessMemory(pHandle, newCode, memory, (UIntPtr)4, IntPtr.Zero))
        {
            return BitConverter.ToInt32(memory, 0);
        }

        return 0;
    }

    public ulong ReadUIntMove(string code, int moveQty, string file = "")
    {
        var memory = new byte[8];
        UIntPtr theCode;
        theCode = GetCode(code, file);

        var newCode = UIntPtr.Add(theCode, moveQty);

        if (ReadProcessMemory(pHandle, newCode, memory, (UIntPtr)8, IntPtr.Zero))
        {
            return BitConverter.ToUInt64(memory, 0);
        }

        return 0;
    }

    public int Read2Byte(string code, string file = "")
    {
        var memoryTiny = new byte[4];

        UIntPtr theCode;
        theCode = GetCode(code, file);

        if (ReadProcessMemory(pHandle, theCode, memoryTiny, (UIntPtr)2, IntPtr.Zero))
        {
            return BitConverter.ToInt32(memoryTiny, 0);
        }

        return 0;
    }

    public int ReadByte(string code, string file = "")
    {
        var memoryTiny = new byte[1];

        var theCode = GetCode(code, file);

        if (ReadProcessMemory(pHandle, theCode, memoryTiny, (UIntPtr)1, IntPtr.Zero))
        {
            return memoryTiny[0];
        }

        return 0;
    }

    public bool[] ReadBits(string code, string file = "")
    {
        var buf = new byte[1];

        var theCode = GetCode(code, file);

        var ret = new bool[8];

        if (!ReadProcessMemory(pHandle, theCode, buf, (UIntPtr)1, IntPtr.Zero))
        {
            return ret;
        }


        if (!BitConverter.IsLittleEndian)
        {
            throw new Exception("Should be little endian");
        }

        for (var i = 0; i < 8; i++)
        {
            ret[i] = Convert.ToBoolean(buf[0] & (1 << i));
        }

        return ret;
    }

    public int ReadPByte(UIntPtr address, string code, string file = "")
    {
        var memory = new byte[4];
        if (ReadProcessMemory(pHandle, address + LoadIntCode(code, file), memory, (UIntPtr)1, IntPtr.Zero))
        {
            return BitConverter.ToInt32(memory, 0);
        }

        return 0;
    }

    public float ReadPFloat(UIntPtr address, string code, string file = "")
    {
        var memory = new byte[4];
        if (ReadProcessMemory(pHandle, address + LoadIntCode(code, file), memory, (UIntPtr)4, IntPtr.Zero))
        {
            var spawn = BitConverter.ToSingle(memory, 0);
            return (float)Math.Round(spawn, 2);
        }

        return 0;
    }

    public int ReadPInt(UIntPtr address, string code, string file = "")
    {
        var memory = new byte[4];
        if (ReadProcessMemory(pHandle, address + LoadIntCode(code, file), memory, (UIntPtr)4, IntPtr.Zero))
        {
            return BitConverter.ToInt32(memory, 0);
        }

        return 0;
    }

    public string ReadPString(UIntPtr address, string code, string file = "")
    {
        var memoryNormal = new byte[32];
        if (ReadProcessMemory(pHandle, address + LoadIntCode(code, file), memoryNormal, (UIntPtr)32, IntPtr.Zero))
        {
            return CutString(Encoding.ASCII.GetString(memoryNormal));
        }

        return "";
    }

    #endregion

    #region writeMemory

    public bool WriteMemory(string code,
        string type,
        string write,
        string file = "",
        Encoding stringEncoding = null)
    {
        var memory = new byte[4];
        var size = 4;

        UIntPtr theCode;
        theCode = GetCode(code, file);

        if (type.ToLower() == "float")
        {
            memory = BitConverter.GetBytes(Convert.ToSingle(write));
            size = 4;
        }
        else
        {
            if (type.ToLower() == "int")
            {
                memory = BitConverter.GetBytes(Convert.ToInt32(write));
                size = 4;
            }
            else
            {
                if (type.ToLower() == "byte")
                {
                    memory = new byte[1];
                    memory[0] = Convert.ToByte(write, 16);
                    size = 1;
                }
                else
                {
                    if (type.ToLower() == "2bytes")
                    {
                        memory = new byte[2];
                        memory[0] = (byte)(Convert.ToInt32(write) % 256);
                        memory[1] = (byte)(Convert.ToInt32(write) / 256);
                        size = 2;
                    }
                    else
                    {
                        if (type.ToLower() == "bytes")
                        {
                            if (write.Contains(",") || write.Contains(" "))
                            {
                                string[] stringBytes;
                                if (write.Contains(","))
                                {
                                    stringBytes = write.Split(',');
                                }
                                else
                                {
                                    stringBytes = write.Split(' ');
                                }

                                var c = stringBytes.Count();
                                memory = new byte[c];
                                for (var i = 0; i < c; i++)
                                {
                                    memory[i] = Convert.ToByte(stringBytes[i], 16);
                                }

                                size = stringBytes.Count();
                            }
                            else
                            {
                                memory = new byte[1];
                                memory[0] = Convert.ToByte(write, 16);
                                size = 1;
                            }
                        }
                        else
                        {
                            if (type.ToLower() == "double")
                            {
                                memory = BitConverter.GetBytes(Convert.ToDouble(write));
                                size = 8;
                            }
                            else
                            {
                                if (type.ToLower() == "long")
                                {
                                    memory = BitConverter.GetBytes(Convert.ToInt64(write));
                                    size = 8;
                                }
                                else
                                {
                                    if (type.ToLower() == "string")
                                    {
                                        if (stringEncoding == null)
                                        {
                                            memory = Encoding.UTF8.GetBytes(write);
                                        }
                                        else
                                        {
                                            memory = stringEncoding.GetBytes(write);
                                        }

                                        size = memory.Length;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        return WriteProcessMemory(pHandle, theCode, memory, (UIntPtr)size, IntPtr.Zero);
    }

    public bool Write<T>(long address, T t)
    {
        var buffer = new byte[Marshal.SizeOf(typeof(T))];

        var gHandle = GCHandle.Alloc(t, GCHandleType.Pinned);
        Marshal.Copy(gHandle.AddrOfPinnedObject(), buffer, 0, buffer.Length);
        gHandle.Free();

        uint oldProtect;
        VirtualProtectEx(pHandle, (IntPtr)address, (UIntPtr)buffer.Length, 0x00000004, out oldProtect);

        IntPtr ptrBytesWritten;
        return WriteProcessMemory(pHandle, (UIntPtr)address, buffer, (UIntPtr)buffer.Length, out ptrBytesWritten);
    }

    public bool WriteMove(string code, string type, string write, int moveQty, string file = "")
    {
        var memory = new byte[4];
        var size = 4;

        UIntPtr theCode;
        theCode = GetCode(code, file);

        if (type == "float")
        {
            memory = new byte[write.Length];
            memory = BitConverter.GetBytes(Convert.ToSingle(write));
            size = write.Length;
        }
        else
        {
            if (type == "int")
            {
                memory = BitConverter.GetBytes(Convert.ToInt32(write));
                size = 4;
            }
            else
            {
                if (type == "double")
                {
                    memory = BitConverter.GetBytes(Convert.ToDouble(write));
                    size = 8;
                }
                else
                {
                    if (type == "long")
                    {
                        memory = BitConverter.GetBytes(Convert.ToInt64(write));
                        size = 8;
                    }
                    else
                    {
                        if (type == "byte")
                        {
                            memory = new byte[1];
                            memory[0] = Convert.ToByte(write, 16);
                            size = 1;
                        }
                        else
                        {
                            if (type == "string")
                            {
                                memory = new byte[write.Length];
                                memory = Encoding.UTF8.GetBytes(write);
                                size = write.Length;
                            }
                        }
                    }
                }
            }
        }

        var newCode = UIntPtr.Add(theCode, moveQty);

        Debug.Write("DEBUG: Writing bytes [TYPE:" + type + " ADDR:[O]" + theCode + " [N]" + newCode + " MQTY:" +
                    moveQty + "] " + string.Join(",", memory) + Environment.NewLine);
        Thread.Sleep(1000);
        return WriteProcessMemory(pHandle, newCode, memory, (UIntPtr)size, IntPtr.Zero);
    }

    public void WriteBytes(string code, byte[] write, string file = "")
    {
        UIntPtr theCode;
        theCode = GetCode(code, file);
        WriteProcessMemory(pHandle, theCode, write, (UIntPtr)write.Length, IntPtr.Zero);
    }

    public void WriteBits(string code, bool[] bits, string file = "")
    {
        if (bits.Length != 8)
        {
            throw new ArgumentException("Not enough bits for a whole byte", nameof(bits));
        }

        var buf = new byte[1];

        var theCode = GetCode(code, file);

        for (var i = 0; i < 8; i++)
        {
            if (bits[i])
            {
                buf[0] |= (byte)(1 << i);
            }
        }

        WriteProcessMemory(pHandle, theCode, buf, (UIntPtr)1, IntPtr.Zero);
    }

    public void WriteBytes(UIntPtr address, byte[] write)
    {
        WriteProcessMemory(pHandle, address, write, (UIntPtr)write.Length, out var bytesRead);
    }

    #endregion

    public UIntPtr GetCode(string name, string path = "", int size = 8)
    {
        var theCode = "";
        if (Is64Bit)
        {
            if (size == 8)
            {
                size = 16;
            }

            return Get64BitCode(name, path, size);
        }

        if (path != "")
        {
            theCode = LoadCode(name, path);
        }
        else
        {
            theCode = name;
        }

        if (theCode == "")
        {
            return UIntPtr.Zero;
        }

        if (theCode.Contains(" "))
        {
            theCode.Replace(" ", string.Empty);
        }

        if (!theCode.Contains("+") && !theCode.Contains(","))
        {
            return new UIntPtr(Convert.ToUInt32(theCode, 16));
        }

        var newOffsets = theCode;

        if (theCode.Contains("+"))
        {
            newOffsets = theCode.Substring(theCode.IndexOf('+') + 1);
        }

        var memoryAddress = new byte[size];

        if (newOffsets.Contains(','))
        {
            var offsetsList = new List<int>();

            var newerOffsets = newOffsets.Split(',');
            foreach (var oldOffsets in newerOffsets)
            {
                var test = oldOffsets;
                if (oldOffsets.Contains("0x"))
                {
                    test = oldOffsets.Replace("0x", "");
                }

                var preParse = 0;
                if (!oldOffsets.Contains("-"))
                {
                    preParse = int.Parse(test, NumberStyles.AllowHexSpecifier);
                }
                else
                {
                    test = test.Replace("-", "");
                    preParse = int.Parse(test, NumberStyles.AllowHexSpecifier);
                    preParse = preParse * -1;
                }

                offsetsList.Add(preParse);
            }

            var offsets = offsetsList.ToArray();

            if (theCode.Contains("base") || theCode.Contains("main"))
            {
                ReadProcessMemory(pHandle, (UIntPtr)((int)mainModule.BaseAddress + offsets[0]), memoryAddress,
                    (UIntPtr)size, IntPtr.Zero);
            }
            else
            {
                if (!theCode.Contains("base") && !theCode.Contains("main") && theCode.Contains("+"))
                {
                    var moduleName = theCode.Split('+');
                    var altModule = IntPtr.Zero;
                    if (!moduleName[0].ToLower().Contains(".dll") && !moduleName[0].ToLower().Contains(".exe") &&
                        !moduleName[0].ToLower().Contains(".bin"))
                    {
                        var theAddr = moduleName[0];
                        if (theAddr.Contains("0x"))
                        {
                            theAddr = theAddr.Replace("0x", "");
                        }

                        altModule = (IntPtr)int.Parse(theAddr, NumberStyles.HexNumber);
                    }
                    else
                    {
                        try
                        {
                            altModule = modules[moduleName[0]];
                        }
                        catch
                        {
                            Debug.WriteLine("Module " + moduleName[0] + " was not found in module list!");
                            Debug.WriteLine("Modules: " + string.Join(",", modules));
                        }
                    }

                    ReadProcessMemory(pHandle, (UIntPtr)((int)altModule + offsets[0]), memoryAddress,
                        (UIntPtr)size, IntPtr.Zero);
                }
                else
                {
                    ReadProcessMemory(pHandle, (UIntPtr)offsets[0], memoryAddress, (UIntPtr)size, IntPtr.Zero);
                }
            }

            var num1 = BitConverter.ToUInt32(memoryAddress, 0);

            var base1 = (UIntPtr)0;

            for (var i = 1; i < offsets.Length; i++)
            {
                base1 = new UIntPtr(Convert.ToUInt32(num1 + offsets[i]));
                ReadProcessMemory(pHandle, base1, memoryAddress, (UIntPtr)size, IntPtr.Zero);
                num1 = BitConverter.ToUInt32(memoryAddress, 0);
            }

            return base1;
        }

        {
            var trueCode = Convert.ToInt32(newOffsets, 16);
            var altModule = IntPtr.Zero;
            if (theCode.ToLower().Contains("base") || theCode.ToLower().Contains("main"))
            {
                altModule = mainModule.BaseAddress;
            }
            else
            {
                if (!theCode.ToLower().Contains("base") && !theCode.ToLower().Contains("main") &&
                    theCode.Contains("+"))
                {
                    var moduleName = theCode.Split('+');
                    if (!moduleName[0].ToLower().Contains(".dll") && !moduleName[0].ToLower().Contains(".exe") &&
                        !moduleName[0].ToLower().Contains(".bin"))
                    {
                        var theAddr = moduleName[0];
                        if (theAddr.Contains("0x"))
                        {
                            theAddr = theAddr.Replace("0x", "");
                        }

                        altModule = (IntPtr)int.Parse(theAddr, NumberStyles.HexNumber);
                    }
                    else
                    {
                        try
                        {
                            altModule = modules[moduleName[0]];
                        }
                        catch
                        {
                            Debug.WriteLine("Module " + moduleName[0] + " was not found in module list!");
                            Debug.WriteLine("Modules: " + string.Join(",", modules));
                        }
                    }
                }
                else
                {
                    altModule = modules[theCode.Split('+')[0]];
                }
            }

            return (UIntPtr)((int)altModule + trueCode);
        }
    }

    public UIntPtr Get64BitCode(string name, string path = "", int size = 16)
    {
        var theCode = "";
        if (path != "")
        {
            theCode = LoadCode(name, path);
        }
        else
        {
            theCode = name;
        }

        if (theCode == "")
        {
            return UIntPtr.Zero;
        }

        if (theCode.Contains(" "))
        {
            theCode.Replace(" ", string.Empty);
        }

        var newOffsets = theCode;
        if (theCode.Contains("+"))
        {
            newOffsets = theCode.Substring(theCode.IndexOf('+') + 1);
        }

        var memoryAddress = new byte[size];

        if (!theCode.Contains("+") && !theCode.Contains(","))
        {
            return new UIntPtr(Convert.ToUInt64(theCode, 16));
        }

        if (newOffsets.Contains(','))
        {
            var offsetsList = new List<long>();

            var newerOffsets = newOffsets.Split(',');
            foreach (var oldOffsets in newerOffsets)
            {
                var test = oldOffsets;
                if (oldOffsets.Contains("0x"))
                {
                    test = oldOffsets.Replace("0x", "");
                }

                long preParse = 0;
                if (!oldOffsets.Contains("-"))
                {
                    preParse = long.Parse(test, NumberStyles.AllowHexSpecifier);
                }
                else
                {
                    test = test.Replace("-", "");
                    preParse = long.Parse(test, NumberStyles.AllowHexSpecifier);
                    preParse = preParse * -1;
                }

                offsetsList.Add(preParse);
            }

            var offsets = offsetsList.ToArray();

            if (theCode.Contains("base") || theCode.Contains("main"))
            {
                ReadProcessMemory(pHandle, (UIntPtr)((long)mainModule.BaseAddress + offsets[0]), memoryAddress,
                    (UIntPtr)size, IntPtr.Zero);
            }
            else
            {
                if (!theCode.Contains("base") && !theCode.Contains("main") && theCode.Contains("+"))
                {
                    var moduleName = theCode.Split('+');
                    var altModule = IntPtr.Zero;
                    if (!moduleName[0].ToLower().Contains(".dll") && !moduleName[0].ToLower().Contains(".exe") &&
                        !moduleName[0].ToLower().Contains(".bin"))
                    {
                        altModule = (IntPtr)long.Parse(moduleName[0], NumberStyles.HexNumber);
                    }
                    else
                    {
                        try
                        {
                            altModule = modules[moduleName[0]];
                        }
                        catch
                        {
                            Debug.WriteLine("Module " + moduleName[0] + " was not found in module list!");
                            Debug.WriteLine("Modules: " + string.Join(",", modules));
                        }
                    }

                    ReadProcessMemory(pHandle, (UIntPtr)((long)altModule + offsets[0]), memoryAddress,
                        (UIntPtr)size, IntPtr.Zero);
                }
                else
                {
                    ReadProcessMemory(pHandle, (UIntPtr)offsets[0], memoryAddress, (UIntPtr)size, IntPtr.Zero);
                }
            }

            var num1 = BitConverter.ToInt64(memoryAddress, 0);

            var base1 = (UIntPtr)0;

            for (var i = 1; i < offsets.Length; i++)
            {
                base1 = new UIntPtr(Convert.ToUInt64(num1 + offsets[i]));
                ReadProcessMemory(pHandle, base1, memoryAddress, (UIntPtr)size, IntPtr.Zero);
                num1 = BitConverter.ToInt64(memoryAddress, 0);
            }

            return base1;
        }

        {
            var trueCode = Convert.ToInt64(newOffsets, 16);
            var altModule = IntPtr.Zero;
            if (theCode.Contains("base") || theCode.Contains("main"))
            {
                altModule = mainModule.BaseAddress;
            }
            else
            {
                if (!theCode.Contains("base") && !theCode.Contains("main") && theCode.Contains("+"))
                {
                    var moduleName = theCode.Split('+');
                    if (!moduleName[0].ToLower().Contains(".dll") && !moduleName[0].ToLower().Contains(".exe") &&
                        !moduleName[0].ToLower().Contains(".bin"))
                    {
                        var theAddr = moduleName[0];
                        if (theAddr.Contains("0x"))
                        {
                            theAddr = theAddr.Replace("0x", "");
                        }

                        altModule = (IntPtr)long.Parse(theAddr, NumberStyles.HexNumber);
                    }
                    else
                    {
                        try
                        {
                            altModule = modules[moduleName[0]];
                        }
                        catch
                        {
                            Debug.WriteLine("Module " + moduleName[0] + " was not found in module list!");
                            Debug.WriteLine("Modules: " + string.Join(",", modules));
                        }
                    }
                }
                else
                {
                    altModule = modules[theCode.Split('+')[0]];
                }
            }

            return (UIntPtr)((long)altModule + trueCode);
        }
    }

    public void CloseProcess()
    {
        if (pHandle == null)
        {
            return;
        }

        CloseHandle(pHandle);
        theProc = null;
    }

    public void InjectDll(string strDllName)
    {
        IntPtr bytesout;

        foreach (ProcessModule pm in theProc.Modules)
        {
            if (pm.ModuleName.StartsWith("inject", StringComparison.InvariantCultureIgnoreCase))
            {
                return;
            }
        }

        if (!theProc.Responding)
        {
            return;
        }

        var lenWrite = strDllName.Length + 1;
        var allocMem = VirtualAllocEx(pHandle, (UIntPtr)null, (uint)lenWrite, MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE);

        WriteProcessMemory(pHandle, allocMem, strDllName, (UIntPtr)lenWrite, out bytesout);
        var injector = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

        if (injector == null)
        {
            return;
        }

        var hThread = CreateRemoteThread(pHandle, (IntPtr)null, 0, injector, allocMem, 0, out bytesout);
        if (hThread == null)
        {
            return;
        }

        var Result = WaitForSingleObject(hThread, 10 * 1000);
        if (Result == 0x00000080L || Result == 0x00000102L)
        {
            if (hThread != null)
            {
                CloseHandle(hThread);
            }

            return;
        }

        VirtualFreeEx(pHandle, allocMem, (UIntPtr)0, 0x8000);

        if (hThread != null)
        {
            CloseHandle(hThread);
        }
    }

#if WINXP
#else
    public UIntPtr CreateCodeCave(string code,
        string write,
        int replaceCount,
        int size = 0x1000,
        string file = "")
    {
        byte[] newBytes;

        if (write.Contains(",") || write.Contains(" "))
        {
            string[] stringBytes;
            if (write.Contains(","))
            {
                stringBytes = write.Split(',');
            }
            else
            {
                stringBytes = write.Split(' ');
            }

            var c = stringBytes.Count();
            newBytes = new byte[c];
            for (var i = 0; i < c; i++)
            {
                newBytes[i] = Convert.ToByte(stringBytes[i], 16);
            }
        }
        else
        {
            newBytes = new byte[1];
            newBytes[0] = Convert.ToByte(write, 16);
        }


        if (replaceCount < 5)
        {
            return UIntPtr.Zero;
        }

        UIntPtr theCode;
        theCode = GetCode(code, file);
        var address = theCode;

        var caveAddress = UIntPtr.Zero;
        var prefered = address;

        for (var i = 0; i < 10 && caveAddress == UIntPtr.Zero; i++)
        {
            caveAddress = VirtualAllocEx(pHandle, FindFreeBlockForRegion(prefered, (uint)size), (uint)size,
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

            if (caveAddress == UIntPtr.Zero)
            {
                prefered = UIntPtr.Add(prefered, 0x10000);
            }
        }

        if (caveAddress == UIntPtr.Zero)
        {
            caveAddress = VirtualAllocEx(pHandle, UIntPtr.Zero, (uint)size, MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE);
        }

        var nopsNeeded = replaceCount > 5 ? replaceCount - 5 : 0;

        var offset = (int)((long)caveAddress - (long)address - 5);

        var jmpBytes = new byte[5 + nopsNeeded];
        jmpBytes[0] = 0xE9;
        BitConverter.GetBytes(offset).CopyTo(jmpBytes, 1);

        for (var i = 5; i < jmpBytes.Length; i++)
        {
            jmpBytes[i] = 0x90;
        }

        WriteBytes(address, jmpBytes);

        var caveBytes = new byte[5 + newBytes.Length];
        offset = (int)((long)address + jmpBytes.Length - ((long)caveAddress + newBytes.Length) - 5);

        newBytes.CopyTo(caveBytes, 0);
        caveBytes[newBytes.Length] = 0xE9;
        BitConverter.GetBytes(offset).CopyTo(caveBytes, newBytes.Length + 1);

        WriteBytes(caveAddress, caveBytes);

        return caveAddress;
    }

    private UIntPtr FindFreeBlockForRegion(UIntPtr baseAddress, uint size)
    {
        var minAddress = UIntPtr.Subtract(baseAddress, 0x70000000);
        var maxAddress = UIntPtr.Add(baseAddress, 0x70000000);

        var ret = UIntPtr.Zero;
        var tmpAddress = UIntPtr.Zero;

        GetSystemInfo(out var si);

        if (Is64Bit)
        {
            if ((long)minAddress > (long)si.maximumApplicationAddress ||
                (long)minAddress < (long)si.minimumApplicationAddress)
            {
                minAddress = si.minimumApplicationAddress;
            }

            if ((long)maxAddress < (long)si.minimumApplicationAddress ||
                (long)maxAddress > (long)si.maximumApplicationAddress)
            {
                maxAddress = si.maximumApplicationAddress;
            }
        }
        else
        {
            minAddress = si.minimumApplicationAddress;
            maxAddress = si.maximumApplicationAddress;
        }

        MEMORY_BASIC_INFORMATION mbi;

        var current = minAddress;
        var previous = current;

        while (VirtualQueryEx(pHandle, current, out mbi).ToUInt64() != 0)
        {
            if ((long)mbi.BaseAddress > (long)maxAddress)
            {
                return UIntPtr.Zero;
            }

            if (mbi.State == MEM_FREE && mbi.RegionSize > size)
            {
                if ((long)mbi.BaseAddress % si.allocationGranularity > 0)
                {
                    tmpAddress = mbi.BaseAddress;
                    var offset = (int)(si.allocationGranularity - (long)tmpAddress % si.allocationGranularity);

                    if (mbi.RegionSize - offset >= size)
                    {
                        tmpAddress = UIntPtr.Add(tmpAddress, offset);

                        if ((long)tmpAddress < (long)baseAddress)
                        {
                            tmpAddress = UIntPtr.Add(tmpAddress, (int)(mbi.RegionSize - offset - size));

                            if ((long)tmpAddress > (long)baseAddress)
                            {
                                tmpAddress = baseAddress;
                            }

                            tmpAddress = UIntPtr.Subtract(tmpAddress,
                                (int)((long)tmpAddress % si.allocationGranularity));
                        }

                        if (Math.Abs((long)tmpAddress - (long)baseAddress) <
                            Math.Abs((long)ret - (long)baseAddress))
                        {
                            ret = tmpAddress;
                        }
                    }
                }
                else
                {
                    tmpAddress = mbi.BaseAddress;

                    if ((long)tmpAddress < (long)baseAddress)
                    {
                        tmpAddress = UIntPtr.Add(tmpAddress, (int)(mbi.RegionSize - size));

                        if ((long)tmpAddress > (long)baseAddress)
                        {
                            tmpAddress = baseAddress;
                        }

                        tmpAddress = UIntPtr.Subtract(tmpAddress,
                            (int)((long)tmpAddress % si.allocationGranularity));
                    }

                    if (Math.Abs((long)tmpAddress - (long)baseAddress) <
                        Math.Abs((long)ret - (long)baseAddress))
                    {
                        ret = tmpAddress;
                    }
                }
            }

            if (mbi.RegionSize % si.allocationGranularity > 0)
            {
                mbi.RegionSize += si.allocationGranularity - mbi.RegionSize % si.allocationGranularity;
            }

            previous = current;
            current = UIntPtr.Add(mbi.BaseAddress, (int)mbi.RegionSize);

            if ((long)current > (long)maxAddress)
            {
                return ret;
            }

            if ((long)previous > (long)current)
            {
                return ret;
            }
        }

        return ret;
    }
#endif

    [Flags]
    public enum ThreadAccess
    {
        TERMINATE = 0x0001, SUSPEND_RESUME = 0x0002, GET_CONTEXT = 0x0008,
        SET_CONTEXT = 0x0010, SET_INFORMATION = 0x0020, QUERY_INFORMATION = 0x0040,
        SET_THREAD_TOKEN = 0x0080, IMPERSONATE = 0x0100, DIRECT_IMPERSONATION = 0x0200
    }

    public static void SuspendProcess(int pid)
    {
        var process = Process.GetProcessById(pid);

        if (process.ProcessName == string.Empty)
        {
            return;
        }

        foreach (ProcessThread pT in process.Threads)
        {
            var pOpenThread = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint)pT.Id);
            if (pOpenThread == IntPtr.Zero)
            {
                continue;
            }

            SuspendThread(pOpenThread);
            CloseHandle(pOpenThread);
        }
    }

    public static void ResumeProcess(int pid)
    {
        var process = Process.GetProcessById(pid);
        if (process.ProcessName == string.Empty)
        {
            return;
        }

        foreach (ProcessThread pT in process.Threads)
        {
            var pOpenThread = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint)pT.Id);
            if (pOpenThread == IntPtr.Zero)
            {
                continue;
            }

            var suspendCount = 0;
            do
            {
                suspendCount = ResumeThread(pOpenThread);
            }
            while (suspendCount > 0);

            CloseHandle(pOpenThread);
        }
    }

#if WINXP
#else
    private async Task PutTaskDelay(int delay)
    {
        await Task.Delay(delay);
    }
#endif

    private void AppendAllBytes(string path, byte[] bytes)
    {
        using (var stream = new FileStream(path, FileMode.Append))
        {
            stream.Write(bytes, 0, bytes.Length);
        }
    }

    public byte[] FileToBytes(string path, bool dontDelete = false)
    {
        var newArray = File.ReadAllBytes(path);
        if (!dontDelete)
        {
            File.Delete(path);
        }

        return newArray;
    }

    public string MSize()
    {
        if (Is64Bit)
        {
            return "x16";
        }

        return "x8";
    }

    public static string ByteArrayToHexString(byte[] ba)
    {
        var hex = new StringBuilder(ba.Length * 2);
        var i = 1;
        foreach (var b in ba)
        {
            if (i == 16)
            {
                hex.AppendFormat("{0:x2}{1}", b, Environment.NewLine);
                i = 0;
            }
            else
            {
                hex.AppendFormat("{0:x2} ", b);
            }

            i++;
        }

        return hex.ToString().ToUpper();
    }

    public static string ByteArrayToString(byte[] ba)
    {
        var hex = new StringBuilder(ba.Length * 2);
        foreach (var b in ba)
        {
            hex.AppendFormat("{0:x2} ", b);
        }

        return hex.ToString();
    }

#if WINXP
#else

    public struct SYSTEM_INFO
    {
        public ushort processorArchitecture;
        private ushort reserved;
        public uint pageSize;
        public UIntPtr minimumApplicationAddress;
        public UIntPtr maximumApplicationAddress;
        public IntPtr activeProcessorMask;
        public uint numberOfProcessors;
        public uint processorType;
        public uint allocationGranularity;
        public ushort processorLevel;
        public ushort processorRevision;
    }

    public struct MEMORY_BASIC_INFORMATION32
    {
        public UIntPtr BaseAddress;
        public UIntPtr AllocationBase;
        public uint AllocationProtect;
        public uint RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    public struct MEMORY_BASIC_INFORMATION64
    {
        public UIntPtr BaseAddress;
        public UIntPtr AllocationBase;
        public uint AllocationProtect;
        public uint __alignment1;
        public ulong RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
        public uint __alignment2;
    }

    public struct MEMORY_BASIC_INFORMATION
    {
        public UIntPtr BaseAddress;
        public UIntPtr AllocationBase;
        public uint AllocationProtect;
        public long RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    public ulong GetMinAddress()
    {
        SYSTEM_INFO SI;
        GetSystemInfo(out SI);
        return (ulong)SI.minimumApplicationAddress;
    }

    public bool DumpMemory(string file = "dump.dmp")
    {
        Debug.Write("[DEBUG] memory dump starting... (" + DateTime.Now.ToString("h:mm:ss tt") + ")" +
                    Environment.NewLine);
        var sys_info = new SYSTEM_INFO();
        GetSystemInfo(out sys_info);

        var proc_min_address = sys_info.minimumApplicationAddress;
        var proc_max_address = sys_info.maximumApplicationAddress;

        var proc_min_address_l = (long)proc_min_address;
        var proc_max_address_l = theProc.VirtualMemorySize64 + proc_min_address_l;

        if (File.Exists(file))
        {
            File.Delete(file);
        }


        var memInfo = new MEMORY_BASIC_INFORMATION();
        while (proc_min_address_l < proc_max_address_l)
        {
            VirtualQueryEx(pHandle, proc_min_address, out memInfo);
            var buffer = new byte[memInfo.RegionSize];
            var test = (UIntPtr)memInfo.RegionSize;
            var test2 = (UIntPtr)(long)memInfo.BaseAddress;

            ReadProcessMemory(pHandle, test2, buffer, test, IntPtr.Zero);

            AppendAllBytes(file, buffer);
            proc_min_address_l += memInfo.RegionSize;
            proc_min_address = new UIntPtr((ulong)proc_min_address_l);
        }


        Debug.Write("[DEBUG] memory dump completed. Saving dump file to " + file + ". (" +
                    DateTime.Now.ToString("h:mm:ss tt") + ")" + Environment.NewLine);
        return true;
    }

    public Task<IEnumerable<long>> AoBScan(string search,
        bool writable = false,
        bool executable = true,
        string file = "")
    {
        return AoBScan(0, long.MaxValue, search, writable, executable, file);
    }

    public Task<IEnumerable<long>> AoBScan(string search, bool writable, bool executable, int[] size)
    {
        return AoBScan(0, long.MaxValue, search, true, writable, executable, "", size);
    }

    public Task<IEnumerable<long>> AoBScan(string search,
        bool readable,
        bool writable,
        bool executable,
        string file = "")
    {
        return AoBScan(0, long.MaxValue, search, readable, writable, executable, file, new int[0]);
    }


    public Task<IEnumerable<long>> AoBScan(long start,
        long end,
        string search,
        bool writable = false,
        bool executable = true,
        string file = "")
    {
        return AoBScan(start, end, search, false, writable, executable, file, new int[0]);
    }

    public Task<IEnumerable<long>> AoBScan(long start,
        long end,
        string search,
        bool readable,
        bool writable,
        bool executable,
        string file,
        int[] size)
    {
        return Task.Run(() =>
        {
            var memRegionList = new List<MemoryRegionResult>();

            var memCode = LoadCode(search, file);

            var stringByteArray = memCode.Split(' ');

            var aobPattern = new byte[stringByteArray.Length];
            var mask = new byte[stringByteArray.Length];

            for (var i = 0; i < stringByteArray.Length; i++)
            {
                var ba = stringByteArray[i];

                if (ba == "??" || ba.Length == 1 && ba == "?")
                {
                    mask[i] = 0x00;
                    stringByteArray[i] = "0x00";
                }
                else
                {
                    if (char.IsLetterOrDigit(ba[0]) && ba[1] == '?')
                    {
                        mask[i] = 0xF0;
                        stringByteArray[i] = ba[0] + "0";
                    }
                    else
                    {
                        if (char.IsLetterOrDigit(ba[1]) && ba[0] == '?')
                        {
                            mask[i] = 0x0F;
                            stringByteArray[i] = "0" + ba[1];
                        }
                        else
                        {
                            mask[i] = 0xFF;
                        }
                    }
                }
            }


            for (var i = 0; i < stringByteArray.Length; i++)
            {
                aobPattern[i] = (byte)(Convert.ToByte(stringByteArray[i], 16) & mask[i]);
            }

            GetSystemInfo(out var sysInfo);

            var procMinAddress = sysInfo.minimumApplicationAddress;
            var procMaxAddress = sysInfo.maximumApplicationAddress;

            if (start < (long)procMinAddress.ToUInt64() || start == 0)
            {
                start = (long)procMinAddress.ToUInt64();
            }

            if (end > (long)procMaxAddress.ToUInt64() || end == 0)
            {
                end = (long)procMaxAddress.ToUInt64();
            }

            Debug.WriteLine("[DEBUG] memory scan starting... (start:0x" + start.ToString(MSize()) + " end:0x" +
                            end.ToString(MSize()) + " time:" + DateTime.Now.ToString("h:mm:ss tt") + ")");
            var currentBaseAddress = new UIntPtr((ulong)start);

            var memInfo = new MEMORY_BASIC_INFORMATION();

            while (VirtualQueryEx(pHandle, currentBaseAddress, out memInfo).ToUInt64() != 0 &&
                   currentBaseAddress.ToUInt64() < (ulong)end &&
                   currentBaseAddress.ToUInt64() + (ulong)memInfo.RegionSize > currentBaseAddress.ToUInt64())
            {
                var isValid = memInfo.State == MEM_COMMIT;
                isValid &= memInfo.BaseAddress.ToUInt64() < procMaxAddress.ToUInt64();
                isValid &= (memInfo.Protect & PAGE_GUARD) == 0;
                isValid &= (memInfo.Protect & PAGE_NOACCESS) == 0;
                isValid &= memInfo.Type == MEM_PRIVATE || memInfo.Type == MEM_IMAGE || memInfo.Type == MEM_MAPPED;

                if (isValid)
                {
                    var isReadable = (memInfo.Protect & PAGE_READONLY) > 0;

                    var isWritable = (memInfo.Protect & PAGE_READWRITE) > 0 ||
                                     (memInfo.Protect & PAGE_WRITECOPY) > 0 ||
                                     (memInfo.Protect & PAGE_EXECUTE_READWRITE) > 0 ||
                                     (memInfo.Protect & PAGE_EXECUTE_WRITECOPY) > 0;

                    var isExecutable = (memInfo.Protect & PAGE_EXECUTE) > 0 ||
                                       (memInfo.Protect & PAGE_EXECUTE_READ) > 0 ||
                                       (memInfo.Protect & PAGE_EXECUTE_READWRITE) > 0 ||
                                       (memInfo.Protect & PAGE_EXECUTE_WRITECOPY) > 0;

                    isReadable &= readable;
                    isWritable &= writable;
                    isExecutable &= executable;

                    isValid &= isReadable || isWritable || isExecutable;
                }

                if (!isValid)
                {
                    currentBaseAddress = new UIntPtr(memInfo.BaseAddress.ToUInt64() + (ulong)memInfo.RegionSize);
                    continue;
                }

                var memRegion = new MemoryRegionResult
                {
                    CurrentBaseAddress = currentBaseAddress,
                    RegionSize = memInfo.RegionSize,
                    RegionBase = memInfo.BaseAddress
                };

                currentBaseAddress = new UIntPtr(memInfo.BaseAddress.ToUInt64() + (ulong)memInfo.RegionSize);

                if (memRegionList.Count > 0)
                {
                    var previousRegion = memRegionList[memRegionList.Count - 1];

                    if ((long)previousRegion.RegionBase + previousRegion.RegionSize == (long)memInfo.BaseAddress)
                    {
                        memRegionList[memRegionList.Count - 1] = new MemoryRegionResult
                        {
                            CurrentBaseAddress = previousRegion.CurrentBaseAddress,
                            RegionBase = previousRegion.RegionBase,
                            RegionSize = previousRegion.RegionSize + memInfo.RegionSize
                        };

                        continue;
                    }
                }

                if (size.Length > 0)
                {
                    foreach (var f in size)
                    {
                        if (memRegion.RegionSize == f)
                        {
                            memRegionList.Add(memRegion);
                        }
                    }
                }
                else
                {
                    memRegionList.Add(memRegion);
                }
            }

            var bagResult = new ConcurrentBag<long>();

            foreach (var result in memRegionList.Select(f => CompareScan(f, aobPattern, mask))
                .SelectMany(compareResults => compareResults))
            {
                bagResult.Add(result);
            }

            Debug.WriteLine("[DEBUG] memory scan completed. (time:" + DateTime.Now.ToString("h:mm:ss tt") + ")");

            return bagResult.ToList().OrderBy(c => c).AsEnumerable();
        });
    }

    public async Task<long> AoBScan(string code, long end, string search, string file = "")
    {
        var start = (long)GetCode(code, file).ToUInt64();

        return (await AoBScan(start, end, search, true, true, true, file, new int[0])).FirstOrDefault();
    }

    private long[] CompareScan(MemoryRegionResult item, byte[] aobPattern, byte[] mask)
    {
        if (mask.Length != aobPattern.Length)
        {
            throw new ArgumentException($"{nameof(aobPattern)}.Length != {nameof(mask)}.Length");
        }

        var buffer = Marshal.AllocHGlobal((int)item.RegionSize);

        ReadProcessMemory(pHandle, item.CurrentBaseAddress, buffer, (UIntPtr)item.RegionSize, out var bytesRead);

        var result = 0 - aobPattern.Length;
        var ret = new List<long>();
        unsafe
        {
            do
            {
                result = FindPattern((byte*)buffer.ToPointer(), (int)bytesRead, aobPattern, mask,
                    result + aobPattern.Length);

                if (result >= 0)
                {
                    ret.Add((long)item.CurrentBaseAddress + result);
                }
            }
            while (result != -1);
        }

        Marshal.FreeHGlobal(buffer);

        return ret.ToArray();
    }

    private int FindPattern(byte[] body, byte[] pattern, byte[] masks, int start = 0)
    {
        var foundIndex = -1;

        if (body.Length <= 0 || pattern.Length <= 0 || start > body.Length - pattern.Length ||
            pattern.Length > body.Length)
        {
            return foundIndex;
        }

        for (var index = start; index <= body.Length - pattern.Length; index++)
        {
            if ((body[index] & masks[0]) == (pattern[0] & masks[0]))
            {
                var match = true;
                for (var index2 = 1; index2 <= pattern.Length - 1; index2++)
                {
                    if ((body[index + index2] & masks[index2]) == (pattern[index2] & masks[index2]))
                    {
                        continue;
                    }

                    match = false;
                    break;
                }

                if (!match)
                {
                    continue;
                }

                foundIndex = index;
                break;
            }
        }

        return foundIndex;
    }

    private unsafe int FindPattern(byte* body, int bodyLength, byte[] pattern, byte[] masks, int start = 0)
    {
        var foundIndex = -1;

        if (bodyLength <= 0 || pattern.Length <= 0 || start > bodyLength - pattern.Length ||
            pattern.Length > bodyLength)
        {
            return foundIndex;
        }

        for (var index = start; index <= bodyLength - pattern.Length; index++)
        {
            if ((body[index] & masks[0]) == (pattern[0] & masks[0]))
            {
                var match = true;
                for (var index2 = 1; index2 <= pattern.Length - 1; index2++)
                {
                    if ((body[index + index2] & masks[index2]) == (pattern[index2] & masks[index2]))
                    {
                        continue;
                    }

                    match = false;
                    break;
                }

                if (!match)
                {
                    continue;
                }

                foundIndex = index;
                break;
            }
        }

        return foundIndex;
    }


    [StructLayout(LayoutKind.Sequential)]
    public struct MemoryBasicInformation64
    {
        public ulong BaseAddress;
        public ulong AllocationBase;
        public int AllocationProtect;
        public int __alignment1;
        public ulong RegionSize;
        public int State;
        public int Protect;
        public int Type;
        public int __alignment2;
    }

#endif
}