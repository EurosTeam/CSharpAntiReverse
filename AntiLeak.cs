using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace detectDebugger
{

    public static class ProcessExtensions
    {
        private static string FindIndexedProcessName(int pid)
        {
            var processName = Process.GetProcessById(pid).ProcessName;
            var processesByName = Process.GetProcessesByName(processName);
            string processIndexdName = null;

            for (var index = 0; index < processesByName.Length; index++)
            {
                processIndexdName = index == 0 ? processName : processName + "#" + index;
                var processId = new PerformanceCounter("Process", "ID Process", processIndexdName);
                if ((int)processId.NextValue() == pid)
                {
                    return processIndexdName;
                }
            }

            return processIndexdName;
        }

        private static Process FindPidFromIndexedProcessName(string indexedProcessName)
        {
            var parentId = new PerformanceCounter("Process", "Creating Process ID", indexedProcessName);
            return Process.GetProcessById((int)parentId.NextValue());
        }

        public static Process Parent(this Process process)
        {
            return FindPidFromIndexedProcessName(FindIndexedProcessName(process.Id));
        }
    }

    class CAntiReverse
    {
        [DllImport("Kernel32.dll", SetLastError = true, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, [MarshalAs(UnmanagedType.Bool)] ref bool isDebuggerPresent);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, IntPtr processInformation, uint processInformationLength, IntPtr returnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess,bool bInheritHandle,int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("msvcrt.dll", CallingConvention = CallingConvention.Cdecl)]
        static extern int memcmp(byte[] b1, byte[] b2, long count);
        [DllImport("User32.dll", CharSet = CharSet.Unicode)]
        public static extern int MessageBox(IntPtr h, string m, string c, int type);

        static bool ByteArrayCompare(byte[] b1, byte[] b2)
        {
            // Validate buffers are the same length.
            // This also ensures that the count does not exceed the length of either buffer.  
            return b1.Length == b2.Length && memcmp(b1, b2, b1.Length) == 0;
        }

        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        public enum ProcessInfo : uint
        {
            ProcessBasicInformation = 0x00,
            ProcessDebugPort = 0x07,
            ProcessExceptionPort = 0x08,
            ProcessAccessToken = 0x09,
            ProcessWow64Information = 0x1A,
            ProcessImageFileName = 0x1B,
            ProcessDebugObjectHandle = 0x1E,
            ProcessDebugFlags = 0x1F,
            ProcessExecuteFlags = 0x22,
            ProcessInstrumentationCallback = 0x28,
            MaxProcessInfoClass = 0x64
        }

        private static string[] IllegalProcessName = { "Fiddler", "Wireshark", "dumpcap", "dnSpy", "dnSpy-x86", "cheatengine-x86_64", "HTTPDebuggerUI", "Procmon", "Procmon64", "Procmon64a","ProcessHacker","x32dbg","x64dbg", "DotNetDataCollector32", "DotNetDataCollector64" };
        private static string[] IllegalWindowName = { "Progress Telerik Fiddler Web Debugger", "Wireshark" };
        private static string[] VmProcess = { "VBoxService","VBoxTray" };
        private static string[] VmDriver = { "VBoxGuest.sys", "VBoxMouse.sys", "VBoxSF.sys", "VBoxWddm.sys" };

        public static void Run()
        {
            if (AntiSandboxie())
            {
                Environment.Exit(0);
            }
            if (AntiDebugger())
            {
                Environment.Exit(0);
            }
            if(IntegrityCheck())
            {
                Environment.Exit(0);
            }    
            if (AntiAnalysisTool())
            {
                Environment.Exit(0);
            }
            if(AntiVM())
            {
                Environment.Exit(0);
            }
            AntiDump(); // maybe cause some problems
        }

        private static void AntiDump()
        {
            IntPtr myMod = GetModuleHandle(null);
            Memory.VirtualProtect(myMod, 0x1000, 0x40, out _);
            Memory.WriteProcessMemory(Process.GetCurrentProcess().Handle, myMod, 0x00, 4, out _); // erase MS DOS HEADER
            Memory.WriteProcessMemory(Process.GetCurrentProcess().Handle, (myMod + 0x3C), 0x00, 4, out _);
        }

        private static bool AntiVM()
        {
            bool bVmIsHere = false;
            Process[] ProcessList = Process.GetProcesses();
            foreach (Process proc in ProcessList)
            {
                for (int i = 0; i < VmProcess.Length; i++)
                {
                    //check process name
                    if (proc.ProcessName == VmProcess[i])
                    {
                        bVmIsHere = true;
                        return bVmIsHere;
                    }
                }
            }
            for(int i = 0; i < VmDriver.Length; i++)
            {
                if (Directory.Exists("C:\\Windows\\System32\\drivers\\" + VmDriver[i]))
                {
                    bVmIsHere = true;
                    return bVmIsHere;
                }
            }
            return bVmIsHere;
        }

        private static bool IntegrityCheck()
        {
            byte[] byteRead = new byte[1];
            byte[] mov = new byte[1] { 0x8B };
            bool bIntegrityCompromised = false;
            IntPtr CheckRemoteDebuggerPresentAddr = GetProcAddress(GetModuleHandle("Kernel32.dll"), "CheckRemoteDebuggerPresent");
            Memory.ReadProcessMemory(Process.GetCurrentProcess().Handle, CheckRemoteDebuggerPresentAddr, byteRead, 2,out _);
            if (!ByteArrayCompare(byteRead,mov)) // normally the CheckRemoteDebuggerPresent start with mov edi,esi but if dnSpy hooked the function, the function start with a jmp
            {
                bIntegrityCompromised = true;
            }
            return bIntegrityCompromised;
        }

        private static bool AntiDebugger()
        {
            bool DebuggerPresent = false;
            CheckRemoteDebuggerPresent(OpenProcess(ProcessAccessFlags.All,false,Process.GetCurrentProcess().Id), ref DebuggerPresent);
            if(DebuggerPresent == false)
            {
                //if check debugger is false, make more check
                IntPtr hProc = OpenProcess(ProcessAccessFlags.All, false, Process.GetCurrentProcess().Id);
                IntPtr dwReturnLength = Marshal.AllocHGlobal(sizeof(long));
                IntPtr dwDebugPort = IntPtr.Zero;

                if (NtQueryInformationProcess(hProc, (int)ProcessInfo.ProcessDebugPort, dwReturnLength, (uint)Marshal.SizeOf(dwDebugPort), dwReturnLength) >= 0)
                {
                    CloseHandle(hProc);
                    if (dwDebugPort == (IntPtr)(-1))
                    {
                        Marshal.FreeHGlobal(dwReturnLength);
                        DebuggerPresent = true;
                    }
                }
                //if someone is debugging the process the parent process will be the debugger and not explorer like almost every process in your computer
                if (!Process.GetCurrentProcess().Parent().ProcessName.Contains("explorer"))
                    DebuggerPresent = true;
            }
            return DebuggerPresent;
        }

        private static bool AntiAnalysisTool()
        {
            Process[] ProcessList = Process.GetProcesses();
            foreach (Process proc in ProcessList)
            {
                for(int i = 0; i < IllegalProcessName.Length; i++)
                {
                    //check process name
                    if(proc.ProcessName == IllegalProcessName[i])
                    {
                        return true;
                    }
                }

                for (int i = 0; i < IllegalWindowName.Length; i++)
                {
                    //check process window title
                    if (proc.MainWindowTitle == IllegalWindowName[i])
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        private static bool AntiSandboxie()
        {
            //get handle of this dll (this dll is used when someone launch your software with sandboxie)
            //If the dll doesn't exist the handle will be NULL
            if (GetModuleHandle("SbieDll.dll").ToInt32() != 0)
                return true;
            else
                return false;
        }

        public static IntPtr OpenProcess(ProcessAccessFlags flags1, Process proc, ProcessAccessFlags flags)
        {
            return OpenProcess(flags, false, proc.Id);
        }
    }
}
