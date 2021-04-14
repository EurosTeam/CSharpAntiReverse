using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace detectDebugger
{
	internal class Memory
	{
		// s/o guidedhacking.com

		public const int MAX_PATH = 260;
		private const int INVALID_HANDLE_VALUE = -1;

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
		[Flags]
		private enum SnapshotFlags : uint
		{
			HeapList = 0x00000001,
			Process = 0x00000002,
			Thread = 0x00000004,
			Module = 0x00000008,
			Module32 = 0x00000010,
			Inherit = 0x80000000,
			All = 0x0000001F,
			NoHeaps = 0x40000000
		}

		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);

		[StructLayout(LayoutKind.Sequential)]
		public struct PROCESSENTRY32
		{
			public uint dwSize;
			public uint cntUsage;
			public uint th32ProcessID;
			public IntPtr th32DefaultHeapID;
			public uint th32ModuleID;
			public uint cntThreads;
			public uint th32ParentProcessID;
			public int pcPriClassBase;
			public uint dwFlags;
			[MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExeFile;
		};

		[StructLayout(LayoutKind.Sequential, CharSet = System.Runtime.InteropServices.CharSet.Ansi)]
		public struct MODULEENTRY32
		{
			internal uint dwSize;
			internal uint th32ModuleID;
			internal uint th32ProcessID;
			internal uint GlblcntUsage;
			internal uint ProccntUsage;
			internal IntPtr modBaseAddr;
			internal uint modBaseSize;
			internal IntPtr hModule;

			[MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
			internal string szModule;

			[MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
			internal string szExePath;
		}

		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern bool ReadProcessMemory(
		IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesRead);

		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern bool WriteProcessMemory(
		IntPtr hProcess, IntPtr lpBaseAddress, [MarshalAs(UnmanagedType.AsAny)] object lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

		[DllImport("kernel32.dll")]
		public static extern bool VirtualProtect(IntPtr lpAddress,int dwSize, uint flNewProtect, out uint lpflOldProtect);

		[DllImport("kernel32.dll")]
		private static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

		[DllImport("kernel32.dll")]
		private static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

		[DllImport("kernel32.dll")]
		private static extern bool Module32First(IntPtr hSnapshot, ref MODULEENTRY32 lpme);

		[DllImport("kernel32.dll")]
		private static extern bool Module32Next(IntPtr hSnapshot, ref MODULEENTRY32 lpme);

		[DllImport("kernel32.dll", SetLastError = true)]
		private static extern bool CloseHandle(IntPtr hHandle);

		[DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		public static extern IntPtr GetModuleHandle(string moduleName);

		[DllImport("kernel32.dll", SetLastError = true)]
		private static extern IntPtr CreateToolhelp32Snapshot(SnapshotFlags dwFlags, int th32ProcessID);

		[DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
		private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

		[DllImport("kernel32.dll")]
		private static extern IntPtr CreateRemoteThread(IntPtr hProcess,
		   IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress,
		   IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

		[Flags]
		public enum AllocationType
		{
			Commit = 0x1000,
			Reserve = 0x2000,
			Decommit = 0x4000,
			Release = 0x8000,
			Reset = 0x80000,
			Physical = 0x400000,
			TopDown = 0x100000,
			WriteWatch = 0x200000,
			LargePages = 0x20000000
		}

		[Flags]
		public enum MemoryProtection
		{
			Execute = 0x10,
			ExecuteRead = 0x20,
			ExecuteReadWrite = 0x40,
			ExecuteWriteCopy = 0x80,
			NoAccess = 0x01,
			ReadOnly = 0x02,
			ReadWrite = 0x04,
			WriteCopy = 0x08,
			GuardModifierflag = 0x100,
			NoCacheModifierflag = 0x200,
			WriteCombineModifierflag = 0x400
		}

		[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
		private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
							uint dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

		public static IntPtr GetModuleBaseAddress(Process proc, string modName)
		{
			IntPtr addr = IntPtr.Zero;

			foreach (ProcessModule m in proc.Modules)
			{
				if (m.ModuleName == modName)
				{
					addr = m.BaseAddress;
					break;
				}
			}
			return addr;
		}

		public static IntPtr GetModuleBaseAddress(int procId, string modName)
		{
			IntPtr modBaseAddr = IntPtr.Zero;

			IntPtr hSnap = CreateToolhelp32Snapshot(SnapshotFlags.Module | SnapshotFlags.Module32, procId);

			if (hSnap.ToInt64() != INVALID_HANDLE_VALUE)
			{
				MODULEENTRY32 modEntry = new MODULEENTRY32();
				modEntry.dwSize = (uint)Marshal.SizeOf(typeof(MODULEENTRY32));

				if (Module32First(hSnap, ref modEntry))
				{
					do
					{
						if (modEntry.szModule.Equals(modName))
						{
							modBaseAddr = modEntry.modBaseAddr;
							break;
						}
					} while (Module32Next(hSnap, ref modEntry));
				}
			}

			CloseHandle(hSnap);
			return modBaseAddr;
		}

		public static int GetProcId(string procname)
		{
			int procid = 0;

			IntPtr hSnap = CreateToolhelp32Snapshot(SnapshotFlags.Process, 0);

			if (hSnap.ToInt64() != INVALID_HANDLE_VALUE)
			{
				PROCESSENTRY32 procEntry = new PROCESSENTRY32();
				procEntry.dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32));

				if (Process32First(hSnap, ref procEntry))
				{
					do
					{
						if (procEntry.szExeFile.Equals(procname))
						{
							procid = (int)procEntry.th32ProcessID;
							break;
						}
					} while (Process32Next(hSnap, ref procEntry));
				}
			}

			CloseHandle(hSnap);
			return procid;
		}

		public static IntPtr FindDMAAddy(IntPtr hProc, IntPtr ptr, int[] offsets)
		{
			var buffer = new byte[IntPtr.Size];

			foreach (int i in offsets)
			{
				ReadProcessMemory(hProc, ptr, buffer, buffer.Length, out
				var read);
				ptr = (IntPtr.Size == 4) ? IntPtr.Add(new IntPtr(BitConverter.ToInt32(buffer, 0)), i) : ptr = IntPtr.Add(new IntPtr(BitConverter.ToInt64(buffer, 0)), i);
			}
			return ptr;
		}

		public static bool InjectDLL(string dllpath, string procname)
		{
			Process[] procs = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(procname));

			if (procs.Length == 0)
			{
				return false;
			}

			Process proc = procs[0];

			//redundant native method example - GetProcessesByName will automatically open a handle
			int procid = GetProcId(procname);
			IntPtr hProc = OpenProcess(ProcessAccessFlags.All, false, proc.Id);
			//

			if (proc.Handle != IntPtr.Zero)
			{
				//proc.Handle = managed
				IntPtr loc = VirtualAllocEx(proc.Handle, IntPtr.Zero, MAX_PATH, AllocationType.Commit | AllocationType.Reserve,
					MemoryProtection.ReadWrite);

				if (loc.Equals(0))
				{
					return false;
				}

				IntPtr bytesRead = IntPtr.Zero;

				bool result = WriteProcessMemory(proc.Handle, loc, dllpath.ToCharArray(), dllpath.Length, out bytesRead);

				if (!result || bytesRead.Equals(0))
				{
					return false;
				}

				IntPtr loadlibAddy = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
				//redundant native method example - MUST BE CASE SENSITIVE CORRECT
				loadlibAddy = GetProcAddress(GetModuleBaseAddress(proc.Id, "KERNEL32.DLL"), "LoadLibraryA");

				IntPtr hThread = CreateRemoteThread(proc.Handle, IntPtr.Zero, 0, loadlibAddy, loc, 0, out _);


				if (!hThread.Equals(0))
					//native method example
					CloseHandle(hThread);
				else return false;
			}
			else return false;

			//this will CloseHandle automatically using the managed method
			proc.Dispose();
			return true;
		}
	}
}