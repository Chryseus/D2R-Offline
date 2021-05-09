using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Diagnostics;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace D2ROffline.Util
{
    public class Memory
    {
        public Process TargetProcess { get; set; }
        public IntPtr ProcessHandle { get; set; }
        public List<Hook> Hooks { get; set; }

        private long[] PatchCRTAddress { get; set; }

        public Memory(Process targetProcess)
        {
            this.TargetProcess = targetProcess;
            this.ProcessHandle = OpenProcess(ProcessAccessFlags.PROCESS_ALL_ACCESS);
            this.PatchCRTAddress = null;
        }

        public void BypassCRT(bool status)
        {
            byte[] patch = { 0x85, 0xC9, 0x75, 0x18 }; // test ecx,ecx jxxx
            if (status)
                patch = new byte[] { 0x90, 0x48, 0xFF, 0xC2 }; // nop, inc rdx

            var addr = (long)GetProcAddress(Imports.GetModuleHandle("KERNEL32"), "BaseThreadInitThunk") + 0x04;

            Write(addr, patch);
        }

        public IntPtr OpenProcess(ProcessAccessFlags Access)
        {
            return Imports.OpenProcess(Access, false, this.TargetProcess.Id);
        }

        public bool CloseHandle(IntPtr Handle)
        {
            return Imports.CloseHandle(Handle);
        }

        public IntPtr OpenThread(ThreadAccess Access = ThreadAccess.SET_CONTEXT | ThreadAccess.GET_CONTEXT | ThreadAccess.SUSPEND_RESUME)
        {
            return Imports.OpenThread(Access, false, (uint)this.TargetProcess.Threads[0].Id);
        }

        public IntPtr CRT(IntPtr Address)
        {
            return Imports.CreateRemoteThread(this.ProcessHandle, IntPtr.Zero, 0, Address, IntPtr.Zero, ThreadFlags.ThreadExecuteImmediately, out IntPtr tID);
        }

        public byte[] Read(long Address, int size)
        {
            if (this.TargetProcess.HasExited)
            {
                Program.ConsolePrint($"Memory.Read failed, Target process with pid {this.TargetProcess} has exited");
                return null;
            }

            IntPtr bRead = IntPtr.Zero;
            byte[] buffer = new byte[size];
            Imports.ReadProcessMemory(this.ProcessHandle, (IntPtr)Address, buffer, buffer.Length, out bRead);
            if (bRead.ToInt32() != size)
                Program.ConsolePrint("Memory.Read fucked up");

            return buffer;
        }

        public byte[] Read(IntPtr Address, int size)
        {
            return Read((long)Address, size);
        }

        public long Read(long Address)
        {
            return BitConverter.ToInt64(Read(Address, 8), 0);
        }

        public float ReadFloat(long Address)
        {
            return BitConverter.ToSingle(Read(Address, 4), 0);
        }

        public void Read(long Address, ref byte[] buffer)
        {
            buffer = Read(Address, buffer.Length);
        }

        public long Read(IntPtr Address)
        {
            return BitConverter.ToInt64(Read(Address, 8), 0);
        }

        public string ReadStr(long Address, int maxSize = 32)
        {
            return Encoding.UTF8.GetString(Read(Address, maxSize)).Split('\0').FirstOrDefault();
        }

        public string ReadStr(IntPtr Address, int maxSize = 32)
        {
            return Encoding.UTF8.GetString(Read(Address, maxSize)).Split('\0').FirstOrDefault();
        }

        public bool Write(long Address, byte[] buffer)
        {
            if (this.TargetProcess.HasExited)
            {
                Program.ConsolePrint($"Memory.Write failed, Target process with pid {this.TargetProcess} has exited");
                return false;
            }

            IntPtr bWrite = IntPtr.Zero;
            Imports.WriteProcessMemory(this.ProcessHandle, (IntPtr)Address, buffer, buffer.Length, out bWrite);
            if (bWrite.ToInt32() != buffer.Length)
                Program.ConsolePrint("Memory.Write fucked up");

            return true;
        }

        public bool Write(long Address, long Data)
        {
            return Write(Address, BitConverter.GetBytes(Data));
        }

        public bool Write(long Address, int Data)
        {
            return Write(Address, BitConverter.GetBytes(Data));
        }

        public bool WriteStr(long Address, string String)
        {
            return Write(Address, Encoding.UTF8.GetBytes(String));
        }

        public IntPtr AllocEx(int Size, MemoryProtectionConstraints MemoryProtection, MemoryAllocationType AllocationType = MemoryAllocationType.MEM_COMMIT, long Address = -1)
        {
            IntPtr BaseAddress = IntPtr.Zero;
            if (Address != -1)
                BaseAddress = (IntPtr)Address;

            return Imports.VirtualAllocEx(this.ProcessHandle, BaseAddress, Size, AllocationType, MemoryProtection);
        }

        public void Write<T>(T value, IntPtr address) where T : struct
        {
            Write((long)address, Toolbox.GetBytes(value));
        }

        public T Read<T>(IntPtr address) where T : struct
        {
            byte[] buffer = Read(address, Unsafe.SizeOf<T>());

            return Toolbox.GetStructure<T>(buffer);
        }


        //public IntPtr SharedAllocEx(int Size, FileMapProtection MemoryProtection, string MapObjName)
        //{
        //    var hMapFile = Imports.CreateFileMapping((IntPtr)(-1), IntPtr.Zero, Imports.FileMapProtection.PageReadWrite, 0, (uint)Size, MapObjName);

        //    if (hMapFile == IntPtr.Zero)
        //        return IntPtr.Zero;

        //    Console.WriteLine("handle: " + hMapFile.ToString("X"));

        //    var pBuf = Imports.MapViewOfFile(hMapFile, Imports.FileMapAccess.FileMapRead, 0, 0, (UIntPtr)Size);

        //    if (pBuf == IntPtr.Zero)
        //    {
        //        Log.Print($"Mapping Shared Memory failed for '{MapObjName}'", ConsoleColor.Red);
        //        CloseHandle(hMapFile);
        //        return IntPtr.Zero;
        //    }

        //    return pBuf;
        //}

        public bool FreeEx(long Address, FreeType FreeType = FreeType.Release)
        {
            return Imports.VirtualFreeEx(this.ProcessHandle, (IntPtr)Address, 0, FreeType);
        }

        public int SuspendThread(IntPtr Handle)
        {
            return Imports.SuspendThread(Handle);
        }

        public int ResumeThread(IntPtr Handle)
        {
            return Imports.ResumeThread(Handle);
        }

        public long GetBaseAddress()
        {
            return (long)this.TargetProcess.MainModule.BaseAddress;
        }

        public IntPtr GetProcAddress(IntPtr Module, string Name)
        {
            return Imports.GetProcAddress(Module, Name);
        }

        public unsafe Dictionary<string, ulong> GetModules()
        {
            var result = new Dictionary<string, ulong>();

            ulong[] moduleHandleArray = new ulong[1000];

            fixed (ulong* hMods = moduleHandleArray)
            {
                if (Imports.EnumProcessModules(ProcessHandle, (ulong)hMods, (uint)(sizeof(ulong) * moduleHandleArray.Length), out uint cbNeeded) > 0)
                {
                    for (int moduleIndex = 0; moduleIndex < cbNeeded / sizeof(ulong); moduleIndex++)
                    {
                        string name = GetModuleBaseName(TargetProcess.Handle, moduleHandleArray[moduleIndex]);

                        result[name.ToLower()] = moduleHandleArray[moduleIndex];

                        //if (String.Equals(name, moduleName, StringComparison.InvariantCultureIgnoreCase))
                        //    return moduleHandleArray[moduleIndex];
                    }
                }
            }

            return result;
        }

        public string GetModuleBaseName(IntPtr handle, ulong moduleHandle)
        {
            StringBuilder name = new StringBuilder(1024);
            Imports.GetModuleBaseName(handle, moduleHandle, name, 1024);
            return name.ToString();
        }

        public bool GetThreadContext(IntPtr Handle, ref CONTEXT64 Context)
        {
            return Imports.GetThreadContext(Handle, ref Context);
        }

        public bool SetThreadContext(IntPtr Handle, ref CONTEXT64 Context)
        {
            return Imports.SetThreadContext(Handle, ref Context);
        }

        public IntPtr CreateSection(MemoryProtectionConstraints memoryProtection, long size)
        {
            IntPtr handle = IntPtr.Zero;
            Ntstatus status = Imports.NtCreateSection(ref handle, ACCESS_MASK.GENERIC_ALL, IntPtr.Zero, ref size, memoryProtection, SectionProtectionConstraints.SEC_COMMIT, IntPtr.Zero);
            if (status != Ntstatus.STATUS_SUCCESS)
                throw new Exception("NtCreatSection failed");
            return handle;
        }

        public IntPtr GetPebAddress()
        {
            PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
            Imports.NtQueryInformationProcess(ProcessHandle, 0, ref pbi, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)), IntPtr.Zero);

            return pbi.PebBaseAddress;
        }
        public _PEB_LDR_DATA GetLoaderData()
        {
            var peb = Read<_PEB>(GetPebAddress());
            return Read<_PEB_LDR_DATA>((IntPtr)peb.Ldr);
        }
        public void WriteLoaderData(_PEB_LDR_DATA ldrData)
        {
            var peb = Read<_PEB>(GetPebAddress());
            Write(ldrData, (IntPtr)peb.Ldr);
        }

    }
}
