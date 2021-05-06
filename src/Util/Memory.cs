using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Diagnostics;
using System.Runtime.InteropServices.WindowsRuntime;

namespace D2ROffline.Tools
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

            var addr = (long)GetProcAddress(GetModuleHandle("KERNEL32"), "BaseThreadInitThunk") + 0x04;

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

        //public IntPtr CRT(IntPtr Address)
        //{
        //    return Imports.CreateRemoteThread(this.ProcessHandle, IntPtr.Zero, 0, Address, IntPtr.Zero, ThreadFlags.ThreadExecuteImmediately, out IntPtr tID);
        //}

        public byte[] Read(long Address, int size)
        {
            if (this.TargetProcess.HasExited)
            {
                Console.WriteLine($"Memory.Read failed, Target process with pid {this.TargetProcess} has exited");
                return null;
            }

            IntPtr bRead = IntPtr.Zero;
            byte[] buffer = new byte[size];
            Imports.ReadProcessMemory(this.ProcessHandle, (IntPtr)Address, buffer, buffer.Length, out bRead);
            if (bRead.ToInt32() != size)
                Console.WriteLine("Memory.Read fucked up");

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
                Console.WriteLine($"Memory.Write failed, Target process with pid {this.TargetProcess} has exited");
                return false;
            }

            IntPtr bWrite = IntPtr.Zero;
            Imports.WriteProcessMemory(this.ProcessHandle, (IntPtr)Address, buffer, buffer.Length, out bWrite);
            if (bWrite.ToInt32() != buffer.Length)
                Console.WriteLine("Memory.Write fucked up");

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

        public IntPtr GetModuleHandle(string Name)
        {
            return Imports.GetModuleHandle(Name);
        }

        public bool GetThreadContext(IntPtr Handle, ref CONTEXT64 Context)
        {
            return Imports.GetThreadContext(Handle, ref Context);
        }

        public bool SetThreadContext(IntPtr Handle, ref CONTEXT64 Context)
        {
            return Imports.SetThreadContext(Handle, ref Context);
        }

    }
}
