using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Runtime.InteropServices;
using D2ROffline.Util;

namespace D2ROffline.Tools
{
    public class StealthMode
    {
        private ManualMap ManualMap;
        private Memory Memory;
        private List<Hook> Hooks;

        static private string[] NtdllHooks = { "NtSetInformationThread", "NtSetDebugFilterState", "NtQuerySystemInformation", "NtQueryInformationProcess", "NtSetInformationProcess",
            "NtQueryObject", "NtYieldExecution", "NtCreateThreadEx", "NtClose", "NtGetContextThread", "NtSetContextThread", "NtContinue", "KiUserExceptionDispatcher", 
            "NtQuerySystemTime", "NtResumeThread", "NtQueryPerformanceCounter", "NtDuplicateObject", "NtCreateThread"};
        static private string[] Kernel32Hooks = { "GetTickCount", "GetTickCount64", "GetLocalTime", "GetSystemTime", "OutputDebugStringA" };

        // TODO: fix these?
        static private string[] UserHooks = { };
        static private string[] Win32uHooks = { }; //{ "NtUserBlockInput", "NtUserFindWindowEx", "NtUserBuildHwndList", "NtUserQueryWindow", "NtUserGetForegroundWindow" };

        public StealthMode(Memory m)
        {
            Memory = m;
            ManualMap = new ManualMap(m);
            Hooks = new List<Hook>();
        }

        public bool Inject(string dllPath)
        {
            byte[] dllBuffer = File.ReadAllBytes(dllPath);
            StartInjectionProcess(dllPath, dllBuffer);
            return true;
        }

        private void StartInjectionProcess(string dllPath, byte[] dllBuffer)
        {
            // suspend?

            // RemoveDebugPrivileges

            // MapModuleToProcess (manual map)
            
            ManualMap.InjectImage(dllPath);

            ///DWORD hookDllDataAddressRva = GetDllFunctionAddressRVA(dllMemory, "HookDllData")

            //StartHooking(dllBuffer, IntPtr.Zero);

            ApplyHooks(ManualMap.LocalScylla, ManualMap.RemoteScylla);
        }

        private bool ApplyHooks(IntPtr localScylla, IntPtr remoteScylla)
        {
            //ApplyAllPEBPatchs(); // TODO: fix
            //ApplyNtdllHooks(Imports.GetModuleHandle("ntdll.dll"));
            //ApplyKernel32Hooks(Imports.GetModuleHandle("KERNEL32.DLL"));
            //ApplyUserHooks(Imports.GetModuleHandle("KERNEL32.DLL"));
            ApplyShadowNtdllHooks(Imports.GetModuleHandle("ntdll.dll")); // TODO: get actual size

            return true;
        }

        private void ApplyNtdllHooks(IntPtr imageBase)
        {
            foreach(string name in NtdllHooks)
            {
                long addrOfDVA = -1;
                Hooks.Add(new Hook(Memory, Imports.GetProcAddress(imageBase, name).ToInt64(), addrOfDVA, 14));
            }
        }

        private void ApplyKernel32Hooks(IntPtr imageBase)
        {
            foreach (string name in Kernel32Hooks)
            {
                long addrOfDVA = -1;
                Hooks.Add(new Hook(Memory, Imports.GetProcAddress(imageBase, name).ToInt64(), addrOfDVA, 14));
            }
        }

        private void ApplyUserHooks(IntPtr imageBase)
        {
            foreach (string name in UserHooks)
            {
                long addrOfDVA = -1;
                Hooks.Add(new Hook(Memory, Imports.GetProcAddress(imageBase, name).ToInt64(), addrOfDVA, 14));
            }
        }

        public void ApplyShadowNtdllHooks(IntPtr ntdllBase)
        {
            IntPtr regionBase = IntPtr.Zero;
            IntPtr regionSize = IntPtr.Zero;
            MEMORY_BASIC_INFORMATION basicInformation = new MEMORY_BASIC_INFORMATION();

            long nextAddr = 0;
            int status = -1;
            byte[] byteSample = Memory.Read(ntdllBase + 0x1000, 32);

            // Scan for ntdll copy
            do
            {
                IntPtr address = (IntPtr)nextAddr;
                status = Imports.VirtualQueryEx(Memory.ProcessHandle, (IntPtr)nextAddr, out basicInformation, Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));
                nextAddr += (long)basicInformation.RegionSize;
                if (!basicInformation.Protect.Equals(MemoryProtectionConstraints.PAGE_EXECUTE_READWRITE) && (long)basicInformation.RegionSize > (0x1000 + byteSample.Length))
                    continue;

                // NOTE: shadow ntdll starts at 0x400
                byte[] shadowNtdllSample = Memory.Read(address+0x400, 32); 

                bool match = true;
                for (int i = 0; i < shadowNtdllSample.Length && i < byteSample.Length; i++)
                {
                    if (shadowNtdllSample[i] == byteSample[i])
                        continue;
                    match = false;
                    break;
                }
                if (!match)
                    continue;

                // Find copy of ntdll function
                Toolbox.GetImageHeaders((ulong)ManualMap.LocalScylla, out _, out _, out IMAGE_OPTIONAL_HEADER64 optionalHeader);
                byte[] shadowNtdll = Memory.Read(address, (int)optionalHeader.SizeOfImage-0xC00); // size matter?
                for (int i = 0; i < NtdllHooks.Length; i++)
                {
                    IntPtr jmpAddr = Imports.GetProcAddress(ntdllBase, NtdllHooks[i]);
                    // find in shadow -> 4c 8b d1 b8 ?? ?? ?? ?? F6 04 25 ?? ?? ?? ?? 01 75 03 0F 05 (first DWORD == Syscall ID)
                    byte[] sample = Memory.Read(jmpAddr, 20);
                    for (int j = 0; j < shadowNtdll.Length - sample.Length; j++)
                    {
                        bool found = true;
                        for (int k = 0; k < sample.Length; k++)
                        {
                            if (shadowNtdll[j + k] == sample[k])
                                continue;
                            found = false;
                            break;
                        }
                        if (!found)
                            continue;

                        // Match found!
                        Program.ConsolePrint($"0x{(address + j).ToString("X12")}: JMP -> 0x{jmpAddr.ToString("X12")} ({NtdllHooks[i]})");

                        // TODO: reaplce jmpAddr with NtdllHooks[i] hook
                        Hook newHook = new Hook(Memory, address.ToInt64() + j, jmpAddr.ToInt64(), 14);
                        newHook.Create();
                        Hooks.Add(newHook);
                        break;
                    }
                }
                break; // shadow ntdll found!

            } while (status != 0);

        }

        public void ApplyAllPEBPatchs()
        {
            // PEB only modified at startup?

            IntPtr pebAddress = Memory.GetPebAddress();
            _PEB peb = Memory.Read<_PEB>(pebAddress);
            _PEB_LDR_DATA ldr = Memory.Read<_PEB_LDR_DATA>((IntPtr)peb.Ldr);
            ulong next = (ulong)(pebAddress + Marshal.SizeOf(peb)) + ldr.Length;

            // NOTE: old
            /*
            //            // copy paste from https://www.pinvoke.net/default.aspx/ntdll.ntqueryinformationprocess
            //            IntPtr pbi = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)));
            //            IntPtr outLong = Marshal.AllocHGlobal(sizeof(long));
            //            IntPtr outPtr = IntPtr.Zero;

            //            int status = NtQueryInformationProcess(pHandle, ProcessInfoClass.ProcessBasicInformation, pbi, (uint)Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)), outLong);
            //
            //            Marshal.FreeHGlobal(outLong);
            //            Marshal.FreeHGlobal(pbi);

            // copy paste from https://www.pinvoke.net/default.aspx/ntdll.ntqueryinformationprocess
            PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
            IntPtr outLong = Marshal.AllocHGlobal(sizeof(long));
            IntPtr outPtr = IntPtr.Zero;
            int status = Imports.NtQueryInformationProcess(Memory.ProcessHandle, ProcessInfClass.ProcessBasicInformation, ref pbi, (uint)Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)), outLong);
            Marshal.FreeHGlobal(outLong);

            byte[] content = new byte[0x100];
            Imports.ReadProcessMemory(Memory.ProcessHandle, pbi.PebBaseAddress, content, content.Length, out _);

            // TODO:
            content[0x02] = 0x01; // - BeingDebugger = False (0x02)
                                  // - NtGlobalFlag &= ~0x70
                                  // - PebPatchProcessParameters
                                  // - PebPatchHeapFlags
                                  // - OSBuildNumber++

            Imports.WriteProcessMemory(Memory.ProcessHandle, pbi.PebBaseAddress, content, content.Length, out _);


            / * typedef struct _PEB
            {
                BYTE Reserved1[2]; //0
                BYTE BeingDebugged; //2
                BYTE Reserved2[1]; //3
                PVOID Reserved3[2]; //4
                PPEB_LDR_DATA Ldr; //6 (size 8+3+(4??)
                PRTL_USER_PROCESS_PARAMETERS ProcessParameters; //21 (size 16+10+??+??
                PVOID Reserved4[3]; //24
                PVOID AtlThunkSListPtr; //30
                PVOID Reserved5; //38
                ULONG Reserved6; //46
                PVOID Reserved7; //54
                ULONG Reserved8; //62
                ULONG AtlThunkSListPtr32; //70
                PVOID Reserved9[45]; //
                BYTE Reserved10[96];
                PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
                BYTE Reserved11[128];
                PVOID Reserved12[1];
                ULONG SessionId;
            } */

        }
    }
}
