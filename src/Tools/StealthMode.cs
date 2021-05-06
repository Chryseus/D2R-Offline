using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace D2ROffline.Tools
{
    public class StealthMode
    {
        private Memory Memory;

        public StealthMode(Memory m)
        {
            Memory = m;
        }

        public bool StartInject(byte[] dllBuffer)
        {

            StartHooking(dllBuffer, IntPtr.Zero);
            return true;
        }

        private bool StartHooking(byte[] dllBuffer, IntPtr imgBase)
        {
            ApplyAllPEBPatchs();
            // TODO: Hook KERNEL32 (ApplyKernel32Hook)
            // 
            return ApplyHook();
        }

        private bool ApplyHook()
        {
            return true;
        }

        private void ApplyAllPEBPatchs()
        {
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


            /* typedef struct _PEB
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
