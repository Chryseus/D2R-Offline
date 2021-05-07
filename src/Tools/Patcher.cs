﻿using System;
using System.Linq;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Security.Cryptography.X509Certificates;
using D2ROffline.Util;

namespace D2ROffline.Tools
{
    internal class Patcher
    {
        public static bool Start(string d2rPath = Constants.DIABLO_MAIN_EXE_FILE_NAME, int crashDelay = 25, string d2rargs = "")
        {
            if (!File.Exists(d2rPath))
            {
                Program.ConsolePrint($"Error, file '{d2rPath}' does not exist!", ConsoleColor.Red);
                Program.ConsolePrint("Usage: D2ROffline.exe PATH_TO_GAMEDOTEXE", ConsoleColor.White);
                return false;
            }

            Program.ConsolePrint("Launching game...");
            var pInfo = new ProcessStartInfo(d2rPath);

            if (d2rargs != "")
                pInfo.Arguments = d2rargs;
            else
                Program.ConsolePrint("Extra parameters not found. Proceeding...", ConsoleColor.White); // not to obvious color or ppl may freak out

            var d2r = Process.Start(pInfo);

            // wait for proc to properly enter userland to bypass first few anti-cheating checks
            Program.ConsolePrint("Process started...");
            IntPtr hProcess = Imports.OpenProcess(ProcessAccessFlags.PROCESS_ALL_ACCESS, false, d2r.Id);
            Program.ConsolePrint("Opening process...");

            if (hProcess == IntPtr.Zero)
            {
                Program.ConsolePrint("Failed on OpenProcess. Handle is invalid.", ConsoleColor.Red);
                return false;
            }

            // pre setup
            WaitForData(hProcess, d2r.MainModule.BaseAddress, 0x22D8858);
            Thread.Sleep(crashDelay); // NOTE: getting crash? extend this delay!

            // suspend process
            Program.ConsolePrint("Suspending process...");
            Imports.NtSuspendProcess(hProcess);
            Program.ConsolePrint("Process suspended");

            X509Certificate data = X509Certificate.CreateFromSignedFile(d2rPath);
            if(!data.Subject.Contains(" Entertainment, "))
            {
                Program.ConsolePrint("Error, the target process is not a game?");
                return false;
            }

            if (Imports.VirtualQueryEx(hProcess, d2r.MainModule.BaseAddress, out MEMORY_BASIC_INFORMATION basicInformation, Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) == 0)
            {
                Program.ConsolePrint("Failed on VirtualQueryEx. Return is 0 bytes.", ConsoleColor.Red);
                return false;
            }

           

            // TODO: move to StealthMode
            StealthMode m = new StealthMode(new Memory(d2r));
            ProcessModule ntdll = null;
            foreach(ProcessModule pm in d2r.Modules)
                if(pm.ModuleName.Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase))
                    ntdll = pm;

            m.ApplyShadowNtdllHooks(ntdll.BaseAddress, ntdll.ModuleMemorySize);

            Program.ConsolePrint("Resuming process..");
            Imports.NtResumeProcess(hProcess);
            Imports.CloseHandle(hProcess);
            return true;
        }

        // Memory function
        public static IntPtr RemapMemoryRegion(IntPtr processHandle, IntPtr baseAddress, int regionSize, MemoryProtectionConstraints mapProtection)
        {
            IntPtr addr = Imports.VirtualAllocEx(processHandle, IntPtr.Zero, regionSize, MemoryAllocationType.MEM_COMMIT | MemoryAllocationType.MEM_RESERVE, mapProtection);
            if (addr == IntPtr.Zero)
                return IntPtr.Zero;

            IntPtr copyBuf = Imports.VirtualAlloc(IntPtr.Zero, regionSize, MemoryAllocationType.MEM_COMMIT | MemoryAllocationType.MEM_RESERVE, mapProtection);
            IntPtr copyBufEx = Imports.VirtualAllocEx(processHandle, IntPtr.Zero, regionSize, MemoryAllocationType.MEM_COMMIT | MemoryAllocationType.MEM_RESERVE, MemoryProtectionConstraints.PAGE_EXECUTE_READWRITE);
            byte[] copyBuf2 = new byte[regionSize];

            if (!Imports.ReadProcessMemory(processHandle, baseAddress, copyBuf, regionSize, out IntPtr bytes))
                return IntPtr.Zero;

            if (!Imports.ReadProcessMemory(processHandle, baseAddress, copyBuf2, regionSize, out bytes))
                return IntPtr.Zero;

            IntPtr sectionHandle = default;
            long sectionMaxSize = regionSize;

            Ntstatus status = Imports.NtCreateSection(ref sectionHandle, AccessMask.SECTION_ALL_ACCESS, IntPtr.Zero, ref sectionMaxSize, MemoryProtectionConstraints.PAGE_EXECUTE_READWRITE, SectionProtectionConstraints.SEC_COMMIT, IntPtr.Zero);

            if (status != Ntstatus.STATUS_SUCCESS)
                return IntPtr.Zero;

            status = Imports.NtUnmapViewOfSection(processHandle, baseAddress);


            if (status != Ntstatus.STATUS_SUCCESS)
                return IntPtr.Zero;

            IntPtr viewBase = baseAddress;
            long sectionOffset = default;
            uint viewSize = 0;
            status = Imports.NtMapViewOfSection(sectionHandle,
                                               processHandle,
                                               ref viewBase,
                                               UIntPtr.Zero,
                                               regionSize,
                                               ref sectionOffset,
                                               ref viewSize,
                                               2,
                                               0,
                                               MemoryProtectionConstraints.PAGE_EXECUTE_READWRITE);

            if (status != Ntstatus.STATUS_SUCCESS)
                return IntPtr.Zero;

            if (!Imports.WriteProcessMemory(processHandle, viewBase, copyBuf, (int)viewSize, out bytes))
                return IntPtr.Zero;

            if (!Imports.WriteProcessMemory(processHandle, copyBufEx, copyBuf, (int)viewSize, out bytes))
                return IntPtr.Zero;

            // apply all request patches
            ApplyAllPatches(processHandle, baseAddress);

            //crc32 bypass
            //search for F2 ?? 0F 38 F1 - F2 REX.W 0F 38 F1 /r CRC32 r64, r/m64	RM	Valid	N.E.	Accumulate CRC32 on r/m64.
            byte[] AoBpattern = { 0xF2, 0x42, 0x0F, 0x38, 0xF1 };
            for (long i = 0; i < regionSize; i++)
            {
                bool isMatch = true;
                for (long j = 0; j < AoBpattern.Length; j++)
                {
                    if (!(copyBuf2[i + j] == AoBpattern[j] || j == 1))
                    {
                        isMatch = false;
                        break;
                    }
                }
                if (isMatch)
                    detourCRC(processHandle, (long)baseAddress + i, (long)baseAddress, (long)copyBufEx);
            }

            byte[] patchA = { 0xCC };
            byte[] patchB = { 0xC3 };

            IntPtr DbgBreakpoint = Imports.GetProcAddress(Imports.GetModuleHandle("ntdll.dll"), "DbgBreakPoint");

            //WriteProcessMemory(processHandle, DbgBreakpoint, patchA, patchA.Length, out _);

            // NOTE: uncomment if you want to snitch a hook inside the .text before it remaps back from RWX to RX
#if DEBUG
            Program.ConsolePrint("Patching complete..");
            Program.ConsolePrint("[!] Press any key to remap and resume proces...", ConsoleColor.Yellow);
            Console.ReadKey();
#endif

            //WriteProcessMemory(processHandle, DbgBreakpoint, patchB, patchB.Length, out _);

            // remap
            status = Imports.NtUnmapViewOfSection(processHandle, baseAddress);

            if (status != Ntstatus.STATUS_SUCCESS)
                return IntPtr.Zero;


            status = Imports.NtMapViewOfSection(sectionHandle,
                                               processHandle,
                                               ref viewBase,
                                               UIntPtr.Zero,
                                               regionSize,
                                               ref sectionOffset,
                                               ref viewSize,
                                               2,
                                               0,
                                               MemoryProtectionConstraints.PAGE_EXECUTE_READ);

            if (status != Ntstatus.STATUS_SUCCESS)
                return IntPtr.Zero;

            if (!Imports.VirtualFree(copyBuf, 0, MemFree.MEM_RELEASE))
                return IntPtr.Zero;

            return addr;
        }
        private static void WaitForData(IntPtr processHandle, IntPtr baseAddress, int offset)
        {
            // now waiting for game  to lock in inf loop
            Program.ConsolePrint($"Waiting for data at 0x{(baseAddress + offset).ToString("X8")}...");
            int count = 0;
            while (count < 500) // 5000ms timeout
            {
                byte[] buff = new byte[3];
                if (!Imports.ReadProcessMemory(processHandle, baseAddress + offset, buff, buff.Length, out _)) // pre
                {
                    Program.ConsolePrint("Failed reading initial process memory", ConsoleColor.Red);
                    continue; // dont break?
                }
                if (buff[0] != 0x00 || buff[2] != 0x00)
                    break;

                Thread.Sleep(10); // continue execution  
                count++;
            }
        }
        private static void ApplyAllPatches(IntPtr processHandle, IntPtr baseAddress)
        {
            // NOTE: you can make a 'patches.txt' file, using the format '0x1234:9090' where 0x1234 indicates the offset (game.exe+0x1234) and 9090 indicates the patch value (nop nop)
            string patchesContent = "";
            if (File.Exists("patches.txt"))
                patchesContent = File.ReadAllText("patches.txt");

            if (patchesContent == "")
            {
                Program.ConsolePrint("WARNING: Not patches are beeing loaded. (If this is unexpected, double check your 'patches.txt' file!)", ConsoleColor.Yellow);
                return;
            }

            string[] split = patchesContent.Split('\n');
            int[] addr = new int[split.Length];
            byte[][] patch = new byte[split.Length][];

            // init arrays
            // NOTE: limiting the amount of bytes to patch to prevent malicous abuse!
            int bytePatchCount = 0;
            for (int i = 0; i < split.Length; i++)
            {
                string[] data = split[i].Split(':');
                if (data.Length < 2)
                    continue; // probs empty line

                addr[i] = Convert.ToInt32(data[0], 0x10);
                if (addr[i] == 0)
                    continue;

                if (data[1][0] == '+')
                {
                    // offset patch
                    string offset = data[1].Substring(1);
                    //byte[] buf = new byte[offset.Length / 2]; // amount of bytes in patch len?
                    byte[] buf = new byte[8]; // qword
                    if (!Imports.ReadProcessMemory(processHandle, IntPtr.Add(baseAddress, addr[i]), buf, buf.Length, out _))
                    {
                        Program.ConsolePrint("Error, failed read patch location!", ConsoleColor.Yellow);
                        continue; // non critical, just skip
                    }
                    patch[i] = BitConverter.GetBytes(BitConverter.ToInt64(buf, 0) + Convert.ToInt64(offset, 0x10));
                }
                else
                {
                    // normal patch
                    patch[i] = new byte[data[1].Length / 2];
                    for (int j = 0; j < patch[i].Length; j++)
                        patch[i][j] = Convert.ToByte(data[1].Substring(j * 2, 2), 0x10);
                }
            }

            // patch arrays
            for (int i = 0; i < split.Length; i++)
            {
                if (addr[i] == 0)
                    continue;

                if (patch[i] == null)
                {
                    Program.ConsolePrint($"Invalid patch at line {i + 1}!", ConsoleColor.Yellow);
                    continue;
                }

                bytePatchCount += patch.Length;
                if(bytePatchCount > 200) // NOTE: this is to prevent people from inject asm malware payloads using the patches.txt feature
                {
                    Program.ConsolePrint($"Patch 0x{(baseAddress + addr[i]).ToString("X8")} reject, maximum patch sized reached!", ConsoleColor.Red);
                    continue;
                }
                Program.ConsolePrint($"Patching 0x{(baseAddress + addr[i]).ToString("X8")}");
                if (!Imports.WriteProcessMemory(processHandle, IntPtr.Add(baseAddress, addr[i]), patch[i], patch[i].Length, out IntPtr bWritten1) || (int)bWritten1 != patch[i].Length)
                    Program.ConsolePrint($"Patch {i} failed!!", ConsoleColor.Red);
            }

        }
        public static bool detourCRC(IntPtr processHandle, long crcLocation, long wowBase, long wowCopyBase)
        {
            #region asmCave

            //stuff that goes in the .text section
            byte[] crcDetour =
            {
                0x50,                                                               //push rax
                0x48, 0xB8, 0xEF, 0xEE, 0xEE, 0xEE, 0xEE, 0xBE, 0xAD, 0xDE,         //mov rax, CaveAddr (0x03)
                0xFF, 0xD0,                                                         //call rax
                0x58,                                                               //pop rax
                0x90                                                                //nop
            };
            byte[] crcDetourRegOffsets = { 0x00, 0x02, 0x0C, 0x0D }; //regiser offsets (may need to change when register is used in code)

            //stuff that goes in new allocated section
            byte[] crcCave =
            {
                0x51,                                                               //push rcx
                0x48, 0xB9, 0xEF, 0xEE, 0xEE, 0xEE, 0xEE, 0xBE, 0xAD, 0xDE,         //mov rcx, imgBase (0x03)
                0x48, 0x39, 0xCF,                                                   //cmp r2, rcx - 0x0B
                0x7C, 0x38,                                                         //jl crc
                0x50,                                                               //push rax
                0x48, 0x8B, 0xC1,                                                   //mov rax, rcx
                0x8B, 0x89, 0x58, 0x02, 0x00, 0x00,                                 //mov ecx, [r1+0x258] // .text Raw Size
                0x90,
                0x48, 0x01, 0xC1,                                                   //add rcx,rax
                0x8B, 0x80, 0x54, 0x02, 0x00, 0x00,                                 //mov eax,[rax+0x254] // .text Virtual Address
                0x90,
                0x48, 0x01, 0xC1,                                                   //add rcx,rax
                0x58,                                                               //pop rax
                0x48, 0x39, 0xCF,                                                   //cmp r2, rcx - 0x29
                0x7F, 0x1A,                                                         //jg crc
                
                // TODO: update codecave with assembly below (and offset crcCaveRegInstructOffsets offsets)

                // psuh rax
                // mov eax, rcx
                // mov ecx, [r1+0x280]  // .rdata Raw Size
                // nop
                // add rcx, rax
                // mov eax, [rax+0x27C] // .rdata Virtual Address
                // nop
                // add rcx, rax
                // pop rax
                // cmp r2, rcx

                0x48, 0xB9, 0xEF, 0xEE, 0xEE, 0xEE, 0xEE, 0xBE, 0xAD, 0xDE,         //mov rcx, imgBase (0x30)
                0x48, 0x29, 0xCF,                                                   //sub r2, rcx - 0x38
                0x48, 0xB9, 0xEF, 0xEE, 0xEE, 0xEE, 0xEE, 0xBE, 0xAD, 0xDE,         //mov rcx, imgCopyBase (0x3D)
                0x48, 0x01, 0xCF,                                                   //add r2, rcx - 0x45
                0x59,                                                               //pop rcx
                //crc:                                                              //crc location start
                0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,                           //+ 0x47 
                0x90, 0x90, 0x90,
                0x90, 0x90, 0x90, 0x90, 0x90,                                       // NOP's as placeholder for the 15-19 bytes
                0x90, 0x90, 0x90,                                                   
                //crc                                                               //crc location end
                0xC3                                                                //ret
            };
            byte[] crcCaveRegInstructOffsets = { 0x0B, 0x29, 0x38, 0x45 }; //register offsets (may need to change when register is used in code)
            #endregion asmCave

            IntPtr CaveAddr = Imports.VirtualAllocEx(processHandle, IntPtr.Zero, crcCave.Length, MemoryAllocationType.MEM_COMMIT, MemoryProtectionConstraints.PAGE_EXECUTE_READWRITE);
            if (CaveAddr == IntPtr.Zero)
            {
                Program.ConsolePrint("VirtualAlloxEx error", ConsoleColor.Red);
                return false;
            }

            byte[] splitCaveAddr = BitConverter.GetBytes(CaveAddr.ToInt64());                       //write CaveAddr to crcDetour buffer
            byte[] splitWowBase = BitConverter.GetBytes(wowBase);                                   //write imgBase to crcCave buffer
            byte[] splitWowCopyBase = BitConverter.GetBytes(wowCopyBase);                           //write imgCopyBase to crcCave buffer

            //replace the beef (placeholders)
            for (int i = 0; i < 8; i++)
            {
                crcDetour[0x03 + i] = splitCaveAddr[i];         //CaveAdr
                crcCave[0x03 + i] = splitWowBase[i];            //imgBase
                crcCave[0x30 + i] = splitWowBase[i];            //imgBase
                crcCave[0x3D + i] = splitWowCopyBase[i];        //imgCopyBase (aka Game_2.exe)
            }

            //obtain crc instructions
            byte[] crcBuffer = new byte[88];
            if (!Imports.ReadProcessMemory(processHandle, (IntPtr)crcLocation, crcBuffer, crcBuffer.Length, out IntPtr bRead))
            {
                Program.ConsolePrint("Reading CRC location failed", ConsoleColor.Red);
                return false;
            }

            bool isJmpFound = false;
            int origCrcInstructionLength = -1;
            for (int i = 0; i < crcCave.Length - 0x49; i++)
            {
                //jb is the last instruction and starts with 0x72 (2 bytes long)
                crcCave[0x49 + i] = crcBuffer[i];                   //write byte to codecave
                if (crcBuffer[i] == 0x72)
                {
                    crcCave[0x49 + i + 1] = crcBuffer[i + 1];       //include last byte of JB instruction before breaking
                    origCrcInstructionLength = i + 2;               //Keep track of bytes used to NOP later
                    isJmpFound = true;
                    break;
                }
            }

            if (!isJmpFound)
            {
                Program.ConsolePrint("NOPE", ConsoleColor.Red);
                return false;
            }

            //list used registers rax,   rcx,   rdx,   rbx,   rsp,   rbp,   rsi,   rdi
            bool[] usedRegs = { false, false, false, false, false, false, false, false };     //rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi


            //check byte code to find used stuff
            usedRegs[(crcBuffer[0x05] - 0x04) / 8] = true;              //x,[reg+reg*8]
            usedRegs[(crcBuffer[0x09] - 0xC0)] = true;                //inc x

            if (crcBuffer[0x0C] >= 0xC0 && crcBuffer[0x0C] < 0xC8)
                usedRegs[(crcBuffer[0x0C] - 0xC0)] = true;            // cmp ?, x

            byte selectReg = 0;
            for (byte r = 0; r < usedRegs.Length; r++)
            {
                if (usedRegs[r] == false)
                {
                    selectReg = r;
                    break;
                }
            }

            //change Detour register to non-used register
            for (int i = 0; i < crcDetourRegOffsets.Length; i++)
            {
                crcDetour[crcDetourRegOffsets[i]] += selectReg;      //increase byte to set selected register
            }

            //Change the register(r2) used to calc crc32
            for (int i = 0; i < crcCaveRegInstructOffsets.Length; i++)
            {
                crcCave[crcCaveRegInstructOffsets[i] + 0] = crcBuffer[0x01]; //copy
                crcCave[crcCaveRegInstructOffsets[i] + 2] = crcBuffer[0x06]; //copy
                if (crcCave[crcCaveRegInstructOffsets[i] + 0] != 0x48) //check if register is extra register (r8 - r15)
                {
                    crcCave[crcCaveRegInstructOffsets[i] + 0] = 0x49; //set to extra register type
                    crcCave[crcCaveRegInstructOffsets[i] + 2] = (byte)(0xC8 + (crcBuffer[0x06] - 0xC0) % 8); //set second reg to rcx and fix first reg
                }
                else
                    crcCave[crcCaveRegInstructOffsets[i] + 2] += 8; //inc to fix basic registers
            }

            //add nops to end of the detour buffer
            byte[] crcDetourFixed = new byte[origCrcInstructionLength];
            for (int i = 0; i < origCrcInstructionLength; i++)
            {
                if (i < crcDetour.Length)
                {
                    //Copy byte from crcDetour to fixed crcDetour
                    crcDetourFixed[i] = crcDetour[i];
                }
                else
                {
                    //add NOPs
                    crcDetourFixed[i] = 0x90;
                }
            }

            if (!Imports.WriteProcessMemory(processHandle, (IntPtr)(crcLocation), crcDetourFixed, crcDetourFixed.Length, out IntPtr bWrite))
            {
                Program.ConsolePrint("Writing CRC detour failed", ConsoleColor.Red);
                return false;
            }
            if (!Imports.WriteProcessMemory(processHandle, CaveAddr, crcCave, crcCave.Length, out bWrite))
            {
                Program.ConsolePrint("Writing CRC CodeCave failed", ConsoleColor.Red);
                return false;
            }

            Program.ConsolePrint($"Bypassed CRC at {crcLocation.ToString("X")}"); // to {CaveAddr.ToString("X")}");
            return true;
        }
    }
}
