using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using D2ROffline;

namespace D2ROffline.Tools
{
    public class Hook
    {
        public Memory Memory { get; set; }
        public byte[] ShellCode { get; set; }
        public long Address { get; set; }
        public long ReturnAddress { get; set; }
        public List<long> Addresses { get; set; }
        public List<long> Locations { get; set; }
        public long HookAddress { get; set; }
        public byte[] OriginalBytes { get; set; }
        private bool CopyOriginalBytesStart { get; set; } //false
        private int JumpSize { get; set; } // Size for the jump+nop

        /// <summary>
        /// Create a Hook objects that can be initialised/removed lateron
        /// </summary>
        /// <param name="memory">Memory class</param>
        /// <param name="shellCode">The code cave</param>
        /// <param name="hookAddress">Address to hook at</param>
        /// <param name="addr">List of addresses to write into the code cave</param>
        /// <param name="loc">List of offsets pointing to the where each address should be written in the code cave</param>
        /// <param name="jumpSize">Amount of bytes that need to be copied from the hook address to the start of the code cave</param>
        /// <param name="copyStart">Copy bytes to the start of the code cave</param>
        public Hook(Memory memory, byte[] shellCode, long hookAddress, List<long> addr, List<long> loc, int jumpSize = -1, bool copyStart = false)
        {
            this.Memory = memory;
            this.Address = -1;
            this.ShellCode = shellCode;
            this.HookAddress = hookAddress;
            this.ReturnAddress = hookAddress;
            this.Addresses = addr;
            this.Locations = loc;
            this.OriginalBytes = new byte[0];
            this.CopyOriginalBytesStart = copyStart;
            if (jumpSize != -1)
                this.JumpSize = jumpSize;
        }

        public Hook(byte[] shellCode, long hookAddress, List<long> addr, List<long> loc, bool copyStart = false)
        {
            this.ShellCode = shellCode;
            this.Address = -1;
            this.HookAddress = hookAddress;
            this.ReturnAddress = hookAddress;
            this.Addresses = addr;
            this.Locations = loc;
            this.OriginalBytes = new byte[0];
            this.CopyOriginalBytesStart = copyStart;
        }


        public void SetAddress(long addr, long loc)
        {
            this.Addresses.Add(addr);
            this.Locations.Add(loc);
        }

        /// <summary>
        /// Save the bytes before the detour overwrites them
        /// </summary>
        /// <param name="asm"></param>
        public void SetOriginalBytes(byte[] asm)
        {
            this.OriginalBytes = asm;
        }

        /// <summary>
        /// Calculates a long jump
        /// </summary>
        /// <param name="codecaveAddr">The address to jump to</param>
        /// <returns>
        /// Returns the array of bytes for the calculate long jump
        /// </returns>
        public byte[] GetJumpBytes(long codecaveAddr)
        {
            byte[] LongJump = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
            List<byte> asm = new List<byte>();
            asm.AddRange(LongJump);
            asm.AddRange(BitConverter.GetBytes(codecaveAddr));
            int len = asm.Count;
            for (int i = OriginalBytes.Length; i > len; i--)
                asm.Add(0x90);  //NOP
            return asm.ToArray();
        }

        public void UpdateReturnJump(long Address)
        {
            this.ReturnAddress = Address;
            Create();
        }

        /// <summary>
        /// Generate the arrat of bytes used for the code cave
        /// </summary>
        /// <returns>
        /// Returns the array of bytes used for the code cave
        /// </returns>
        public byte[] GenerateCave()
        {
            // make list
            List<byte> asm = new List<byte>();

            // add to start
            if (this.CopyOriginalBytesStart)
            {
                asm.AddRange(this.OriginalBytes);
                asm.AddRange(this.ShellCode);
            }
            else
                asm = this.ShellCode.ToList();

            // add addresses into code cave
            for (int i = 0; i < Addresses.Count; i++)
            {
                byte[] bAddress;
                if (Addresses[i] > 0xFFFFFFFF)
                    bAddress = BitConverter.GetBytes(Addresses[i]);
                else
                    bAddress = BitConverter.GetBytes((int)Addresses[i]);

                for (int j = 0; j < bAddress.Length; j++)
                {
                    if (this.CopyOriginalBytesStart)
                        asm[(int)(this.OriginalBytes.Length + Locations[i] + j)] = bAddress[j]; //add padding
                    else
                        asm[(int)(Locations[i] + j)] = bAddress[j];
                }
            }

            // Copy X bytes from the removed code
            if (this.JumpSize > -1)
            {
                if (OriginalBytes != null && !this.CopyOriginalBytesStart)
                {
                    // add bytes to end if not added to front
                    asm.AddRange(this.OriginalBytes);
                }

                // add return jump
                byte[] LongJump = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
                asm.AddRange(LongJump);
                asm.AddRange(BitConverter.GetBytes(this.ReturnAddress + OriginalBytes.Length)); //should be atleast 14 bytes
            }

            // turn back to array
            return asm.ToArray();
        }

        /// <summary>
        /// Writes the hook into memory
        /// </summary>
        /// <returns>
        /// Returns the address of the code cave (or -1 when there is no detour)
        /// </returns>
        public long Create()
        {
            if (this.JumpSize > -1 && this.HookAddress > -1)
                this.OriginalBytes = Memory.Read(this.HookAddress, this.JumpSize);

            byte[] asmHook = GenerateCave();
            if (this.Address == -1)
                this.Address = (long)Memory.AllocEx(ShellCode.Length, MemoryProtectionConstraints.PAGE_EXECUTE_READWRITE);
            Memory.Write(this.Address, asmHook);

            if (this.HookAddress != -1)
            {
                // Write the detour
                Memory.Write(this.HookAddress, GetJumpBytes(this.Address));
                Console.WriteLine($"Hooking at {this.HookAddress.ToString("X")} {this.Address.ToString("X")}");
            }
            else
            {
                Console.WriteLine($"Looking at {this.HookAddress.ToString("X")} {this.Address.ToString("X")}");
                return this.Address; //return the code cave :p
            }
            return -1;
        }

        /// <summary>
        /// Patches the detour and frees the code cave
        /// </summary>
        public void Dispose()
        {
            Disable();
            if (!Memory.FreeEx(this.Address))
                Console.WriteLine($"VirtualFreeEx error {Imports.GetLastError()}");
            else
            {
                this.Address = -1;
                Console.WriteLine($"Hook has been restored {this.HookAddress.ToString("X")}");
            }

        }

        /// <summary>
        /// Patches the detour
        /// </summary>
        public void Disable()
        {
            if (this.HookAddress != -1 && this.OriginalBytes.Length > 0)
                Memory.Write(this.HookAddress, this.OriginalBytes);
        }
    }
}
