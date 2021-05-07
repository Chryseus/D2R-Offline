﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace D2ROffline.Util
{
    public static unsafe class Toolbox
    {
        // COULDN'T DO THIS CLEAN, SO I'LL JUST 
        // HIDE IT HERE FOR NO ONE TO SEE
        public static ushort GetRelocationData(void* baseRelocation, int index) =>
            *(ushort*)((long)baseRelocation + Marshal.SizeOf<IMAGE_BASE_RELOCATION>() + sizeof(ushort) * index);

        // SAME TBH
        public static IMAGE_SECTION_HEADER* GetFirstSection(ulong localImage, IMAGE_DOS_HEADER dosHeader) =>
            (IMAGE_SECTION_HEADER*)(localImage + (uint)dosHeader.e_lfanew/*START OF NTHEADER*/ + (uint)Marshal.SizeOf<IMAGE_NT_HEADERS>());

        public static void GetImageHeaders(byte[] rawImage, out IMAGE_DOS_HEADER dosHeader, out IMAGE_FILE_HEADER fileHeader, out IMAGE_OPTIONAL_HEADER64 optionalHeader)
        {
            fixed (byte* imagePointer = &rawImage[0])
            {
                dosHeader = *(IMAGE_DOS_HEADER*)imagePointer;
                IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)(imagePointer + dosHeader.e_lfanew);
                fileHeader = ntHeader->FileHeader;
                optionalHeader = ntHeader->OptionalHeader;
            }
        }

        public static string FindDll(string imageName)
        {
            // https://msdn.microsoft.com/en-us/library/7d83bc18.aspx?f=255&MSPPError=-2147217396
            // The Windows system directory. The GetSystemDirectory function retrieves the path of this directory.
            // The Windows directory. The GetWindowsDirectory function retrieves the path of this directory.

            return
                SearchDirectoryForImage(Environment.GetFolderPath(Environment.SpecialFolder.Windows)) ??
                SearchDirectoryForImage(Environment.GetFolderPath(Environment.SpecialFolder.System));

            // HELPER FUNCTION TO FIND IMAGES
            string SearchDirectoryForImage(string directoryPath)
            {
                foreach (string imagePath in Directory.GetFiles(directoryPath, "*.dll"))
                    if (String.Equals(Path.GetFileName(imagePath), imageName, StringComparison.InvariantCultureIgnoreCase))
                        return imagePath;

                return null;
            }
        }

        public static unsafe T GetStructure<T>(byte[] bytes) where T : struct
        {
            T structure = new T();
            fixed (byte* pByte = &bytes[0])
                Unsafe.Copy(ref structure, pByte);

            return structure;
        }
        public static unsafe byte[] GetBytes<T>(T structure) where T : struct
        {
            byte[] arr = new byte[Unsafe.SizeOf<T>()];

            fixed (byte* pByte = &arr[0])
                Unsafe.Copy(pByte, ref structure);

            return arr;
        }
    }
}
