using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using D2ROffline.Util;

namespace D2ROffline.Tools
{
    public unsafe class ManualMap
    {
        public Memory Memory;

        private Dictionary<string, ulong> MappedModules = new Dictionary<string, ulong>(StringComparer.InvariantCultureIgnoreCase);
        private Dictionary<string, byte[]> MappedRawImages = new Dictionary<string, byte[]>(StringComparer.InvariantCultureIgnoreCase);
        private Dictionary<string, ulong> LinkedModules = new Dictionary<string, ulong>(StringComparer.InvariantCultureIgnoreCase);

        public ManualMap(Memory m)
        {
            Memory = m;
        }

        public ulong InjectImage(string path, byte[] rawImage)
        {
            LinkedModules = Memory.GetModules();

            // MAP OUR DLL, AND DEPENDENCIES, INTO REMOTE PROCESS
            //  dependenc
            //MapImage("lib/HookLibraryx64.dll", File.ReadAllBytes("lib/HookLibraryx64.dll"));
            ulong remoteImage = MapImage(path, rawImage);

            Program.ConsolePrint($"Remote Image {remoteImage.ToString("x2")}");

            CallEntrypoint(rawImage, remoteImage);

            return remoteImage;
        }
        public ulong InjectImage(string imagePath)
        {
            // READ IMAGE FROM DISK
            byte[] imageBytes = File.ReadAllBytes(imagePath);

            // FORWARD TO RAW INJECTION
            return this.InjectImage(imagePath, imageBytes);
        }

        #region Manual Map Helpers
        public ulong MapImage(string imageName, byte[] rawImage)
        {
            Program.ConsolePrint($"Mapping {imageName}");

            // GET HEADERS
            Toolbox.GetImageHeaders(rawImage, out IMAGE_DOS_HEADER dosHeader, out IMAGE_FILE_HEADER fileHeader, out IMAGE_OPTIONAL_HEADER64 optionalHeader);

            // CREATE A MEMORY SECTION IN TARGET PROCESS
            ulong sectionHandle = (ulong)Memory.CreateSection(MemoryProtectionConstraints.PAGE_EXECUTE_READWRITE, optionalHeader.SizeOfImage);

            // MAP THE SECTION INTO BOTH OUR OWN AND THE TARGET PROCESS
            // THIS WILL RESULT IN A MIRRORED MEMORY SECTION, WHERE EVERY CHANGE
            // TO THE LOCAL SECTION WILL ALSO CHANGE IN THE TARGET PROCESS
            // AND VICE VERSA
            IntPtr remoteImage = IntPtr.Zero;
            IntPtr localImage = IntPtr.Zero;
            long secOffset = 0;
            uint viewSize = 0;
            Imports.NtMapViewOfSection((IntPtr)sectionHandle, Memory.ProcessHandle, ref remoteImage, UIntPtr.Zero, 0, ref secOffset, ref viewSize, 2, 0x00000000, MemoryProtectionConstraints.PAGE_EXECUTE_READWRITE);
            Imports.NtMapViewOfSection((IntPtr)sectionHandle, Process.GetCurrentProcess().Handle, ref localImage, UIntPtr.Zero, 0, ref secOffset, ref viewSize, 2, 0x00000000, MemoryProtectionConstraints.PAGE_EXECUTE_READWRITE);

            // SAVE MAPPED EXECUTABLES IN A LIST
            // SO WE CAN RECURSIVELY MAP DEPENDENCIES, AND THEIR DEPENDENCIES
            // WITHOUT BEING STUCK IN A LOOP :)
            MappedModules[imageName] = (ulong)remoteImage;
            MappedRawImages[imageName] = rawImage;

            // NOTE: detected
            //AddLoaderEntry(imageName, (ulong)remoteImage);

            // COPY HEADERS TO SECTION
            Marshal.Copy(rawImage, 0, (IntPtr)localImage, (int)optionalHeader.SizeOfHeaders);

            // DO THE ACTUAL MANUALMAPPING
            this.WriteImageSections(rawImage, dosHeader, (ulong)localImage, fileHeader.NumberOfSections);
            this.RelocateImageByDelta((ulong)localImage, (ulong)remoteImage, optionalHeader);
            this.FixImportTable((ulong)localImage, optionalHeader);
            
            // TODO: unmap localImage??

            return (ulong)remoteImage;
        }
        public void CallEntrypoint(byte[] rawImage, ulong moduleHandle)
        {
            // GET HEADERS
            Toolbox.GetImageHeaders(rawImage, out IMAGE_DOS_HEADER dosHeader, out IMAGE_FILE_HEADER fileHeader, out IMAGE_OPTIONAL_HEADER64 optionalHeader);

            // GET DLLMAIN
            ulong entrypoint = moduleHandle + optionalHeader.AddressOfEntryPoint;

            if (optionalHeader.AddressOfEntryPoint == 0)
            {
                Program.ConsolePrint($"Invalid Entrypoint - skipping {moduleHandle.ToString("x2")}");
                return;
            }

            Program.ConsolePrint($"AddressOfEntryPoint {optionalHeader.AddressOfEntryPoint.ToString("x2")}");

            Hook callDllMain = new Hook(
                Memory,
                new byte[]
                {
                    0x90,                                                           // NOP
                    0x48, 0x83, 0xEC, 0x28,                                         // sub      RSP, 0x28
                    0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // movabs   RCX, 0x0000000000000000
                    0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00,                       // mov      rdx, 0x1
                    0x4D, 0x31, 0xC0,                                               // xor      r8, r8
                    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // movabs   RAX, 0x0000000000000000
                    0xFF, 0xD0,                                                     // call     RAX
                    0x48, 0x83, 0xC4, 0x28,                                         // add      RSP, 0x28
                    0xC3                                                            // ret
                },
                -1,
                new List<long> { (long)moduleHandle, (long)entrypoint },
                new List<long> { 7, 27 }
            );
            callDllMain.Create();
            Memory.BypassCRT(true);
            Memory.CRT((IntPtr)callDllMain.Address);
            Thread.Sleep(50);
            Memory.BypassCRT(false);
            //Thread.Sleep(2000); // waitForObject?
            //callDllMain.Dispose();
        }

        public void WriteImageSections(byte[] rawImage, IMAGE_DOS_HEADER dosHeader, ulong localImage, int numberOfSections)
        {
            // GET POINTER TO FIRST MEMORY SECTION - LOCATED RIGHT AFTER HEADERS
            IMAGE_SECTION_HEADER* sections = Toolbox.GetFirstSection(localImage, dosHeader);

            // ITERATE PE SECTIONS
            for (int index = 0; index < numberOfSections; index++)
            {
                if (sections[index].SizeOfRawData > 0)
                {
                    ulong localSectionPointer = localImage + sections[index].VirtualAddress;
                    Marshal.Copy(rawImage, (int)sections[index].PointerToRawData, (IntPtr)localSectionPointer, (int)sections[index].SizeOfRawData);
                    //Log.LogInfo($"{sections[index].SectionName} - {sections[index].SizeOfRawData}");
                }
            }
        }
        public void RelocateImageByDelta(ulong localImage, ulong remoteImage, IMAGE_OPTIONAL_HEADER64 optionalHeader)
        {
            // https://github.com/DarthTon/Blackbone/blob/master/src/BlackBone/ManualMap/MMap.cpp#L691
            IMAGE_BASE_RELOCATION* baseRelocation = (IMAGE_BASE_RELOCATION*)(localImage + optionalHeader.BaseRelocationTable.VirtualAddress);

            var memoryDelta = remoteImage - optionalHeader.ImageBase;
            int relocBaseSize = Marshal.SizeOf<IMAGE_BASE_RELOCATION>();

            while (baseRelocation->SizeOfBlock > 0)
            {
                // START OF RELOCATION
                ulong relocStartAddress = localImage + baseRelocation->VirtualAddress;

                // AMOUNT OF RELOCATIONS IN THIS BLOCK
                int relocationAmount = ((int)baseRelocation->SizeOfBlock - relocBaseSize/*DONT COUNT THE MEMBERS*/) / sizeof(ushort)/*SIZE OF DATA*/;

                // ITERATE ALL RELOCATIONS AND FIX THE HIGHLOWS
                for (int i = 0; i < relocationAmount; i++)
                {
                    // GET RELOCATION DATA
                    var data = GetRelocationData(i);

                    // WORD Offset : 12; 
                    // WORD Type   : 4;
                    var fixOffset = data & 0x0FFF;
                    var fixType = data & 0xF000;

                    // THIS IS A HIGHLOW ACCORDING TO MY GHETTO MASK
                    // ¯\_(ツ)_/¯
                    if (fixType == 40960)
                        *(ulong*)(relocStartAddress + (uint)fixOffset) += memoryDelta; // ADD MEMORY DELTA TO SPECIFIED ADDRESS
                }

                // GET THE NEXT BLOCK
                baseRelocation = (IMAGE_BASE_RELOCATION*)((ulong)baseRelocation + baseRelocation->SizeOfBlock);
            }

            ushort GetRelocationData(int index) =>
            *(ushort*)((long)baseRelocation + Marshal.SizeOf<IMAGE_BASE_RELOCATION>() + sizeof(ushort) * index);
        }
        public void FixImportTable(ulong localImage, IMAGE_OPTIONAL_HEADER64 optionalHeader)
        {
            IMAGE_IMPORT_DESCRIPTOR* importDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)(localImage + optionalHeader.ImportTable.VirtualAddress);
            for (; importDescriptor->FirstThunk > 0; ++importDescriptor)
            {
                string libraryName = Marshal.PtrToStringAnsi((IntPtr)(localImage + importDescriptor->Name));

                // RECODE THIS, THIS IS STUPID & DANGEROUS
                // I AM ONLY DOING THIS BECAUSE OF API-SET DLLS
                // I COULDNT BE ARSED TO MAKE A PINVOKE FOR ApiSetResolveToHost
                ulong localLibraryHandle = Imports.LoadLibrary(libraryName);
                libraryName = Memory.GetModuleBaseName(Process.GetCurrentProcess().Handle, localLibraryHandle).ToLower();

                // IF WE MAPPED DEPENDENCY EARLIER, WE SHOULD USE RVA 
                // INSTEAD OF STATIC MEMORY ADDRESS
                bool mappedDependency = MappedModules.TryGetValue(libraryName, out ulong remoteLibraryHandle);
                bool linkedInProcess = LinkedModules.TryGetValue(libraryName, out remoteLibraryHandle);

                if (!mappedDependency && !linkedInProcess) // DEPENDENCY NOT FOUND, MAP IT!
                {
                    string dependencyPath = Toolbox.FindDll(libraryName);

                    // SKIP IF DEPENDENCY COULDN'T BE FOUND
                    if (dependencyPath == null)
                        continue;

                    // TODO: look into this
                    //if (libraryName == "msvcp140.dll")
                    //{
                    //    var tempOptions = Options;
                    //    tempOptions.EraseHeaders = false;

                    //    new LoadLibraryInjection(TargetProcess, TypeOfExecution, tempOptions).InjectImage(dependencyPath);
                    //    --importDescriptor;
                    //    continue;
                    //}

                    remoteLibraryHandle = MapImage(libraryName, File.ReadAllBytes(dependencyPath));
                    mappedDependency = true;
                }

                ulong* functionAddress = (ulong*)(localImage + importDescriptor->FirstThunk);
                ulong* importEntry = (ulong*)(localImage + importDescriptor->OriginalFirstThunk);

                do
                {
                    ulong procNamePointer = *importEntry < 0x8000000000000000/*IMAGE_ORDINAL_FLAG64*/ ?  // IS ORDINAL?
                        localImage + *importEntry + sizeof(ushort)/*SKIP HINT*/ :  // FUNCTION BY NAME
                        *importEntry & 0xFFFF;                                     // ORDINAL

                    var localFunctionPointer = Imports.GetProcAddress(localLibraryHandle, procNamePointer);
                    var rva = localFunctionPointer - localLibraryHandle;

                    // SET NEW FUNCTION POINTER
                    *functionAddress = mappedDependency ? remoteLibraryHandle + rva : localFunctionPointer;

                    // GET NEXT ENTRY
                    ++functionAddress;
                    ++importEntry;
                } while (*importEntry > 0);
            }
        }

        public void AddLoaderEntry(string imageName, ulong moduleHandle)
        {
            Program.ConsolePrint($"Linking {imageName}({moduleHandle.ToString("x2")}) to module list");

            var imagePath = Toolbox.FindDll(imageName) ?? imageName;

            var listBase = Memory.GetLoaderData().InLoadOrderModuleList;
            var lastEntry = Memory.Read<_LDR_DATA_TABLE_ENTRY>((IntPtr)listBase.Blink);

            byte[] dllpathBuff = Encoding.Unicode.GetBytes(imagePath);
            IntPtr allocatedDllPath = Memory.AllocEx(dllpathBuff.Length, MemoryProtectionConstraints.PAGE_EXECUTE_READWRITE);
            Memory.Write((long)allocatedDllPath, dllpathBuff);

            // CRAFT CUSTOM LOADER ENTRY
            var fileName = Path.GetFileName(imagePath);
            _LDR_DATA_TABLE_ENTRY myEntry = new _LDR_DATA_TABLE_ENTRY()
            {
                InLoadOrderLinks = new _LIST_ENTRY()
                {
                    Flink = lastEntry.InLoadOrderLinks.Flink,
                    Blink = listBase.Flink
                },
                InMemoryOrderLinks = lastEntry.InMemoryOrderLinks,
                InInitializationOrderLinks = lastEntry.InInitializationOrderLinks,
                DllBase = moduleHandle,
                EntryPoint = 0,
                SizeOfImage = (ulong)MappedRawImages[imageName].Length,
                FullDllName = new UNICODE_STRING(imagePath) { Buffer = (ulong)allocatedDllPath },
                BaseDllName = new UNICODE_STRING(fileName) { Buffer = (ulong)allocatedDllPath + (ulong)imagePath.IndexOf(fileName) * 2/*WIDE CHAR*/ },
                Flags = lastEntry.Flags,
                LoadCount = lastEntry.LoadCount,
                TlsIndex = lastEntry.TlsIndex,
                Reserved4 = lastEntry.Reserved4,
                CheckSum = lastEntry.CheckSum,
                TimeDateStamp = lastEntry.TimeDateStamp,
                EntryPointActivationContext = lastEntry.EntryPointActivationContext,
                PatchInformation = lastEntry.PatchInformation,
                ForwarderLinks = lastEntry.ForwarderLinks,
                ServiceTagLinks = lastEntry.ServiceTagLinks,
                StaticLinks = lastEntry.StaticLinks,
            };

            // ALLOCATE AND WRITE OUR MODULE ENTRY
            byte[] buff = Toolbox.GetBytes(myEntry);
            IntPtr newEntryPoint = Memory.AllocEx(buff.Length, MemoryProtectionConstraints.PAGE_EXECUTE_READWRITE);
            Memory.Write((long)newEntryPoint, buff);

            // SET LAST LINK IN InLoadOrderLinks CHAIN TO POINT TO OUR ENTRY
            lastEntry.InLoadOrderLinks.Flink = (ulong)newEntryPoint;
            Memory.Write(lastEntry, (IntPtr)listBase.Blink);

        }
        #endregion
    }
}