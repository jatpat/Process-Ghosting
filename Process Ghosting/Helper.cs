using System;
using System.IO;
using System.Text;
using Microsoft.Win32.SafeHandles;
using System.Reflection;
using System.Diagnostics;
using System.Runtime.InteropServices;


namespace Process_Ghosting
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct FILE_LINK_INFORMATION
    {
        [MarshalAs(UnmanagedType.U1)]
        public bool ReplaceIfExists;
        public IntPtr RootDirectory;
        public UInt32 FileNameLength;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public String FileName;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr ExitStatus;
        public IntPtr PebBaseAddress;
        public IntPtr AffinityMask;
        public IntPtr BasePriority;
        public UIntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct LARGE_INTEGER
    {
        public UInt64 LowPart;
        public UInt64 HighPart;
    }


    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING
    {
        public UInt16 Length;
        public UInt16 MaximumLength;
        public IntPtr Buffer;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct OBJECT_ATTRIBUTES
    {
        public Int32 Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public UInt32 Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct IO_STATUS_BLOCK
    {
        public IntPtr Status;
        public IntPtr Information;
    }
    public class Native
    {
        [DllImport("ntdll.dll")]
        public static extern IntPtr NtClose(IntPtr handle);
        [DllImport("ntdll.dll")]
        public static extern UInt32 NtSetInformationFile(
               IntPtr FileHandle,
               ref IO_STATUS_BLOCK IoStatusBlock,
               IntPtr FileInformation,
               UInt32 Length,
               UInt32 FileInformationClass);
        [DllImport("ntdll.dll")]
        public static extern IntPtr NtOpenFile(
            ref IntPtr FileHandle,
            UInt32 DesiredAccess,
            ref OBJECT_ATTRIBUTES ObjAttr,
            ref IO_STATUS_BLOCK IoStatusBlock,
            UInt32 ShareAccess,
            UInt32 OpenOptions);
        [DllImport("KtmW32.dll")]
        public static extern IntPtr CreateTransaction(
                IntPtr lpEventAttributes,
                IntPtr UOW,
                UInt32 CreateOptions,
                UInt32 IsolationLevel,
                UInt32 IsolationFlags,
                UInt32 Timeout,
                IntPtr Description);

        [DllImport("Kernel32.dll")]
        public static extern IntPtr CreateFileTransacted(
            string lpFileName,
            UInt32 dwDesiredAccess,
            UInt32 dwShareMode,
            IntPtr lpSecurityAttributes,
            UInt32 dwCreationDisposition,
            UInt32 dwFlagsAndAttributes,
            IntPtr hTemplateFile,
            IntPtr hTransaction,
            IntPtr pusMiniVersion,
            IntPtr pExtendedParameter);

        [DllImport("Kernel32.dll")]
        public static extern bool WriteFile(
            IntPtr hFile,
            Byte[] lpBuffer,
            UInt32 nNumberOfBytesToWrite,
            ref UInt32 lpNumberOfBytesWritten,
            IntPtr lpOverlapped);

        [DllImport("ntdll.dll")]
        public static extern int NtCreateSection(
            ref IntPtr section,
            UInt32 desiredAccess,
            IntPtr pAttrs,
            IntPtr pMaxSize,
            uint pageProt,
            uint allocationAttribs,
            IntPtr hFile);

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(
            UInt32 processAccess,
            bool bInheritHandle,
            int processId);

        [DllImport("ntdll.dll")]
        public static extern IntPtr NtCreateProcessEx(
            ref IntPtr ProcessHandle,
            UInt32 DesiredAccess,
            IntPtr ObjectAttributes,
            IntPtr hInheritFromProcess,
            uint Flags,
            IntPtr SectionHandle,
            IntPtr DebugPort,
            IntPtr ExceptionPort,
            Byte InJob);

        [DllImport("ktmw32.dll", CharSet = CharSet.Auto)]
        public static extern bool RollbackTransaction(
            IntPtr transaction);

        [DllImport("kernel32.dll")]
        public static extern bool CloseHandle(
            IntPtr hObject);

        [DllImport("kernel32.dll")]
        public static extern Boolean VirtualProtectEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            UInt32 dwSize,
            UInt32 flNewProtect,
            ref UInt32 lpflOldProtect);

        [DllImport("kernel32.dll")]
        public static extern Boolean WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            IntPtr lpBuffer,
            UInt32 nSize,
            ref UInt32 lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        public static extern Boolean ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            IntPtr lpBuffer,
            UInt32 dwSize,
            ref UInt32 lpNumberOfBytesRead);

        [DllImport("ntdll.dll")]
        public static extern IntPtr NtQueryInformationProcess(
            IntPtr processHandle,
            int processInformationClass,
            ref PROCESS_BASIC_INFORMATION processInformation,
            int processInformationLength,
            ref int returnLength);

        [DllImport("ntdll.dll")]
        public static extern int RtlCreateProcessParametersEx(
            ref IntPtr pProcessParameters,
            IntPtr ImagePathName,
            IntPtr DllPath,
            IntPtr CurrentDirectory,
            IntPtr CommandLine,
            IntPtr Environment,
            IntPtr WindowTitle,
            IntPtr DesktopInfo,
            IntPtr ShellInfo,
            IntPtr RuntimeData,
            UInt32 Flags);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtWriteFile(
            IntPtr fileHandle,
            IntPtr @event,
            IntPtr apcRoutine,
            IntPtr appContext,
            out IntPtr IoStatusBlock,
            IntPtr buffer,
            ulong Length,
            IntPtr byteOffset,
            IntPtr key
        );

        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualAllocEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            UInt32 dwSize,
            Int32 flAllocationType,
            Int32 flProtect);

        [DllImport("ntdll.dll")]
        public static extern int NtCreateThreadEx(
            ref IntPtr hThread,
            UInt32 DesiredAccess,
            IntPtr ObjectAttributes,
            IntPtr ProcessHandle,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            bool CreateSuspended,
            UInt32 StackZeroBits,
            UInt32 SizeOfStackCommit,
            UInt32 SizeOfStackReserve,
            IntPtr lpBytesBuffer);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern bool NtReadVirtualMemory(
        IntPtr ProcessHandle,
        IntPtr BaseAddress,
        IntPtr Buffer,
        int NumberOfBytesToRead,
        out UInt32 liRet);
        public static IntPtr CreateUnicodeStruct(string data)
        {
            UNICODE_STRING UnicodeObject = new UNICODE_STRING();
            string UnicodeObject_Buffer = data;
            UnicodeObject.Length = Convert.ToUInt16(UnicodeObject_Buffer.Length * 2);
            UnicodeObject.MaximumLength = Convert.ToUInt16(UnicodeObject.Length + 1);
            UnicodeObject.Buffer = Marshal.StringToHGlobalUni(UnicodeObject_Buffer);
            IntPtr InMemoryStruct = Marshal.AllocHGlobal(16);
            Marshal.StructureToPtr(UnicodeObject, InMemoryStruct, true);

            return InMemoryStruct;

        }
    }
}