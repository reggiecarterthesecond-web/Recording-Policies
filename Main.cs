using System;
using System.Text;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

class UsnJournalViewer
{
    const uint GENERIC_READ = 0x80000000;
    const uint FILE_SHARE_READ = 0x00000001;
    const uint FILE_SHARE_WRITE = 0x00000002;
    const uint FILE_SHARE_DELETE = 0x00000004;
    const uint OPEN_EXISTING = 3;

    const uint FSCTL_QUERY_USN_JOURNAL = 0x000900F4;
    const uint FSCTL_READ_USN_JOURNAL  = 0x000900B8;

    const int BUFFER_SIZE = 1024 * 1024;

    [StructLayout(LayoutKind.Sequential)]
    struct USN_JOURNAL_DATA_V0
    {
        public ulong UsnJournalID;
        public long FirstUsn;
        public long NextUsn;
        public long LowestValidUsn;
        public long MaxUsn;
        public ulong MaximumSize;
        public ulong AllocationDelta;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct READ_USN_JOURNAL_DATA_V0
    {
        public long StartUsn;
        public uint ReasonMask;
        public uint ReturnOnlyOnClose;
        public ulong Timeout;
        public ulong BytesToWaitFor;
        public ulong UsnJournalID;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern SafeFileHandle CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DeviceIoControl(
        SafeFileHandle hDevice,
        uint dwIoControlCode,
        IntPtr lpInBuffer,
        int nInBufferSize,
        IntPtr lpOutBuffer,
        int nOutBufferSize,
        out int lpBytesReturned,
        IntPtr lpOverlapped
    );

    static void Main(string[] args)
    {
        string drive = args.Length > 0 ? args[0].TrimEnd('\\') : "C:";
        int maxRecords = args.Length > 1 ? int.Parse(args[1]) : 500;

        if (!drive.EndsWith(":"))
            drive += ":";

        string volumePath = @"\\.\" + drive;

        Console.WriteLine("Opening volume: " + volumePath);

        SafeFileHandle volume = CreateFile(
            volumePath,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            IntPtr.Zero,
            OPEN_EXISTING,
            0,
            IntPtr.Zero
        );

        if (volume.IsInvalid)
            Fail("Failed to open volume. Run as Administrator.");

        USN_JOURNAL_DATA_V0 journal = QueryJournal(volume);

        Console.WriteLine("Journal ID: " + journal.UsnJournalID);
        Console.WriteLine("First USN:  " + journal.FirstUsn);
        Console.WriteLine("Next USN:   " + journal.NextUsn);
        Console.WriteLine();

        // Start near the end for recent-ish records.
        // Increase this number if you want to look farther back.
        long startUsn = Math.Max(journal.FirstUsn, journal.NextUsn - 128L * 1024L * 1024L);

        ReadJournal(volume, journal, startUsn, maxRecords);

        volume.Close();
    }

    static USN_JOURNAL_DATA_V0 QueryJournal(SafeFileHandle volume)
    {
        int size = Marshal.SizeOf(typeof(USN_JOURNAL_DATA_V0));
        IntPtr outBuffer = Marshal.AllocHGlobal(size);

        try
        {
            int bytesReturned;

            bool ok = DeviceIoControl(
                volume,
                FSCTL_QUERY_USN_JOURNAL,
                IntPtr.Zero,
                0,
                outBuffer,
                size,
                out bytesReturned,
                IntPtr.Zero
            );

            if (!ok)
                Fail("FSCTL_QUERY_USN_JOURNAL failed.");

            return (USN_JOURNAL_DATA_V0)Marshal.PtrToStructure(
                outBuffer,
                typeof(USN_JOURNAL_DATA_V0)
            );
        }
        finally
        {
            Marshal.FreeHGlobal(outBuffer);
        }
    }

    static void ReadJournal(
        SafeFileHandle volume,
        USN_JOURNAL_DATA_V0 journal,
        long startUsn,
        int maxRecords
    )
    {
        READ_USN_JOURNAL_DATA_V0 readData = new READ_USN_JOURNAL_DATA_V0();
        readData.StartUsn = startUsn;
        readData.ReasonMask = 0xFFFFFFFF;
        readData.ReturnOnlyOnClose = 0;
        readData.Timeout = 0;
        readData.BytesToWaitFor = 0;
        readData.UsnJournalID = journal.UsnJournalID;

        int inputSize = Marshal.SizeOf(typeof(READ_USN_JOURNAL_DATA_V0));
        IntPtr inputBuffer = Marshal.AllocHGlobal(inputSize);
        IntPtr outputBuffer = Marshal.AllocHGlobal(BUFFER_SIZE);

        int totalRecords = 0;

        try
        {
            while (totalRecords < maxRecords)
            {
                Marshal.StructureToPtr(readData, inputBuffer, false);

                int bytesReturned;

                bool ok = DeviceIoControl(
                    volume,
                    FSCTL_READ_USN_JOURNAL,
                    inputBuffer,
                    inputSize,
                    outputBuffer,
                    BUFFER_SIZE,
                    out bytesReturned,
                    IntPtr.Zero
                );

                if (!ok)
                    Fail("FSCTL_READ_USN_JOURNAL failed.");

                if (bytesReturned <= 8)
                    break;

                long nextUsn = Marshal.ReadInt64(outputBuffer);
                int offset = 8;

                while (offset < bytesReturned && totalRecords < maxRecords)
                {
                    int recordLength = Marshal.ReadInt32(outputBuffer, offset);

                    if (recordLength <= 0 || offset + recordLength > bytesReturned)
                        break;

                    ushort majorVersion = (ushort)Marshal.ReadInt16(outputBuffer, offset + 4);

                    if (majorVersion == 2)
                    {
                        PrintUsnRecordV2(outputBuffer, offset);
                        totalRecords++;
                    }
                    else if (majorVersion == 3)
                    {
                        PrintUsnRecordV3(outputBuffer, offset);
                        totalRecords++;
                    }

                    offset += recordLength;
                }

                if (nextUsn <= readData.StartUsn)
                    break;

                readData.StartUsn = nextUsn;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(inputBuffer);
            Marshal.FreeHGlobal(outputBuffer);
        }

        Console.WriteLine();
        Console.WriteLine("Records shown: " + totalRecords);
    }

    static void PrintUsnRecordV2(IntPtr buffer, int offset)
    {
        ulong fileRef = (ulong)Marshal.ReadInt64(buffer, offset + 8);
        ulong parentRef = (ulong)Marshal.ReadInt64(buffer, offset + 16);
        long usn = Marshal.ReadInt64(buffer, offset + 24);
        long fileTime = Marshal.ReadInt64(buffer, offset + 32);
        uint reason = (uint)Marshal.ReadInt32(buffer, offset + 40);
        ushort nameLength = (ushort)Marshal.ReadInt16(buffer, offset + 56);
        ushort nameOffset = (ushort)Marshal.ReadInt16(buffer, offset + 58);

        string name = Marshal.PtrToStringUni(
            IntPtr.Add(buffer, offset + nameOffset),
            nameLength / 2
        );

        DateTime time = DateTime.FromFileTimeUtc(fileTime).ToLocalTime();

        Console.WriteLine("[" + time + "]");
        Console.WriteLine("  Name:       " + name);
        Console.WriteLine("  USN:        " + usn);
        Console.WriteLine("  FileRef:    " + fileRef);
        Console.WriteLine("  ParentRef:  " + parentRef);
        Console.WriteLine("  Reason:     " + ReasonToString(reason));
        Console.WriteLine();
    }

    static void PrintUsnRecordV3(IntPtr buffer, int offset)
    {
        long usn = Marshal.ReadInt64(buffer, offset + 40);
        long fileTime = Marshal.ReadInt64(buffer, offset + 48);
        uint reason = (uint)Marshal.ReadInt32(buffer, offset + 56);
        ushort nameLength = (ushort)Marshal.ReadInt16(buffer, offset + 72);
        ushort nameOffset = (ushort)Marshal.ReadInt16(buffer, offset + 74);

        string name = Marshal.PtrToStringUni(
            IntPtr.Add(buffer, offset + nameOffset),
            nameLength / 2
        );

        DateTime time = DateTime.FromFileTimeUtc(fileTime).ToLocalTime();

        Console.WriteLine("[" + time + "]");
        Console.WriteLine("  Name:       " + name);
        Console.WriteLine("  USN:        " + usn);
        Console.WriteLine("  Reason:     " + ReasonToString(reason));
        Console.WriteLine();
    }

    static string ReasonToString(uint reason)
    {
        StringBuilder sb = new StringBuilder();

        AddReason(sb, reason, 0x00000001, "DATA_OVERWRITE");
        AddReason(sb, reason, 0x00000002, "DATA_EXTEND");
        AddReason(sb, reason, 0x00000004, "DATA_TRUNCATION");
        AddReason(sb, reason, 0x00000100, "FILE_CREATE");
        AddReason(sb, reason, 0x00000200, "FILE_DELETE");
        AddReason(sb, reason, 0x00001000, "RENAME_OLD_NAME");
        AddReason(sb, reason, 0x00002000, "RENAME_NEW_NAME");
        AddReason(sb, reason, 0x00008000, "BASIC_INFO_CHANGE");
        AddReason(sb, reason, 0x00010000, "HARD_LINK_CHANGE");
        AddReason(sb, reason, 0x00020000, "COMPRESSION_CHANGE");
        AddReason(sb, reason, 0x00040000, "ENCRYPTION_CHANGE");
        AddReason(sb, reason, 0x00080000, "OBJECT_ID_CHANGE");
        AddReason(sb, reason, 0x00100000, "REPARSE_POINT_CHANGE");
        AddReason(sb, reason, 0x00200000, "STREAM_CHANGE");
        AddReason(sb, reason, 0x80000000, "CLOSE");

        if (sb.Length == 0)
            return "0x" + reason.ToString("X8");

        return sb.ToString().TrimEnd('|');
    }

    static void AddReason(StringBuilder sb, uint reason, uint flag, string name)
    {
        if ((reason & flag) != 0)
            sb.Append(name).Append("|");
    }

    static void Fail(string message)
    {
        int error = Marshal.GetLastWin32Error();
        Console.WriteLine("ERROR: " + message);
        Console.WriteLine("Win32 error: " + error);
        Environment.Exit(1);
    }
}
