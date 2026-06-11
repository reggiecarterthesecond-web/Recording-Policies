using System;
using System.Text;
using System.Threading;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using System.Drawing;
using System.IO;
using Microsoft.Win32.SafeHandles;

class PrefetchJournalGui : Form
{
    TextBox outputBox;
    TextBox driveBox;
    NumericUpDown maxRecordsBox;
    NumericUpDown lookbackBox;
    Button runButton;
    Button prefetchTimesButton;
    Button copyButton;
    Button clearButton;
    Label statusLabel;

    const uint GENERIC_READ = 0x80000000;
    const uint FILE_SHARE_READ = 0x00000001;
    const uint FILE_SHARE_WRITE = 0x00000002;
    const uint FILE_SHARE_DELETE = 0x00000004;
    const uint OPEN_EXISTING = 3;

    const uint FSCTL_QUERY_USN_JOURNAL = 0x000900F4;

    // IMPORTANT: Correct value
    const uint FSCTL_READ_USN_JOURNAL = 0x000900BB;

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

    [STAThread]
    static void Main()
    {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new PrefetchJournalGui());
    }

    public PrefetchJournalGui()
    {
        Text = "Prefetch Journal Checker";
        Width = 1050;
        Height = 700;
        StartPosition = FormStartPosition.CenterScreen;

        Label driveLabel = new Label();
        driveLabel.Text = "Drive:";
        driveLabel.Left = 10;
        driveLabel.Top = 15;
        driveLabel.Width = 45;

        driveBox = new TextBox();
        driveBox.Text = "C:";
        driveBox.Left = 60;
        driveBox.Top = 12;
        driveBox.Width = 60;

        Label maxLabel = new Label();
        maxLabel.Text = "Max Records:";
        maxLabel.Left = 140;
        maxLabel.Top = 15;
        maxLabel.Width = 85;

        maxRecordsBox = new NumericUpDown();
        maxRecordsBox.Left = 230;
        maxRecordsBox.Top = 12;
        maxRecordsBox.Width = 90;
        maxRecordsBox.Minimum = 1;
        maxRecordsBox.Maximum = 500000;
        maxRecordsBox.Value = 5000;

        Label lookbackLabel = new Label();
        lookbackLabel.Text = "Lookback MB:";
        lookbackLabel.Left = 340;
        lookbackLabel.Top = 15;
        lookbackLabel.Width = 85;

        lookbackBox = new NumericUpDown();
        lookbackBox.Left = 430;
        lookbackBox.Top = 12;
        lookbackBox.Width = 90;
        lookbackBox.Minimum = 1;
        lookbackBox.Maximum = 8192;
        lookbackBox.Value = 512;

        runButton = new Button();
        runButton.Text = "Check Prefetch Journal";
        runButton.Left = 540;
        runButton.Top = 10;
        runButton.Width = 160;
        runButton.Click += new EventHandler(RunButton_Click);

        prefetchTimesButton = new Button();
        prefetchTimesButton.Text = "Check Prefetch Times";
        prefetchTimesButton.Left = 710;
        prefetchTimesButton.Top = 10;
        prefetchTimesButton.Width = 150;
        prefetchTimesButton.Click += new EventHandler(PrefetchTimesButton_Click);

        copyButton = new Button();
        copyButton.Text = "Copy";
        copyButton.Left = 870;
        copyButton.Top = 10;
        copyButton.Width = 70;
        copyButton.Click += new EventHandler(CopyButton_Click);

        clearButton = new Button();
        clearButton.Text = "Clear";
        clearButton.Left = 950;
        clearButton.Top = 10;
        clearButton.Width = 70;
        clearButton.Click += new EventHandler(ClearButton_Click);

        statusLabel = new Label();
        statusLabel.Left = 10;
        statusLabel.Top = 45;
        statusLabel.Width = 1000;
        statusLabel.Height = 25;

        if (IsAdmin())
        {
            statusLabel.Text = "Status: Running as Administrator";
            statusLabel.ForeColor = Color.Green;
        }
        else
        {
            statusLabel.Text = "Status: Not Administrator. USN Journal access may fail.";
            statusLabel.ForeColor = Color.Red;
        }

        outputBox = new TextBox();
        outputBox.Left = 10;
        outputBox.Top = 75;
        outputBox.Width = 1010;
        outputBox.Height = 570;
        outputBox.Multiline = true;
        outputBox.ScrollBars = ScrollBars.Both;
        outputBox.WordWrap = false;
        outputBox.Font = new Font("Consolas", 9);

        Controls.Add(driveLabel);
        Controls.Add(driveBox);
        Controls.Add(maxLabel);
        Controls.Add(maxRecordsBox);
        Controls.Add(lookbackLabel);
        Controls.Add(lookbackBox);
        Controls.Add(runButton);
        Controls.Add(prefetchTimesButton);
        Controls.Add(copyButton);
        Controls.Add(clearButton);
        Controls.Add(statusLabel);
        Controls.Add(outputBox);
    }

    void RunButton_Click(object sender, EventArgs e)
    {
        runButton.Enabled = false;
        outputBox.Clear();

        string drive = driveBox.Text.Trim();
        int maxRecords = (int)maxRecordsBox.Value;
        long lookbackBytes = (long)lookbackBox.Value * 1024L * 1024L;

        Thread t = new Thread(delegate()
        {
            try
            {
                string result = CheckPrefetchJournal(drive, maxRecords, lookbackBytes);
                SetOutput(result);
            }
            catch (Exception ex)
            {
                SetOutput("ERROR:\r\n" + ex.ToString());
            }
            finally
            {
                SetRunEnabled(true);
            }
        });

        t.IsBackground = true;
        t.Start();
    }

    void PrefetchTimesButton_Click(object sender, EventArgs e)
    {
        outputBox.Clear();
        SetOutput(CheckCurrentPrefetchTimes());
    }

    void CopyButton_Click(object sender, EventArgs e)
    {
        if (outputBox.Text.Length > 0)
            Clipboard.SetText(outputBox.Text);
    }

    void ClearButton_Click(object sender, EventArgs e)
    {
        outputBox.Clear();
    }

    void SetOutput(string text)
    {
        if (outputBox.InvokeRequired)
        {
            outputBox.Invoke(new Action<string>(SetOutput), text);
            return;
        }

        outputBox.Text = text;
    }

    void SetRunEnabled(bool enabled)
    {
        if (runButton.InvokeRequired)
        {
            runButton.Invoke(new Action<bool>(SetRunEnabled), enabled);
            return;
        }

        runButton.Enabled = enabled;
    }

    static bool IsAdmin()
    {
        WindowsIdentity identity = WindowsIdentity.GetCurrent();
        WindowsPrincipal principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    static string CheckPrefetchJournal(string drive, int maxRecords, long lookbackBytes)
    {
        StringBuilder log = new StringBuilder();

        if (drive.EndsWith("\\"))
            drive = drive.TrimEnd('\\');

        if (!drive.EndsWith(":"))
            drive += ":";

        string volumePath = @"\\.\" + drive;

        log.AppendLine("PREFETCH USN JOURNAL CHECK");
        log.AppendLine("==========================");
        log.AppendLine("Volume: " + volumePath);
        log.AppendLine("Looking for .pf files that were renamed, deleted, edited, or timestamp/metadata changed.");
        log.AppendLine("");

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
            throw new Exception("Failed to open volume. Run as Administrator. Win32: " + Marshal.GetLastWin32Error());

        USN_JOURNAL_DATA_V0 journal = QueryJournal(volume);

        log.AppendLine("Journal ID: " + journal.UsnJournalID);
        log.AppendLine("First USN:  " + journal.FirstUsn);
        log.AppendLine("Next USN:   " + journal.NextUsn);
        log.AppendLine("");

        long startUsn = journal.NextUsn - lookbackBytes;

        if (startUsn < journal.FirstUsn)
            startUsn = journal.FirstUsn;

        log.AppendLine("Start USN:   " + startUsn);
        log.AppendLine("Max Records: " + maxRecords);
        log.AppendLine("");

        int hits = ReadJournalRecords(volume, journal, startUsn, maxRecords, log);

        volume.Close();

        log.AppendLine("");
        log.AppendLine("Prefetch-related hits: " + hits);
        log.AppendLine("");
        log.AppendLine("Meaning:");
        log.AppendLine("- FILE_DELETE = prefetch file was deleted.");
        log.AppendLine("- RENAME_OLD_NAME / RENAME_NEW_NAME = prefetch file was renamed.");
        log.AppendLine("- DATA_OVERWRITE / DATA_EXTEND / DATA_TRUNCATION = prefetch file content was edited.");
        log.AppendLine("- BASIC_INFO_CHANGE = metadata/timestamp/attributes may have changed.");
        log.AppendLine("");
        log.AppendLine("Important:");
        log.AppendLine("USN Journal shows change reason flags. It does not show the old and new timestamp values.");

        return log.ToString();
    }

    static string CheckCurrentPrefetchTimes()
    {
        StringBuilder log = new StringBuilder();

        string prefetchDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");

        log.AppendLine("CURRENT PREFETCH TIMESTAMP CHECK");
        log.AppendLine("================================");
        log.AppendLine("Folder: " + prefetchDir);
        log.AppendLine("");

        if (!Directory.Exists(prefetchDir))
        {
            log.AppendLine("Prefetch folder not found.");
            return log.ToString();
        }

        FileInfo[] files = new DirectoryInfo(prefetchDir).GetFiles("*.pf");

        int suspicious = 0;

        foreach (FileInfo file in files)
        {
            DateTime c = file.CreationTime;
            DateTime w = file.LastWriteTime;
            DateTime a = file.LastAccessTime;

            bool flag = false;
            StringBuilder reasons = new StringBuilder();

            if (w < c.AddMinutes(-2))
            {
                flag = true;
                reasons.Append("LastWrite earlier than Creation; ");
            }

            if (a < c.AddMinutes(-2))
            {
                flag = true;
                reasons.Append("LastAccess earlier than Creation; ");
            }

            if (file.Length == 0)
            {
                flag = true;
                reasons.Append("Zero-byte prefetch file; ");
            }

            if (flag)
            {
                suspicious++;

                log.AppendLine("[SUSPICIOUS]");
                log.AppendLine("  File:       " + file.Name);
                log.AppendLine("  Created:    " + c);
                log.AppendLine("  Modified:   " + w);
                log.AppendLine("  Accessed:   " + a);
                log.AppendLine("  Size:       " + file.Length);
                log.AppendLine("  Reason:     " + reasons.ToString());
                log.AppendLine("");
            }
        }

        log.AppendLine("Total .pf files: " + files.Length);
        log.AppendLine("Suspicious timestamp hits: " + suspicious);
        log.AppendLine("");
        log.AppendLine("Note:");
        log.AppendLine("This is only a weak signal. Some timestamp differences can happen naturally.");
        log.AppendLine("Use this together with USN Journal BASIC_INFO_CHANGE records.");

        return log.ToString();
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
                throw new Exception("FSCTL_QUERY_USN_JOURNAL failed. Win32: " + Marshal.GetLastWin32Error());

            return (USN_JOURNAL_DATA_V0)Marshal.PtrToStructure(outBuffer, typeof(USN_JOURNAL_DATA_V0));
        }
        finally
        {
            Marshal.FreeHGlobal(outBuffer);
        }
    }

    static int ReadJournalRecords(
        SafeFileHandle volume,
        USN_JOURNAL_DATA_V0 journal,
        long startUsn,
        int maxRecords,
        StringBuilder log
    )
    {
        READ_USN_JOURNAL_DATA_V0 readData = new READ_USN_JOURNAL_DATA_V0();
        readData.StartUsn = startUsn;

        // Only suspicious/change-heavy reasons
        readData.ReasonMask =
            0x00000001 | // DATA_OVERWRITE
            0x00000002 | // DATA_EXTEND
            0x00000004 | // DATA_TRUNCATION
            0x00000100 | // FILE_CREATE
            0x00000200 | // FILE_DELETE
            0x00001000 | // RENAME_OLD_NAME
            0x00002000 | // RENAME_NEW_NAME
            0x00008000 | // BASIC_INFO_CHANGE
            0x80000000;  // CLOSE

        readData.ReturnOnlyOnClose = 0;
        readData.Timeout = 0;
        readData.BytesToWaitFor = 0;
        readData.UsnJournalID = journal.UsnJournalID;

        int inputSize = Marshal.SizeOf(typeof(READ_USN_JOURNAL_DATA_V0));
        IntPtr inputBuffer = Marshal.AllocHGlobal(inputSize);
        IntPtr outputBuffer = Marshal.AllocHGlobal(BUFFER_SIZE);

        int totalRecords = 0;
        int hits = 0;

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
                    throw new Exception("FSCTL_READ_USN_JOURNAL failed. Win32: " + Marshal.GetLastWin32Error());

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

                    UsnHit hit = null;

                    if (majorVersion == 2)
                    {
                        hit = ParseUsnRecordV2(outputBuffer, offset);
                    }
                    else if (majorVersion == 3)
                    {
                        hit = ParseUsnRecordV3(outputBuffer, offset);
                    }

                    if (hit != null)
                    {
                        totalRecords++;

                        if (IsPrefetchTarget(hit.Name) && IsSuspiciousPrefetchReason(hit.Reason))
                        {
                            hits++;
                            PrintHit(hit, log);
                        }
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

        return hits;
    }

    class UsnHit
    {
        public string Version;
        public string Name;
        public long Usn;
        public ulong FileRef;
        public ulong ParentRef;
        public DateTime Time;
        public uint Reason;
    }

    static UsnHit ParseUsnRecordV2(IntPtr buffer, int offset)
    {
        UsnHit hit = new UsnHit();

        hit.Version = "V2";
        hit.FileRef = (ulong)Marshal.ReadInt64(buffer, offset + 8);
        hit.ParentRef = (ulong)Marshal.ReadInt64(buffer, offset + 16);
        hit.Usn = Marshal.ReadInt64(buffer, offset + 24);

        long fileTime = Marshal.ReadInt64(buffer, offset + 32);
        hit.Time = DateTime.FromFileTimeUtc(fileTime).ToLocalTime();

        hit.Reason = (uint)Marshal.ReadInt32(buffer, offset + 40);

        ushort nameLength = (ushort)Marshal.ReadInt16(buffer, offset + 56);
        ushort nameOffset = (ushort)Marshal.ReadInt16(buffer, offset + 58);

        hit.Name = Marshal.PtrToStringUni(AddPtr(buffer, offset + nameOffset), nameLength / 2);

        return hit;
    }

    static UsnHit ParseUsnRecordV3(IntPtr buffer, int offset)
    {
        UsnHit hit = new UsnHit();

        hit.Version = "V3";
        hit.FileRef = 0;
        hit.ParentRef = 0;
        hit.Usn = Marshal.ReadInt64(buffer, offset + 40);

        long fileTime = Marshal.ReadInt64(buffer, offset + 48);
        hit.Time = DateTime.FromFileTimeUtc(fileTime).ToLocalTime();

        hit.Reason = (uint)Marshal.ReadInt32(buffer, offset + 56);

        ushort nameLength = (ushort)Marshal.ReadInt16(buffer, offset + 72);
        ushort nameOffset = (ushort)Marshal.ReadInt16(buffer, offset + 74);

        hit.Name = Marshal.PtrToStringUni(AddPtr(buffer, offset + nameOffset), nameLength / 2);

        return hit;
    }

    static bool IsPrefetchTarget(string name)
    {
        if (String.IsNullOrEmpty(name))
            return false;

        string upper = name.ToUpperInvariant();

        if (upper.EndsWith(".PF"))
            return true;

        if (upper == "PREFETCH")
            return true;

        return false;
    }

    static bool IsSuspiciousPrefetchReason(uint reason)
    {
        uint suspicious =
            0x00000001 | // DATA_OVERWRITE
            0x00000002 | // DATA_EXTEND
            0x00000004 | // DATA_TRUNCATION
            0x00000200 | // FILE_DELETE
            0x00001000 | // RENAME_OLD_NAME
            0x00002000 | // RENAME_NEW_NAME
            0x00008000;  // BASIC_INFO_CHANGE

        return (reason & suspicious) != 0;
    }

    static void PrintHit(UsnHit hit, StringBuilder log)
    {
        log.AppendLine("[PREFETCH CHANGE]");
        log.AppendLine("  Time:      " + hit.Time);
        log.AppendLine("  Version:   " + hit.Version);
        log.AppendLine("  Name:      " + hit.Name);
        log.AppendLine("  USN:       " + hit.Usn);

        if (hit.FileRef != 0)
            log.AppendLine("  FileRef:   " + hit.FileRef);

        if (hit.ParentRef != 0)
            log.AppendLine("  ParentRef: " + hit.ParentRef);

        log.AppendLine("  Reason:    " + ReasonToString(hit.Reason));

        if ((hit.Reason & 0x00008000) != 0)
            log.AppendLine("  FLAG:      Possible timestamp/metadata change");

        if ((hit.Reason & 0x00000200) != 0)
            log.AppendLine("  FLAG:      Prefetch file deleted");

        if ((hit.Reason & 0x00001000) != 0 || (hit.Reason & 0x00002000) != 0)
            log.AppendLine("  FLAG:      Prefetch file renamed");

        if ((hit.Reason & 0x00000001) != 0 || (hit.Reason & 0x00000002) != 0 || (hit.Reason & 0x00000004) != 0)
            log.AppendLine("  FLAG:      Prefetch file content changed");

        log.AppendLine("");
    }

    static IntPtr AddPtr(IntPtr ptr, int offset)
    {
        return new IntPtr(ptr.ToInt64() + offset);
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
}
