using System;
using System.IO;
using System.Text;
using System.Drawing;
using System.Threading;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Windows.Forms;
using Microsoft.Win32.SafeHandles;

class PrefetchForensicsUI : Form
{
    DataGridView grid;
    TextBox detailsBox;
    TextBox driveBox;
    NumericUpDown maxRecordsBox;
    NumericUpDown lookbackBox;
    Button checkJournalButton;
    Button checkCurrentButton;
    Button copyAllButton;
    Button clearButton;
    Label statusLabel;
    Label summaryLabel;

    List<ArtifactRecord> records = new List<ArtifactRecord>();

    const uint GENERIC_READ = 0x80000000;
    const uint FILE_SHARE_READ = 0x00000001;
    const uint FILE_SHARE_WRITE = 0x00000002;
    const uint FILE_SHARE_DELETE = 0x00000004;
    const uint OPEN_EXISTING = 3;

    const uint FSCTL_QUERY_USN_JOURNAL = 0x000900F4;
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

    class ArtifactRecord
    {
        public string Severity;
        public string Time;
        public string Artifact;
        public string Action;
        public string Reason;
        public string Path;
        public string PathType;
        public string Exists;
        public string Size;
        public string Sha256;
        public string Signature;
        public string Signer;
        public string Notes;
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
        Application.Run(new PrefetchForensicsUI());
    }

    public PrefetchForensicsUI()
    {
        Text = "Prefetch Journal Forensics";
        Width = 1250;
        Height = 760;
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = Color.FromArgb(245, 247, 250);

        Panel header = new Panel();
        header.Left = 0;
        header.Top = 0;
        header.Width = 1250;
        header.Height = 70;
        header.BackColor = Color.FromArgb(30, 41, 59);
        header.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;

        Label title = new Label();
        title.Text = "Prefetch Journal Forensics";
        title.Left = 20;
        title.Top = 12;
        title.Width = 500;
        title.Height = 25;
        title.ForeColor = Color.White;
        title.Font = new Font("Segoe UI", 15, FontStyle.Bold);

        Label subtitle = new Label();
        subtitle.Text = "Checks Prefetch changes, deletes, renames, timestamp edits, hashes, and signatures.";
        subtitle.Left = 22;
        subtitle.Top = 40;
        subtitle.Width = 900;
        subtitle.Height = 20;
        subtitle.ForeColor = Color.FromArgb(203, 213, 225);
        subtitle.Font = new Font("Segoe UI", 9);

        header.Controls.Add(title);
        header.Controls.Add(subtitle);
        Controls.Add(header);

        Panel controls = new Panel();
        controls.Left = 15;
        controls.Top = 85;
        controls.Width = 1200;
        controls.Height = 80;
        controls.BackColor = Color.White;
        controls.BorderStyle = BorderStyle.FixedSingle;
        controls.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;

        Label driveLabel = new Label();
        driveLabel.Text = "Drive";
        driveLabel.Left = 15;
        driveLabel.Top = 12;
        driveLabel.Width = 70;
        driveLabel.Font = new Font("Segoe UI", 9, FontStyle.Bold);

        driveBox = new TextBox();
        driveBox.Text = "C:";
        driveBox.Left = 15;
        driveBox.Top = 35;
        driveBox.Width = 70;

        Label maxLabel = new Label();
        maxLabel.Text = "Max Records";
        maxLabel.Left = 105;
        maxLabel.Top = 12;
        maxLabel.Width = 100;
        maxLabel.Font = new Font("Segoe UI", 9, FontStyle.Bold);

        maxRecordsBox = new NumericUpDown();
        maxRecordsBox.Left = 105;
        maxRecordsBox.Top = 35;
        maxRecordsBox.Width = 100;
        maxRecordsBox.Minimum = 1;
        maxRecordsBox.Maximum = 500000;
        maxRecordsBox.Value = 10000;

        Label lookbackLabel = new Label();
        lookbackLabel.Text = "Lookback MB";
        lookbackLabel.Left = 225;
        lookbackLabel.Top = 12;
        lookbackLabel.Width = 100;
        lookbackLabel.Font = new Font("Segoe UI", 9, FontStyle.Bold);

        lookbackBox = new NumericUpDown();
        lookbackBox.Left = 225;
        lookbackBox.Top = 35;
        lookbackBox.Width = 100;
        lookbackBox.Minimum = 1;
        lookbackBox.Maximum = 16384;
        lookbackBox.Value = 1024;

        checkJournalButton = new Button();
        checkJournalButton.Text = "Check Journal";
        checkJournalButton.Left = 350;
        checkJournalButton.Top = 25;
        checkJournalButton.Width = 130;
        checkJournalButton.Height = 35;
        checkJournalButton.Click += new EventHandler(CheckJournalButton_Click);

        checkCurrentButton = new Button();
        checkCurrentButton.Text = "Current Prefetch";
        checkCurrentButton.Left = 490;
        checkCurrentButton.Top = 25;
        checkCurrentButton.Width = 140;
        checkCurrentButton.Height = 35;
        checkCurrentButton.Click += new EventHandler(CheckCurrentButton_Click);

        copyAllButton = new Button();
        copyAllButton.Text = "Copy Logs";
        copyAllButton.Left = 640;
        copyAllButton.Top = 25;
        copyAllButton.Width = 110;
        copyAllButton.Height = 35;
        copyAllButton.Click += new EventHandler(CopyAllButton_Click);

        clearButton = new Button();
        clearButton.Text = "Clear";
        clearButton.Left = 760;
        clearButton.Top = 25;
        clearButton.Width = 90;
        clearButton.Height = 35;
        clearButton.Click += new EventHandler(ClearButton_Click);

        statusLabel = new Label();
        statusLabel.Left = 875;
        statusLabel.Top = 15;
        statusLabel.Width = 300;
        statusLabel.Height = 22;
        statusLabel.Font = new Font("Segoe UI", 9, FontStyle.Bold);

        if (IsAdmin())
        {
            statusLabel.Text = "Administrator: Yes";
            statusLabel.ForeColor = Color.Green;
        }
        else
        {
            statusLabel.Text = "Administrator: No";
            statusLabel.ForeColor = Color.Red;
        }

        summaryLabel = new Label();
        summaryLabel.Left = 875;
        summaryLabel.Top = 40;
        summaryLabel.Width = 300;
        summaryLabel.Height = 22;
        summaryLabel.Text = "Ready";
        summaryLabel.ForeColor = Color.FromArgb(71, 85, 105);

        controls.Controls.Add(driveLabel);
        controls.Controls.Add(driveBox);
        controls.Controls.Add(maxLabel);
        controls.Controls.Add(maxRecordsBox);
        controls.Controls.Add(lookbackLabel);
        controls.Controls.Add(lookbackBox);
        controls.Controls.Add(checkJournalButton);
        controls.Controls.Add(checkCurrentButton);
        controls.Controls.Add(copyAllButton);
        controls.Controls.Add(clearButton);
        controls.Controls.Add(statusLabel);
        controls.Controls.Add(summaryLabel);
        Controls.Add(controls);

        grid = new DataGridView();
        grid.Left = 15;
        grid.Top = 180;
        grid.Width = 1200;
        grid.Height = 390;
        grid.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Bottom;
        grid.BackgroundColor = Color.White;
        grid.BorderStyle = BorderStyle.FixedSingle;
        grid.ReadOnly = true;
        grid.AllowUserToAddRows = false;
        grid.AllowUserToDeleteRows = false;
        grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
        grid.MultiSelect = false;
        grid.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.None;
        grid.RowHeadersVisible = false;
        grid.Font = new Font("Segoe UI", 9);
        grid.ColumnHeadersDefaultCellStyle.Font = new Font("Segoe UI", 9, FontStyle.Bold);
        grid.CellClick += new DataGridViewCellEventHandler(Grid_CellClick);
        grid.CellFormatting += new DataGridViewCellFormattingEventHandler(Grid_CellFormatting);

        AddColumn("Severity", 85);
        AddColumn("Time", 145);
        AddColumn("Artifact", 120);
        AddColumn("Action", 120);
        AddColumn("Reason", 230);
        AddColumn("Path", 330);
        AddColumn("Exists", 70);
        AddColumn("SHA256", 260);
        AddColumn("Signature", 110);
        AddColumn("Signer", 260);

        Controls.Add(grid);

        detailsBox = new TextBox();
        detailsBox.Left = 15;
        detailsBox.Top = 585;
        detailsBox.Width = 1200;
        detailsBox.Height = 120;
        detailsBox.Anchor = AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Bottom;
        detailsBox.Multiline = true;
        detailsBox.ScrollBars = ScrollBars.Vertical;
        detailsBox.WordWrap = true;
        detailsBox.Font = new Font("Consolas", 9);
        detailsBox.BackColor = Color.White;
        Controls.Add(detailsBox);
    }

    void AddColumn(string name, int width)
    {
        DataGridViewTextBoxColumn col = new DataGridViewTextBoxColumn();
        col.Name = name;
        col.HeaderText = name;
        col.Width = width;
        grid.Columns.Add(col);
    }

    void CheckJournalButton_Click(object sender, EventArgs e)
    {
        DisableButtons();
        summaryLabel.Text = "Reading journal...";

        string drive = driveBox.Text.Trim();
        int maxRecords = (int)maxRecordsBox.Value;
        long lookbackBytes = (long)lookbackBox.Value * 1024L * 1024L;

        Thread t = new Thread(delegate()
        {
            try
            {
                List<ArtifactRecord> result = CheckPrefetchJournal(drive, maxRecords, lookbackBytes);
                SetRecords(result, "Journal check complete");
            }
            catch (Exception ex)
            {
                List<ArtifactRecord> errorList = new List<ArtifactRecord>();
                errorList.Add(MakeErrorRecord(ex.ToString()));
                SetRecords(errorList, "Error");
            }
            finally
            {
                EnableButtons();
            }
        });

        t.IsBackground = true;
        t.Start();
    }

    void CheckCurrentButton_Click(object sender, EventArgs e)
    {
        DisableButtons();
        summaryLabel.Text = "Checking current prefetch files...";

        Thread t = new Thread(delegate()
        {
            try
            {
                List<ArtifactRecord> result = CheckCurrentPrefetchFiles();
                SetRecords(result, "Current prefetch check complete");
            }
            catch (Exception ex)
            {
                List<ArtifactRecord> errorList = new List<ArtifactRecord>();
                errorList.Add(MakeErrorRecord(ex.ToString()));
                SetRecords(errorList, "Error");
            }
            finally
            {
                EnableButtons();
            }
        });

        t.IsBackground = true;
        t.Start();
    }

    void CopyAllButton_Click(object sender, EventArgs e)
    {
        Clipboard.SetText(BuildTextLog(records));
    }

    void ClearButton_Click(object sender, EventArgs e)
    {
        records.Clear();
        grid.Rows.Clear();
        detailsBox.Clear();
        summaryLabel.Text = "Cleared";
    }

    void Grid_CellClick(object sender, DataGridViewCellEventArgs e)
    {
        if (e.RowIndex < 0 || e.RowIndex >= records.Count)
            return;

        detailsBox.Text = FormatRecord(records[e.RowIndex]);
    }

    void Grid_CellFormatting(object sender, DataGridViewCellFormattingEventArgs e)
    {
        if (e.RowIndex < 0 || e.RowIndex >= records.Count)
            return;

        string sev = records[e.RowIndex].Severity;

        if (sev == "High")
        {
            grid.Rows[e.RowIndex].DefaultCellStyle.BackColor = Color.FromArgb(254, 226, 226);
        }
        else if (sev == "Warning")
        {
            grid.Rows[e.RowIndex].DefaultCellStyle.BackColor = Color.FromArgb(255, 247, 237);
        }
        else if (sev == "OK")
        {
            grid.Rows[e.RowIndex].DefaultCellStyle.BackColor = Color.FromArgb(240, 253, 244);
        }
        else
        {
            grid.Rows[e.RowIndex].DefaultCellStyle.BackColor = Color.White;
        }
    }

    void DisableButtons()
    {
        if (InvokeRequired)
        {
            Invoke(new Action(DisableButtons));
            return;
        }

        checkJournalButton.Enabled = false;
        checkCurrentButton.Enabled = false;
    }

    void EnableButtons()
    {
        if (InvokeRequired)
        {
            Invoke(new Action(EnableButtons));
            return;
        }

        checkJournalButton.Enabled = true;
        checkCurrentButton.Enabled = true;
    }

    void SetRecords(List<ArtifactRecord> newRecords, string status)
    {
        if (InvokeRequired)
        {
            Invoke(new Action<List<ArtifactRecord>, string>(SetRecords), newRecords, status);
            return;
        }

        records = newRecords;
        grid.Rows.Clear();

        int high = 0;
        int warning = 0;
        int ok = 0;

        foreach (ArtifactRecord r in records)
        {
            if (r.Severity == "High") high++;
            if (r.Severity == "Warning") warning++;
            if (r.Severity == "OK") ok++;

            grid.Rows.Add(
                r.Severity,
                r.Time,
                r.Artifact,
                r.Action,
                r.Reason,
                r.Path,
                r.Exists,
                r.Sha256,
                r.Signature,
                r.Signer
            );
        }

        summaryLabel.Text = status + " | High: " + high + " Warning: " + warning + " OK: " + ok;

        if (records.Count > 0)
            detailsBox.Text = FormatRecord(records[0]);
        else
            detailsBox.Text = "No results.";
    }

    static List<ArtifactRecord> CheckPrefetchJournal(string drive, int maxRecords, long lookbackBytes)
    {
        List<ArtifactRecord> result = new List<ArtifactRecord>();

        if (drive.EndsWith("\\"))
            drive = drive.TrimEnd('\\');

        if (!drive.EndsWith(":"))
            drive += ":";

        string volumePath = @"\\.\" + drive;

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

        long startUsn = journal.NextUsn - lookbackBytes;

        if (startUsn < journal.FirstUsn)
            startUsn = journal.FirstUsn;

        result.Add(MakeInfoRecord(
            "USN Journal Info",
            "Volume: " + volumePath +
            "\r\nJournal ID: " + journal.UsnJournalID +
            "\r\nFirst USN: " + journal.FirstUsn +
            "\r\nNext USN: " + journal.NextUsn +
            "\r\nStart USN: " + startUsn
        ));

        ReadJournalRecords(volume, journal, startUsn, maxRecords, result);

        volume.Close();

        return result;
    }

    static void ReadJournalRecords(
        SafeFileHandle volume,
        USN_JOURNAL_DATA_V0 journal,
        long startUsn,
        int maxRecords,
        List<ArtifactRecord> result
    )
    {
        READ_USN_JOURNAL_DATA_V0 readData = new READ_USN_JOURNAL_DATA_V0();
        readData.StartUsn = startUsn;
        readData.ReasonMask =
            0x00000001 |
            0x00000002 |
            0x00000004 |
            0x00000100 |
            0x00000200 |
            0x00001000 |
            0x00002000 |
            0x00008000 |
            0x80000000;

        readData.ReturnOnlyOnClose = 0;
        readData.Timeout = 0;
        readData.BytesToWaitFor = 0;
        readData.UsnJournalID = journal.UsnJournalID;

        int inputSize = Marshal.SizeOf(typeof(READ_USN_JOURNAL_DATA_V0));
        IntPtr inputBuffer = Marshal.AllocHGlobal(inputSize);
        IntPtr outputBuffer = Marshal.AllocHGlobal(BUFFER_SIZE);

        int seen = 0;

        try
        {
            while (seen < maxRecords)
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
                {
                    int err = Marshal.GetLastWin32Error();

                    if (err == 38)
                        break;

                    throw new Exception("FSCTL_READ_USN_JOURNAL failed. Win32: " + err);
                }

                if (bytesReturned <= 8)
                    break;

                long nextUsn = Marshal.ReadInt64(outputBuffer);
                int offset = 8;

                while (offset < bytesReturned && seen < maxRecords)
                {
                    int recordLength = Marshal.ReadInt32(outputBuffer, offset);

                    if (recordLength <= 0 || offset + recordLength > bytesReturned)
                        break;

                    ushort majorVersion = (ushort)Marshal.ReadInt16(outputBuffer, offset + 4);

                    UsnHit hit = null;

                    if (majorVersion == 2)
                        hit = ParseUsnRecordV2(outputBuffer, offset);
                    else if (majorVersion == 3)
                        hit = ParseUsnRecordV3(outputBuffer, offset);

                    if (hit != null)
                    {
                        seen++;

                        if (IsPrefetchTarget(hit.Name) && IsSuspiciousPrefetchReason(hit.Reason))
                            result.Add(BuildPrefetchJournalRecord(hit));
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
    }

    static List<ArtifactRecord> CheckCurrentPrefetchFiles()
    {
        List<ArtifactRecord> result = new List<ArtifactRecord>();

        string prefetchDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");

        if (!Directory.Exists(prefetchDir))
        {
            result.Add(MakeErrorRecord("Prefetch folder not found: " + prefetchDir));
            return result;
        }

        FileInfo[] files = new DirectoryInfo(prefetchDir).GetFiles("*.pf");

        result.Add(MakeInfoRecord(
            "Current Prefetch Info",
            "Folder: " + prefetchDir + "\r\nTotal .pf files: " + files.Length
        ));

        foreach (FileInfo file in files)
        {
            ArtifactRecord r = new ArtifactRecord();

            bool suspicious = false;
            StringBuilder reason = new StringBuilder();

            if (file.LastWriteTime < file.CreationTime.AddMinutes(-2))
            {
                suspicious = true;
                reason.Append("Modified time earlier than creation time; ");
            }

            if (file.LastAccessTime < file.CreationTime.AddMinutes(-2))
            {
                suspicious = true;
                reason.Append("Access time earlier than creation time; ");
            }

            if (file.Length == 0)
            {
                suspicious = true;
                reason.Append("Zero-byte prefetch file; ");
            }

            r.Severity = suspicious ? "Warning" : "OK";
            r.Time = DateTime.Now.ToString();
            r.Artifact = "Current Prefetch";
            r.Action = suspicious ? "Possible timestomp" : "Existing file";
            r.Reason = suspicious ? reason.ToString() : "No simple timestamp issue found";
            r.Path = file.FullName;
            r.PathType = "Full path";
            r.Exists = "Yes";
            r.Size = file.Length.ToString();
            r.Notes =
                "Created: " + file.CreationTime +
                "\r\nModified: " + file.LastWriteTime +
                "\r\nAccessed: " + file.LastAccessTime +
                "\r\nPrefetch files are usually unsigned. Signature applies to the .pf file itself.";

            FillHashAndSignature(r, file.FullName);

            result.Add(r);
        }

        return result;
    }

    static ArtifactRecord BuildPrefetchJournalRecord(UsnHit hit)
    {
        ArtifactRecord r = new ArtifactRecord();

        string path = InferPrefetchPath(hit.Name);
        bool exists = File.Exists(path);
        bool isFolder = Directory.Exists(path);

        r.Severity = GetSeverity(hit.Reason);
        r.Time = hit.Time.ToString();
        r.Artifact = "Prefetch Journal";
        r.Action = GetAction(hit.Reason);
        r.Reason = ReasonToString(hit.Reason);
        r.Path = path;
        r.PathType = "Inferred from USN filename";
        r.Exists = exists ? "Yes" : (isFolder ? "Folder" : "No");
        r.Size = exists ? new FileInfo(path).Length.ToString() : "Unavailable";
        r.Notes =
            "USN Version: " + hit.Version +
            "\r\nUSN: " + hit.Usn +
            "\r\nFileRef: " + hit.FileRef +
            "\r\nParentRef: " + hit.ParentRef +
            "\r\nOriginal USN Name: " + hit.Name +
            "\r\nNote: Deleted or renamed files may no longer exist, so signature/hash may be unavailable.";

        if (exists)
            FillHashAndSignature(r, path);
        else
        {
            r.Sha256 = "Unavailable";
            r.Signature = "Unavailable";
            r.Signer = "Unavailable";
        }

        return r;
    }

    static void FillHashAndSignature(ArtifactRecord r, string path)
    {
        r.Sha256 = GetSha256Safe(path);
        SignatureResult sig = GetSignatureSafe(path);
        r.Signature = sig.Status;
        r.Signer = sig.Signer;
    }

    class SignatureResult
    {
        public string Status;
        public string Signer;
    }

    static SignatureResult GetSignatureSafe(string path)
    {
        SignatureResult result = new SignatureResult();
        result.Status = "Unavailable";
        result.Signer = "Unavailable";

        try
        {
            X509Certificate cert = X509Certificate.CreateFromSignedFile(path);
            X509Certificate2 cert2 = new X509Certificate2(cert);

            result.Status = "Signed";
            result.Signer = cert2.Subject;
            return result;
        }
        catch
        {
            result.Status = "Unsigned";
            result.Signer = "None";
            return result;
        }
    }

    static string GetSha256Safe(string path)
    {
        try
        {
            using (FileStream stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                using (SHA256Managed sha = new SHA256Managed())
                {
                    byte[] hash = sha.ComputeHash(stream);
                    StringBuilder sb = new StringBuilder();

                    for (int i = 0; i < hash.Length; i++)
                        sb.Append(hash[i].ToString("X2"));

                    return sb.ToString();
                }
            }
        }
        catch (Exception ex)
        {
            return "Error: " + ex.Message;
        }
    }

    static string InferPrefetchPath(string name)
    {
        string prefetchDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");

        if (String.IsNullOrEmpty(name))
            return prefetchDir;

        if (name.ToUpperInvariant() == "PREFETCH")
            return prefetchDir;

        return Path.Combine(prefetchDir, name);
    }

    static string GetSeverity(uint reason)
    {
        if ((reason & 0x00000200) != 0)
            return "High";

        if ((reason & 0x00008000) != 0)
            return "Warning";

        if ((reason & 0x00001000) != 0 || (reason & 0x00002000) != 0)
            return "Warning";

        if ((reason & 0x00000001) != 0 || (reason & 0x00000002) != 0 || (reason & 0x00000004) != 0)
            return "Warning";

        return "Info";
    }

    static string GetAction(uint reason)
    {
        if ((reason & 0x00000200) != 0)
            return "Deleted";

        if ((reason & 0x00001000) != 0 || (reason & 0x00002000) != 0)
            return "Renamed";

        if ((reason & 0x00008000) != 0)
            return "Timestamp/metadata changed";

        if ((reason & 0x00000001) != 0 || (reason & 0x00000002) != 0 || (reason & 0x00000004) != 0)
            return "Content changed";

        if ((reason & 0x00000100) != 0)
            return "Created";

        return "Changed";
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
            0x00000001 |
            0x00000002 |
            0x00000004 |
            0x00000200 |
            0x00001000 |
            0x00002000 |
            0x00008000;

        return (reason & suspicious) != 0;
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

    static ArtifactRecord MakeInfoRecord(string artifact, string note)
    {
        ArtifactRecord r = new ArtifactRecord();
        r.Severity = "Info";
        r.Time = DateTime.Now.ToString();
        r.Artifact = artifact;
        r.Action = "Info";
        r.Reason = "Information";
        r.Path = "N/A";
        r.PathType = "N/A";
        r.Exists = "N/A";
        r.Size = "N/A";
        r.Sha256 = "N/A";
        r.Signature = "N/A";
        r.Signer = "N/A";
        r.Notes = note;
        return r;
    }

    static ArtifactRecord MakeErrorRecord(string note)
    {
        ArtifactRecord r = new ArtifactRecord();
        r.Severity = "High";
        r.Time = DateTime.Now.ToString();
        r.Artifact = "Error";
        r.Action = "Failed";
        r.Reason = "Exception";
        r.Path = "N/A";
        r.PathType = "N/A";
        r.Exists = "N/A";
        r.Size = "N/A";
        r.Sha256 = "N/A";
        r.Signature = "N/A";
        r.Signer = "N/A";
        r.Notes = note;
        return r;
    }

    static string FormatRecord(ArtifactRecord r)
    {
        StringBuilder sb = new StringBuilder();

        sb.AppendLine("Severity:   " + r.Severity);
        sb.AppendLine("Time:       " + r.Time);
        sb.AppendLine("Artifact:   " + r.Artifact);
        sb.AppendLine("Action:     " + r.Action);
        sb.AppendLine("Reason:     " + r.Reason);
        sb.AppendLine("Path:       " + r.Path);
        sb.AppendLine("Path Type:  " + r.PathType);
        sb.AppendLine("Exists:     " + r.Exists);
        sb.AppendLine("Size:       " + r.Size);
        sb.AppendLine("SHA256:     " + r.Sha256);
        sb.AppendLine("Signature:  " + r.Signature);
        sb.AppendLine("Signer:     " + r.Signer);
        sb.AppendLine("");
        sb.AppendLine("Notes:");
        sb.AppendLine(r.Notes);

        return sb.ToString();
    }

    static string BuildTextLog(List<ArtifactRecord> list)
    {
        StringBuilder sb = new StringBuilder();

        sb.AppendLine("Prefetch Journal Forensics Log");
        sb.AppendLine("Generated: " + DateTime.Now);
        sb.AppendLine("Records: " + list.Count);
        sb.AppendLine("");

        foreach (ArtifactRecord r in list)
        {
            sb.AppendLine("----------------------------------------");
            sb.AppendLine(FormatRecord(r));
        }

        return sb.ToString();
    }

    static bool IsAdmin()
    {
        WindowsIdentity identity = WindowsIdentity.GetCurrent();
        WindowsPrincipal principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }
}
