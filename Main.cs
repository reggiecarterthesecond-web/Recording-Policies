using System;
using System.IO;
using System.Text;
using System.Drawing;
using System.Threading;
using System.Diagnostics;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Windows.Forms;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

class AntiCheatForensicsUI : Form
{
    DataGridView grid;
    TextBox detailsBox;
    Label statusLabel;
    Label summaryLabel;
    NumericUpDown maxUsnRecordsBox;
    NumericUpDown lookbackMbBox;
    Button runButton;
    Button copyButton;
    Button clearButton;
    CheckBox cbPrefetch;
    CheckBox cbUsn;
    CheckBox cbBam;
    CheckBox cbUserAssist;
    CheckBox cbProcesses;
    CheckBox cbShimcache;
    CheckBox cbAmcache;

    List<ArtifactRecord> records = new List<ArtifactRecord>();
    HashSet<string> runningPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    HashSet<string> trustedHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

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
        public string Severity = "Info";
        public string Source = "";
        public string Time = "";
        public string Action = "";
        public string Path = "";
        public string Exists = "";
        public string Running = "";
        public string HashMatch = "";
        public string Sha256 = "";
        public string Signature = "";
        public string Signer = "";
        public string Company = "";
        public string FileVersion = "";
        public string Product = "";
        public string Size = "";
        public string Created = "";
        public string Modified = "";
        public string Accessed = "";
        public string PE = "";
        public string Evidence = "";
    }

    class UsnHit
    {
        public string Name;
        public DateTime Time;
        public uint Reason;
        public long Usn;
        public ulong FileRef;
        public ulong ParentRef;
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
        Application.Run(new AntiCheatForensicsUI());
    }

    public AntiCheatForensicsUI()
    {
        Text = "Client Anti-Cheat Forensics Viewer";
        Width = 1350;
        Height = 820;
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = Color.FromArgb(245, 247, 250);

        Panel header = new Panel();
        header.Left = 0;
        header.Top = 0;
        header.Width = 1350;
        header.Height = 75;
        header.BackColor = Color.FromArgb(15, 23, 42);
        header.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;

        Label title = new Label();
        title.Text = "Client Anti-Cheat Forensics Viewer";
        title.Left = 20;
        title.Top = 12;
        title.Width = 600;
        title.Height = 28;
        title.ForeColor = Color.White;
        title.Font = new Font("Segoe UI", 16, FontStyle.Bold);

        Label subtitle = new Label();
        subtitle.Text = "Local-only scanner: Prefetch, USN Journal, BAM, UserAssist, Shimcache strings, Amcache strings, running processes, hashes, signatures, PE info.";
        subtitle.Left = 22;
        subtitle.Top = 43;
        subtitle.Width = 1250;
        subtitle.Height = 24;
        subtitle.ForeColor = Color.FromArgb(203, 213, 225);
        subtitle.Font = new Font("Segoe UI", 9);

        header.Controls.Add(title);
        header.Controls.Add(subtitle);
        Controls.Add(header);

        Panel options = new Panel();
        options.Left = 15;
        options.Top = 90;
        options.Width = 1300;
        options.Height = 105;
        options.BackColor = Color.White;
        options.BorderStyle = BorderStyle.FixedSingle;
        options.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
        Controls.Add(options);

        cbPrefetch = AddCheck(options, "Prefetch files", 15, 15, true);
        cbUsn = AddCheck(options, "USN deleted/renamed/edited", 140, 15, true);
        cbBam = AddCheck(options, "BAM", 350, 15, true);
        cbUserAssist = AddCheck(options, "UserAssist", 420, 15, true);
        cbProcesses = AddCheck(options, "Running processes", 530, 15, true);
        cbShimcache = AddCheck(options, "Shimcache strings", 680, 15, true);
        cbAmcache = AddCheck(options, "Amcache strings", 830, 15, true);

        Label maxLabel = new Label();
        maxLabel.Text = "USN max records";
        maxLabel.Left = 15;
        maxLabel.Top = 58;
        maxLabel.Width = 110;
        options.Controls.Add(maxLabel);

        maxUsnRecordsBox = new NumericUpDown();
        maxUsnRecordsBox.Left = 125;
        maxUsnRecordsBox.Top = 55;
        maxUsnRecordsBox.Width = 110;
        maxUsnRecordsBox.Minimum = 1;
        maxUsnRecordsBox.Maximum = 500000;
        maxUsnRecordsBox.Value = 15000;
        options.Controls.Add(maxUsnRecordsBox);

        Label lookLabel = new Label();
        lookLabel.Text = "USN lookback MB";
        lookLabel.Left = 255;
        lookLabel.Top = 58;
        lookLabel.Width = 115;
        options.Controls.Add(lookLabel);

        lookbackMbBox = new NumericUpDown();
        lookbackMbBox.Left = 370;
        lookbackMbBox.Top = 55;
        lookbackMbBox.Width = 110;
        lookbackMbBox.Minimum = 1;
        lookbackMbBox.Maximum = 32768;
        lookbackMbBox.Value = 2048;
        options.Controls.Add(lookbackMbBox);

        runButton = new Button();
        runButton.Text = "Run Scan";
        runButton.Left = 510;
        runButton.Top = 50;
        runButton.Width = 120;
        runButton.Height = 34;
        runButton.Click += new EventHandler(RunButton_Click);
        options.Controls.Add(runButton);

        copyButton = new Button();
        copyButton.Text = "Copy Logs";
        copyButton.Left = 640;
        copyButton.Top = 50;
        copyButton.Width = 120;
        copyButton.Height = 34;
        copyButton.Click += new EventHandler(CopyButton_Click);
        options.Controls.Add(copyButton);

        clearButton = new Button();
        clearButton.Text = "Clear";
        clearButton.Left = 770;
        clearButton.Top = 50;
        clearButton.Width = 90;
        clearButton.Height = 34;
        clearButton.Click += new EventHandler(ClearButton_Click);
        options.Controls.Add(clearButton);

        statusLabel = new Label();
        statusLabel.Left = 895;
        statusLabel.Top = 48;
        statusLabel.Width = 380;
        statusLabel.Height = 20;
        statusLabel.Font = new Font("Segoe UI", 9, FontStyle.Bold);
        statusLabel.Text = IsAdmin() ? "Administrator: Yes" : "Administrator: No - some artifacts may fail";
        statusLabel.ForeColor = IsAdmin() ? Color.Green : Color.Red;
        options.Controls.Add(statusLabel);

        summaryLabel = new Label();
        summaryLabel.Left = 895;
        summaryLabel.Top = 70;
        summaryLabel.Width = 380;
        summaryLabel.Height = 20;
        summaryLabel.Text = "Ready";
        options.Controls.Add(summaryLabel);

        grid = new DataGridView();
        grid.Left = 15;
        grid.Top = 210;
        grid.Width = 1300;
        grid.Height = 420;
        grid.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Bottom;
        grid.ReadOnly = true;
        grid.AllowUserToAddRows = false;
        grid.AllowUserToDeleteRows = false;
        grid.RowHeadersVisible = false;
        grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
        grid.MultiSelect = false;
        grid.BackgroundColor = Color.White;
        grid.Font = new Font("Segoe UI", 9);
        grid.ColumnHeadersDefaultCellStyle.Font = new Font("Segoe UI", 9, FontStyle.Bold);
        grid.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.None;
        grid.CellClick += new DataGridViewCellEventHandler(Grid_CellClick);
        grid.CellFormatting += new DataGridViewCellFormattingEventHandler(Grid_CellFormatting);
        Controls.Add(grid);

        AddColumn("Severity", 80);
        AddColumn("Source", 110);
        AddColumn("Time", 145);
        AddColumn("Action", 145);
        AddColumn("Path", 360);
        AddColumn("Exists", 65);
        AddColumn("Running", 75);
        AddColumn("Hash Match", 100);
        AddColumn("SHA256", 250);
        AddColumn("Signature", 95);
        AddColumn("Signer", 250);
        AddColumn("PE", 180);

        detailsBox = new TextBox();
        detailsBox.Left = 15;
        detailsBox.Top = 645;
        detailsBox.Width = 1300;
        detailsBox.Height = 130;
        detailsBox.Anchor = AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Bottom;
        detailsBox.Multiline = true;
        detailsBox.ScrollBars = ScrollBars.Vertical;
        detailsBox.WordWrap = true;
        detailsBox.Font = new Font("Consolas", 9);
        detailsBox.BackColor = Color.White;
        Controls.Add(detailsBox);
    }

    CheckBox AddCheck(Control parent, string text, int left, int top, bool value)
    {
        CheckBox c = new CheckBox();
        c.Text = text;
        c.Left = left;
        c.Top = top;
        c.Width = 180;
        c.Checked = value;
        parent.Controls.Add(c);
        return c;
    }

    void AddColumn(string name, int width)
    {
        DataGridViewTextBoxColumn col = new DataGridViewTextBoxColumn();
        col.Name = name;
        col.HeaderText = name;
        col.Width = width;
        grid.Columns.Add(col);
    }

    void RunButton_Click(object sender, EventArgs e)
    {
        runButton.Enabled = false;
        records.Clear();
        grid.Rows.Clear();
        detailsBox.Clear();
        summaryLabel.Text = "Scanning...";

        bool doPrefetch = cbPrefetch.Checked;
        bool doUsn = cbUsn.Checked;
        bool doBam = cbBam.Checked;
        bool doUserAssist = cbUserAssist.Checked;
        bool doProcesses = cbProcesses.Checked;
        bool doShimcache = cbShimcache.Checked;
        bool doAmcache = cbAmcache.Checked;
        int maxUsn = (int)maxUsnRecordsBox.Value;
        long lookbackBytes = (long)lookbackMbBox.Value * 1024L * 1024L;

        Thread t = new Thread(delegate()
        {
            List<ArtifactRecord> output = new List<ArtifactRecord>();
            try
            {
                trustedHashes = LoadTrustedHashes();
                runningPaths = BuildRunningPathSet();

                output.Add(MakeInfo("Scan Info", "Started local scan. No network upload is performed by this program."));
                output.Add(MakeInfo("Trusted Hashes", "Loaded trusted_hashes.txt entries: " + trustedHashes.Count));

                if (doProcesses) CollectRunningProcesses(output);
                if (doPrefetch) CollectPrefetchFiles(output);
                if (doUsn) CollectPrefetchUsn(output, maxUsn, lookbackBytes);
                if (doBam) CollectBam(output);
                if (doUserAssist) CollectUserAssist(output);
                if (doShimcache) CollectShimcacheStrings(output);
                if (doAmcache) CollectAmcacheStrings(output);
            }
            catch (Exception ex)
            {
                output.Add(MakeError("Fatal Error", ex.ToString()));
            }
            finally
            {
                SetRecords(output);
                SetRunEnabled(true);
            }
        });
        t.IsBackground = true;
        t.Start();
    }

    void CopyButton_Click(object sender, EventArgs e)
    {
        Clipboard.SetText(BuildLog(records));
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
        if (e.RowIndex >= 0 && e.RowIndex < records.Count)
            detailsBox.Text = FormatRecord(records[e.RowIndex]);
    }

    void Grid_CellFormatting(object sender, DataGridViewCellFormattingEventArgs e)
    {
        if (e.RowIndex < 0 || e.RowIndex >= records.Count) return;
        string sev = records[e.RowIndex].Severity;
        if (sev == "High") grid.Rows[e.RowIndex].DefaultCellStyle.BackColor = Color.FromArgb(254, 226, 226);
        else if (sev == "Warning") grid.Rows[e.RowIndex].DefaultCellStyle.BackColor = Color.FromArgb(255, 247, 237);
        else if (sev == "OK") grid.Rows[e.RowIndex].DefaultCellStyle.BackColor = Color.FromArgb(240, 253, 244);
        else grid.Rows[e.RowIndex].DefaultCellStyle.BackColor = Color.White;
    }

    void SetRunEnabled(bool value)
    {
        if (InvokeRequired) { Invoke(new Action<bool>(SetRunEnabled), value); return; }
        runButton.Enabled = value;
    }

    void SetRecords(List<ArtifactRecord> list)
    {
        if (InvokeRequired) { Invoke(new Action<List<ArtifactRecord>>(SetRecords), list); return; }
        records = list;
        grid.Rows.Clear();
        int high = 0, warn = 0, ok = 0, info = 0;
        foreach (ArtifactRecord r in records)
        {
            if (r.Severity == "High") high++;
            else if (r.Severity == "Warning") warn++;
            else if (r.Severity == "OK") ok++;
            else info++;
            grid.Rows.Add(r.Severity, r.Source, r.Time, r.Action, r.Path, r.Exists, r.Running, r.HashMatch, r.Sha256, r.Signature, r.Signer, r.PE);
        }
        summaryLabel.Text = "Done | High: " + high + " Warning: " + warn + " OK: " + ok + " Info: " + info;
        if (records.Count > 0) detailsBox.Text = FormatRecord(records[0]);
    }

    static bool IsAdmin()
    {
        WindowsIdentity id = WindowsIdentity.GetCurrent();
        WindowsPrincipal p = new WindowsPrincipal(id);
        return p.IsInRole(WindowsBuiltInRole.Administrator);
    }

    HashSet<string> LoadTrustedHashes()
    {
        HashSet<string> set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            string path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "trusted_hashes.txt");
            if (!File.Exists(path)) return set;
            string[] lines = File.ReadAllLines(path);
            foreach (string raw in lines)
            {
                string line = raw.Trim();
                if (line.Length == 0 || line.StartsWith("#")) continue;
                string[] parts = line.Split(new char[] { ' ', '\t', ',', ';' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length > 0 && parts[0].Length == 64) set.Add(parts[0]);
            }
        }
        catch { }
        return set;
    }

    HashSet<string> BuildRunningPathSet()
    {
        HashSet<string> set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (Process p in Process.GetProcesses())
        {
            try
            {
                string path = p.MainModule.FileName;
                if (!String.IsNullOrEmpty(path)) set.Add(Norm(path));
            }
            catch { }
        }
        return set;
    }

    void CollectRunningProcesses(List<ArtifactRecord> output)
    {
        foreach (Process p in Process.GetProcesses())
        {
            try
            {
                string path = p.MainModule.FileName;
                ArtifactRecord r = BuildRecordFromPath("Running Process", path, "Running", "PID: " + p.Id + "\r\nProcess: " + p.ProcessName, "OK");
                output.Add(r);
            }
            catch
            {
                ArtifactRecord r = new ArtifactRecord();
                r.Source = "Running Process";
                r.Severity = "Info";
                r.Time = DateTime.Now.ToString();
                r.Action = "Access denied";
                r.Path = p.ProcessName;
                r.Exists = "Unknown";
                r.Running = "Yes";
                r.HashMatch = "Unavailable";
                r.Signature = "Unavailable";
                r.Evidence = "Could not read MainModule for PID: " + p.Id;
                output.Add(r);
            }
        }
    }

    void CollectPrefetchFiles(List<ArtifactRecord> output)
    {
        string dir = Path.Combine(Environment.GetEnvironmentVariable("WINDIR"), "Prefetch");
        if (!Directory.Exists(dir)) { output.Add(MakeError("Prefetch", "Folder not found: " + dir)); return; }
        FileInfo[] files = new DirectoryInfo(dir).GetFiles("*.pf");
        output.Add(MakeInfo("Prefetch", "Found .pf files: " + files.Length + "\r\nFolder: " + dir));
        foreach (FileInfo f in files)
        {
            string sev = "OK";
            string action = "Existing Prefetch";
            string ev = "Prefetch file metadata.";
            if (f.Length == 0) { sev = "Warning"; action = "Suspicious Prefetch"; ev += "\r\nZero-byte file."; }
            if (f.LastWriteTime < f.CreationTime.AddMinutes(-2)) { sev = "Warning"; action = "Possible timestomp"; ev += "\r\nModified time is earlier than creation time."; }
            ArtifactRecord r = BuildRecordFromPath("Prefetch", f.FullName, action, ev, sev);
            output.Add(r);
        }
    }

    void CollectBam(List<ArtifactRecord> output)
    {
        string[] roots = new string[] {
            @"SYSTEM\CurrentControlSet\Services\bam\UserSettings",
            @"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
        };
        foreach (string root in roots)
        {
            try
            {
                RegistryKey baseKey = Registry.LocalMachine.OpenSubKey(root);
                if (baseKey == null) { output.Add(MakeInfo("BAM", "Key not found: HKLM\\" + root)); continue; }
                foreach (string sid in baseKey.GetSubKeyNames())
                {
                    RegistryKey sidKey = baseKey.OpenSubKey(sid);
                    if (sidKey == null) continue;
                    foreach (string valueName in sidKey.GetValueNames())
                    {
                        object val = sidKey.GetValue(valueName);
                        string evidence = "Registry: HKLM\\" + root + "\\" + sid + "\r\nSID: " + sid;
                        byte[] bytes = val as byte[];
                        if (bytes != null && bytes.Length >= 8)
                        {
                            long ft = BitConverter.ToInt64(bytes, 0);
                            try { evidence += "\r\nLast time: " + DateTime.FromFileTimeUtc(ft).ToLocalTime(); } catch { }
                        }
                        string path = valueName;
                        ArtifactRecord r = BuildRecordFromPath("BAM", path, "Execution artifact", evidence, File.Exists(path) ? "OK" : "Warning");
                        output.Add(r);
                    }
                }
            }
            catch (Exception ex)
            {
                output.Add(MakeError("BAM", ex.Message));
            }
        }
    }

    void CollectUserAssist(List<ArtifactRecord> output)
    {
        string root = @"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";
        try
        {
            RegistryKey ua = Registry.CurrentUser.OpenSubKey(root);
            if (ua == null) { output.Add(MakeInfo("UserAssist", "Key not found: HKCU\\" + root)); return; }
            foreach (string guid in ua.GetSubKeyNames())
            {
                RegistryKey count = ua.OpenSubKey(guid + "\\Count");
                if (count == null) continue;
                foreach (string valueName in count.GetValueNames())
                {
                    string decoded = Rot13(valueName);
                    object val = count.GetValue(valueName);
                    byte[] bytes = val as byte[];
                    string evidence = "Registry: HKCU\\" + root + "\\" + guid + "\\Count\r\nEncoded: " + valueName + "\r\nDecoded: " + decoded;
                    if (bytes != null) evidence += "\r\nRaw bytes: " + BytesToHex(bytes, Math.Min(bytes.Length, 64));
                    string path = NormalizeUserAssistPath(decoded);
                    ArtifactRecord r = BuildRecordFromPath("UserAssist", path, "UserAssist entry", evidence, File.Exists(path) ? "OK" : "Info");
                    output.Add(r);
                }
            }
        }
        catch (Exception ex)
        {
            output.Add(MakeError("UserAssist", ex.Message));
        }
    }

    void CollectShimcacheStrings(List<ArtifactRecord> output)
    {
        string keyPath = @"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache";
        try
        {
            RegistryKey key = Registry.LocalMachine.OpenSubKey(keyPath);
            if (key == null) { output.Add(MakeInfo("Shimcache", "Key not found: HKLM\\" + keyPath)); return; }
            object val = key.GetValue("AppCompatCache");
            byte[] data = val as byte[];
            if (data == null) { output.Add(MakeInfo("Shimcache", "AppCompatCache value not found or not binary.")); return; }
            output.Add(MakeInfo("Shimcache", "Raw AppCompatCache bytes: " + data.Length + "\r\nThis lite parser extracts visible UTF-16 path strings, not full OS-specific Shimcache records."));
            List<string> strings = ExtractUnicodePathStrings(data);
            foreach (string s in strings)
            {
                ArtifactRecord r = BuildRecordFromPath("Shimcache", s, "Path string", "Extracted from AppCompatCache binary. Full timestamp parsing requires OS-specific Shimcache parser.", File.Exists(s) ? "OK" : "Info");
                output.Add(r);
            }
        }
        catch (Exception ex)
        {
            output.Add(MakeError("Shimcache", ex.Message));
        }
    }

    void CollectAmcacheStrings(List<ArtifactRecord> output)
    {
        string path = Path.Combine(Environment.GetEnvironmentVariable("WINDIR"), @"AppCompat\Programs\Amcache.hve");
        if (!File.Exists(path)) { output.Add(MakeInfo("Amcache", "Amcache hive not found: " + path)); return; }
        output.Add(BuildRecordFromPath("Amcache", path, "Hive file", "Amcache hive file. Lite parser extracts visible UTF-16 path strings.", "Info"));
        try
        {
            byte[] data = File.ReadAllBytes(path);
            List<string> strings = ExtractUnicodePathStrings(data);
            int limit = Math.Min(strings.Count, 1000);
            output.Add(MakeInfo("Amcache", "Extracted path-like strings: " + strings.Count + "\r\nShowing first: " + limit));
            for (int i = 0; i < limit; i++)
            {
                string s = strings[i];
                ArtifactRecord r = BuildRecordFromPath("Amcache", s, "Path string", "Extracted from Amcache.hve raw hive bytes. Full Amcache parsing should be added with a real hive parser.", File.Exists(s) ? "OK" : "Info");
                output.Add(r);
            }
        }
        catch (Exception ex)
        {
            output.Add(MakeError("Amcache", ex.Message));
        }
    }

    void CollectPrefetchUsn(List<ArtifactRecord> output, int maxRecords, long lookbackBytes)
    {
        try
        {
            string drive = "C:";
            string volumePath = @"\.\" + drive;
            SafeFileHandle volume = CreateFile(volumePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
            if (volume.IsInvalid) { output.Add(MakeError("USN Journal", "Failed to open C: volume. Run as Administrator. Win32: " + Marshal.GetLastWin32Error())); return; }
            USN_JOURNAL_DATA_V0 journal = QueryJournal(volume);
            long startUsn = journal.NextUsn - lookbackBytes;
            if (startUsn < journal.FirstUsn) startUsn = journal.FirstUsn;
            output.Add(MakeInfo("USN Journal", "Journal ID: " + journal.UsnJournalID + "\r\nFirst USN: " + journal.FirstUsn + "\r\nNext USN: " + journal.NextUsn + "\r\nStart USN: " + startUsn));
            ReadUsn(volume, journal, startUsn, maxRecords, output);
            volume.Close();
        }
        catch (Exception ex)
        {
            output.Add(MakeError("USN Journal", ex.ToString()));
        }
    }

    USN_JOURNAL_DATA_V0 QueryJournal(SafeFileHandle volume)
    {
        int size = Marshal.SizeOf(typeof(USN_JOURNAL_DATA_V0));
        IntPtr outBuffer = Marshal.AllocHGlobal(size);
        try
        {
            int bytesReturned;
            bool ok = DeviceIoControl(volume, FSCTL_QUERY_USN_JOURNAL, IntPtr.Zero, 0, outBuffer, size, out bytesReturned, IntPtr.Zero);
            if (!ok) throw new Exception("FSCTL_QUERY_USN_JOURNAL failed. Win32: " + Marshal.GetLastWin32Error());
            return (USN_JOURNAL_DATA_V0)Marshal.PtrToStructure(outBuffer, typeof(USN_JOURNAL_DATA_V0));
        }
        finally { Marshal.FreeHGlobal(outBuffer); }
    }

    void ReadUsn(SafeFileHandle volume, USN_JOURNAL_DATA_V0 journal, long startUsn, int maxRecords, List<ArtifactRecord> output)
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
        int seen = 0;
        try
        {
            while (seen < maxRecords)
            {
                Marshal.StructureToPtr(readData, inputBuffer, false);
                int bytesReturned;
                bool ok = DeviceIoControl(volume, FSCTL_READ_USN_JOURNAL, inputBuffer, inputSize, outputBuffer, BUFFER_SIZE, out bytesReturned, IntPtr.Zero);
                if (!ok)
                {
                    int err = Marshal.GetLastWin32Error();
                    if (err == 38) break;
                    throw new Exception("FSCTL_READ_USN_JOURNAL failed. Win32: " + err);
                }
                if (bytesReturned <= 8) break;
                long nextUsn = Marshal.ReadInt64(outputBuffer);
                int offset = 8;
                while (offset < bytesReturned && seen < maxRecords)
                {
                    int len = Marshal.ReadInt32(outputBuffer, offset);
                    if (len <= 0 || offset + len > bytesReturned) break;
                    ushort major = (ushort)Marshal.ReadInt16(outputBuffer, offset + 4);
                    UsnHit hit = null;
                    if (major == 2) hit = ParseUsnV2(outputBuffer, offset);
                    else if (major == 3) hit = ParseUsnV3(outputBuffer, offset);
                    if (hit != null)
                    {
                        seen++;
                        if (IsInterestingUsn(hit.Name, hit.Reason))
                            output.Add(BuildUsnRecord(hit));
                    }
                    offset += len;
                }
                if (nextUsn <= readData.StartUsn) break;
                readData.StartUsn = nextUsn;
            }
        }
        finally { Marshal.FreeHGlobal(inputBuffer); Marshal.FreeHGlobal(outputBuffer); }
    }

    UsnHit ParseUsnV2(IntPtr buffer, int offset)
    {
        UsnHit h = new UsnHit();
        h.FileRef = (ulong)Marshal.ReadInt64(buffer, offset + 8);
        h.ParentRef = (ulong)Marshal.ReadInt64(buffer, offset + 16);
        h.Usn = Marshal.ReadInt64(buffer, offset + 24);
        h.Time = DateTime.FromFileTimeUtc(Marshal.ReadInt64(buffer, offset + 32)).ToLocalTime();
        h.Reason = (uint)Marshal.ReadInt32(buffer, offset + 40);
        ushort nameLen = (ushort)Marshal.ReadInt16(buffer, offset + 56);
        ushort nameOff = (ushort)Marshal.ReadInt16(buffer, offset + 58);
        h.Name = Marshal.PtrToStringUni(AddPtr(buffer, offset + nameOff), nameLen / 2);
        return h;
    }

    UsnHit ParseUsnV3(IntPtr buffer, int offset)
    {
        UsnHit h = new UsnHit();
        h.FileRef = 0;
        h.ParentRef = 0;
        h.Usn = Marshal.ReadInt64(buffer, offset + 40);
        h.Time = DateTime.FromFileTimeUtc(Marshal.ReadInt64(buffer, offset + 48)).ToLocalTime();
        h.Reason = (uint)Marshal.ReadInt32(buffer, offset + 56);
        ushort nameLen = (ushort)Marshal.ReadInt16(buffer, offset + 72);
        ushort nameOff = (ushort)Marshal.ReadInt16(buffer, offset + 74);
        h.Name = Marshal.PtrToStringUni(AddPtr(buffer, offset + nameOff), nameLen / 2);
        return h;
    }

    bool IsInterestingUsn(string name, uint reason)
    {
        if (String.IsNullOrEmpty(name)) return false;
        string u = name.ToUpperInvariant();
        bool artifact = u.EndsWith(".PF") || u.EndsWith(".EXE") || u.EndsWith(".DLL") || u.EndsWith(".SYS") || u.EndsWith(".BAT") || u.EndsWith(".CMD") || u.EndsWith(".PS1") || u == "PREFETCH";
        bool change = (reason & (0x00000001 | 0x00000002 | 0x00000004 | 0x00000200 | 0x00001000 | 0x00002000 | 0x00008000)) != 0;
        return artifact && change;
    }

    ArtifactRecord BuildUsnRecord(UsnHit hit)
    {
        string path = hit.Name;
        if (!String.IsNullOrEmpty(hit.Name) && hit.Name.ToUpperInvariant().EndsWith(".PF"))
            path = Path.Combine(Environment.GetEnvironmentVariable("WINDIR"), "Prefetch", hit.Name);
        ArtifactRecord r = BuildRecordFromPath("USN Journal", path, UsnAction(hit.Reason), "Name: " + hit.Name + "\r\nUSN: " + hit.Usn + "\r\nFileRef: " + hit.FileRef + "\r\nParentRef: " + hit.ParentRef + "\r\nReason: " + ReasonToString(hit.Reason) + "\r\nUSN stores filename/reference. Full path may be inferred or unavailable after deletion.", UsnSeverity(hit.Reason));
        r.Time = hit.Time.ToString();
        return r;
    }

    ArtifactRecord BuildRecordFromPath(string source, string path, string action, string evidence, string severity)
    {
        ArtifactRecord r = new ArtifactRecord();
        r.Source = source;
        r.Severity = severity;
        r.Time = DateTime.Now.ToString();
        r.Action = action;
        r.Path = path;
        r.Evidence = evidence;
        r.HashMatch = trustedHashes.Count == 0 ? "No baseline" : "No hash";
        r.Signature = "Unavailable";
        r.Signer = "Unavailable";
        r.Exists = "No";
        r.Running = runningPaths.Contains(Norm(path)) ? "Yes" : "No";

        try
        {
            if (!String.IsNullOrEmpty(path) && File.Exists(path))
            {
                FileInfo fi = new FileInfo(path);
                r.Exists = "Yes";
                r.Size = fi.Length.ToString();
                r.Created = fi.CreationTime.ToString();
                r.Modified = fi.LastWriteTime.ToString();
                r.Accessed = fi.LastAccessTime.ToString();
                r.Sha256 = Sha256(path);
                if (trustedHashes.Count == 0) r.HashMatch = "No baseline";
                else r.HashMatch = trustedHashes.Contains(r.Sha256) ? "Match" : "No match";
                FillVersionInfo(r, path);
                FillSignature(r, path);
                r.PE = PeInfo(path);
            }
            else if (!String.IsNullOrEmpty(path) && Directory.Exists(path))
            {
                r.Exists = "Folder";
            }
        }
        catch (Exception ex)
        {
            r.Evidence += "\r\nVerification error: " + ex.Message;
        }
        return r;
    }

    void FillVersionInfo(ArtifactRecord r, string path)
    {
        try
        {
            FileVersionInfo vi = FileVersionInfo.GetVersionInfo(path);
            r.Company = Safe(vi.CompanyName);
            r.FileVersion = Safe(vi.FileVersion);
            r.Product = Safe(vi.ProductName);
        }
        catch { }
    }

    void FillSignature(ArtifactRecord r, string path)
    {
        try
        {
            X509Certificate cert = X509Certificate.CreateFromSignedFile(path);
            X509Certificate2 cert2 = new X509Certificate2(cert);
            r.Signature = "Signed";
            r.Signer = cert2.Subject;
        }
        catch
        {
            r.Signature = "Unsigned";
            r.Signer = "None";
        }
    }

    string Sha256(string path)
    {
        using (FileStream fs = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
        using (SHA256Managed sha = new SHA256Managed())
        {
            byte[] hash = sha.ComputeHash(fs);
            StringBuilder sb = new StringBuilder();
            foreach (byte b in hash) sb.Append(b.ToString("X2"));
            return sb.ToString();
        }
    }

    string PeInfo(string path)
    {
        try
        {
            using (FileStream fs = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            using (BinaryReader br = new BinaryReader(fs))
            {
                if (fs.Length < 0x40) return "Not PE";
                if (br.ReadUInt16() != 0x5A4D) return "Not PE";
                fs.Seek(0x3C, SeekOrigin.Begin);
                int peOff = br.ReadInt32();
                if (peOff <= 0 || peOff > fs.Length - 24) return "Bad PE";
                fs.Seek(peOff, SeekOrigin.Begin);
                if (br.ReadUInt32() != 0x00004550) return "Bad PE";
                ushort machine = br.ReadUInt16();
                ushort sections = br.ReadUInt16();
                uint timestamp = br.ReadUInt32();
                fs.Seek(12, SeekOrigin.Current);
                ushort optSize = br.ReadUInt16();
                br.ReadUInt16();
                long optStart = fs.Position;
                ushort magic = br.ReadUInt16();
                string arch = machine == 0x8664 ? "x64" : (machine == 0x14c ? "x86" : "Machine 0x" + machine.ToString("X"));
                string peKind = magic == 0x20B ? "PE32+" : (magic == 0x10B ? "PE32" : "Optional 0x" + magic.ToString("X"));
                DateTime ts = new DateTime(1970,1,1,0,0,0,DateTimeKind.Utc).AddSeconds(timestamp).ToLocalTime();
                return arch + " " + peKind + " Sections:" + sections + " LinkTime:" + ts;
            }
        }
        catch { return "Unavailable"; }
    }

    List<string> ExtractUnicodePathStrings(byte[] data)
    {
        List<string> list = new List<string>();
        HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < data.Length - 1; i += 2)
        {
            char c = BitConverter.ToChar(data, i);
            if (c >= 32 && c < 127) sb.Append(c);
            else
            {
                AddExtractedIfPath(sb.ToString(), list, seen);
                sb.Length = 0;
            }
        }
        AddExtractedIfPath(sb.ToString(), list, seen);
        return list;
    }

    void AddExtractedIfPath(string s, List<string> list, HashSet<string> seen)
    {
        if (String.IsNullOrEmpty(s) || s.Length < 6) return;
        string u = s.ToUpperInvariant();
        bool looks = u.Contains("\\") && (u.Contains(".EXE") || u.Contains(".DLL") || u.Contains(".SYS") || u.Contains(".BAT") || u.Contains(".CMD") || u.Contains(".PS1"));
        if (!looks) return;
        int start = FindPathStart(s);
        if (start > 0) s = s.Substring(start);
        s = s.Trim('\0', ' ', '\t', '\r', '\n');
        if (s.Length > 260) s = s.Substring(0, 260);
        if (!seen.Contains(s)) { seen.Add(s); list.Add(s); }
    }

    int FindPathStart(string s)
    {
        for (int i = 0; i < s.Length - 2; i++)
        {
            if (((s[i] >= 'A' && s[i] <= 'Z') || (s[i] >= 'a' && s[i] <= 'z')) && s[i+1] == ':' && s[i+2] == '\\') return i;
        }
        int idx = s.IndexOf(@"\Device\");
        if (idx >= 0) return idx;
        idx = s.IndexOf(@"\??\");
        if (idx >= 0) return idx;
        return 0;
    }

    string NormalizeUserAssistPath(string decoded)
    {
        if (String.IsNullOrEmpty(decoded)) return decoded;
        string s = decoded;
        s = s.Replace("{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\", "");
        s = s.Replace("{F38BF404-1D43-42F2-9305-67DE0B28FC23}", Environment.GetEnvironmentVariable("WINDIR"));
        s = s.Replace("{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}", Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
        return s;
    }

    string Rot13(string input)
    {
        char[] arr = input.ToCharArray();
        for (int i = 0; i < arr.Length; i++)
        {
            char c = arr[i];
            if (c >= 'a' && c <= 'z') arr[i] = (char)('a' + ((c - 'a' + 13) % 26));
            else if (c >= 'A' && c <= 'Z') arr[i] = (char)('A' + ((c - 'A' + 13) % 26));
        }
        return new string(arr);
    }

    string BytesToHex(byte[] bytes, int count)
    {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < count; i++) sb.Append(bytes[i].ToString("X2"));
        return sb.ToString();
    }

    string Norm(string p)
    {
        if (String.IsNullOrEmpty(p)) return "";
        try { return Path.GetFullPath(p).TrimEnd('\\'); } catch { return p.TrimEnd('\\'); }
    }

    string Safe(string s) { return String.IsNullOrEmpty(s) ? "" : s; }

    IntPtr AddPtr(IntPtr ptr, int offset) { return new IntPtr(ptr.ToInt64() + offset); }

    string UsnSeverity(uint reason)
    {
        if ((reason & 0x00000200) != 0) return "High";
        if ((reason & (0x00008000 | 0x00001000 | 0x00002000 | 0x00000001 | 0x00000002 | 0x00000004)) != 0) return "Warning";
        return "Info";
    }

    string UsnAction(uint reason)
    {
        if ((reason & 0x00000200) != 0) return "Deleted";
        if ((reason & (0x00001000 | 0x00002000)) != 0) return "Renamed";
        if ((reason & 0x00008000) != 0) return "Timestamp/metadata changed";
        if ((reason & (0x00000001 | 0x00000002 | 0x00000004)) != 0) return "Content changed";
        return "Changed";
    }

    string ReasonToString(uint reason)
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
        AddReason(sb, reason, 0x80000000, "CLOSE");
        return sb.Length == 0 ? "0x" + reason.ToString("X8") : sb.ToString().TrimEnd('|');
    }

    void AddReason(StringBuilder sb, uint reason, uint flag, string name)
    {
        if ((reason & flag) != 0) sb.Append(name).Append("|");
    }

    ArtifactRecord MakeInfo(string source, string evidence)
    {
        ArtifactRecord r = new ArtifactRecord();
        r.Severity = "Info";
        r.Source = source;
        r.Time = DateTime.Now.ToString();
        r.Action = "Info";
        r.Path = "N/A";
        r.Exists = "N/A";
        r.Running = "N/A";
        r.HashMatch = "N/A";
        r.Signature = "N/A";
        r.Signer = "N/A";
        r.Evidence = evidence;
        return r;
    }

    ArtifactRecord MakeError(string source, string evidence)
    {
        ArtifactRecord r = MakeInfo(source, evidence);
        r.Severity = "High";
        r.Action = "Error";
        return r;
    }

    string FormatRecord(ArtifactRecord r)
    {
        StringBuilder sb = new StringBuilder();
        sb.AppendLine("Severity:    " + r.Severity);
        sb.AppendLine("Source:      " + r.Source);
        sb.AppendLine("Time:        " + r.Time);
        sb.AppendLine("Action:      " + r.Action);
        sb.AppendLine("Path:        " + r.Path);
        sb.AppendLine("Exists:      " + r.Exists);
        sb.AppendLine("Running:     " + r.Running);
        sb.AppendLine("Hash Match:  " + r.HashMatch);
        sb.AppendLine("SHA256:      " + r.Sha256);
        sb.AppendLine("Signature:   " + r.Signature);
        sb.AppendLine("Signer:      " + r.Signer);
        sb.AppendLine("Company:     " + r.Company);
        sb.AppendLine("Product:     " + r.Product);
        sb.AppendLine("Version:     " + r.FileVersion);
        sb.AppendLine("Size:        " + r.Size);
        sb.AppendLine("Created:     " + r.Created);
        sb.AppendLine("Modified:    " + r.Modified);
        sb.AppendLine("Accessed:    " + r.Accessed);
        sb.AppendLine("PE:          " + r.PE);
        sb.AppendLine();
        sb.AppendLine("Evidence:");
        sb.AppendLine(r.Evidence);
        return sb.ToString();
    }

    string BuildLog(List<ArtifactRecord> list)
    {
        StringBuilder sb = new StringBuilder();
        sb.AppendLine("Client Anti-Cheat Forensics Viewer Log");
        sb.AppendLine("Generated: " + DateTime.Now);
        sb.AppendLine("Records: " + list.Count);
        sb.AppendLine();
        foreach (ArtifactRecord r in list)
        {
            sb.AppendLine("------------------------------------------------------------");
            sb.AppendLine(FormatRecord(r));
        }
        return sb.ToString();
    }
}
