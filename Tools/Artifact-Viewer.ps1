# ===============================
# STEP 3 – ARTIFACT REVIEW (UI)
# ===============================
$ErrorActionPreference = 'SilentlyContinue'
$script:DarkModeEnabled = $true
$script:SignatureCache = @{}
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Update-RealLoadingBar {
    param([int]$Current,[int]$Total)
    if ($Total -le 0) { $Total = 1 }
    $percent = [math]::Floor(($Current / $Total) * 100)
    if ($percent -lt 0) { $percent = 0 }
    if ($percent -gt 100) { $percent = 100 }
    $filled = [math]::Floor($percent / 5)
    if ($filled -lt 0) { $filled = 0 }
    if ($filled -gt 20) { $filled = 20 }
    $bar = ("#" * $filled) + ("-" * (20 - $filled))
    Write-Host "`r[ $bar ] $percent%" -NoNewline
}

function Format-ElapsedTime {
    param([datetime]$FromTime)
    $span = (Get-Date) - $FromTime
    if ($span.TotalSeconds -lt 60) { return "$([math]::Floor($span.TotalSeconds)) seconds ago" }
    elseif ($span.TotalMinutes -lt 60) { return "$([math]::Floor($span.TotalMinutes)) minutes ago" }
    elseif ($span.TotalHours -lt 24) { return "$([math]::Floor($span.TotalHours)) hours ago" }
    else { return "$([math]::Floor($span.TotalDays)) days ago" }
}

function Get-NonDefaultRegistryProps {
    param([string]$Path)
    try {
        $props = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
        if (-not $props) { return @() }
        return @($props.PSObject.Properties | Where-Object {
            $_.Name -notlike 'PS*' -and
            $_.Name -ne '(default)' -and
            $_.Name -ne 'LangID' -and
            $_.Name -ne 'MRUList' -and
            $_.Value -ne $null -and
            "$($_.Value)".Trim() -ne ''
        })
    } catch { return @() }
}

function Resolve-PathFromText {
    param([string]$Text)
    if (-not $Text) { return "" }
    if ($Text -match '([A-Za-z]:\\[^`"''\r\n]+?\.(exe|dll|cpl|msc|bat|ps1|lnk))') { return $matches[1] }
    if ($Text -match '^([A-Za-z]:\\.*)$') { return $matches[1] }
    return ""
}

function Resolve-MuiPath {
    param([string]$EntryName,[string]$EntryValue)
    foreach ($candidate in @($EntryName,$EntryValue)) {
        $resolved = Resolve-PathFromText -Text $candidate
        if ($resolved) { return $resolved }
    }
    return ""
}

function Resolve-BamPath {
    param([string]$RawPath)
    if (-not $RawPath) { return "" }
    if ($RawPath -match '^\\Device\\HarddiskVolume\d+\\(.+)$') {
        $remaining = $matches[1]
        try {
            $drives = Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue | Where-Object { $_.Root -match '^[A-Za-z]:\\$' }
            foreach ($drive in $drives) {
                $candidate = Join-Path $drive.Root $remaining
                if (Test-Path $candidate) { return $candidate }
            }
        } catch {}
        if ($env:SystemDrive) { return (Join-Path ($env:SystemDrive + "\") $remaining) }
    }
    if ($RawPath -match '^[A-Za-z]:\\') { return $RawPath }
    return $RawPath
}

function Get-SignatureState {
    param([string]$FilePath)
    if (-not $FilePath) { return "N/A" }
    try { $FilePath = [System.IO.Path]::GetFullPath($FilePath) } catch {}
    if (-not (Test-Path -LiteralPath $FilePath)) { return "N/A" }
    try {
        $item = Get-Item -LiteralPath $FilePath -ErrorAction SilentlyContinue
        if (-not $item -or $item.PSIsContainer) { return "N/A" }
        $cacheKey = "$($item.FullName.ToLowerInvariant())|$($item.LastWriteTimeUtc.Ticks)|$($item.Length)"
        if ($script:SignatureCache.ContainsKey($cacheKey)) { return $script:SignatureCache[$cacheKey] }
        $sig = Get-AuthenticodeSignature -LiteralPath $item.FullName -ErrorAction SilentlyContinue
        $state = "Invalid"
        if ($sig -and $sig.Status -eq "Valid") { $state = "Valid" }
        $script:SignatureCache[$cacheKey] = $state
        if ($script:SignatureCache.Count -gt 2500) { $script:SignatureCache.Clear() }
        return $state
    } catch { return "Invalid" }
}

function Get-SignatureSortOrder {
    param([string]$Signature)
    switch ($Signature) {
        "Invalid" { return 0 }
        "Valid" { return 1 }
        "N/A" { return 2 }
        default { return 3 }
    }
}

function Get-BamSignatureSortOrder {
    param([string]$Signature)
    switch ($Signature) {
        "Invalid" { return 0 }
        "N/A" { return 1 }
        "Valid" { return 2 }
        default { return 3 }
    }
}

function Get-QuickReviewSeverityFromSignature {
    param([string]$Signature)
    if (-not $Signature -or $Signature -eq "No Signature Field") { $Signature = "N/A" }
    switch ($Signature) {
        "Invalid" { return "High Review" }
        "N/A" { return "Review" }
        "Valid" { return "Info" }
        default { return "Info" }
    }
}

function Get-QuickReviewSeverityFromChange {
    param([string]$Change,[string]$Signature)
    if ($Change -eq "Removed") { return "High Review" }
    if ($Change -eq "Changed") { return "Review" }
    if ($Change -eq "Added") {
        if ($Signature -eq "Invalid") { return "High Review" }
        if ($Signature -eq "N/A" -or $Signature -eq "Processing") { return "Review" }
        return "New"
    }
    return (Get-QuickReviewSeverityFromSignature -Signature $Signature)
}

function Add-QuickReviewRow {
    param([ref]$ListRef,[int]$SortOrder,[string]$Section,[string]$Severity,[string]$Signature,[string]$Artifact,[string]$Application,[string]$Path,[string]$Time,[string]$Detail)
    if (-not $Signature -or $Signature -eq "No Signature Field") { $Signature = "N/A" }
    if (-not $Severity) { $Severity = Get-QuickReviewSeverityFromSignature -Signature $Signature }
    $ListRef.Value += [PSCustomObject]@{
        SortOrder = $SortOrder
        Section = $Section
        Severity = $Severity
        Signature = $Signature
        Artifact = $Artifact
        Application = $Application
        Path = $Path
        Time = $Time
        Detail = $Detail
    }
}

function Get-RegistryTree {
    param([string]$RootPath)
    $items = @()
    if (-not (Test-Path $RootPath)) { return @() }
    try {
        $items += Get-Item -Path $RootPath -ErrorAction SilentlyContinue
        $items += Get-ChildItem -Path $RootPath -Recurse -ErrorAction SilentlyContinue
    } catch {}
    return @($items)
}

function Get-PathArtifactEntries {
    param([string]$RegistryPath,[string]$ArtifactLabel)
    $results = @()
    if (-not (Test-Path $RegistryPath)) { return @() }
    try {
        $props = Get-NonDefaultRegistryProps -Path $RegistryPath
        foreach ($prop in $props) {
            $nameText = [string]$prop.Name
            $valueText = [string]$prop.Value
            $foundPath = Resolve-PathFromText -Text $nameText
            if (-not $foundPath) { $foundPath = Resolve-PathFromText -Text $valueText }
            if ($foundPath) {
                $sig = Get-SignatureState -FilePath $foundPath
                $results += [PSCustomObject]@{
                    SortOrder = Get-SignatureSortOrder -Signature $sig
                    Signature = $sig
                    Name = $nameText
                    Path = $foundPath
                    Artifact = $ArtifactLabel
                }
            }
        }
    } catch {}
    return @($results | Sort-Object SortOrder, Name -Unique)
}

function Get-FeatureUsageEntries {
    param([string]$RegistryPath,[string]$ArtifactLabel)
    $results = @()
    if (-not (Test-Path $RegistryPath)) { return @() }
    try {
        $props = Get-NonDefaultRegistryProps -Path $RegistryPath
        foreach ($prop in $props) {
            $nameText = [string]$prop.Name
            $valueText = ""
            try {
                if ($prop.Value -is [System.Array]) { $valueText = ($prop.Value -join ",") }
                else { $valueText = [string]$prop.Value }
            } catch { $valueText = "" }
            $foundPath = Resolve-PathFromText -Text $nameText
            if (-not $foundPath) { $foundPath = Resolve-PathFromText -Text $valueText }
            $pathGroup = 1
            $sig = "N/A"
            $sort = 9
            if ($foundPath) {
                $pathGroup = 0
                $sig = Get-SignatureState -FilePath $foundPath
                $sort = Get-SignatureSortOrder -Signature $sig
            }
            $results += [PSCustomObject]@{
                PathGroup = $pathGroup
                SortOrder = $sort
                Signature = $sig
                Name = $nameText
                Path = $foundPath
                Value = $valueText
                Artifact = $ArtifactLabel
            }
        }
    } catch {}
    return @($results | Sort-Object PathGroup, SortOrder, Name -Unique)
}


function Format-WrappedCellText {
    param([string]$Text,[string]$ColumnName,[int]$MaxLineLength = 58)
    if ($null -eq $Text) { return "" }
    $rawText = [string]$Text
    if ($rawText.Length -le $MaxLineLength) { return $rawText }

    $longColumns = @("Path","AppPath","Detail","Value","Name","Entry","Item","Sources","Application","AppName","EventName","Report","Reason","Match","Section")
    if ($longColumns -notcontains $ColumnName) { return $rawText }

    $resultLines = New-Object System.Collections.Generic.List[string]
    foreach ($baseLine in ($rawText -split "`r?`n")) {
        $line = [string]$baseLine
        while ($line.Length -gt $MaxLineLength) {
            $cut = -1
            $searchLength = [math]::Min($MaxLineLength, $line.Length - 1)
            for ($i = $searchLength; $i -ge 28; $i--) {
                $ch = $line[$i]
                if ($ch -eq '\' -or $ch -eq '/' -or $ch -eq ' ' -or $ch -eq ',' -or $ch -eq ';') {
                    $cut = $i
                    break
                }
            }
            if ($cut -lt 28) { $cut = $searchLength }
            if ($line[$cut] -eq '\' -or $line[$cut] -eq '/') {
                $resultLines.Add($line.Substring(0, $cut + 1))
                $line = $line.Substring($cut + 1)
            } else {
                $resultLines.Add($line.Substring(0, $cut + 1).TrimEnd())
                $line = $line.Substring($cut + 1).TrimStart()
            }
        }
        $resultLines.Add($line)
    }
    return ($resultLines -join [Environment]::NewLine)
}

function ConvertTo-DataTable {
    param([object[]]$Data,[string[]]$Columns)
    $table = New-Object System.Data.DataTable
    foreach ($col in $Columns) { [void]$table.Columns.Add($col) }
    if ($Data) {
        foreach ($item in $Data) {
            $row = $table.NewRow()
            foreach ($col in $Columns) {
                $value = ""
                if ($null -ne $item -and $item.PSObject.Properties[$col]) { $value = $item.$col }
                $displayValue = if ($null -eq $value) { "" } else { [string]$value }
                $row[$col] = Format-WrappedCellText -Text $displayValue -ColumnName $col
            }
            [void]$table.Rows.Add($row)
        }
    }
    Write-Output -NoEnumerate $table
}

function Enable-DoubleBuffer {
    param([object]$Control)
    try {
        $prop = $Control.GetType().GetProperty("DoubleBuffered", [System.Reflection.BindingFlags] "Instance, NonPublic")
        if ($prop) { $prop.SetValue($Control, $true, $null) }
    } catch {}
}

function New-UIFont {
    param([float]$Size,[switch]$Bold)
    $style = [System.Drawing.FontStyle]::Regular
    if ($Bold) { $style = [System.Drawing.FontStyle]::Bold }
    return New-Object System.Drawing.Font -ArgumentList 'Segoe UI', $Size, $style
}

function Get-ResponsiveFormSize {
    try {
        $screen = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
        $width = [int]($screen.Width * 0.96)
        $height = [int]($screen.Height * 0.92)
        if ($width -lt 1180) { $width = [math]::Max(1000, [int]($screen.Width * 0.98)) }
        if ($height -lt 760) { $height = [math]::Max(680, [int]($screen.Height * 0.95)) }
        if ($width -gt 1850) { $width = 1850 }
        if ($height -gt 1080) { $height = 1080 }
        return New-Object System.Drawing.Size -ArgumentList $width, $height
    } catch { return New-Object System.Drawing.Size -ArgumentList 1600, 950 }
}

function New-DataGrid {
    param([object]$DataTable)
    $grid = New-Object System.Windows.Forms.DataGridView
    $grid.Dock = 'Fill'
    $grid.ReadOnly = $true
    $grid.AllowUserToAddRows = $false
    $grid.AllowUserToDeleteRows = $false
    $grid.AllowUserToResizeRows = $false
    $grid.AllowUserToResizeColumns = $true
    $grid.MultiSelect = $false
    $grid.SelectionMode = 'FullRowSelect'
    $grid.RowHeadersVisible = $false
    $grid.AutoSizeColumnsMode = 'None'
    $grid.AutoSizeRowsMode = [System.Windows.Forms.DataGridViewAutoSizeRowsMode]::DisplayedCellsExceptHeaders
    $grid.BackgroundColor = [System.Drawing.Color]::White
    $grid.GridColor = [System.Drawing.Color]::LightGray
    $grid.BorderStyle = 'FixedSingle'
    $grid.DefaultCellStyle.Font = New-UIFont -Size 10
    $grid.DefaultCellStyle.WrapMode = [System.Windows.Forms.DataGridViewTriState]::True
    $grid.DefaultCellStyle.Padding = New-Object System.Windows.Forms.Padding -ArgumentList 6, 3, 6, 3
    $grid.DefaultCellStyle.Alignment = [System.Windows.Forms.DataGridViewContentAlignment]::MiddleLeft
    $grid.AlternatingRowsDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(248,248,248)
    $grid.ColumnHeadersDefaultCellStyle.Font = New-UIFont -Size 10 -Bold
    $grid.ColumnHeadersDefaultCellStyle.Alignment = [System.Windows.Forms.DataGridViewContentAlignment]::MiddleLeft
    $grid.ColumnHeadersDefaultCellStyle.Padding = New-Object System.Windows.Forms.Padding -ArgumentList 6, 3, 6, 3
    $grid.EnableHeadersVisualStyles = $false
    $grid.ColumnHeadersHeightSizeMode = 'DisableResizing'
    $grid.ColumnHeadersHeight = 36
    $grid.RowTemplate.Height = 44
    $grid.ClipboardCopyMode = 'EnableAlwaysIncludeHeaderText'
    $grid.VirtualMode = $false
    $grid.ScrollBars = 'Both'
    $grid.ShowCellToolTips = $true
    $grid.DataSource = $DataTable
    $grid.Add_CellToolTipTextNeeded({
        param($sender,$e)
        if ($e.RowIndex -ge 0 -and $e.ColumnIndex -ge 0) {
            try {
                $value = $sender.Rows[$e.RowIndex].Cells[$e.ColumnIndex].Value
                if ($null -ne $value) { $e.ToolTipText = [string]$value }
            } catch {}
        }
    })
    Enable-DoubleBuffer -Control $grid
    return $grid
}

function Set-GridColumnLayout {
    param([System.Windows.Forms.DataGridView]$Grid)
    foreach ($col in $Grid.Columns) {
        $col.SortMode = [System.Windows.Forms.DataGridViewColumnSortMode]::Automatic
        $col.AutoSizeMode = [System.Windows.Forms.DataGridViewAutoSizeColumnMode]::None
        $col.Resizable = [System.Windows.Forms.DataGridViewTriState]::True
        switch ($col.Name) {
            "Section" { $col.Width = 190; $col.MinimumWidth = 150 }
            "Severity" { $col.Width = 135; $col.MinimumWidth = 115 }
            "Reason" { $col.Width = 300; $col.MinimumWidth = 220 }
            "Match" { $col.Width = 180; $col.MinimumWidth = 145 }
            "Signature" { $col.Width = 120; $col.MinimumWidth = 105 }
            "Time" { $col.Width = 175; $col.MinimumWidth = 155 }
            "LastRun" { $col.Width = 175; $col.MinimumWidth = 155 }
            "RelativeTime" { $col.Width = 170; $col.MinimumWidth = 145 }
            "Application" { $col.Width = 300; $col.MinimumWidth = 210 }
            "Entry" { $col.Width = 470; $col.MinimumWidth = 300 }
            "Name" { $col.Width = 470; $col.MinimumWidth = 300 }
            "Artifact" { $col.Width = 230; $col.MinimumWidth = 185 }
            "Path" { $col.Width = 560; $col.MinimumWidth = 360 }
            "AppPath" { $col.Width = 560; $col.MinimumWidth = 360 }
            "Report" { $col.Width = 280; $col.MinimumWidth = 220 }
            "EventName" { $col.Width = 330; $col.MinimumWidth = 245 }
            "AppName" { $col.Width = 300; $col.MinimumWidth = 220 }
            "Metric" { $col.Width = 260; $col.MinimumWidth = 210 }
            "Detail" { $col.Width = 500; $col.MinimumWidth = 320 }
            "Supported" { $col.Width = 115; $col.MinimumWidth = 95 }
            "Enabled" { $col.Width = 140; $col.MinimumWidth = 115 }
            "Cleared" { $col.Width = 145; $col.MinimumWidth = 110 }
            "Status" { $col.Width = 245; $col.MinimumWidth = 185 }
            "Count" { $col.Width = 100; $col.MinimumWidth = 85 }
            "Sources" { $col.Width = 430; $col.MinimumWidth = 300 }
            "Value" { $col.Width = 370; $col.MinimumWidth = 250 }
            "BAM" { $col.Width = 85; $col.MinimumWidth = 70 }
            "Prefetch" { $col.Width = 105; $col.MinimumWidth = 90 }
            "MuICache" { $col.Width = 110; $col.MinimumWidth = 95 }
            "AppCompat" { $col.Width = 120; $col.MinimumWidth = 100 }
            "AppSwitched" { $col.Width = 130; $col.MinimumWidth = 110 }
            "CrashLogs" { $col.Width = 120; $col.MinimumWidth = 100 }
            "Change" { $col.Width = 115; $col.MinimumWidth = 95 }
            "Source" { $col.Width = 230; $col.MinimumWidth = 170 }
            "Item" { $col.Width = 440; $col.MinimumWidth = 290 }
            default { $col.Width = 210; $col.MinimumWidth = 150 }
        }
    }
}

function Resize-GridColumnsToContent {
    param([System.Windows.Forms.DataGridView]$Grid)
    try {
        $gridWidth = [math]::Max(1000, $Grid.ClientSize.Width)
        foreach ($col in $Grid.Columns) {
            $maxLen = [int]$col.HeaderText.Length
            $source = $Grid.DataSource
            if ($source -is [System.Data.DataTable]) {
                foreach ($row in $source.Rows) {
                    try {
                        $text = [string]$row[$col.Name]
                        if ($null -ne $text) {
                            foreach ($line in ($text -split "`r?`n")) {
                                if ($line.Length -gt $maxLen) { $maxLen = $line.Length }
                            }
                        }
                    } catch {}
                }
            }
            $wanted = ($maxLen * 7) + 42
            $cap = 520
            $isMonitoringGrid = ($Grid.Tag -eq "Monitoring")
            switch ($col.Name) {
                "Section" { $cap = 230 }
                "Path" { $cap = [math]::Max(400, [math]::Floor($gridWidth * 0.38)) }
                "AppPath" { $cap = [math]::Max(400, [math]::Floor($gridWidth * 0.38)) }
                "Detail" { $cap = [math]::Max(380, [math]::Floor($gridWidth * 0.36)) }
                "Value" { $cap = [math]::Max(340, [math]::Floor($gridWidth * 0.32)) }
                "Entry" { $cap = [math]::Max(360, [math]::Floor($gridWidth * 0.34)) }
                "Name" { $cap = [math]::Max(360, [math]::Floor($gridWidth * 0.34)) }
                "Item" { $cap = [math]::Max(360, [math]::Floor($gridWidth * 0.36)) }
                "Sources" { $cap = [math]::Max(330, [math]::Floor($gridWidth * 0.32)) }
                "Application" { $cap = [math]::Max(280, [math]::Floor($gridWidth * 0.28)) }
                "AppName" { $cap = [math]::Max(280, [math]::Floor($gridWidth * 0.28)) }
                "EventName" { $cap = [math]::Max(300, [math]::Floor($gridWidth * 0.30)) }
                "Report" { $cap = [math]::Max(260, [math]::Floor($gridWidth * 0.26)) }
                "Reason" { $cap = [math]::Max(280, [math]::Floor($gridWidth * 0.28)) }
                "Match" { $cap = 260 }
                "Signature" { $cap = 135 }
                "Time" { $cap = 190 }
                "LastRun" { $cap = 190 }
                "RelativeTime" { $cap = 185 }
                "Count" { $cap = 120 }
                "Supported" { $cap = 130 }
                "Enabled" { $cap = 170 }
                "Cleared" { $cap = 170 }
                "BAM" { $cap = 95 }
                "Prefetch" { $cap = 120 }
                "MuICache" { $cap = 130 }
                "AppCompat" { $cap = 140 }
                "AppSwitched" { $cap = 155 }
                "CrashLogs" { $cap = 145 }
            }
            if ($isMonitoringGrid) {
                switch ($col.Name) {
                    "Time" { $cap = 195 }
                    "Change" { $cap = 135 }
                    "Source" { $cap = [math]::Max(230, [math]::Floor($gridWidth * 0.18)) }
                    "Signature" { $cap = 145 }
                    "Item" { $cap = [math]::Max(360, [math]::Floor($gridWidth * 0.30)) }
                    "Detail" { $cap = [math]::Max(440, [math]::Floor($gridWidth * 0.42)) }
                }
            }
            if ($wanted -lt $col.MinimumWidth) { $wanted = $col.MinimumWidth }
            if ($wanted -gt $cap) { $wanted = $cap }
            $col.Width = [int]$wanted
        }
        $Grid.ScrollBars = 'Both'
    } catch {}
}

function Update-ResponsiveStackLayout {
    param([System.Windows.Forms.Panel]$ScrollPanel,[System.Windows.Forms.TableLayoutPanel]$Layout,[int]$SectionCount,[int]$MinimumSectionHeight)
    try {
        $width = [math]::Max(900, $ScrollPanel.ClientSize.Width - 24)
        $availableHeight = [math]::Max(200, $ScrollPanel.ClientSize.Height - 12)
        $neededHeight = [math]::Max($availableHeight, ($SectionCount * $MinimumSectionHeight))
        $Layout.Width = $width
        $Layout.Height = $neededHeight
        $rowHeight = [math]::Floor($neededHeight / $SectionCount)
        for ($i = 0; $i -lt $Layout.RowStyles.Count; $i++) {
            $Layout.RowStyles[$i].SizeType = [System.Windows.Forms.SizeType]::Absolute
            $Layout.RowStyles[$i].Height = $rowHeight
        }
    } catch {}
}

function New-ResponsiveStackPage {
    param([string]$Title,[object[]]$Sections,[int]$MinimumSectionHeight)
    $page = New-Object System.Windows.Forms.TabPage
    $page.Text = $Title
    $scroll = New-Object System.Windows.Forms.Panel
    $scroll.Dock = 'Fill'
    $scroll.AutoScroll = $true
    $scroll.BackColor = [System.Drawing.Color]::White
    $layout = New-Object System.Windows.Forms.TableLayoutPanel
    $layout.Dock = 'None'
    $layout.AutoSize = $false
    $layout.ColumnCount = 1
    $layout.RowCount = $Sections.Count
    $layout.Margin = New-Object System.Windows.Forms.Padding -ArgumentList 0
    $layout.Padding = New-Object System.Windows.Forms.Padding -ArgumentList 0
    $layout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle -ArgumentList ([System.Windows.Forms.SizeType]::Percent), 100)) | Out-Null
    for ($i = 0; $i -lt $Sections.Count; $i++) {
        $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle -ArgumentList ([System.Windows.Forms.SizeType]::Absolute), $MinimumSectionHeight)) | Out-Null
        $panel = New-SectionPanel -Title $Sections[$i].Title -Control $Sections[$i].Control
        $panel.Margin = New-Object System.Windows.Forms.Padding -ArgumentList 0, 0, 0, 8
        $layout.Controls.Add($panel, 0, $i)
    }
    $scroll.Controls.Add($layout)
    $page.Controls.Add($scroll)
    $sectionCount = [int]$Sections.Count
    $minimumHeight = [int]$MinimumSectionHeight
    $resizeHandler = { Update-ResponsiveStackLayout -ScrollPanel $scroll -Layout $layout -SectionCount $sectionCount -MinimumSectionHeight $minimumHeight }.GetNewClosure()
    $scroll.Add_Resize($resizeHandler)
    Update-ResponsiveStackLayout -ScrollPanel $scroll -Layout $layout -SectionCount $sectionCount -MinimumSectionHeight $minimumHeight
    return [PSCustomObject]@{ Page = $page; Layout = $layout; Scroll = $scroll }
}

function Apply-GridFormatting {
    param([System.Windows.Forms.DataGridView]$Grid,[string]$SystemDriveRoot,[datetime]$BootTime)
    $formatSystemDriveRoot = [string]$SystemDriveRoot
    $formatBootTime = [datetime]$BootTime
    $Grid.Add_CellFormatting({
        param($sender,$e)
        if ($e.RowIndex -lt 0 -or $e.ColumnIndex -lt 0) { return }
        $columnName = $sender.Columns[$e.ColumnIndex].Name
        $cellValue = ""
        if ($null -ne $e.Value) { $cellValue = [string]$e.Value }
        if ($script:DarkModeEnabled) {
            $e.CellStyle.ForeColor = [System.Drawing.Color]::Gainsboro
            $e.CellStyle.BackColor = [System.Drawing.Color]::FromArgb(30,30,30)
        } else {
            $e.CellStyle.ForeColor = [System.Drawing.Color]::Black
            $e.CellStyle.BackColor = [System.Drawing.Color]::White
        }
        $prefetchKeywordHit = $false
        try {
            if ((([string]$sender.Tag -eq "Prefetch") -or ([string]$sender.Tag -eq "QuickReview")) -and $script:SuspiciousKeywordRegex) {
                $gridRow = $sender.Rows[$e.RowIndex]
                if ($null -eq $gridRow.Tag) {
                    $rowTextParts = New-Object System.Collections.Generic.List[string]
                    foreach ($gridColumn in $sender.Columns) { [void]$rowTextParts.Add([string]$gridRow.Cells[$gridColumn.Name].Value) }
                    if (($rowTextParts -join " ") -match $script:SuspiciousKeywordRegex) { $gridRow.Tag = "KeywordHit" } else { $gridRow.Tag = "NoKeywordHit" }
                }
                if ([string]$gridRow.Tag -eq "KeywordHit") { $prefetchKeywordHit = $true }
            }
        } catch {}
        if ($prefetchKeywordHit) {
            if ($script:DarkModeEnabled) { $e.CellStyle.BackColor = [System.Drawing.Color]::FromArgb(82,38,60); $e.CellStyle.ForeColor = [System.Drawing.Color]::FromArgb(255,190,220) }
            else { $e.CellStyle.BackColor = [System.Drawing.Color]::FromArgb(255,228,242); $e.CellStyle.ForeColor = [System.Drawing.Color]::MediumVioletRed }
        }
        if ([string]$sender.Tag -eq "Prefetch" -and $columnName -eq "RelativeTime") {
            if ($script:DarkModeEnabled) { $e.CellStyle.BackColor = [System.Drawing.Color]::FromArgb(95,62,12); $e.CellStyle.ForeColor = [System.Drawing.Color]::FromArgb(255,214,120) }
            else { $e.CellStyle.BackColor = [System.Drawing.Color]::FromArgb(255,236,179); $e.CellStyle.ForeColor = [System.Drawing.Color]::DarkOrange }
        }
        if ($columnName -eq "Signature") {
            switch ($cellValue) {
                "Valid" { if ($script:DarkModeEnabled) { $e.CellStyle.BackColor = [System.Drawing.Color]::FromArgb(28,72,40); $e.CellStyle.ForeColor = [System.Drawing.Color]::FromArgb(190,255,200) } else { $e.CellStyle.BackColor = [System.Drawing.Color]::FromArgb(220,255,220); $e.CellStyle.ForeColor = [System.Drawing.Color]::DarkGreen } }
                "N/A" { if ($script:DarkModeEnabled) { $e.CellStyle.BackColor = [System.Drawing.Color]::FromArgb(84,72,20); $e.CellStyle.ForeColor = [System.Drawing.Color]::FromArgb(255,235,150) } else { $e.CellStyle.BackColor = [System.Drawing.Color]::FromArgb(255,249,196); $e.CellStyle.ForeColor = [System.Drawing.Color]::DarkGoldenrod } }
                "Invalid" { if ($script:DarkModeEnabled) { $e.CellStyle.BackColor = [System.Drawing.Color]::FromArgb(90,30,34); $e.CellStyle.ForeColor = [System.Drawing.Color]::FromArgb(255,180,185) } else { $e.CellStyle.BackColor = [System.Drawing.Color]::FromArgb(255,205,210); $e.CellStyle.ForeColor = [System.Drawing.Color]::DarkRed } }
            }
        }
        if ($columnName -eq "Severity") {
            switch ($cellValue) {
                "High Review" { if ($script:DarkModeEnabled) { $e.CellStyle.BackColor = [System.Drawing.Color]::FromArgb(90,30,34); $e.CellStyle.ForeColor = [System.Drawing.Color]::FromArgb(255,180,185) } else { $e.CellStyle.BackColor = [System.Drawing.Color]::FromArgb(255,205,210); $e.CellStyle.ForeColor = [System.Drawing.Color]::DarkRed } }
                "Review" { if ($script:DarkModeEnabled) { $e.CellStyle.BackColor = [System.Drawing.Color]::FromArgb(84,72,20); $e.CellStyle.ForeColor = [System.Drawing.Color]::FromArgb(255,235,150) } else { $e.CellStyle.BackColor = [System.Drawing.Color]::FromArgb(255,249,196); $e.CellStyle.ForeColor = [System.Drawing.Color]::DarkGoldenrod } }
                "New" { if ($script:DarkModeEnabled) { $e.CellStyle.BackColor = [System.Drawing.Color]::FromArgb(24,55,86); $e.CellStyle.ForeColor = [System.Drawing.Color]::FromArgb(180,220,255) } else { $e.CellStyle.BackColor = [System.Drawing.Color]::FromArgb(227,242,253); $e.CellStyle.ForeColor = [System.Drawing.Color]::DarkBlue } }
                "Info" { if ($script:DarkModeEnabled) { $e.CellStyle.BackColor = [System.Drawing.Color]::FromArgb(28,72,40); $e.CellStyle.ForeColor = [System.Drawing.Color]::FromArgb(190,255,200) } else { $e.CellStyle.BackColor = [System.Drawing.Color]::FromArgb(232,245,233); $e.CellStyle.ForeColor = [System.Drawing.Color]::DarkGreen } }
            }
        }
        if ($columnName -eq "Change") {
            switch ($cellValue) {
                "Added" { if ($script:DarkModeEnabled) { $e.CellStyle.BackColor = [System.Drawing.Color]::FromArgb(28,72,40); $e.CellStyle.ForeColor = [System.Drawing.Color]::FromArgb(190,255,200) } else { $e.CellStyle.BackColor = [System.Drawing.Color]::FromArgb(220,255,220); $e.CellStyle.ForeColor = [System.Drawing.Color]::DarkGreen } }
                "Removed" { if ($script:DarkModeEnabled) { $e.CellStyle.BackColor = [System.Drawing.Color]::FromArgb(90,30,34); $e.CellStyle.ForeColor = [System.Drawing.Color]::FromArgb(255,180,185) } else { $e.CellStyle.BackColor = [System.Drawing.Color]::FromArgb(255,205,210); $e.CellStyle.ForeColor = [System.Drawing.Color]::DarkRed } }
                "Changed" { if ($script:DarkModeEnabled) { $e.CellStyle.BackColor = [System.Drawing.Color]::FromArgb(84,72,20); $e.CellStyle.ForeColor = [System.Drawing.Color]::FromArgb(255,235,150) } else { $e.CellStyle.BackColor = [System.Drawing.Color]::FromArgb(255,249,196); $e.CellStyle.ForeColor = [System.Drawing.Color]::DarkGoldenrod } }
                "Opened" { if ($script:DarkModeEnabled) { $e.CellStyle.BackColor = [System.Drawing.Color]::FromArgb(24,55,86); $e.CellStyle.ForeColor = [System.Drawing.Color]::FromArgb(180,220,255) } else { $e.CellStyle.BackColor = [System.Drawing.Color]::FromArgb(227,242,253); $e.CellStyle.ForeColor = [System.Drawing.Color]::DarkBlue } }
            }
        }
        if ($columnName -eq "Path" -or $columnName -eq "AppPath") {
            if ($cellValue -match '^[A-Za-z]:\\') {
                $driveRoot = $cellValue.Substring(0,2).ToLowerInvariant()
                if ($driveRoot -ne $formatSystemDriveRoot.ToLowerInvariant()) {
                    if ($script:DarkModeEnabled) { $e.CellStyle.BackColor = [System.Drawing.Color]::FromArgb(82,38,60); $e.CellStyle.ForeColor = [System.Drawing.Color]::FromArgb(255,190,220) }
                    else { $e.CellStyle.BackColor = [System.Drawing.Color]::FromArgb(255,228,242); $e.CellStyle.ForeColor = [System.Drawing.Color]::MediumVioletRed }
                }
            }
        }
        if ($columnName -eq "RelativeTime" -and $sender.Columns.Contains("LastRun") -and [string]$sender.Tag -ne "Prefetch") {
            try {
                $lastRunText = [string]$sender.Rows[$e.RowIndex].Cells["LastRun"].Value
                $lastRunTime = [datetime]::Parse($lastRunText)
                if ($lastRunTime -lt $formatBootTime) {
                    if ($script:DarkModeEnabled) { $e.CellStyle.BackColor = [System.Drawing.Color]::FromArgb(82,38,60); $e.CellStyle.ForeColor = [System.Drawing.Color]::FromArgb(255,190,220) }
                    else { $e.CellStyle.BackColor = [System.Drawing.Color]::FromArgb(255,228,242); $e.CellStyle.ForeColor = [System.Drawing.Color]::MediumVioletRed }
                }
            } catch {}
        }
    }.GetNewClosure())
}

function New-SectionPanel {
    param([string]$Title,[System.Windows.Forms.Control]$Control)
    $panel = New-Object System.Windows.Forms.Panel
    $panel.Dock = 'Fill'
    $panel.Padding = New-Object System.Windows.Forms.Padding -ArgumentList 8
    $panel.BackColor = [System.Drawing.Color]::White
    $label = New-Object System.Windows.Forms.Label
    $label.Text = $Title
    $label.Dock = 'Top'
    $label.Height = 32
    $label.Font = New-UIFont -Size 11 -Bold
    $label.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
    $panel.Controls.Add($Control)
    $panel.Controls.Add($label)
    return $panel
}

function New-GridPage {
    param([string]$Title,[System.Data.DataTable]$DataTable)
    $page = New-Object System.Windows.Forms.TabPage
    $page.Text = $Title
    $grid = New-DataGrid -DataTable $DataTable
    $panel = New-SectionPanel -Title $Title -Control $grid
    $page.Controls.Add($panel)
    return [PSCustomObject]@{ Page = $page; Grid = $grid }
}

function New-TextPage {
    param([string]$Title,[string]$Text)
    $page = New-Object System.Windows.Forms.TabPage
    $page.Text = $Title
    $box = New-Object System.Windows.Forms.TextBox
    $box.Dock = 'Fill'
    $box.Multiline = $true
    $box.ReadOnly = $true
    $box.ScrollBars = 'Both'
    $box.WordWrap = $false
    $box.Font = New-Object System.Drawing.Font -ArgumentList "Consolas", 10
    $box.Text = $Text
    $panel = New-SectionPanel -Title $Title -Control $box
    $page.Controls.Add($panel)
    return [PSCustomObject]@{ Page = $page; Box = $box }
}


function Apply-ThemeToControl {
    param([object]$Control)
    if (-not $Control) { return }
    $darkBack = [System.Drawing.Color]::FromArgb(22,22,22)
    $darkPanel = [System.Drawing.Color]::FromArgb(30,30,30)
    $darkAlt = [System.Drawing.Color]::FromArgb(38,38,38)
    $darkHeader = [System.Drawing.Color]::FromArgb(44,44,44)
    $darkText = [System.Drawing.Color]::Gainsboro
    $darkGrid = [System.Drawing.Color]::FromArgb(65,65,65)
    $lightBack = [System.Drawing.Color]::White
    $lightPanel = [System.Drawing.Color]::FromArgb(245,245,245)
    $lightAlt = [System.Drawing.Color]::FromArgb(248,248,248)
    $lightText = [System.Drawing.Color]::Black
    if ($script:DarkModeEnabled) {
        if ($Control -is [System.Windows.Forms.Form] -or $Control -is [System.Windows.Forms.TabPage] -or $Control -is [System.Windows.Forms.Panel] -or $Control -is [System.Windows.Forms.TableLayoutPanel]) { $Control.BackColor = $darkBack; $Control.ForeColor = $darkText }
        elseif ($Control -is [System.Windows.Forms.Label]) { $Control.BackColor = [System.Drawing.Color]::Transparent; $Control.ForeColor = $darkText }
        elseif ($Control -is [System.Windows.Forms.CheckBox]) { $Control.BackColor = [System.Drawing.Color]::Transparent; $Control.ForeColor = $darkText }
        elseif ($Control -is [System.Windows.Forms.Button]) { $Control.BackColor = $darkHeader; $Control.ForeColor = $darkText; $Control.FlatStyle = 'Flat' }
        elseif ($Control -is [System.Windows.Forms.TextBox]) { $Control.BackColor = [System.Drawing.Color]::FromArgb(24,24,24); $Control.ForeColor = $darkText }
        elseif ($Control -is [System.Windows.Forms.TabControl]) { $Control.BackColor = $darkBack; $Control.ForeColor = $darkText }
        elseif ($Control -is [System.Windows.Forms.DataGridView]) {
            $Control.BackgroundColor = $darkBack
            $Control.GridColor = $darkGrid
            $Control.ForeColor = $darkText
            $Control.DefaultCellStyle.BackColor = $darkPanel
            $Control.DefaultCellStyle.ForeColor = $darkText
            $Control.DefaultCellStyle.SelectionBackColor = [System.Drawing.Color]::FromArgb(64,84,112)
            $Control.DefaultCellStyle.SelectionForeColor = [System.Drawing.Color]::White
            $Control.AlternatingRowsDefaultCellStyle.BackColor = $darkAlt
            $Control.AlternatingRowsDefaultCellStyle.ForeColor = $darkText
            $Control.ColumnHeadersDefaultCellStyle.BackColor = $darkHeader
            $Control.ColumnHeadersDefaultCellStyle.ForeColor = $darkText
            $Control.RowHeadersDefaultCellStyle.BackColor = $darkHeader
            $Control.RowHeadersDefaultCellStyle.ForeColor = $darkText
            $Control.EnableHeadersVisualStyles = $false
        }
    } else {
        if ($Control -is [System.Windows.Forms.Form] -or $Control -is [System.Windows.Forms.TabPage] -or $Control -is [System.Windows.Forms.Panel] -or $Control -is [System.Windows.Forms.TableLayoutPanel]) { $Control.BackColor = $lightBack; $Control.ForeColor = $lightText }
        elseif ($Control -is [System.Windows.Forms.Label]) { $Control.BackColor = [System.Drawing.Color]::Transparent; $Control.ForeColor = $lightText }
        elseif ($Control -is [System.Windows.Forms.CheckBox]) { $Control.BackColor = [System.Drawing.Color]::Transparent; $Control.ForeColor = $lightText }
        elseif ($Control -is [System.Windows.Forms.Button]) { $Control.BackColor = $lightPanel; $Control.ForeColor = $lightText; $Control.FlatStyle = 'Standard' }
        elseif ($Control -is [System.Windows.Forms.TextBox]) { $Control.BackColor = [System.Drawing.Color]::White; $Control.ForeColor = $lightText }
        elseif ($Control -is [System.Windows.Forms.TabControl]) { $Control.BackColor = $lightBack; $Control.ForeColor = $lightText }
        elseif ($Control -is [System.Windows.Forms.DataGridView]) {
            $Control.BackgroundColor = [System.Drawing.Color]::White
            $Control.GridColor = [System.Drawing.Color]::LightGray
            $Control.ForeColor = $lightText
            $Control.DefaultCellStyle.BackColor = [System.Drawing.Color]::White
            $Control.DefaultCellStyle.ForeColor = $lightText
            $Control.DefaultCellStyle.SelectionBackColor = [System.Drawing.SystemColors]::Highlight
            $Control.DefaultCellStyle.SelectionForeColor = [System.Drawing.SystemColors]::HighlightText
            $Control.AlternatingRowsDefaultCellStyle.BackColor = $lightAlt
            $Control.AlternatingRowsDefaultCellStyle.ForeColor = $lightText
            $Control.ColumnHeadersDefaultCellStyle.BackColor = [System.Drawing.SystemColors]::Control
            $Control.ColumnHeadersDefaultCellStyle.ForeColor = $lightText
            $Control.RowHeadersDefaultCellStyle.BackColor = [System.Drawing.SystemColors]::Control
            $Control.RowHeadersDefaultCellStyle.ForeColor = $lightText
            $Control.EnableHeadersVisualStyles = $false
        }
    }
    foreach ($child in $Control.Controls) { Apply-ThemeToControl -Control $child }
    try { $Control.Invalidate() } catch {}
}

function Refresh-GridsForTheme {
    param([object[]]$Grids)
    foreach ($grid in $Grids) {
        try {
            $grid.Refresh()
            Resize-GridColumnsToContent -Grid $grid
        } catch {}
    }
}

function Get-NormalizedArtifactName {
    param([string]$Name,[string]$Path)
    $candidate = ""
    if ($Path) { try { $candidate = [System.IO.Path]::GetFileNameWithoutExtension($Path) } catch {} }
    if (-not $candidate -and $Name) {
        $tmp = $Name
        if ($tmp -match '^[A-Za-z]:\\') { try { $candidate = [System.IO.Path]::GetFileNameWithoutExtension($tmp) } catch {} }
        elseif ($tmp -match '([A-Za-z0-9_\-\.]+)\.(exe|dll|cpl|msc|bat|ps1)') { try { $candidate = [System.IO.Path]::GetFileNameWithoutExtension($matches[0]) } catch {} }
        else { $candidate = $tmp }
    }
    if (-not $candidate) { return "" }
    return $candidate.Trim().ToLowerInvariant()
}

function Add-DetectionRow {
    param([ref]$ListRef,[string]$Severity,[string]$Reason,[string]$Match,[string]$Artifact,[string]$Signature,[string]$Application,[string]$Path,[string]$Time,[string]$Detail)
    $ListRef.Value += [PSCustomObject]@{
        Severity = $Severity
        Reason = $Reason
        Match = $Match
        Artifact = $Artifact
        Signature = $Signature
        Application = $Application
        Path = $Path
        Time = $Time
        Detail = $Detail
    }
}

function Read-FileLinesShared {
    param([string]$Path)
    $lines = @()
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return @() }
    try {
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {
            $reader = New-Object System.IO.StreamReader($fs)
            try {
                $list = New-Object System.Collections.Generic.List[string]
                while (-not $reader.EndOfStream) { [void]$list.Add($reader.ReadLine()) }
                $lines = $list.ToArray()
            } finally { $reader.Close() }
        } finally { $fs.Close() }
    } catch {
        try { $lines = @(Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue) } catch { $lines = @() }
    }
    return @($lines)
}

function Get-PowerShellHistoryFiles {
    $paths = New-Object System.Collections.Generic.List[string]
    try {
        if ($env:APPDATA) {
            $currentPath = Join-Path $env:APPDATA "Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
            if (Test-Path $currentPath) { $paths.Add($currentPath) }
        }
    } catch {}
    try {
        $userRoots = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue
        foreach ($userRoot in $userRoots) {
            $historyPath = Join-Path $userRoot.FullName "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
            if (Test-Path $historyPath) { $paths.Add($historyPath) }
        }
    } catch {}
    return @($paths | Select-Object -Unique)
}

function Get-CommandHistoryData {
    $powerRows = @()
    $powerBuilder = New-Object System.Text.StringBuilder
    $historyPaths = Get-PowerShellHistoryFiles

    if ($historyPaths.Count -eq 0) { [void]$powerBuilder.AppendLine("No PowerShell history file found.") }
    foreach ($path in $historyPaths) {
        [void]$powerBuilder.AppendLine("==============================")
        [void]$powerBuilder.AppendLine($path)
        [void]$powerBuilder.AppendLine("==============================")
        $historyWriteTime = ""
        try {
            $historyItem = Get-Item -Path $path -ErrorAction SilentlyContinue
            if ($historyItem) { $historyWriteTime = $historyItem.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') }
        } catch {}
        try {
            $content = Get-Content -Path $path -ErrorAction SilentlyContinue
            if ($null -eq $content -or $content.Count -eq 0) {
                [void]$powerBuilder.AppendLine("No PowerShell history entries found in this file.")
            } else {
                $lineNumber = 0
                foreach ($line in $content) {
                    $lineNumber++
                    [void]$powerBuilder.AppendLine($line)
                    $powerRows += [PSCustomObject]@{
                        Source = "PowerShell History"
                        Line = "Line $lineNumber"
                        Path = $path
                        Time = $historyWriteTime
                        Command = $line
                    }
                }
            }
        } catch { [void]$powerBuilder.AppendLine("Unable to read this PowerShell history file.") }
        [void]$powerBuilder.AppendLine("")
    }

    return [PSCustomObject]@{
        PowerShellText = $powerBuilder.ToString()
        PowerShellRows = @($powerRows)
    }
}

function New-SnapshotRow {
    param([string]$Source,[string]$Id,[string]$Value,[string]$Detail)
    return [PSCustomObject]@{ Source = $Source; Id = $Id; Value = $Value; Detail = $Detail }
}


function Resolve-MonitoringSignaturePath {
    param([string]$Source,[string]$Item,[string]$Detail)
    $candidate = ""
    if ($Source -eq "BAM") { $candidate = Resolve-BamPath -RawPath $Detail }
    if (-not $candidate) { $candidate = Resolve-PathFromText -Text $Detail }
    if (-not $candidate) { $candidate = Resolve-PathFromText -Text $Item }
    if ($candidate -and $candidate -match '\.wer$' -and (Test-Path $candidate)) {
        try {
            $lines = Get-Content -Path $candidate -ErrorAction SilentlyContinue
            foreach ($line in $lines) {
                if ($line -like "AppPath=*") {
                    $appPath = $line.Substring(8)
                    if ($appPath) { return $appPath }
                }
            }
        } catch {}
    }
    return $candidate
}

function Get-MonitoringSignatureState {
    param([string]$Source,[string]$Item,[string]$Detail)
    $sigPath = Resolve-MonitoringSignaturePath -Source $Source -Item $Item -Detail $Detail
    if (-not $sigPath) { return "N/A" }
    if ($Source -eq "Prefetch" -and $sigPath -match '\.pf$') { return "N/A" }
    return (Get-SignatureState -FilePath $sigPath)
}

function Get-LiveArtifactSnapshot {
    $rows = @()
    try {
        if (Test-Path $script:prefetchPath) {
            $files = @(Get-ChildItem -Path $script:prefetchPath -Filter "*.pf" -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne "Layout.ini" })
            foreach ($f in $files) { $rows += New-SnapshotRow -Source "Prefetch" -Id $f.FullName -Value "$($f.LastWriteTimeUtc.Ticks)|$($f.Length)" -Detail $f.FullName }
        }
    } catch {}
    try {
        foreach ($root in $script:crashRoots) {
            if (Test-Path $root) {
                $files = @(Get-ChildItem -Path $root -Recurse -Filter "*.wer" -File -ErrorAction SilentlyContinue | Select-Object -First 500)
                foreach ($f in $files) { $rows += New-SnapshotRow -Source "Crash Logs" -Id $f.FullName -Value "$($f.LastWriteTimeUtc.Ticks)|$($f.Length)" -Detail $f.FullName }
            }
        }
    } catch {}
    try {
        if (Test-Path $script:bamRoot) {
            $sidKeys = @(Get-ChildItem -Path $script:bamRoot -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -ne "S-1-5-18" })
            foreach ($sidKey in $sidKeys) {
                $itemProps = Get-ItemProperty -Path $sidKey.PSPath -ErrorAction SilentlyContinue
                foreach ($prop in $sidKey.Property) {
                    $valueText = ""
                    try {
                        $raw = $itemProps.$prop
                        if ($raw -and $raw.Length -ge 8) { $valueText = [BitConverter]::ToInt64($raw[0..7], 0) }
                    } catch {}
                    $rows += New-SnapshotRow -Source "BAM" -Id "$($sidKey.PSChildName)|$prop" -Value $valueText -Detail $prop
                }
            }
        }
    } catch {}
    try {
        foreach ($path in Get-PowerShellHistoryFiles) {
            $item = Get-Item -Path $path -ErrorAction SilentlyContinue
            if ($item) { $rows += New-SnapshotRow -Source "PowerShell History File" -Id $path -Value "$($item.LastWriteTimeUtc.Ticks)|$($item.Length)" -Detail $path }
            $lines = @(Read-FileLinesShared -Path $path)
            $startIndex = [math]::Max(0, $lines.Count - 1500)
            for ($i = $startIndex; $i -lt $lines.Count; $i++) {
                $lineNumber = $i + 1
                $line = $lines[$i]
                $rows += New-SnapshotRow -Source "PowerShell History" -Id "$path|$lineNumber" -Value ([string]$line) -Detail ([string]$line)
            }
        }
    } catch {}
    try {
        foreach ($root in $script:muiRoots) {
            foreach ($key in (Get-RegistryTree -RootPath $root)) {
                foreach ($prop in Get-NonDefaultRegistryProps -Path $key.PSPath) {
                    $entryName = [string]$prop.Name
                    $entryValue = [string]$prop.Value
                    $resolvedMui = Resolve-MuiPath -EntryName $entryName -EntryValue $entryValue
                    $rows += New-SnapshotRow -Source "MuICache" -Id "$($key.PSPath)|$entryName" -Value $entryValue -Detail $resolvedMui
                }
            }
        }
    } catch {}
    try {
        if (Test-Path $script:appCompatStorePath) {
            foreach ($prop in Get-NonDefaultRegistryProps -Path $script:appCompatStorePath) { $rows += New-SnapshotRow -Source "Compatibility Assistant Store" -Id $prop.Name -Value ([string]$prop.Value) -Detail $prop.Name }
        }
    } catch {}
    try {
        if (Test-Path $script:appSwitchedPath) {
            foreach ($prop in Get-NonDefaultRegistryProps -Path $script:appSwitchedPath) { $rows += New-SnapshotRow -Source "FeatureUsage AppSwitched" -Id $prop.Name -Value ([string]$prop.Value) -Detail $prop.Name }
        }
    } catch {}
    return @($rows)
}

function Compare-LiveSnapshots {
    param([object[]]$Old,[object[]]$New)
    $changes = @()
    $oldMap = @{}
    $newMap = @{}
    foreach ($item in $Old) { $oldMap["$($item.Source)|$($item.Id)"] = $item }
    foreach ($item in $New) { $newMap["$($item.Source)|$($item.Id)"] = $item }
    foreach ($key in $newMap.Keys) {
        if (-not $oldMap.ContainsKey($key)) {
            $item = $newMap[$key]
            $changes += [PSCustomObject]@{ Time = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'); Change = "Added"; Source = $item.Source; Signature = "Processing"; Item = $item.Id; Detail = $item.Detail }
        } elseif ([string]$oldMap[$key].Value -ne [string]$newMap[$key].Value) {
            $item = $newMap[$key]
            $changes += [PSCustomObject]@{ Time = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'); Change = "Changed"; Source = $item.Source; Signature = "Processing"; Item = $item.Id; Detail = $item.Detail }
        }
    }
    foreach ($key in $oldMap.Keys) {
        if (-not $newMap.ContainsKey($key)) {
            $item = $oldMap[$key]
            $changes += [PSCustomObject]@{ Time = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'); Change = "Removed"; Source = $item.Source; Signature = "Processing"; Item = $item.Id; Detail = $item.Detail }
        }
    }
    return @($changes)
}

function New-ProcessSnapshotRow {
    param([int]$ProcessId,[string]$Name,[string]$Path,[string]$CreationTime)
    return [PSCustomObject]@{ ProcessId = $ProcessId; Name = $Name; Path = $Path; CreationTime = $CreationTime; Value = "$Name|$Path|$CreationTime" }
}

function Get-LiveProcessSnapshot {
    $rows = New-Object System.Collections.Generic.List[object]
    try {
        $processes = @(Get-Process -ErrorAction SilentlyContinue)
        foreach ($proc in $processes) {
            $path = ""
            $created = ""
            try { $path = [string]$proc.Path } catch {}
            try { if ($proc.StartTime) { $created = $proc.StartTime.ToString('yyyy-MM-dd HH:mm:ss') } } catch {}
            [void]$rows.Add((New-ProcessSnapshotRow -ProcessId ([int]$proc.Id) -Name ([string]$proc.ProcessName + ".exe") -Path $path -CreationTime $created))
        }
    } catch {
        try {
            $processes = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Select-Object ProcessId, Name, ExecutablePath, CreationDate)
            foreach ($proc in $processes) {
                $created = ""
                try { if ($proc.CreationDate) { $created = ([Management.ManagementDateTimeConverter]::ToDateTime($proc.CreationDate)).ToString('yyyy-MM-dd HH:mm:ss') } } catch {}
                [void]$rows.Add((New-ProcessSnapshotRow -ProcessId ([int]$proc.ProcessId) -Name ([string]$proc.Name) -Path ([string]$proc.ExecutablePath) -CreationTime $created))
            }
        } catch {}
    }
    return @($rows)
}


function Compare-LiveProcessSnapshots {
    param([object[]]$Old,[object[]]$New)
    $changes = @()
    $oldMap = @{}
    foreach ($item in $Old) { $oldMap[[string]$item.ProcessId] = $item }
    foreach ($item in $New) {
        $pidKey = [string]$item.ProcessId
        if (-not $oldMap.ContainsKey($pidKey)) {
            $changes += [PSCustomObject]@{
                Time = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                Change = "Opened"
                Source = "Opened Application"
                Signature = "Processing"
                Item = "$($item.Name) (PID $($item.ProcessId))"
                Detail = $item.Path
                ProcessName = $item.Name
                ProcessPath = $item.Path
                CreationTime = $item.CreationTime
            }
        }
    }
    return @($changes)
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

Clear-Host
Write-Host "[ Step 3 of 4 - Artifact Review ]" -ForegroundColor Cyan
Write-Host ""

$isAdmin = $false
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal -ArgumentList $identity
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {}

if (-not $isAdmin) {
    Write-Host "Please run this script as Administrator." -ForegroundColor Red
    Write-Host ""
    Write-Host "Press Enter to exit..." -ForegroundColor Yellow
    [Console]::ReadLine() | Out-Null
    exit
}

Write-Host "Instructions:" -ForegroundColor Yellow
Write-Host "1. Go through Overview and scroll through everything."
Write-Host "2. Go to Quick Review and scroll through everything."
Write-Host "3. Go to PowerShell History and scroll through that."
Write-Host ""

$SystemDriveRoot = $env:SystemDrive.TrimEnd('\')
$bootTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$prefetchPath = "$env:SystemRoot\Prefetch"
$prefetchRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"
$bamRoot = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
$bamServicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\bam"
$muiRoots = @("HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache","HKCU:\Software\Microsoft\Windows\ShellNoRoam\MUICache")
$shellBagRoots = @("HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU","HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags")
$appCompatStorePath = "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store"
$appSwitchedPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched"
$crashRoots = @("$env:ProgramData\Microsoft\Windows\WER\ReportArchive","$env:ProgramData\Microsoft\Windows\WER\ReportQueue")

$script:prefetchPath = $prefetchPath
$script:crashRoots = $crashRoots
$script:bamRoot = $bamRoot
$script:appCompatStorePath = $appCompatStorePath
$script:appSwitchedPath = $appSwitchedPath
$script:muiRoots = $muiRoots

$PrefetchEntries = @()
$Bam = @()
$MuiCacheEntries = @()
$CrashLogs = @()
$AppCompatStoreEntries = @()
$AppSwitchedEntries = @()

$pfFiles = @()
if (Test-Path $prefetchPath) { $pfFiles = @(Get-ChildItem -Path $prefetchPath -Filter "*.pf" -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne "Layout.ini" }) }

$SIDs = @()
if (Test-Path $bamRoot) { $SIDs = @(Get-ChildItem -Path $bamRoot -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -ne "S-1-5-18" } | Select-Object -ExpandProperty PSChildName) }

$totalBamProps = 0
foreach ($sid in $SIDs) {
    $keyPath = Join-Path $bamRoot $sid
    try {
        $regKey = Get-Item -Path $keyPath -ErrorAction SilentlyContinue
        if ($regKey -and $regKey.Property) { $totalBamProps += $regKey.Property.Count }
    } catch {}
}

$muiKeys = @()
foreach ($root in $muiRoots) { $muiKeys += Get-RegistryTree -RootPath $root }
$totalMuiProps = 0
foreach ($key in $muiKeys) { $totalMuiProps += @(Get-NonDefaultRegistryProps -Path $key.PSPath).Count }

$shellBagKeys = @()
foreach ($root in $shellBagRoots) { $shellBagKeys += Get-RegistryTree -RootPath $root }
$totalShellBagProps = 0
foreach ($key in $shellBagKeys) { $totalShellBagProps += @(Get-NonDefaultRegistryProps -Path $key.PSPath).Count }

$werFiles = @()
foreach ($root in $crashRoots) {
    if (Test-Path $root) { try { $werFiles += Get-ChildItem -Path $root -Recurse -Filter "*.wer" -File -ErrorAction SilentlyContinue } catch {} }
}

$appCompatProps = @(Get-NonDefaultRegistryProps -Path $appCompatStorePath)
$appSwitchedProps = @(Get-NonDefaultRegistryProps -Path $appSwitchedPath)
$totalWork = $pfFiles.Count + $SIDs.Count + $totalBamProps + $totalMuiProps + $totalShellBagProps + $werFiles.Count + $appCompatProps.Count + $appSwitchedProps.Count + 25
if ($totalWork -lt 1) { $totalWork = 1 }
$doneWork = 0
Update-RealLoadingBar -Current $doneWork -Total $totalWork

foreach ($pf in $pfFiles) {
    $appName = $pf.BaseName
    if ($pf.Name -match '^(.*)-[A-F0-9]{8}\.pf$') { $appName = $matches[1] }
    $PrefetchEntries += [PSCustomObject]@{
        Application = $appName
        LastRun = $pf.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
        RelativeTime = Format-ElapsedTime -FromTime $pf.LastWriteTime
        Path = $pf.FullName
    }
    $doneWork++
    Update-RealLoadingBar -Current $doneWork -Total $totalWork
}
$PrefetchEntries = @($PrefetchEntries | Sort-Object @{Expression = { [datetime]$_.LastRun }; Descending = $true }, Application)

foreach ($sid in $SIDs) {
    $keyPath = Join-Path $bamRoot $sid
    $doneWork++
    Update-RealLoadingBar -Current $doneWork -Total $totalWork
    try {
        $regKey = Get-Item -Path $keyPath -ErrorAction SilentlyContinue
        if (-not $regKey) { continue }
        $itemProps = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
        if (-not $itemProps) { continue }
        foreach ($prop in $regKey.Property) {
            try {
                $raw = $itemProps.$prop
                if (-not $raw -or $raw.Length -lt 8) { $doneWork++; Update-RealLoadingBar -Current $doneWork -Total $totalWork; continue }
                $fileTime = [BitConverter]::ToInt64($raw[0..7], 0)
                if ($fileTime -le 0) { $doneWork++; Update-RealLoadingBar -Current $doneWork -Total $totalWork; continue }
                $execTime = [DateTime]::FromFileTimeUtc($fileTime).ToLocalTime()
                $exeName = Split-Path $prop -Leaf
                $resolvedPath = Resolve-BamPath -RawPath $prop
                $sigStatus = Get-SignatureState -FilePath $resolvedPath
                $Bam += [PSCustomObject]@{
                    SortOrder = Get-SignatureSortOrder -Signature $sigStatus
                    Signature = $sigStatus
                    Time = $execTime.ToString('yyyy-MM-dd HH:mm:ss')
                    Application = $exeName
                    Path = $resolvedPath
                }
            } catch {}
            $doneWork++
            Update-RealLoadingBar -Current $doneWork -Total $totalWork
        }
    } catch {}
}
$Bam = @($Bam | Sort-Object @{Expression = { Get-BamSignatureSortOrder -Signature $_.Signature }}, Application, @{Expression = { $_.Time }; Descending = $true })

foreach ($key in $muiKeys) {
    $props = @(Get-NonDefaultRegistryProps -Path $key.PSPath)
    foreach ($prop in $props) {
        try {
            $entryName = [string]$prop.Name
            $entryValue = [string]$prop.Value
            if ($entryName -match '\.(exe|dll|cpl|msc)' -or $entryName -match '^[A-Za-z]:\\' -or $entryValue -match '\.(exe|dll|cpl|msc)' -or $entryValue -match '^[A-Za-z]:\\') {
                $resolvedMuiPath = Resolve-MuiPath -EntryName $entryName -EntryValue $entryValue
                $muiSignature = Get-SignatureState -FilePath $resolvedMuiPath
                $MuiCacheEntries += [PSCustomObject]@{
                    SortOrder = Get-SignatureSortOrder -Signature $muiSignature
                    Signature = $muiSignature
                    Entry = $entryName
                    Path = $resolvedMuiPath
                }
            }
        } catch {}
        $doneWork++
        Update-RealLoadingBar -Current $doneWork -Total $totalWork
    }
}
$MuiCacheEntries = @($MuiCacheEntries | Sort-Object SortOrder, Entry -Unique)

foreach ($key in $shellBagKeys) {
    $props = @(Get-NonDefaultRegistryProps -Path $key.PSPath)
    foreach ($prop in $props) { $doneWork++; Update-RealLoadingBar -Current $doneWork -Total $totalWork }
}

foreach ($werFile in $werFiles) {
    $appName = ""
    $appPath = ""
    $eventName = ""
    try {
        $lines = Get-Content -Path $werFile.FullName -ErrorAction SilentlyContinue
        foreach ($line in $lines) {
            if (-not $appName -and $line -like "AppName=*") { $appName = $line.Substring(8) }
            elseif (-not $appPath -and $line -like "AppPath=*") { $appPath = $line.Substring(8) }
            elseif (-not $eventName -and $line -like "FriendlyEventName=*") { $eventName = $line.Substring(18) }
        }
    } catch {}
    $crashSigStatus = Get-SignatureState -FilePath $appPath
    $CrashLogs += [PSCustomObject]@{
        SortOrder = Get-SignatureSortOrder -Signature $crashSigStatus
        Signature = $crashSigStatus
        Time = $werFile.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
        Report = $werFile.Name
        AppName = $appName
        AppPath = $appPath
        EventName = $eventName
    }
    $doneWork++
    Update-RealLoadingBar -Current $doneWork -Total $totalWork
}
$CrashLogs = @($CrashLogs | Sort-Object SortOrder, Time -Descending)

foreach ($prop in $appCompatProps) { $doneWork++; Update-RealLoadingBar -Current $doneWork -Total $totalWork }
foreach ($prop in $appSwitchedProps) { $doneWork++; Update-RealLoadingBar -Current $doneWork -Total $totalWork }

$AppCompatStoreEntries = @(Get-PathArtifactEntries -RegistryPath $appCompatStorePath -ArtifactLabel "Compatibility Assistant Store" | Select-Object SortOrder, Signature, Name, Path, Artifact)
$AppSwitchedEntries = @(Get-FeatureUsageEntries -RegistryPath $appSwitchedPath -ArtifactLabel "FeatureUsage AppSwitched" | Select-Object PathGroup, SortOrder, Signature, Name, Path, Value, Artifact)
$doneWork++
Update-RealLoadingBar -Current $doneWork -Total $totalWork

$bagMRURoot = $shellBagRoots[0]
$bagsRoot = $shellBagRoots[1]
$bagMRUExists = Test-Path $bagMRURoot
$bagsExists = Test-Path $bagsRoot
$bagMRUSubkeys = 0
$bagsSubkeys = 0
if ($bagMRUExists) { try { $bagMRUSubkeys = @(Get-ChildItem -Path $bagMRURoot -Recurse -ErrorAction SilentlyContinue).Count } catch {} }
if ($bagsExists) { try { $bagsSubkeys = @(Get-ChildItem -Path $bagsRoot -Recurse -ErrorAction SilentlyContinue).Count } catch {} }
$bagMRUEntries = 0
$bagsEntries = 0
foreach ($key in $shellBagKeys) {
    $count = @(Get-NonDefaultRegistryProps -Path $key.PSPath).Count
    if ($key.Name -like "*\BagMRU*") { $bagMRUEntries += $count }
    if ($key.Name -like "*\Bags*") { $bagsEntries += $count }
}
$shellBagSupported = $bagMRUExists -or $bagsExists
$shellBagTotalArtifacts = $bagMRUSubkeys + $bagsSubkeys + $bagMRUEntries + $bagsEntries
$shellBagStatus = if ($shellBagTotalArtifacts -eq 0) { "Possibly Cleared" } else { "Artifacts Present" }
$doneWork++
Update-RealLoadingBar -Current $doneWork -Total $totalWork

$muiRootExistsCount = 0
foreach ($root in $muiRoots) { if (Test-Path $root) { $muiRootExistsCount++ } }
$muiSupported = ($muiRootExistsCount -gt 0)
$muiTotalArtifacts = $MuiCacheEntries.Count
$muiStatus = if ($muiTotalArtifacts -eq 0) { "Possibly Cleared" } else { "Artifacts Present" }

$bamRootExists = Test-Path $bamRoot
$bamSIDCount = $SIDs.Count
$bamArtifactCount = $Bam.Count
$bamRawValueCount = $totalBamProps
$bamSupported = $bamRootExists
$bamStartValue = $null
try { $bamStartValue = Get-ItemPropertyValue -Path $bamServicePath -Name Start -ErrorAction SilentlyContinue } catch {}
$bamEnabledText = "Unknown"
if ($bamSupported -and $null -ne $bamStartValue) { $bamEnabledText = if ($bamStartValue -ne 4) { "Yes" } else { "No" } }
$bamStatus = if (-not $bamRootExists -or $bamSIDCount -eq 0 -or $bamRawValueCount -eq 0) { "Possibly Cleared" } else { "Artifacts Present" }

$prefetchFolderExists = Test-Path $prefetchPath
$prefetchCount = $pfFiles.Count
$prefetchSupported = $prefetchFolderExists
$enablePrefetcher = $null
try { $enablePrefetcher = Get-ItemPropertyValue -Path $prefetchRegPath -Name EnablePrefetcher -ErrorAction SilentlyContinue } catch {}
$prefetchEnabledText = "Unknown"
if ($prefetchSupported -and $null -ne $enablePrefetcher) { $prefetchEnabledText = if ($enablePrefetcher -ne 0) { "Yes" } else { "No" } }
$prefetchStatus = if (-not $prefetchFolderExists -or $prefetchCount -eq 0) { "Possibly Cleared" } else { "Artifacts Present" }

$crashSupported = $false
foreach ($root in $crashRoots) { if (Test-Path $root) { $crashSupported = $true; break } }
$werSvc = Get-Service -Name WerSvc -ErrorAction SilentlyContinue
$crashEnabledText = "Unknown"
if ($werSvc) { $crashEnabledText = if ($werSvc.StartType -eq 'Disabled') { "No" } else { "Yes" } }
$crashStatus = if ($CrashLogs.Count -eq 0) { "No Crash Logs Found" } else { "Artifacts Present" }

$appCompatSupported = Test-Path $appCompatStorePath
$appCompatStatus = if ($AppCompatStoreEntries.Count -eq 0) { "No Path Artifacts Found" } else { "Artifacts Present" }
$appSwitchedSupported = Test-Path $appSwitchedPath
$appSwitchedStatus = if ($AppSwitchedEntries.Count -eq 0) { "No FeatureUsage Entries Found" } else { "Artifacts Present" }

$CommandHistoryData = Get-CommandHistoryData
$PowerShellHistoryText = $CommandHistoryData.PowerShellText
$PowerShellHistoryRows = @($CommandHistoryData.PowerShellRows)
$powerShellHistoryStatus = if ($PowerShellHistoryRows.Count -eq 0) { "No History Found" } else { "Artifacts Present" }

Update-RealLoadingBar -Current $totalWork -Total $totalWork
Write-Host "`n"

function Get-ClearedStateText {
    param([string]$Status)
    if ($Status -match 'Possibly Cleared') { return 'Possible' }
    if ($Status -match 'Artifacts Present') { return 'No' }
    if ($Status -match 'No .* Found') { return 'Possible / None Found' }
    if ($Status -match 'No Path Artifacts Found') { return 'Possible / No Path Artifacts' }
    return 'Unknown'
}

$OverviewRows = @(
    [PSCustomObject]@{ Artifact = "Prefetch"; Supported = $(if ($prefetchSupported) { "Yes" } else { "No" }); Enabled = $prefetchEnabledText; Cleared = (Get-ClearedStateText -Status $prefetchStatus); Status = $prefetchStatus; Count = $prefetchCount },
    [PSCustomObject]@{ Artifact = "Crash Logs"; Supported = $(if ($crashSupported) { "Yes" } else { "No" }); Enabled = $crashEnabledText; Cleared = (Get-ClearedStateText -Status $crashStatus); Status = $crashStatus; Count = $CrashLogs.Count },
    [PSCustomObject]@{ Artifact = "ShellBags"; Supported = $(if ($shellBagSupported) { "Yes" } else { "No" }); Enabled = "Artifact Only"; Cleared = (Get-ClearedStateText -Status $shellBagStatus); Status = $shellBagStatus; Count = $shellBagTotalArtifacts },
    [PSCustomObject]@{ Artifact = "BAM"; Supported = $(if ($bamSupported) { "Yes" } else { "No" }); Enabled = $bamEnabledText; Cleared = (Get-ClearedStateText -Status $bamStatus); Status = $bamStatus; Count = $bamArtifactCount },
    [PSCustomObject]@{ Artifact = "Compatibility Assistant Store"; Supported = $(if ($appCompatSupported) { "Yes" } else { "No" }); Enabled = "Artifact Only"; Cleared = (Get-ClearedStateText -Status $appCompatStatus); Status = $appCompatStatus; Count = $AppCompatStoreEntries.Count },
    [PSCustomObject]@{ Artifact = "FeatureUsage AppSwitched"; Supported = $(if ($appSwitchedSupported) { "Yes" } else { "No" }); Enabled = "Artifact Only"; Cleared = (Get-ClearedStateText -Status $appSwitchedStatus); Status = $appSwitchedStatus; Count = $AppSwitchedEntries.Count },
    [PSCustomObject]@{ Artifact = "MuICache"; Supported = $(if ($muiSupported) { "Yes" } else { "No" }); Enabled = "Artifact Only"; Cleared = (Get-ClearedStateText -Status $muiStatus); Status = $muiStatus; Count = $muiTotalArtifacts },
    [PSCustomObject]@{ Artifact = "PowerShell History"; Supported = "Yes"; Enabled = "User History"; Cleared = (Get-ClearedStateText -Status $powerShellHistoryStatus); Status = $powerShellHistoryStatus; Count = $PowerShellHistoryRows.Count }
)

$ShellBagSummaryRows = @(
    [PSCustomObject]@{ Metric = "BagMRU Exists"; Detail = $bagMRUExists },
    [PSCustomObject]@{ Metric = "Bags Exists"; Detail = $bagsExists },
    [PSCustomObject]@{ Metric = "BagMRU Subkeys"; Detail = $bagMRUSubkeys },
    [PSCustomObject]@{ Metric = "Bags Subkeys"; Detail = $bagsSubkeys },
    [PSCustomObject]@{ Metric = "BagMRU Entries"; Detail = $bagMRUEntries },
    [PSCustomObject]@{ Metric = "Bags Entries"; Detail = $bagsEntries },
    [PSCustomObject]@{ Metric = "Artifact Status"; Detail = $shellBagStatus }
)

$AllArtifactRows = @()
function Add-AllArtifactRow {
    param([string]$Signature,[string]$Artifact,[string]$Application,[string]$Path,[string]$Time,[string]$Detail)
    if (-not $Signature -or $Signature -eq "No Signature Field") { $Signature = "N/A" }
    $script:AllArtifactRows += [PSCustomObject]@{
        Signature = $Signature
        Artifact = $Artifact
        Application = $Application
        Path = $Path
        Time = $Time
        Detail = $Detail
    }
}

foreach ($entry in $Bam) { Add-AllArtifactRow -Signature $entry.Signature -Artifact "BAM" -Application $entry.Application -Path $entry.Path -Time $entry.Time -Detail $entry.Application }
foreach ($entry in $MuiCacheEntries) { Add-AllArtifactRow -Signature $entry.Signature -Artifact "MuICache" -Application (Get-NormalizedArtifactName -Name $entry.Entry -Path $entry.Path) -Path $entry.Path -Time "" -Detail $entry.Entry }
foreach ($entry in $CrashLogs) { Add-AllArtifactRow -Signature $entry.Signature -Artifact "Crash Logs" -Application (Get-NormalizedArtifactName -Name $entry.AppName -Path $entry.AppPath) -Path $entry.AppPath -Time $entry.Time -Detail "$($entry.Report) $($entry.EventName)" }
foreach ($entry in $AppCompatStoreEntries) { Add-AllArtifactRow -Signature $entry.Signature -Artifact "Compatibility Assistant Store" -Application (Get-NormalizedArtifactName -Name $entry.Name -Path $entry.Path) -Path $entry.Path -Time "" -Detail $entry.Name }
foreach ($entry in $AppSwitchedEntries) { Add-AllArtifactRow -Signature $entry.Signature -Artifact "FeatureUsage AppSwitched" -Application (Get-NormalizedArtifactName -Name $entry.Name -Path $entry.Path) -Path $entry.Path -Time "" -Detail "$($entry.Name) $($entry.Value)" }
foreach ($entry in $PrefetchEntries) { Add-AllArtifactRow -Signature "N/A" -Artifact "Prefetch" -Application $entry.Application -Path $entry.Path -Time $entry.LastRun -Detail $entry.RelativeTime }

$SignatureRows = @(
    $AllArtifactRows | ForEach-Object {
        $sig = $_.Signature
        if (-not $sig -or $sig -eq "No Signature Field") { $sig = "N/A" }
        $sigOrder = switch ($sig) { "Invalid" { 0 } "N/A" { 1 } "Valid" { 2 } default { 3 } }
        [PSCustomObject]@{
            SignatureOrder = $sigOrder
            Signature = $sig
            Artifact = $_.Artifact
            Application = $_.Application
            Path = $_.Path
            Time = $_.Time
            Detail = $_.Detail
        }
    } | Sort-Object SignatureOrder, Artifact, Application, Time | Select-Object Signature, Artifact, Application, Path, Time, Detail
)

$SuspiciousKeywords = @(
    'matcha','evolve','mooze','isabelle','matrix','tsar','melatonin','serotonin','aimmy','aimbot','valex','vector','photon','nezur','yebra','haze/myst','haze','myst','horizon','havoc','colorbot','xeno','solara','olduimatrix','monkeyaim','thunderaim','thunderclient','celex','zarora','juju','nezure','fluxus','clumsy','matcha\.exe','triggerbot\.exe','aimmy\.exe','mystw\.exe','thing\.exe','dx9ware\.exe','fusionhacks\.zip','bootstrappernew','santoware','bootstrappernew\.exe','xeno\.exe','xenoui\.exe','solara\.exe','mapper\.exe','map','evolve\.exe','boostrapper\.exe','boostrappernew\.exe','authenticator\.exe','thing\.exe','app\.exe','update\.exe','updater\.exe','upgrade','threat-','cleaner','upgrader','aura','loader','mainrunner','usermode','newui','oldui'
)
$script:SuspiciousKeywords = $SuspiciousKeywords
$script:SuspiciousKeywordRegex = "(?i)(" + (($SuspiciousKeywords | ForEach-Object { $_ }) -join "|") + ")"
function Get-QuickReviewKeywordMatch {
    param([string]$Text)
    if (-not $Text) { return "" }
    foreach ($keyword in $script:SuspiciousKeywords) {
        try {
            if ($Text -match "(?i)$keyword") { return $keyword }
        } catch {}
    }
    return ""
}
function Get-QuickReviewKeywordSeverity {
    param([string]$Signature,[string]$Text)
    $keywordMatch = Get-QuickReviewKeywordMatch -Text $Text
    if ($keywordMatch) {
        if ($Signature -eq "Invalid") { return "High Review" }
        return "Review"
    }
    return (Get-QuickReviewSeverityFromSignature -Signature $Signature)
}
$TrustedApplicationRegex = '(?i)(valorant|riot games|riot client|epicgames|epic games|steam|razer|razor|microsoft|windowsapps|windows defender|nvidia|amd|intel|discord|roblox|google|chrome|brave|mozilla|firefox|battle\.net|blizzard|ea app|ubisoft|office|onedrive|teams)'
$PossibleDetectionRows = @()
$DetectionSeen = @{}
$RowsForDetectionScan = @($AllArtifactRows)
foreach ($historyCommand in $PowerShellHistoryRows) { $RowsForDetectionScan += [PSCustomObject]@{ Signature = "N/A"; Artifact = "PowerShell History"; Application = $historyCommand.Line; Path = $historyCommand.Path; Time = $historyCommand.Time; Detail = $historyCommand.Command } }

foreach ($row in $RowsForDetectionScan) {
    $combinedText = "$($row.Signature) $($row.Artifact) $($row.Application) $($row.Path) $($row.Time) $($row.Detail)"
    foreach ($keyword in $SuspiciousKeywords) {
        $matched = $false
        try { if ($combinedText -match "(?i)$keyword") { $matched = $true } } catch {}
        if ($matched) {
            $dedupeKey = "Keyword|$keyword|$($row.Artifact)|$($row.Application)|$($row.Path)|$($row.Time)|$($row.Detail)"
            if (-not $DetectionSeen.ContainsKey($dedupeKey)) {
                $DetectionSeen[$dedupeKey] = $true
                Add-DetectionRow -ListRef ([ref]$PossibleDetectionRows) -Severity "Review" -Reason "Suspicious keyword match" -Match $keyword -Artifact $row.Artifact -Signature $row.Signature -Application $row.Application -Path $row.Path -Time $row.Time -Detail $row.Detail
            }
            break
        }
    }
    if ($row.Signature -eq "Invalid" -and $combinedText -match $TrustedApplicationRegex) {
        $dedupeKey = "TrustedInvalid|$($row.Artifact)|$($row.Application)|$($row.Path)|$($row.Time)|$($row.Detail)"
        if (-not $DetectionSeen.ContainsKey($dedupeKey)) {
            $DetectionSeen[$dedupeKey] = $true
            Add-DetectionRow -ListRef ([ref]$PossibleDetectionRows) -Severity "High Review" -Reason "Trusted application path with invalid signature" -Match "Trusted app invalid signature" -Artifact $row.Artifact -Signature $row.Signature -Application $row.Application -Path $row.Path -Time $row.Time -Detail $row.Detail
        }
    }
}
$PossibleDetectionRows = @($PossibleDetectionRows | Sort-Object Severity, Artifact, Application, Time)

$CorrelationMap = @{}
function Add-CorrelationHit {
    param([string]$AppKey,[string]$Source)
    if (-not $AppKey) { return }
    if (-not $CorrelationMap.ContainsKey($AppKey)) {
        $CorrelationMap[$AppKey] = [ordered]@{ Application = $AppKey; BAM = $false; Prefetch = $false; MuICache = $false; AppCompat = $false; AppSwitched = $false; CrashLogs = $false }
    }
    $CorrelationMap[$AppKey][$Source] = $true
}
foreach ($entry in $Bam) { Add-CorrelationHit -AppKey (Get-NormalizedArtifactName -Name $entry.Application -Path $entry.Path) -Source "BAM" }
foreach ($entry in $PrefetchEntries) { Add-CorrelationHit -AppKey (Get-NormalizedArtifactName -Name $entry.Application -Path "") -Source "Prefetch" }
foreach ($entry in $MuiCacheEntries) { Add-CorrelationHit -AppKey (Get-NormalizedArtifactName -Name $entry.Entry -Path $entry.Path) -Source "MuICache" }
foreach ($entry in $AppCompatStoreEntries) { Add-CorrelationHit -AppKey (Get-NormalizedArtifactName -Name $entry.Name -Path $entry.Path) -Source "AppCompat" }
foreach ($entry in $AppSwitchedEntries) { Add-CorrelationHit -AppKey (Get-NormalizedArtifactName -Name $entry.Name -Path $entry.Path) -Source "AppSwitched" }
foreach ($entry in $CrashLogs) { Add-CorrelationHit -AppKey (Get-NormalizedArtifactName -Name $entry.AppName -Path $entry.AppPath) -Source "CrashLogs" }
$CorrelationRows = @()
foreach ($pair in $CorrelationMap.GetEnumerator()) {
    $v = $pair.Value
    $hits = @()
    if ($v.BAM) { $hits += "BAM" }
    if ($v.Prefetch) { $hits += "Prefetch" }
    if ($v.MuICache) { $hits += "MuICache" }
    if ($v.AppCompat) { $hits += "AppCompat" }
    if ($v.AppSwitched) { $hits += "AppSwitched" }
    if ($v.CrashLogs) { $hits += "CrashLogs" }
    if ($hits.Count -ge 2) {
        $CorrelationRows += [PSCustomObject]@{
            Application = $v.Application
            BAM = $(if ($v.BAM) { "Yes" } else { "No" })
            Prefetch = $(if ($v.Prefetch) { "Yes" } else { "No" })
            MuICache = $(if ($v.MuICache) { "Yes" } else { "No" })
            AppCompat = $(if ($v.AppCompat) { "Yes" } else { "No" })
            AppSwitched = $(if ($v.AppSwitched) { "Yes" } else { "No" })
            CrashLogs = $(if ($v.CrashLogs) { "Yes" } else { "No" })
            Sources = ($hits -join ", ")
        }
    }
}
$CorrelationRows = @($CorrelationRows | Sort-Object Application)

$script:ArtifactLookupByName = @{}
$script:ArtifactLookupByPath = @{}
function Add-ArtifactLookupHit {
    param([string]$NameKey,[string]$Path,[string]$Artifact)
    if ($NameKey) {
        if (-not $script:ArtifactLookupByName.ContainsKey($NameKey)) { $script:ArtifactLookupByName[$NameKey] = New-Object System.Collections.Generic.List[string] }
        if (-not $script:ArtifactLookupByName[$NameKey].Contains($Artifact)) { $script:ArtifactLookupByName[$NameKey].Add($Artifact) }
    }
    if ($Path) {
        $pathKey = $Path.ToLowerInvariant()
        if (-not $script:ArtifactLookupByPath.ContainsKey($pathKey)) { $script:ArtifactLookupByPath[$pathKey] = New-Object System.Collections.Generic.List[string] }
        if (-not $script:ArtifactLookupByPath[$pathKey].Contains($Artifact)) { $script:ArtifactLookupByPath[$pathKey].Add($Artifact) }
    }
}
foreach ($artifactRow in $AllArtifactRows) {
    Add-ArtifactLookupHit -NameKey (Get-NormalizedArtifactName -Name $artifactRow.Application -Path $artifactRow.Path) -Path $artifactRow.Path -Artifact $artifactRow.Artifact
}
function Get-ArtifactCheckSummaryForApplication {
    param([string]$ProcessName,[string]$ProcessPath)
    $hits = New-Object System.Collections.Generic.List[string]
    $nameKey = Get-NormalizedArtifactName -Name $ProcessName -Path $ProcessPath
    if ($nameKey -and $script:ArtifactLookupByName.ContainsKey($nameKey)) {
        foreach ($hit in $script:ArtifactLookupByName[$nameKey]) { if (-not $hits.Contains($hit)) { $hits.Add($hit) } }
    }
    if ($ProcessPath) {
        $pathKey = $ProcessPath.ToLowerInvariant()
        if ($script:ArtifactLookupByPath.ContainsKey($pathKey)) {
            foreach ($hit in $script:ArtifactLookupByPath[$pathKey]) { if (-not $hits.Contains($hit)) { $hits.Add($hit) } }
        }
    }
    if ($hits.Count -eq 0) { return "Artifact Check: No matching stored artifact found yet" }
    return "Artifact Check: " + (($hits | Sort-Object) -join ", ")
}

$overviewTable = ConvertTo-DataTable -Data $OverviewRows -Columns @("Artifact","Supported","Enabled","Cleared","Status","Count")
$signatureTable = ConvertTo-DataTable -Data $SignatureRows -Columns @("Signature","Artifact","Application","Path","Time","Detail")
$QuickReviewRows = @()
foreach ($row in $SignatureRows) {
    $sig = if ($row.Signature) { [string]$row.Signature } else { "N/A" }
    $sigOrder = Get-SignatureSortOrder -Signature $sig
    $quickText = "$($row.Artifact) $($row.Application) $($row.Path) $($row.Time) $($row.Detail)"
    $severity = Get-QuickReviewKeywordSeverity -Signature $sig -Text $quickText
    Add-QuickReviewRow -ListRef ([ref]$QuickReviewRows) -SortOrder $sigOrder -Section "Artifact Review" -Severity $severity -Signature $sig -Artifact $row.Artifact -Application $row.Application -Path $row.Path -Time $row.Time -Detail $row.Detail
}
foreach ($row in $PossibleDetectionRows) {
    if ([string]$row.Artifact -eq "PowerShell History") { continue }
    $sig = if ($row.Signature) { [string]$row.Signature } else { "N/A" }
    $sigOrder = Get-SignatureSortOrder -Signature $sig
    Add-QuickReviewRow -ListRef ([ref]$QuickReviewRows) -SortOrder (10 + $sigOrder) -Section "Possible Detection" -Severity $row.Severity -Signature $sig -Artifact $row.Artifact -Application $row.Application -Path $row.Path -Time $row.Time -Detail "$($row.Reason) | Match: $($row.Match) | $($row.Detail)"
}
foreach ($row in $OverviewRows) {
    if ([string]$row.Artifact -eq "PowerShell History") { continue }
    Add-QuickReviewRow -ListRef ([ref]$QuickReviewRows) -SortOrder 20 -Section "Artifact Summary" -Severity "Info" -Signature "N/A" -Artifact $row.Artifact -Application $row.Artifact -Path "" -Time "" -Detail "Supported: $($row.Supported) | Enabled: $($row.Enabled) | Cleared: $($row.Cleared) | Status: $($row.Status) | Count: $($row.Count)"
}
foreach ($row in $CorrelationRows) {
    Add-QuickReviewRow -ListRef ([ref]$QuickReviewRows) -SortOrder 21 -Section "Cross-Artifact Match" -Severity "Review" -Signature "N/A" -Artifact "Cross-Artifact Match" -Application $row.Application -Path "" -Time "" -Detail "Sources: $($row.Sources) | BAM: $($row.BAM) | Prefetch: $($row.Prefetch) | MuICache: $($row.MuICache) | AppCompat: $($row.AppCompat) | AppSwitched: $($row.AppSwitched) | CrashLogs: $($row.CrashLogs)"
}
$QuickReviewRows = @($QuickReviewRows | Sort-Object SortOrder, Section, Artifact, Application, Time | Select-Object Section, Severity, Signature, Artifact, Application, Path, Time, Detail)
function Add-QuickReviewDisplayRow {
    param(
        [System.Data.DataTable]$PriorityTable,
        [System.Data.DataTable]$ValidTable,
        [System.Data.DataTable]$NAOtherTable,
        [System.Data.DataTable]$MonitoringTable,
        [string]$Section,
        [string]$Severity,
        [string]$Signature,
        [string]$Artifact,
        [string]$Application,
        [string]$Path,
        [string]$Time,
        [string]$Detail,
        [switch]$InsertTop
    )
    if (-not $Signature -or $Signature -eq "No Signature Field") { $Signature = "N/A" }
    if (-not $Severity) { $Severity = Get-QuickReviewSeverityFromSignature -Signature $Signature }
    $rowText = "$Section $Severity $Signature $Artifact $Application $Path $Time $Detail"
    $keywordMatch = Get-QuickReviewKeywordMatch -Text $rowText
    if ($keywordMatch) {
        if ($Detail -notmatch '(?i)Keyword Match:') { $Detail = "Keyword Match: $keywordMatch | $Detail" }
        if ($Signature -eq "Invalid") { $Severity = "High Review" }
        elseif ($Severity -eq "Info" -or -not $Severity) { $Severity = "Review" }
    }
    $targetTable = $NAOtherTable
    if ($Section -eq "Monitoring" -and $MonitoringTable) { $targetTable = $MonitoringTable }
    elseif ($Signature -eq "Invalid" -or $Severity -eq "High Review" -or $keywordMatch) { $targetTable = $PriorityTable }
    elseif ($Signature -eq "Valid") { $targetTable = $ValidTable }
    $newRow = $targetTable.NewRow()
    $newRow["Section"] = Format-WrappedCellText -Text $Section -ColumnName "Section"
    $newRow["Severity"] = Format-WrappedCellText -Text $Severity -ColumnName "Severity"
    $newRow["Signature"] = Format-WrappedCellText -Text $Signature -ColumnName "Signature"
    $newRow["Artifact"] = Format-WrappedCellText -Text $Artifact -ColumnName "Artifact"
    $newRow["Application"] = Format-WrappedCellText -Text $Application -ColumnName "Application"
    $newRow["Path"] = Format-WrappedCellText -Text $Path -ColumnName "Path"
    $newRow["Time"] = Format-WrappedCellText -Text $Time -ColumnName "Time"
    $newRow["Detail"] = Format-WrappedCellText -Text $Detail -ColumnName "Detail"
    if ($InsertTop) { [void]$targetTable.Rows.InsertAt($newRow,0) }
    else { [void]$targetTable.Rows.Add($newRow) }
}
$quickReviewPriorityTable = ConvertTo-DataTable -Data @() -Columns @("Section","Severity","Signature","Artifact","Application","Path","Time","Detail")
$quickReviewMonitoringTable = ConvertTo-DataTable -Data @() -Columns @("Section","Severity","Signature","Artifact","Application","Path","Time","Detail")
$quickReviewValidTable = ConvertTo-DataTable -Data @() -Columns @("Section","Severity","Signature","Artifact","Application","Path","Time","Detail")
$quickReviewNAOtherTable = ConvertTo-DataTable -Data @() -Columns @("Section","Severity","Signature","Artifact","Application","Path","Time","Detail")
foreach ($quickRowItem in $QuickReviewRows) {
    Add-QuickReviewDisplayRow -PriorityTable $quickReviewPriorityTable -MonitoringTable $quickReviewMonitoringTable -ValidTable $quickReviewValidTable -NAOtherTable $quickReviewNAOtherTable -Section $quickRowItem.Section -Severity $quickRowItem.Severity -Signature $quickRowItem.Signature -Artifact $quickRowItem.Artifact -Application $quickRowItem.Application -Path $quickRowItem.Path -Time $quickRowItem.Time -Detail $quickRowItem.Detail
}
$possibleDetectionTable = ConvertTo-DataTable -Data $PossibleDetectionRows -Columns @("Severity","Reason","Match","Artifact","Signature","Application","Path","Time","Detail")
$correlationTable = ConvertTo-DataTable -Data $CorrelationRows -Columns @("Application","BAM","Prefetch","MuICache","AppCompat","AppSwitched","CrashLogs","Sources")
$detectionLogTable = ConvertTo-DataTable -Data @() -Columns @("Time","Change","Source","Signature","Item","Detail")
$prefetchTable = ConvertTo-DataTable -Data $PrefetchEntries -Columns @("Application","LastRun","RelativeTime")
$crashTable = ConvertTo-DataTable -Data ($CrashLogs | Select-Object Signature, Time, Report, AppName, AppPath, EventName) -Columns @("Signature","Time","Report","AppName","AppPath","EventName")
$shellTable = ConvertTo-DataTable -Data $ShellBagSummaryRows -Columns @("Metric","Detail")
$bamTable = ConvertTo-DataTable -Data ($Bam | Select-Object Signature, Time, Application, Path) -Columns @("Signature","Time","Application","Path")
$appCompatTable = ConvertTo-DataTable -Data ($AppCompatStoreEntries | ForEach-Object { [PSCustomObject]@{ Signature = $_.Signature; Application = (Get-NormalizedArtifactName -Name $_.Name -Path $_.Path); Path = $_.Path; Name = $_.Name } }) -Columns @("Signature","Application","Path","Name")
$appSwitchedTable = ConvertTo-DataTable -Data ($AppSwitchedEntries | ForEach-Object { [PSCustomObject]@{ Signature = $_.Signature; Application = (Get-NormalizedArtifactName -Name $_.Name -Path $_.Path); Path = $_.Path; Value = $_.Value; Name = $_.Name } }) -Columns @("Signature","Application","Path","Value","Name")
$muiTable = ConvertTo-DataTable -Data ($MuiCacheEntries | Select-Object Signature, Entry, Path) -Columns @("Signature","Entry","Path")

$form = New-Object System.Windows.Forms.Form
$form.Text = "Step 3 of 4 - Artifact Review"
$form.StartPosition = 'CenterScreen'
$form.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Dpi
$form.Size = Get-ResponsiveFormSize
$form.MinimumSize = New-Object System.Drawing.Size -ArgumentList 1000, 680
$form.BackColor = [System.Drawing.Color]::White
$form.TopMost = $false
$form.KeyPreview = $true
Enable-DoubleBuffer -Control $form

$topPanel = New-Object System.Windows.Forms.Panel
$topPanel.Dock = 'Top'
$topPanel.Height = 86
$topPanel.BackColor = [System.Drawing.Color]::FromArgb(245,245,245)
$titleLabel = New-Object System.Windows.Forms.Label
$titleLabel.Text = "Artifact Review"
$titleLabel.Font = New-UIFont -Size 17 -Bold
$titleLabel.AutoSize = $true
$titleLabel.Location = New-Object System.Drawing.Point -ArgumentList 16, 10
$infoLabel = New-Object System.Windows.Forms.Label
$infoLabel.Text = "Instructions: Overview - scroll through everything. Quick Review - scroll through everything. PowerShell History - scroll through that."
$infoLabel.Font = New-UIFont -Size 10
$infoLabel.AutoSize = $false
$infoLabel.Location = New-Object System.Drawing.Point -ArgumentList 18, 46
$infoLabel.Size = New-Object System.Drawing.Size -ArgumentList 1200, 30
$infoLabel.Anchor = 'Top,Left,Right'
$darkModeCheck = New-Object System.Windows.Forms.CheckBox
$darkModeCheck.Text = "Dark Mode"
$darkModeCheck.Checked = $true
$darkModeCheck.AutoSize = $true
$darkModeCheck.Font = New-UIFont -Size 10 -Bold
$darkModeCheck.Anchor = 'Top,Right'
$darkModeCheck.Location = New-Object System.Drawing.Point -ArgumentList 0, 14
$topPanel.Controls.Add($titleLabel)
$topPanel.Controls.Add($infoLabel)
$topPanel.Controls.Add($darkModeCheck)
$topPanel.Add_Resize({
    $infoLabel.Width = [math]::Max(200, $topPanel.ClientSize.Width - 170)
    $darkModeCheck.Location = New-Object System.Drawing.Point -ArgumentList ([math]::Max(20, $topPanel.ClientSize.Width - 140)), 16
})

$tabs = New-Object System.Windows.Forms.TabControl
$tabs.Dock = 'Fill'
$tabs.Font = New-UIFont -Size 10

$overviewGrid = New-DataGrid -DataTable $overviewTable
$correlationGrid = New-DataGrid -DataTable $correlationTable
$detectionGrid = New-DataGrid -DataTable $possibleDetectionTable
$monitoringGrid = New-DataGrid -DataTable $detectionLogTable
$monitoringGrid.Tag = "Monitoring"
$overviewStackPage = New-ResponsiveStackPage -Title "Overview" -MinimumSectionHeight 230 -Sections @(
    [PSCustomObject]@{ Title = "Artifact Summary"; Control = $overviewGrid },
    [PSCustomObject]@{ Title = "Cross-Artifact Matches"; Control = $correlationGrid },
    [PSCustomObject]@{ Title = "Possible Detections"; Control = $detectionGrid },
    [PSCustomObject]@{ Title = "Monitoring"; Control = $monitoringGrid }
)
$tabOverview = $overviewStackPage.Page

$tabPrefetchCrashShell = New-Object System.Windows.Forms.TabPage
$tabPrefetchCrashShell.Text = "Execution Trace Review"
$prefetchCrashShellLayout = New-Object System.Windows.Forms.TableLayoutPanel
$prefetchCrashShellLayout.Dock = 'Fill'
$prefetchCrashShellLayout.ColumnCount = 2
$prefetchCrashShellLayout.RowCount = 1
$prefetchCrashShellLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle -ArgumentList ([System.Windows.Forms.SizeType]::Percent), 50)) | Out-Null
$prefetchCrashShellLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle -ArgumentList ([System.Windows.Forms.SizeType]::Percent), 50)) | Out-Null
$prefetchCrashShellLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle -ArgumentList ([System.Windows.Forms.SizeType]::Percent), 100)) | Out-Null
$rightCrashShellLayout = New-Object System.Windows.Forms.TableLayoutPanel
$rightCrashShellLayout.Dock = 'Fill'
$rightCrashShellLayout.ColumnCount = 1
$rightCrashShellLayout.RowCount = 2
$rightCrashShellLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle -ArgumentList ([System.Windows.Forms.SizeType]::Percent), 55)) | Out-Null
$rightCrashShellLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle -ArgumentList ([System.Windows.Forms.SizeType]::Percent), 45)) | Out-Null
$rightCrashShellLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle -ArgumentList ([System.Windows.Forms.SizeType]::Percent), 100)) | Out-Null
$prefetchGrid = New-DataGrid -DataTable $prefetchTable
$prefetchGrid.Tag = "Prefetch"
$crashGrid = New-DataGrid -DataTable $crashTable
$shellGrid = New-DataGrid -DataTable $shellTable
$prefetchCrashShellLayout.Controls.Add((New-SectionPanel -Title "Prefetch" -Control $prefetchGrid),0,0)
$rightCrashShellLayout.Controls.Add((New-SectionPanel -Title "Crash Logs" -Control $crashGrid),0,0)
$rightCrashShellLayout.Controls.Add((New-SectionPanel -Title "ShellBags" -Control $shellGrid),0,1)
$prefetchCrashShellLayout.Controls.Add($rightCrashShellLayout,1,0)
$tabPrefetchCrashShell.Controls.Add($prefetchCrashShellLayout)

$bamGrid = New-DataGrid -DataTable $bamTable
$appCompatGrid = New-DataGrid -DataTable $appCompatTable
$appSwitchedGrid = New-DataGrid -DataTable $appSwitchedTable
$muiGrid = New-DataGrid -DataTable $muiTable
$executionStackPage = New-ResponsiveStackPage -Title "Application Usage Review" -MinimumSectionHeight 220 -Sections @(
    [PSCustomObject]@{ Title = "BAM"; Control = $bamGrid },
    [PSCustomObject]@{ Title = "Compatibility Assistant Store"; Control = $appCompatGrid },
    [PSCustomObject]@{ Title = "FeatureUsage AppSwitched"; Control = $appSwitchedGrid },
    [PSCustomObject]@{ Title = "MuICache"; Control = $muiGrid }
)
$tabExecutionUsage = $executionStackPage.Page
$powerTextPage = New-TextPage -Title "PowerShell History" -Text $PowerShellHistoryText

$quickPriorityGrid = New-DataGrid -DataTable $quickReviewPriorityTable
$quickPriorityGrid.Tag = "QuickReview"
$quickMonitoringGrid = New-DataGrid -DataTable $quickReviewMonitoringTable
$quickMonitoringGrid.Tag = "QuickReview"
$quickValidGrid = New-DataGrid -DataTable $quickReviewValidTable
$quickValidGrid.Tag = "QuickReview"
$quickNAOtherGrid = New-DataGrid -DataTable $quickReviewNAOtherTable
$quickNAOtherGrid.Tag = "QuickReview"
$quickReviewStackPage = New-ResponsiveStackPage -Title "Quick Review" -MinimumSectionHeight 230 -Sections @(
    [PSCustomObject]@{ Title = "Invalid / High Review / Keyword Hits"; Control = $quickPriorityGrid },
    [PSCustomObject]@{ Title = "Monitoring"; Control = $quickMonitoringGrid },
    [PSCustomObject]@{ Title = "Valid"; Control = $quickValidGrid },
    [PSCustomObject]@{ Title = "N/A / Other"; Control = $quickNAOtherGrid }
)

$tabs.TabPages.Add($tabOverview)
$tabs.TabPages.Add($quickReviewStackPage.Page)
$tabs.TabPages.Add($powerTextPage.Page)
$tabs.TabPages.Add($tabPrefetchCrashShell)
$tabs.TabPages.Add($tabExecutionUsage)

$form.Controls.Add($tabs)
$form.Controls.Add($topPanel)
Apply-ThemeToControl -Control $form

$allGrids = @(
    $overviewGrid,$correlationGrid,$detectionGrid,$monitoringGrid,
    $quickPriorityGrid,$quickMonitoringGrid,$quickValidGrid,$quickNAOtherGrid,
    $prefetchGrid,$crashGrid,$shellGrid,
    $bamGrid,$appCompatGrid,$appSwitchedGrid,$muiGrid
)

$darkModeCheck.Add_CheckedChanged({
    $script:DarkModeEnabled = [bool]$darkModeCheck.Checked
    Apply-ThemeToControl -Control $form
    Refresh-GridsForTheme -Grids $allGrids
})

foreach ($grid in $allGrids) {
    Set-GridColumnLayout -Grid $grid
    Resize-GridColumnsToContent -Grid $grid
    Apply-GridFormatting -Grid $grid -SystemDriveRoot $SystemDriveRoot -BootTime $bootTime
}

$script:LiveSnapshot = Get-LiveArtifactSnapshot
$script:ProcessSnapshot = Get-LiveProcessSnapshot
$script:LiveScanBusy = $false
$liveTimer = New-Object System.Windows.Forms.Timer
$liveTimer.Interval = 10000
$liveTimer.Add_Tick({
    if ($script:LiveScanBusy) { return }
    $script:LiveScanBusy = $true
    try {
        $newSnapshot = Get-LiveArtifactSnapshot
        $changes = Compare-LiveSnapshots -Old $script:LiveSnapshot -New $newSnapshot
        foreach ($change in $changes) {
            $row = $detectionLogTable.NewRow()
            $row["Time"] = [string]$change.Time
            $row["Change"] = [string]$change.Change
            $row["Source"] = [string]$change.Source
            $row["Signature"] = "Processing"
            $row["Item"] = Format-WrappedCellText -Text ([string]$change.Item) -ColumnName "Item"
            $row["Detail"] = Format-WrappedCellText -Text ([string]$change.Detail) -ColumnName "Detail"
            [void]$detectionLogTable.Rows.InsertAt($row,0)
            [System.Windows.Forms.Application]::DoEvents()
            $monitorSig = Get-MonitoringSignatureState -Source ([string]$change.Source) -Item ([string]$change.Item) -Detail ([string]$change.Detail)
            $row["Signature"] = $monitorSig
            $quickSeverity = Get-QuickReviewSeverityFromChange -Change ([string]$change.Change) -Signature $monitorSig
            Add-QuickReviewDisplayRow -PriorityTable $quickReviewPriorityTable -MonitoringTable $quickReviewMonitoringTable -ValidTable $quickReviewValidTable -NAOtherTable $quickReviewNAOtherTable -Section "Monitoring" -Severity $quickSeverity -Signature $monitorSig -Artifact ([string]$change.Source) -Application ([string]$change.Change) -Path "" -Time ([string]$change.Time) -Detail ("$($change.Item) | $($change.Detail)") -InsertTop
        }
        $newProcessSnapshot = Get-LiveProcessSnapshot
        $openedProcesses = Compare-LiveProcessSnapshots -Old $script:ProcessSnapshot -New $newProcessSnapshot
        foreach ($opened in $openedProcesses) {
            $procPath = [string]$opened.ProcessPath
            $artifactCheck = Get-ArtifactCheckSummaryForApplication -ProcessName ([string]$opened.ProcessName) -ProcessPath $procPath
            $detailText = "$procPath | $artifactCheck"
            if ($opened.CreationTime) { $detailText = "$detailText | Started: $($opened.CreationTime)" }
            $row = $detectionLogTable.NewRow()
            $row["Time"] = [string]$opened.Time
            $row["Change"] = "Opened"
            $row["Source"] = "Opened Application"
            $row["Signature"] = "Processing"
            $row["Item"] = Format-WrappedCellText -Text ([string]$opened.Item) -ColumnName "Item"
            $row["Detail"] = Format-WrappedCellText -Text $detailText -ColumnName "Detail"
            [void]$detectionLogTable.Rows.InsertAt($row,0)
            [System.Windows.Forms.Application]::DoEvents()
            $procSig = "N/A"
            if ($procPath) { $procSig = Get-SignatureState -FilePath $procPath }
            $row["Signature"] = $procSig
            $openedSeverity = Get-QuickReviewSeverityFromChange -Change "Added" -Signature $procSig
            Add-QuickReviewDisplayRow -PriorityTable $quickReviewPriorityTable -MonitoringTable $quickReviewMonitoringTable -ValidTable $quickReviewValidTable -NAOtherTable $quickReviewNAOtherTable -Section "Monitoring" -Severity $openedSeverity -Signature $procSig -Artifact "Opened Application" -Application ([string]$opened.Item) -Path $procPath -Time ([string]$opened.Time) -Detail $artifactCheck -InsertTop
        }
        $script:ProcessSnapshot = $newProcessSnapshot
        while ($detectionLogTable.Rows.Count -gt 500) { $detectionLogTable.Rows.RemoveAt($detectionLogTable.Rows.Count - 1) }
        if ($changes.Count -gt 0 -or $openedProcesses.Count -gt 0) {
            Resize-GridColumnsToContent -Grid $monitoringGrid
            Resize-GridColumnsToContent -Grid $quickMonitoringGrid
        }
        $script:LiveSnapshot = $newSnapshot
    } catch {}
    $script:LiveScanBusy = $false
})

$form.Add_Shown({
    $form.Activate()
    Apply-ThemeToControl -Control $form
    foreach ($grid in $allGrids) { Resize-GridColumnsToContent -Grid $grid }
    Update-ResponsiveStackLayout -ScrollPanel $overviewStackPage.Scroll -Layout $overviewStackPage.Layout -SectionCount 4 -MinimumSectionHeight 230
    Update-ResponsiveStackLayout -ScrollPanel $quickReviewStackPage.Scroll -Layout $quickReviewStackPage.Layout -SectionCount 4 -MinimumSectionHeight 230
    Update-ResponsiveStackLayout -ScrollPanel $executionStackPage.Scroll -Layout $executionStackPage.Layout -SectionCount 4 -MinimumSectionHeight 220
    $liveTimer.Start()
})
$form.Add_FormClosing({
    try { $liveTimer.Stop() } catch {}
})

[void]$form.ShowDialog()

Clear-Host
Write-Host "[ Step 3 of 4 - Artifact Review Complete ]" -ForegroundColor Cyan
