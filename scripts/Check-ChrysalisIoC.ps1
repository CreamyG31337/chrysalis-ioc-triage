#Requires -Version 5.1
<#
.SYNOPSIS
  Checks the local Windows system for Chrysalis / Lotus Blossom IoCs.

.DESCRIPTION
  Uses IoCs from Rapid7's Chrysalis backdoor write-up:
  https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/

  Checks: file hashes, suspicious paths, mutex, Run keys, and optional drive scan.

.EXAMPLE
  .\Check-ChrysalisIoC.ps1
  Run with default (paths + known dirs + registry + mutex).

.EXAMPLE
  .\Check-ChrysalisIoC.ps1 -ScanPaths "C:\Users","C:\ProgramData"
  Also hash and compare files under given paths (slower).

.EXAMPLE
  .\Check-ChrysalisIoC.ps1 -Admin
  Check every user profile's AppData\Bluetooth folder, not just the current
  user's. Requires permission to read other users' profiles (run elevated).
#>

[CmdletBinding()]
param(
    [string[]] $ScanPaths = @(),
    [string]   $IocFile    = '',
    [switch]   $NoRegistry,
    [switch]   $NoMutex,
    [switch]   $Admin
)

$ErrorActionPreference = 'Stop'
$script:Findings = [System.Collections.ArrayList]::new()
$script:Checked  = [System.Collections.ArrayList]::new()

# Resolve IoC file path when not specified
if (-not $IocFile) {
    $scriptDir = $PSScriptRoot
    if (-not $scriptDir -and $MyInvocation.MyCommand.Path) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
    $IocFile = if ($scriptDir) { Join-Path (Join-Path $scriptDir '..') 'iocs.json' } else { Join-Path (Get-Location) 'iocs.json' }
}

function Expand-PathEnv {
    param([string]$p)
    $p = $p -replace '%AppData%', $env:APPDATA
    $p = $p -replace '%ProgramData%', $env:ProgramData
    $p = $p -replace '%TEMP%', $env:TEMP
    $p = $p -replace '%TMP%', $env:TMP
    return $p
}

function Add-Finding {
    param([string]$Category, [string]$Detail, [string]$Severity = 'High')
    [void] $script:Findings.Add([PSCustomObject]@{
        Category = $Category
        Detail   = $Detail
        Severity = $Severity
        Time     = (Get-Date).ToString('o')
    })
}

# Returns the AppData\Bluetooth directories to inspect. By default this is just
# the current user's. With -Admin, every user profile under the profiles root
# (parent of $env:USERPROFILE, e.g. C:\Users) is enumerated -- reading other
# users' AppData requires elevation, so unreadable profiles are skipped quietly.
function Get-BluetoothDirsToCheck {
    if (-not $Admin) {
        return ,(Expand-PathEnv '%AppData%\Bluetooth')
    }
    $dirs = [System.Collections.Generic.List[string]]::new()
    $usersRoot = Split-Path -Parent $env:USERPROFILE
    if (-not (Test-Path -LiteralPath $usersRoot)) { return $dirs }
    Get-ChildItem -LiteralPath $usersRoot -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object {
        # AppData\Roaming is the per-user expansion of %AppData%
        $dirs.Add((Join-Path $_.FullName 'AppData\Roaming\Bluetooth'))
    }
    return $dirs
}

# Reads a file once and checks it against both the SHA-256 and SHA-1 IoC sets.
# Returns a descriptive match string (e.g. "SHA1: <hash>") or $null. Reporting
# vendors publish different algorithms -- Rapid7 used SHA-256, Kaspersky SHA-1 --
# so a single-algorithm check would silently miss half the known-bad files.
function Get-FileHashIocMatch {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    try {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
    } catch {
        return $null
    }
    if ($hashSet.Count -gt 0) {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try { $h = (($sha.ComputeHash($bytes)) | ForEach-Object { $_.ToString('x2') }) -join '' } finally { $sha.Dispose() }
        if ($hashSet.Contains($h)) { return "SHA256: $h" }
    }
    if ($hashSetSha1.Count -gt 0) {
        $sha = [System.Security.Cryptography.SHA1]::Create()
        try { $h = (($sha.ComputeHash($bytes)) | ForEach-Object { $_.ToString('x2') }) -join '' } finally { $sha.Dispose() }
        if ($hashSetSha1.Contains($h)) { return "SHA1: $h" }
    }
    return $null
}

# Load IoCs
if (-not (Test-Path -LiteralPath $IocFile)) {
    Write-Error "IoC file not found: $IocFile"
}
$iocs = Get-Content -Raw -Path $IocFile | ConvertFrom-Json
$hashSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($h in $iocs.fileHashes) { [void] $hashSet.Add($h.Trim()) }
$hashSetSha1 = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($h in $iocs.fileHashesSha1) { [void] $hashSetSha1.Add($h.Trim()) }

# ---- 1) Paths ----
Write-Host "[*] Checking known paths..." -ForegroundColor Cyan
foreach ($rel in $iocs.paths) {
    $full = Expand-PathEnv $rel
    if (Test-Path -LiteralPath $full) {
        Add-Finding -Category 'Path' -Detail "Path exists: $full" -Severity 'High'
        Write-Host "  [FOUND] $full" -ForegroundColor Red
    }
}
# Hidden Bluetooth folder (Chrysalis-specific). With -Admin, check every user's.
$bluetoothDirs = @(Get-BluetoothDirsToCheck)
if ($Admin) { Write-Host "[*] -Admin: checking $($bluetoothDirs.Count) user profile(s)' Bluetooth folders." -ForegroundColor Cyan }
foreach ($btDir in $bluetoothDirs) {
    if (-not (Test-Path -LiteralPath $btDir)) { continue }
    $item = Get-Item -LiteralPath $btDir -Force -ErrorAction SilentlyContinue
    if ($item -and ($item.Attributes -band [System.IO.FileAttributes]::Hidden)) {
        Add-Finding -Category 'Path' -Detail "Hidden directory (Chrysalis install): $btDir" -Severity 'High'
        Write-Host "  [FOUND] Hidden dir: $btDir" -ForegroundColor Red
    }
}

# ---- 2) File hashes in known paths (Bluetooth + USOShared only; TEMP/TMP skipped to avoid slow scan) ----
# %ProgramData% is machine-wide, so it is hashed once regardless of -Admin.
$pathsToHash = @($bluetoothDirs + (Expand-PathEnv '%ProgramData%\USOShared'))
foreach ($dir in $pathsToHash) {
    if (-not (Test-Path -LiteralPath $dir)) { continue }
    Get-ChildItem -LiteralPath $dir -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        $match = Get-FileHashIocMatch -Path $_.FullName
        if ($match) {
            Add-Finding -Category 'FileHash' -Detail "Known malicious hash: $($_.FullName) ($match)" -Severity 'Critical'
            Write-Host "  [MATCH] $($_.FullName) => $match" -ForegroundColor Red
        }
    }
}

# Optional: scan additional paths
foreach ($scanRoot in $ScanPaths) {
    if (-not (Test-Path -LiteralPath $scanRoot)) { continue }
    Write-Host "[*] Scanning hashes under: $scanRoot" -ForegroundColor Cyan
    Get-ChildItem -LiteralPath $scanRoot -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        $match = Get-FileHashIocMatch -Path $_.FullName
        if ($match) {
            Add-Finding -Category 'FileHash' -Detail "Known malicious hash: $($_.FullName) ($match)" -Severity 'Critical'
            Write-Host "  [MATCH] $($_.FullName) => $match" -ForegroundColor Red
        }
    }
}

# ---- 3) Mutex ----
if (-not $NoMutex -and $iocs.mutexes) {
    Write-Host "[*] Checking mutexes..." -ForegroundColor Cyan
    foreach ($mutexName in $iocs.mutexes) {
        try {
            $m = [Threading.Mutex]::OpenExisting($mutexName)
            $m.Dispose()
            Add-Finding -Category 'Mutex' -Detail "Chrysalis mutex present (possible live implant): $mutexName" -Severity 'Critical'
            Write-Host "  [FOUND] $mutexName" -ForegroundColor Red
        } catch {
            # Mutex does not exist - expected on clean system
        }
    }
}

# ---- 4) Registry Run keys (Chrysalis: BluetoothService with -i/-k in AppData\Bluetooth) ----
if (-not $NoRegistry -and $iocs.registryRunPaths) {
    Write-Host "[*] Checking Run keys..." -ForegroundColor Cyan
    foreach ($regPath in $iocs.registryRunPaths) {
        $base = if ($regPath -match '^HKCU') { 'HKCU:' } else { 'HKLM:' }
        $path = $base + '\' + ($regPath -replace '^(HKCU|HKLM)\\|', '' -replace '^Software\\', 'Software\')
        if (-not (Test-Path -LiteralPath $path)) { continue }
        try {
            $props = Get-ItemProperty -LiteralPath $path -ErrorAction SilentlyContinue
            if (-not $props) { continue }
            $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^(PSPath|PSParentPath|PSChildName|PSDrive|PSProvider)$' } | ForEach-Object {
                $valStr = if ($null -eq $_.Value) { '' } else { $_.Value.ToString() }
                if (-not $valStr) { return }
                # Chrysalis: path in AppData\Bluetooth and uses -i or -k
                if ($valStr -match 'Bluetooth\\BluetoothService\.exe' -or ($valStr -match 'AppData[\\/].*Bluetooth' -and $valStr -match '\s-[ik]\s')) {
                    Add-Finding -Category 'Registry' -Detail "Run key (Chrysalis-like): $path -> $($_.Name) = $valStr" -Severity 'High'
                    Write-Host "  [SUSPICIOUS] $path | $($_.Name) = $valStr" -ForegroundColor Yellow
                }
            }
        } catch { }
    }
}

# ---- 5) Services: Chrysalis uses "BluetoothService" or path in AppData\Bluetooth ----
if (-not $NoRegistry) {
    Write-Host "[*] Checking services..." -ForegroundColor Cyan
    Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -eq 'BluetoothService' -or ($_.PathName -match 'AppData[\\/].*Bluetooth[\\/]BluetoothService\.exe')
    } | ForEach-Object {
        Add-Finding -Category 'Service' -Detail "Service (Chrysalis-like): $($_.Name) | Path: $($_.PathName)" -Severity 'High'
        Write-Host "  [SUSPICIOUS] $($_.Name) => $($_.PathName)" -ForegroundColor Yellow
    }
}

# ---- Report ----
Write-Host "`n========== Summary ==========" -ForegroundColor Cyan
$critical = @($script:Findings | Where-Object { $_.Severity -eq 'Critical' })
$high     = @($script:Findings | Where-Object { $_.Severity -eq 'High' })
if ($critical.Count -gt 0) {
    Write-Host "CRITICAL: $($critical.Count) finding(s)" -ForegroundColor Red
}
if ($high.Count -gt 0) {
    Write-Host "HIGH:     $($high.Count) finding(s)" -ForegroundColor Yellow
}
if ($script:Findings.Count -eq 0) {
    Write-Host "No Chrysalis IoCs detected in checked locations." -ForegroundColor Green
    Write-Host "Consider running with -ScanPaths to hash more directories (e.g. -ScanPaths 'C:\Users','C:\ProgramData')." -ForegroundColor Gray
}

# Write report next to the IoC file; fall back to the current directory if
# $IocFile has no directory component (e.g. a bare filename was passed).
$reportDir = Split-Path -Parent $IocFile
if ([string]::IsNullOrWhiteSpace($reportDir)) { $reportDir = (Get-Location).Path }
$reportPath = Join-Path $reportDir "chrysalis-scan-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"

# Build the JSON explicitly. Piping an empty collection into ConvertTo-Json
# yields $null, and `$null | Set-Content` writes nothing, so a clean scan
# would silently produce no file. Force an array and a '[]' fallback.
$reportJson = ConvertTo-Json -InputObject @($script:Findings.ToArray()) -Depth 5
if ([string]::IsNullOrWhiteSpace($reportJson)) { $reportJson = '[]' }
try {
    Set-Content -Path $reportPath -Value $reportJson -Encoding UTF8
    Write-Host "Report saved: $reportPath" -ForegroundColor Gray
} catch {
    Write-Warning "Failed to write report to ${reportPath}: $($_.Exception.Message)"
}

exit $(if ($script:Findings.Count -gt 0) { 1 } else { 0 })
