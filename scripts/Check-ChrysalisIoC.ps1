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
#>

[CmdletBinding()]
param(
    [string[]] $ScanPaths = @(),
    [string]   $IocFile    = '',
    [switch]   $NoRegistry,
    [switch]   $NoMutex
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

function Get-FileSha256 {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    try {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        $sha   = [System.Security.Cryptography.SHA256]::Create()
        $hash  = $sha.ComputeHash($bytes)
        $sha.Dispose()
        return ($hash | ForEach-Object { $_.ToString('x2') }) -join ''
    } catch {
        return $null
    }
}

# Load IoCs
if (-not (Test-Path -LiteralPath $IocFile)) {
    Write-Error "IoC file not found: $IocFile"
}
$iocs = Get-Content -Raw -Path $IocFile | ConvertFrom-Json
$hashSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($h in $iocs.fileHashes) { [void] $hashSet.Add($h.Trim()) }

# ---- 1) Paths ----
Write-Host "[*] Checking known paths..." -ForegroundColor Cyan
foreach ($rel in $iocs.paths) {
    $full = Expand-PathEnv $rel
    if (Test-Path -LiteralPath $full) {
        Add-Finding -Category 'Path' -Detail "Path exists: $full" -Severity 'High'
        Write-Host "  [FOUND] $full" -ForegroundColor Red
    }
}
# Hidden Bluetooth folder (Chrysalis-specific)
$bluetoothDir = Expand-PathEnv '%AppData%\Bluetooth'
if (Test-Path -LiteralPath $bluetoothDir) {
    $item = Get-Item -LiteralPath $bluetoothDir -Force -ErrorAction SilentlyContinue
    if ($item -and ($item.Attributes -band [System.IO.FileAttributes]::Hidden)) {
        Add-Finding -Category 'Path' -Detail "Hidden directory (Chrysalis install): $bluetoothDir" -Severity 'High'
        Write-Host "  [FOUND] Hidden dir: $bluetoothDir" -ForegroundColor Red
    }
}

# ---- 2) File hashes in known paths (Bluetooth + USOShared only; TEMP/TMP skipped to avoid slow scan) ----
$pathsToHash = @($bluetoothDir, (Expand-PathEnv '%ProgramData%\USOShared'))
foreach ($dir in $pathsToHash) {
    if (-not (Test-Path -LiteralPath $dir)) { continue }
    Get-ChildItem -LiteralPath $dir -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        $hash = Get-FileSha256 -Path $_.FullName
        if ($hash -and $hashSet.Contains($hash)) {
            Add-Finding -Category 'FileHash' -Detail "Known malicious hash: $($_.FullName) (SHA256: $hash)" -Severity 'Critical'
            Write-Host "  [MATCH] $($_.FullName) => $hash" -ForegroundColor Red
        }
    }
}

# Optional: scan additional paths
foreach ($scanRoot in $ScanPaths) {
    if (-not (Test-Path -LiteralPath $scanRoot)) { continue }
    Write-Host "[*] Scanning hashes under: $scanRoot" -ForegroundColor Cyan
    Get-ChildItem -LiteralPath $scanRoot -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        $hash = Get-FileSha256 -Path $_.FullName
        if ($hash -and $hashSet.Contains($hash)) {
            Add-Finding -Category 'FileHash' -Detail "Known malicious hash: $($_.FullName) (SHA256: $hash)" -Severity 'Critical'
            Write-Host "  [MATCH] $($_.FullName) => $hash" -ForegroundColor Red
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
