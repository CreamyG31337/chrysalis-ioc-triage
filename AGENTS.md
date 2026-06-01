# Triage – Chrysalis / Lotus Blossom IoC Investigation

## Purpose

This project checks a host for **Indicators of Compromise (IoC)** related to the **Chrysalis backdoor** and **Lotus Blossom (Billbug)** campaign described in Rapid7’s write-up. It runs on Windows PowerShell 5.1 and on PowerShell 7+ (Windows, Linux, macOS); registry and service checks are Windows-only and skipped elsewhere.

- **Blog:** [The Chrysalis Backdoor: A Deep Dive into Lotus Blossom's toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/)
- **Threat:** Chinese APT Lotus Blossom; initial access via abused Notepad++ update (e.g. `update.exe` from 95.179.213.0).

## What Gets Checked

- **Paths** – Known install paths (e.g. `%AppData%\Bluetooth`, `C:\ProgramData\USOShared`). With `-Admin`, every user profile's `AppData\Bluetooth` is checked.
- **File hashes** – SHA-256 **and** SHA-1 of known malicious files (installers, DLLs, loaders, shellcode) in those paths and optionally under extra directories.
- **Mutex** – `Global\Jdhfv_1.0.1` (Chrysalis single-instance).
- **Registry** *(Windows only)* – Run keys (HKCU/HKLM) for values referencing BluetoothService, update.exe, or `-i`/`-k` style arguments.
- **Services** *(Windows only)* – Services named or pointing to BluetoothService/update.exe.

## Project Layout

- **`iocs.json`** – Machine-readable IoCs (hashes, paths, mutexes, registry keys, network).
- **`docs/chrysalis-iocs.md`** – Human-readable IoC reference and MITRE mapping.
- **`scripts/Check-ChrysalisIoC.ps1`** – PowerShell script that runs the checks and writes a JSON report.

## How to Run the Check

From the repo root (or with correct relative path to `iocs.json`):

```powershell
# Default: paths, hashes in known dirs, registry, mutex, services
.\scripts\Check-ChrysalisIoC.ps1

# Also hash files under given paths (slower)
.\scripts\Check-ChrysalisIoC.ps1 -ScanPaths 'C:\Users','C:\ProgramData'

# Skip registry or mutex
.\scripts\Check-ChrysalisIoC.ps1 -NoRegistry -NoMutex

# Check every user profile's AppData\Bluetooth (run elevated)
.\scripts\Check-ChrysalisIoC.ps1 -Admin
```

Reports are written under the same directory as `iocs.json` as `chrysalis-scan-YYYYMMdd-HHmmss.json`. Exit code 1 if any finding, 0 if none.

## Agent / AI Guidelines

- When adding IoCs, update `iocs.json`, `docs/chrysalis-iocs.md`, and the README/CHANGELOG, and keep them in sync. Note hashes come in two sets: `fileHashes` (SHA-256) and `fileHashesSha1` (SHA-1) — add each hash to the set matching its algorithm.
- Prefer the script’s existing categories (Path, FileHash, Mutex, Registry, Service) for new findings; add new categories only when they don’t fit.
- Do not modify live system state (e.g. delete files or change registry) from the script; keep it read-only.
- For network IoCs (IPs/domains), use external tools or manual review; the script focuses on host-based IoCs.
