# Script reference: Check-ChrysalisIoC.ps1

Reference for the Chrysalis IoC checker script.

## Synopsis

```powershell
.\scripts\Check-ChrysalisIoC.ps1 [-ScanPaths <string[]>] [-IocFile <path>] [-NoRegistry] [-NoMutex] [-Admin]
```

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `Admin` | `switch` | `$false` | Check every user profile's `AppData\Bluetooth` (parent of `$env:USERPROFILE`, e.g. `C:\Users`), not just the current user's. Requires permission to read other profiles; run elevated. Unreadable profiles are skipped quietly. |
| `ScanPaths` | `string[]` | `@()` | Additional directories to hash and compare (e.g. `'C:\Users','C:\ProgramData'`). Can be slow on large trees. |
| `IocFile` | `string` | (auto) | Path to IoC JSON file. Default: `iocs.json` in repo root (resolved from script location). |
| `NoRegistry` | `switch` | `$false` | Skip Run key **and** service checks. |
| `NoMutex` | `switch` | `$false` | Skip mutex check. |

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | No IoCs detected in checked locations. |
| `1` | One or more findings (path, hash, mutex, registry, or service). |

## Output

- **Console** – Progress lines (`[*] Checking ...`) and findings (`[FOUND]`, `[MATCH]`, `[SUSPICIOUS]`). Summary at the end.
- **Report file** – `chrysalis-scan-YYYYMMdd-HHmmss.json` in the same directory as `iocs.json`. Contains an array of findings with:
  - `Category` – Path, FileHash, Mutex, Registry, Service.
  - `Detail` – Human-readable description.
  - `Severity` – Critical or High.
  - `Time` – ISO 8601 timestamp.

## Requirements

- **OS:** Windows, Linux, or macOS. Registry and service checks are Windows-only and are skipped automatically on other platforms; file-hash, path, and mutex checks run everywhere.
- **PowerShell:** Windows PowerShell 5.1, or PowerShell 7+ (any OS).
- **Permissions:** Run as Administrator for full registry and service checks, and for `-Admin` (reading other users' profiles); script is read-only.

## Examples

```powershell
# Default run (paths, hashes in Bluetooth/USOShared, mutex, Run keys, services)
.\scripts\Check-ChrysalisIoC.ps1

# Broader hash scan
.\scripts\Check-ChrysalisIoC.ps1 -ScanPaths 'C:\Users','C:\ProgramData'

# Custom IoC file
.\scripts\Check-ChrysalisIoC.ps1 -IocFile C:\custom\iocs.json

# Skip registry and mutex (e.g. in constrained environments)
.\scripts\Check-ChrysalisIoC.ps1 -NoRegistry -NoMutex

# Check every user profile's AppData\Bluetooth (run elevated)
.\scripts\Check-ChrysalisIoC.ps1 -Admin
```

## IoC file format

The script expects `iocs.json` (or the path given by `-IocFile`) with at least:

- `fileHashes` – Array of SHA-256 strings (lowercase).
- `fileHashesSha1` – Array of SHA-1 strings (lowercase). Files are matched against both this and `fileHashes`, since vendors publish different algorithms (Rapid7 SHA-256, Kaspersky SHA-1).
- `paths` – Array of path strings; `%AppData%`, `%ProgramData%` are expanded.
- `mutexes` – Array of mutex names (e.g. `Global\Jdhfv_1.0.1`).
- `registryRunPaths` – Array of registry paths (e.g. `HKCU\Software\...\Run`).
- `network` – Optional; not used by the script (for reference only).

See `iocs.json` in the repo root for the full structure.
