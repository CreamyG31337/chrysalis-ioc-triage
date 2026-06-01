# Chrysalis IoC Triage

A read-only host-based checker for **Indicators of Compromise (IoC)** associated with the **Chrysalis** backdoor and **Lotus Blossom (Billbug)** campaign. Runs on Windows PowerShell 5.1 and on PowerShell 7+ (Windows, Linux, macOS), and does not modify the system.

## Source

All IoCs are derived from the following publication:

**Rapid7 – *The Chrysalis Backdoor: A Deep Dive into Lotus Blossom's toolkit***  
<https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/>

| | |
|--|--|
| **Threat** | Chrysalis backdoor, Lotus Blossom (Billbug) APT |
| **Platform** | Windows PowerShell 5.1; PowerShell 7+ on Windows, Linux, macOS |

---

## Table of contents

- [Quick start](#quick-start)
- [What is checked](#what-is-checked)
- [Options](#options)
- [Project layout](#project-layout)
- [Documentation](#documentation)
- [Interpretation](#interpretation)
- [Contributing](#contributing)
- [License](#license)

---

## Quick start

**Requirements:** PowerShell 5.1 or later (Windows PowerShell or PowerShell 7+). On non-Windows, the registry and service checks are skipped automatically; all other checks run. Run as Administrator for full registry and service checks, and for `-Admin` (scanning other users' profiles).

```powershell
git clone <repository-url>
cd chrysalis-ioc-triage
.\scripts\Check-ChrysalisIoC.ps1
```

- **Exit code 0** — No IoCs detected in checked locations.
- **Exit code 1** — One or more findings; review console output and the generated `chrysalis-scan-<timestamp>.json` report.

---

## What is checked

| Check | Description |
|-------|-------------|
| **Paths** | `%AppData%\Bluetooth` (and if hidden); files under that folder and `%ProgramData%\USOShared`. With `-Admin`, every user profile's `AppData\Bluetooth` is checked |
| **File hashes** | SHA-256 **and** SHA-1 of files in those folders (and optional `-ScanPaths`); compared to known malicious hashes (16 SHA-256 + 32 SHA-1) |
| **Mutex** | `Global\Jdhfv_1.0.1` (Chrysalis single-instance; presence suggests possible live implant) |
| **Registry** *(Windows only)* | HKCU/HKLM Run keys for Chrysalis-like values (e.g. `BluetoothService.exe` in `AppData\Bluetooth` with `-i`/`-k`) |
| **Services** *(Windows only)* | Services named `BluetoothService` or path under `AppData\...\Bluetooth\BluetoothService.exe` |

The script is read-only and does not modify files or registry. Registry and service checks run on Windows only and are skipped automatically on Linux/macOS.

---

## Options

| Parameter | Description |
|-----------|-------------|
| `-Admin` | Check **every** user profile's `AppData\Bluetooth` folder, not just the current user's (requires permission to read other profiles; run elevated) |
| `-ScanPaths 'C:\Users','C:\ProgramData'` | Hash and compare files under these paths (may be slow) |
| `-NoRegistry` | Skip Run key and service checks |
| `-NoMutex` | Skip mutex check |
| `-IocFile <path>` | Path to IoC JSON file (default: `iocs.json` in repository root) |

Example — broader hash scan:

```powershell
.\scripts\Check-ChrysalisIoC.ps1 -ScanPaths 'C:\Users','C:\ProgramData'
```

Example — check all user profiles (elevated):

```powershell
.\scripts\Check-ChrysalisIoC.ps1 -Admin
```

---

## Project layout

```
chrysalis-ioc-triage/
├── README.md
├── AGENTS.md
├── CONTRIBUTING.md
├── LICENSE
├── CHANGELOG.md
├── iocs.json
├── docs/
│   ├── README.md
│   ├── chrysalis-iocs.md
│   └── script-reference.md
└── scripts/
    └── Check-ChrysalisIoC.ps1
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [docs/README.md](docs/README.md) | Documentation index |
| [docs/chrysalis-iocs.md](docs/chrysalis-iocs.md) | IoC reference (hashes, paths, mutex, registry, network, MITRE ATT&CK) |
| [docs/script-reference.md](docs/script-reference.md) | Script parameters, exit codes, report format |
| [AGENTS.md](AGENTS.md) | Project context for AI/agent use |

---

## Interpretation

- **Critical** — Known malicious file hash match or Chrysalis mutex present: treat as compromise until proven otherwise.
- **High** — Suspicious path, Run key, or service: investigate (may overlap with legitimate software).

`C:\ProgramData\USOShared` is a legitimate Windows path; the script does not flag its existence, only known malicious hashes within it. Registry and service checks use Chrysalis-specific patterns to limit false positives.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. See [LICENSE](LICENSE).
