# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

- **`-Admin` switch** – check every user profile's `AppData\Bluetooth` folder, not just the current user's (#1).
- **SHA-1 hash matching** – `iocs.json` gains a `fileHashesSha1` array (32 hashes from the Kaspersky Notepad++ supply-chain report); files are now matched against both SHA-256 and SHA-1 (#2).
- **Additional network IoCs** – new C2 IPs (`45.32.144.255`, `45.76.155.202`, `45.77.31.210`) and domains (`cdncheck.it.com`, `self-dns.it.com`, `safe-dns.it.com`) (#2).
- **Cross-platform support** – runs under PowerShell 7+ on Linux/macOS; Windows-only registry and service checks are skipped automatically off Windows (#4).

### Fixed

- **Report file now always written** – a clean scan previously printed "Report saved" but produced no file (empty findings serialized to `$null`); the report is now always written, with a `[]` fallback (#3).

### Notes

- Additional SHA-1 IoCs and C2 indicators sourced from [Kaspersky – Notepad++ supply-chain attack](https://securelist.com/notepad-supply-chain-attack/118708/).

## [1.0.0] – 2026-02-02 (initial release)

Chrysalis / Lotus Blossom IoC checker (Rapid7, Feb 2026).

## [1.0.0] – 2026-02-02

### Added

- **Script:** `Check-ChrysalisIoC.ps1` – Checks paths, file hashes, mutex `Global\Jdhfv_1.0.1`, Run keys, and services.
- **IoC data:** `iocs.json` – 16 file hashes, paths, mutex, registry Run paths, network (IPs/domains).
- **Docs:** `docs/chrysalis-iocs.md` – Human-readable IoC reference and MITRE mapping.
- **Docs:** `docs/script-reference.md` – Script parameters, exit codes, report format.
- **Docs:** README, AGENTS.md, CONTRIBUTING.md, LICENSE (MIT), CHANGELOG.
- **Options:** `-ScanPaths`, `-NoRegistry`, `-NoMutex`, `-IocFile`.
- **Report:** JSON report `chrysalis-scan-<timestamp>.json` with category, detail, severity, time.

### Notes

- IoCs sourced from [Rapid7 – The Chrysalis Backdoor: A Deep Dive into Lotus Blossom's toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/).
- Script is read-only; no files or registry are modified.
