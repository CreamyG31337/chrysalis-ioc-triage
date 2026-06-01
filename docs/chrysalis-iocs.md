# Chrysalis / Lotus Blossom IoC Reference

**Source:** [Rapid7 – The Chrysalis Backdoor: A Deep Dive into Lotus Blossom's toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/)  
**Attribution:** Chinese APT Lotus Blossom (Billbug). Active since 2009.  
**Initial access:** Abuse of Notepad++ distribution (update.exe from 95.179.213.0).

---

## File indicators (SHA-256)

| Artifact | SHA-256 |
|----------|---------|
| update.exe | a511be5164dc1122fb5a7daa3eef9467e43d8458425b15a640235796006590c9 |
| [NSIS].nsi | 8ea8b83645fba6e23d48075a0d3fc73ad2ba515b4536710cda4f1f232718f53e |
| BluetoothService.exe | 2da00de67720f5f13b17e9d985fe70f10f153da60c9ab1086fe58f069a156924 |
| BluetoothService (encrypted shellcode) | 77bfea78def679aa1117f569a35e8fd1542df21f7e00e27f192c907e61d63a2e |
| log.dll | 3bdc4c0637591533f1d4198a72a33426c01f69bd2e15ceee547866f65e26b7ad |
| u.bat | 9276594e73cda1c69b7d265b3f08dc8fa84bf2d6599086b9acc0bb3745146600 |
| conf.c | f4d829739f2d6ba7e3ede83dad428a0ced1a703ec582fc73a4eee3df3704629a |
| libtcc.dll | 4a52570eeaf9d27722377865df312e295a7a23c3b6eb991944c2ecd707cc9906 |
| admin (shellcode) | 831e1ea13a1bd405f5bda2b9d8f2265f7b1db6c668dd2165ccc8a9c4c15ea7dd |
| loader1 / uffhxpSy shellcode | 0a9b8df968df41920b6ff07785cbfebe8bda29e6b512c94a3b2a83d10014d2fd / 4c2ea8193f4a5db63b897a2d3ce127cc5d89687f380b97a1d91e0c8db542e4f8 |
| loader2 / 3yZR31VK shellcode | e7cd605568c38bd6e0aba31045e1633205d0598c607a855e2e1bca4cca1c6eda / 078a9e5c6c787e5532a7e728720cbafee9021bfec4a30e3c2be110748d7c43c5 |
| ConsoleApplication2.exe | b4169a831292e245ebdffedd5820584d73b129411546e7d3eccf4663d5fc5be3 |
| system (shellcode) | 7add554a98d3a99b319f2127688356c1283ed073a084805f14e33b4f6a6126fd |
| s047t5g.exe | fcc2765305bcd213b7558025b2039df2265c3e0b6401e4833123c461df2de51a |

---

## Paths & artifacts to check

- **%AppData%\Bluetooth** – NSIS install target; HIDDEN dir with BluetoothService.exe, BluetoothService, log.dll
- **%AppData%\Bluetooth\BluetoothService.exe**
- **%AppData%\Bluetooth\log.dll**
- **C:\ProgramData\USOShared\** – conf.c / Tiny-C loader path
- **C:\ProgramData\USOShared\svchost.exe** (renamed tcc.exe)
- **C:\ProgramData\USOShared\conf.c**
- **C:\ProgramData\USOShared\libtcc.dll**
- **Temp u.bat** – cleanup batch script (path varies)

---

## Registry

- **Run key:** persistence fallback (value pointing to binary with `-i` flag)
- **Windows Service:** persistence via new service pointing to same binary

---

## Mutex

- **Global\Jdhfv_1.0.1** – Chrysalis single-instance mutex

---

## Network indicators

| Type | Value |
|------|--------|
| IP | 95.179.213.0 |
| IP | 61.4.102.97 |
| IP | 59.110.7.32 |
| IP | 124.222.137.114 |
| IP | 45.32.144.255 |
| IP | 45.76.155.202 |
| IP | 45.77.31.210 |
| Domain | api.skycloudcenter.com |
| Domain | api.wiresguard.com |
| Domain | cdncheck.it.com |
| Domain | self-dns.it.com |
| Domain | safe-dns.it.com |
| C2 URL (Chrysalis) | https://api.skycloudcenter.com/a/chat/s/70521ddf-a2ef-4adf-9cf0-6d8e24aaa821 |

Additional SHA-1 file hashes (from the Kaspersky Notepad++ supply-chain report) are tracked in `iocs.json` under `fileHashesSha1` and matched alongside the SHA-256 set above.

**Sources:** [Rapid7 – Chrysalis backdoor](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/) (SHA-256, paths, mutex); [Kaspersky – Notepad++ supply-chain attack](https://securelist.com/notepad-supply-chain-attack/118708/) (SHA-1, additional C2 IPs/domains).

---

## MITRE ATT&CK (selected)

- T1204.002 User Execution: Malicious File  
- T1036 Masquerading  
- T1027 Obfuscated Files or Information  
- T1574.002 DLL Side-Loading  
- T1547.001 Registry Run Keys  
- T1543.003 Windows Service  
- T1480.002 Mutual Exclusion (mutex)
