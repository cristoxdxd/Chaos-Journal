---
challenge_name: "Metaverse"
category: "Forensics"
solved_by: "Individual"
competition: "Latin America and Caribe Team Selection Event 2025"
---

# Metaverse Writeup

## Challenge Analysis

The challenge provides a memory dump (`memory_dump.elf`) from a compromised workstation. The description states that the attacker moves laterally to stay stealthy, indicating the need to analyze in-memory artifacts for evidence of intrusion, persistence, and command & control (C2) communication. Initial file analysis confirms it is an ELF64 core file containing a Windows 10 x64 memory image.

## Phase 1-2: Recon & Scanning

- Volatility3 was used for memory analysis. The `windows.info` plugin confirmed the OS as Windows 10 Build 19041 x64.
- The `windows.pslist` and `windows.psscan` plugins revealed a highly suspicious process: `ChromeX.exe` (PID 8812) located at `C:\Users\developer\Downloads\ChromeX.exe`. This is an obvious lure executable.
- `windows.netscan` showed that `ChromeX.exe` established a connection to the IP `13.60.193.87` on port 80 before closing it.
- Further analysis with `windows.cmdline` and `windows.handles` revealed that `ChromeX.exe` interacted with `svchost.exe` (PID 3904). The `windows.malfind` plugin detected code injection into this `svchost.exe` process, evidenced by an MZ header in an anomalous memory region.
- Two additional persistent processes were found: `fontdrvhost.ex` (PIDs 832 and 840). The misspelled name (missing 'e') and their PPIDs indicated they were spawned through process hollowing or injection from a legitimate system process.

## Phase 3: Exploitation

### Solution Path

1.  The initial compromise was traced to the user executing `ChromeX.exe` from their Downloads folder. This malware immediately beaconed to the C2 IP `13.60.193.87`.
2.  To achieve persistence and stealth, the malware injected its payload into a remote system process, `svchost.exe` (PID 3904). This was identified via handle analysis and the `malfind` plugin.
3.  The memory of the injected `svchost.exe` process was dumped and analyzed with the `strings` command.
4.  The final answer for the C2 server name was found within these strings. The malware's configuration used a specific URI path for communication.

### Flag Capture

<details>
  <summary>Flag (spoiler below)</summary>
  The answers to the challenge questions were as follows:
  1. PID of suspicious process: 8812
  2. Full path of executable: C:\Users\developer\Downloads\ChromeX.exe
  3. PID of injected remote process: 3904
  4. C2 IP address: 13.60.193.87
</details>

## Alternative Approaches

- The Cobalt Strike configuration could have been extracted automatically using the `volatility3` community plugin `windows.cobaltstrike.Config`, if available.
- The strings in the memory dump of the original `ChromeX.exe` process (PID 8812) could also have been analyzed to find the C2 server name.
- The network traffic could be reconstructed from the memory dump to see the exact HTTP requests made to the C2 server.

## Toolchain

- Volatility3
- strings
- grep
- binwalk (for initial file analysis)
