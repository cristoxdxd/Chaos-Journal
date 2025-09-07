# UniVsThreats CTF 2025 Writeup

## 0xL0cK (Misc)

**Points:** 100  
**Solved by:** Individual  
**Competition:** UniVsThreats CTF 2025

### Challenge Analysis

A terminal-based challenge requiring authentication and memory analysis to uncover hidden flags through a series of system commands.

### Phase 1-2: Recon & Scanning

- Connected via netcat: `nc 91.99.1.179 8654`
- Initial command `HELP` revealed available commands
- Used `LIST` to view files and `MEMDUMP` to analyze memory contents
- Found authentication keyword `SURVIVOR` in memory dump

### Phase 3: Exploitation

#### Solution Path

1. Authenticated with `AUTH SURVIVOR` to unlock additional commands
2. Used `ANALYZE` to identify corrupted memory section blocking `vault.log`
3. Located correct memory address through `UNLOCK` command
4. Decrypted Base64-encoded message from `vault.log` revealing layered encryption
5. Extracted final decryption key from the second layer of encoded text
6. Decrypted `.emergency_override` file to obtain admin password
7. Accessed `.memdump_cache` with admin privileges to reveal flag

#### Flag Capture

<details>
  <summary>Flag (spoiler below)</summary>
  UVT{Th3_m3ch4n1sM_UNs3a15_4nd_tH3_DaRK_uNBl1nk5}
</details>

### Alternative Approaches

- Brute force memory addresses for UNLOCK command
- Different decoding methods for the layered encryption

### Toolchain

- Netcat
- Base64 decoding tools
- Custom Python scripts for decryption

---

## error=-300 (Web)

**Points:** 100  
**Solved by:** Individual  
**Competition:** UniVsThreats CTF 2025

### Challenge Analysis

Web application with SQL injection vulnerability in login form, protected by WAF.

### Phase 1-2: Recon & Scanning

- Identified SQL error messages in login responses
- Discovered `users` and `flags` tables through error-based SQLi
- WAF blocked standard UNION SELECT payloads

### Phase 3: Exploitation

#### Solution Path

1. Bypassed login with `' OR 1=1 --`
2. Used time-based blind SQL injection to enumerate database structure
3. Employed WAF evasion techniques including:
   - Unicode encoding
   - HTTP parameter pollution
   - Alternative comment syntax
4. Extracted flag with final payload: `' UNION/*!50000SELECT*/flag/*!50000FROM*/flags--`

#### Flag Capture

<details>
  <summary>Flag (spoiler below)</summary>
  UVT{Th3_sy5t3M_7ru5Ts_1tS_oWn_9r4Mmar_..._S0_5tR1ng5_4r3_m0r3_tHaN_qu3r13s_1n_th3_3nd}
</details>

### Alternative Approaches

- Boolean-based blind SQL injection
- Out-of-band data exfiltration

### Toolchain

- Burp Suite
- SQLMap with tamper scripts
- Custom Python scripts for payload generation

---

## so-hidden (Reversing/Mobile)

**Points:** 100  
**Solved by:** Individual  
**Competition:** UniVsThreats CTF 2025

### Challenge Analysis

Android application containing hidden flag accessed through native library.

### Phase 1-2: Recon & Scanning

- Decompiled APK using jadx and apktool
- Identified native library `libnative-lib.so`
- Found suspicious function: `Java_com_example_uvt_1ctf_12025_Utils_getHiddenFlag`
- Extracted relevant strings using `strings` command

### Phase 3: Exploitation

#### Solution Path

1. Analyzed native library with Ghidra
2. Reverse engineered `getHiddenFlag` function
3. Discovered hidden API endpoint path
4. Accessed endpoint via curl to retrieve flag

#### Flag Capture

<details>
  <summary>Flag (spoiler below)</summary>
  UVT{m0b1l3_.s0_m4y_c0nt4in_s3ns1tiv3_1nf0}
</details>

### Alternative Approaches

- Dynamic analysis with Frida
- Runtime debugging with Android Studio

### Toolchain

- jadx
- apktool
- Ghidra
- strings
- curl

---

## Conclusion

The UniVsThreats CTF 2025 provided challenges across multiple domains including pwn, web, and mobile security. Key skills demonstrated included memory analysis, WAF evasion, and mobile reverse engineering. Although not all challenges were solved, the competition offered valuable learning opportunities in advanced exploitation techniques.
