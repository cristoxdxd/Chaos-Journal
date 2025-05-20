---
challenge_name: "0xL0cK"
category: "Misc"
points: 500
solved_by: "Individual"
competition: "UniVsThreats CTF 2025"
---

# 0xL0cK Writeup

## Challenge Analysis

The terminal screen remains unnaturally active, with no flickering or static. The challenge hints at interacting with a machine that expects specific commands and responds in unusual ways. A connection is provided: `nc 91.99.1.179 8654`.

## Phase 1-2: Recon & Scanning

- Connected to the service using `nc 91.99.1.179 8654`.
- Entered `HELP` to display available commands:
  - `LIST` - View visible system files
  - `VIEW <file>` - Display contents of a file
  - `MEMDUMP` - Display memory sectors (restricted)
  - `AUTH` - Attempt authentication
  - `HELP` - Show help menu
  - `RESTART` - Reboot interface
  - `EXIT` - Close session
- Used `LIST` to see accessible files.
- Used `VIEW <file>` to inspect files from the list.
- Ran `MEMDUMP` to display memory sectors, searching for possible credentials.
- Tried `AUTH <password>` with words found in `MEMDUMP`, discovering `AUTH SURVIVOR` was correct.

## Phase 3: Exploitation

### Solution Path

1. Connect to the service: `nc 91.99.1.179 8654`
2. Display help and available commands `HELP`
3. List files `LIST`
4. View file contents `VIEW <file>`
5. Dump memory sectors for clues `MEMDUMP`
6. Attempt authentication with found credentials `AUTH`, with `SURVIVOR` works.
7. Upon successful authentication, new commands become available:
    - `LIST -A` - View all system files (level 2 access)
    - `DECRYPT <file>` - Decrypt protected files
    - `ANALYZE` - Run memory pattern analysis
    - `UNLOCK <file>` - Attempt to unlock a restricted file (level 2 access)
    - `ADMIN` - Log as admin
8. Analyze memory for patterns `ANALYZE`
9. Unlock restricted file `UNLOCK vault.log` with the address corrupted.
10. Obtain the key from `vault.log` and decrypt the `.emergency_override` file `DECRYPT .emergency_override`
11. View the decrypted file `VIEW .emergency_override`
    - Reveals an encrypted RSA message.
12. Use the obtained key to decrypt and reveal the admin password: `Adm1NP4a55wordNoTS0Secure`.
13. Authenticate as admin with the command `ADMIN` using the password decrypted.
14. Notice the flag is now in `.memdump_cache` (encrypted).
15. View the encrypted flag `VIEW .memdump_cache`
16. Decrypt the flag
    - Reveals the final flag.

### Flag Capture

<details>
        <summary>Flag (spoiler below)</summary>
        UVT{Th3_m3ch4n1sM_UNs3a15_4nd_tH3_DaRK_uNBl1nk5}
</details>

## Alternative Approaches

- Automate interaction with a script to test command and memory address combinations.
- Analyze patterns in the memory dump to identify other possible credentials or keys.

## Toolchain

- netcat (`nc`)
- base64 encoder/decoder
- RSA decryption tools
- Hex editors (e.g., `xxd`, `hexedit`)
