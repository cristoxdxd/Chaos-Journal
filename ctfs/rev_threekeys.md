---
challenge_name: "ThreeKeys"
category: "Reversing"
solved_by: "Individual"
competition: "Latin America and Caribe Team Selection Event 2025"
---

# ThreeKeys Writeup

You've gathered the three secret keys and you're ready to claim your prize. But in your rush, the keys have got mixed up - which one goes where?

## Challenge Analysis

The challenge involves a binary named 'threekeys' that requires three keys to be provided in the correct order to decrypt and display the flag. Static analysis using Ghidra revealed that the program uses hardcoded keys obtained from functions named `the_first_key()`, `the_second_key()`, and `the_third_key()`. The decryption process involves AES decryption routines, and the keys are applied in the order: third key, second key, then first key. The program compares the decrypted output against the expected flag format to determine success.

## Phase 1-2: Recon & Scanning

- Strings analysis showed prompts like "[*] Insert the three keys to claim your prize!" and "[*] Just be careful to insert them in the right order...", but no direct key strings were found in plaintext.
- Binary analysis in Ghidra indicated that the program does not accept user input; instead, it relies on internal functions to retrieve keys.
- The functions `the_first_key()`, `the_second_key()`, and `the_third_key()` were identified as returning strings used for decryption. The program calls `decrypt` three times using these keys in reverse order (third, second, first).

## Phase 3: Exploitation

### Solution Path

1. Decompiled the binary using Ghidra to understand the key retrieval and decryption flow.
2. Identified that the keys are hardcoded and accessed via specific functions, but the returned strings were not immediately visible in the decompilation.
3. Recognized that the decryption order (third key first, then second, then first) might imply a specific sequence required for successful decryption.
4. Attempted to dynamically analyze the binary to extract key values, but the program lacked input mechanisms and relied on internal state.

## Alternative Approaches

- Patching the binary to modify the key strings returned by the functions to common key guesses (e.g., based on Ready Player One lore) was considered but not implemented due to complexity.
- Emulating the decryption process externally by extracting the encrypted data and key values from the binary could have been pursued if the keys were identified.

## Toolchain

- Ghidra for static analysis and decompilation.
- Strings utility for initial binary inspection.
- Linux environment for execution attempts.
