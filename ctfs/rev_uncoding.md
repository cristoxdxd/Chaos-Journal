---
challenge_name: "Uncoding"
category: "Reversing"
solved_by: "Individual"
competition: "Latin America and Caribe Team Selection Event 2025"
---

# Uncoding Writeup

Deep in the archives of Halliday's memories, you've come across a secret cabinet - extra layers of protection have been applied to these memories. What secrets could they hide?

## Challenge Analysis

The challenge involved analyzing a hex dump of an ELF binary that contained references to Halliday's memories from Ready Player One. The binary presented four options (0-3) when executed, each revealing different memory fragments. Static analysis showed the binary contained functions like `decrypt_message` and referenced encrypted messages, suggesting the need to decrypt hidden content to find the flag.

## Phase 1-2: Recon & Scanning

- The provided file was a hex dump of an ELF executable, which was reconstructed using `xxd -r -p` into a working binary.
- Strings analysis revealed prompts like "Which memory would you like to review today (0 -> 3)?" and error messages such as "-- ERROR -- [That memory has been locked away!] -- ERROR --".
- Executing the binary and testing options 0-3 yielded textual outputs referencing Ready Player One themes: option 0 described three challenges and keys, option 1 discussed an invisible key in a maze, option 2 referenced a racing challenge, and option 3 returned an error.
- Ghidra decompilation showed a `main` function that called `decrypt_message` for certain options, but the exact decryption logic was not fully reversed during the attempt.

## Phase 3: Exploitation

### Solution Path

1. Ran the binary and interacted with the menu, capturing outputs for each option.
2. Options 1 and 2 produced meaningful narrative texts, while options 0 and 3 provided descriptive context or errors.
3. Attempted to analyze the `decrypt_message` function in Ghidra to understand the decryption mechanism but faced challenges in identifying the exact algorithm or key.
4. The outputs hinted at three keys from the Ready Player One story.

## Alternative Approaches

- Dynamic analysis using GDB to trace the `decrypt_message` function could have revealed the decryption process.
- Brute-forcing the decryption with common XOR keys or substitution ciphers might have been effective if the encrypted messages were extracted.
- Focusing on the strings in the binary might have revealed embedded encrypted data or keys.

## Toolchain

- Ghidra for static analysis and decompilation.
- Linux command-line for execution and strings analysis.
