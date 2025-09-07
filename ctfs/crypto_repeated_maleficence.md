---
challenge_name: "Repeated Maleficence"
category: "Crypto"
solved_by: "Individual"
competition: "Latin America and Caribe Team Selection Event 2025"
---

# Repeated Maleficence

After successfully uncovering the first key, you find yourself being pursued by the powerful corporation known as "101". The company's leader is determined to eliminate you, but you managed to intercept their internal communications. The problem is, the information is encrypted. Can you decipher it, so that you can stay one step ahead of your pursuers?

## Challenge Analysis

We are given two files:
- `source.py`: A Python script that encrypts a flag using a XOR cipher with a 5-byte random key.
- `encrypted.txt`: A hex-encoded ciphertext.

The encryption process XORs each byte of the message with a repeating 5-byte key. Since the key is short and the plaintext (flag) has a known format ("HTB{...}"), this is vulnerable to a known-plaintext attack.

## Phase 1: Recon & Static Analysis

- The ciphertext is 35 bytes long (70 hex characters).
- The flag is encrypted using a XOR cipher with a 5-byte key.
- The encryption and decryption functions are identical (XOR is symmetric).

## Phase 2: Key Recovery via Known-Plaintext Attack

1. **Assume the flag starts with "HTB{"**:
   - The first 4 plaintext bytes are known: `H` (72), `T` (84), `B` (66), `{` (123).
   - XOR these with the first 4 ciphertext bytes to recover the first 4 key bytes:
     - `key[0] = 114 ^ 72 = 58`
     - `key[1] = 12 ^ 84 = 88`
     - `key[2] = 65 ^ 66 = 3`
     - `key[3] = 3 ^ 123 = 120`

2. **Brute-force the 5th key byte**:
   - Iterate over all possible values for `key[4]` (0-255).
   - For each candidate, decrypt the entire ciphertext and check if all resulting bytes are printable ASCII (32-126).
   - The correct `key[4]` (240) yields a fully printable flag that starts with "HTB{" and ends with "}".

## Phase 3: Exploitation

### Solution Path

1. Extract the ciphertext from `encrypted.txt` and convert to bytes.
2. Recover the first 4 key bytes by XORing the first 4 ciphertext bytes with "HTB{".
3. Brute-force the 5th key byte to find the value that makes the entire decrypted message printable.
4. Decrypt the full ciphertext with the complete key `[58, 88, 3, 120, 240]`.

### Flag Capture

<details>
  <summary>Flag (spoiler below)</summary>
  HTB{x0r_1S_w34k_w15h_kn0wn_p141n53x5}
</details>

## Alternative Approaches

- Instead of brute-forcing `key[4]`, one could assume the flag contains common words (e.g., "xor", "weak", "known") and solve for the key using frequency analysis.

## Toolchain

- Python for decryption and brute-forcing.
- No specialized tools required—just basic XOR operations and byte manipulation.
