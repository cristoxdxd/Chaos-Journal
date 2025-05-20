---
challenge_name: "so_hidden"
category: "Reverse Engineering"
points: 500
solved_by: "Individual"
competition: "UniVsThreats CTF 2025"
---

# so_hidden Writeup

## Challenge Analysis

The challenge provided an APK file. Upon installation and execution, the app only displayed a joke and some irrelevant information. Static analysis revealed the presence of a native library (`libnative-lib.so`).

## Phase 1-2: Recon & Scanning

- **Relevant strings/headers found:**
  - Using `strings` on the APK and native library, the following were discovered:
    - IP address: `91.99.1.179`
    - Path: `/somebody-found-a-random-flag-path`
    - Function: `Java_com_example_uvt_1ctf_12025_Utils_getHiddenFlag`
- **Binary analysis:**
  - Decompiling with `Ghidra` and inspecting confirmed the native method call.
- **Web directory brute-forcing:**
  - Not applicable; the APK hinted directly at the path.

## Phase 3: Exploitation

### Solution Path

1. Extracted and decompiled the APK.
2. Identified the suspicious native function and analyzed `libnative-lib.so` with `strings` and Ghidra.
3. Found the IP and hidden path in the binary.
4. Used `curl` to access the endpoint and retrieve the flag `http://91.99.1.179:42234/somebody-found-a-random-flag-path`.

### Flag Capture

<details>
  <summary>Flag (spoiler below)</summary>
  UVT{m0b1l3_.s0_m4y_c0n t4in_s3ns1tiv3_1nf0}
</details>

## Alternative Approaches

- Dynamic analysis with Frida or hooking the native function at runtime.
- Using an emulator to monitor network requests from the APK.

## Toolchain

- `strings` (binary string extraction)
- `Ghidra` (native library reverse engineering)
- `curl` (HTTP request for flag retrieval)
