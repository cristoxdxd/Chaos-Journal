---
name: "Injection"
platform: "DockerLabs"
author: "El Pingüino de Mario"
difficulty: "easy"
date_solved: "2025-05-19"
techniques: ["SQL Injection", "SSH Access", "SUID Abuse"]

---

# Injection Writeup

## Overview

Injection is a Linux-based machine focused on web application exploitation and local privilege escalation. The main theme revolves around exploiting SQL injection vulnerabilities to gain initial access, followed by abusing misconfigured SUID binaries for privilege escalation. This machine fits into the Web and Privilege Escalation CTF categories.

## Reconnaissance

### Passive Information Gathering

- Tools: None used for OSINT.
- No domains/subdomains identified.
- No metadata discovered.

### Active Scanning

- Nmap scan:  
    `nmap -sCV -sS -n -Pn -p- 172.17.0.2`
- Key ports/services found:
  - 22/tcp (OpenSSH)
  - 80/tcp (HTTP)

## Scanning

### Vulnerability Analysis

- Tools: Manual testing, browser.
- Critical vulnerability: SQL Injection on the login form.
- Manual testing with payload `' or 1=1 -- -` bypassed authentication.

## Gaining Access

### Initial Foothold

- Exploit: SQL Injection (`' or 1=1 -- -`) on the web login.
- Vulnerability chain: SQLi → Access to Dylan's account → Password disclosure.
- SSH login as `dylan` using the obtained password.

### Privilege Escalation

- Escalation path: SUID binary abuse.
- Misconfiguration: SUID bit set on `/usr/bin/env`.
- Command used:

    ```bash
    find / -user root -perm -4000 -type f 2>/dev/null
    /usr/bin/env /bin/bash

    ```

- Final privilege: Root access (`whoami` returns `root`).

## Maintaining Access

### Persistence Mechanisms

- No backdoors installed.
- No credential harvesting performed.

## Covering Tracks

### Artifact Removal

- No log cleaning performed.
- No file timestamp manipulation.
- No anti-forensics techniques used.

## Lessons Learned

- Importance of input validation to prevent SQL injection.
- SUID binaries can be dangerous if misconfigured.
- Manual testing is crucial for discovering simple but impactful vulnerabilities.

## References

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [GTFOBins: env](https://gtfobins.github.io/gtfobins/env/)
- [Nmap](https://nmap.org/)
