---
challenge_name: "Predictable"
category: "Web"
solved_by: "Individual"
competition: "Latin America and Caribe Team Selection Event 2025"
---

# Predictable Writeup

You've been tasked on a pentest engagement to understand the token generation process and exploit it, do you have what it takes?

## Challenge Analysis

The challenge involves a Node.js web application with password reset functionality. The application uses Express.js with EJS templating and has an admin dashboard that displays the flag when accessed with admin credentials. The main vulnerability lies in the predictable token generation algorithm used for password resets.

## Phase 1-2: Recon & Scanning

Initial analysis revealed a web application with user registration, login, and password reset functionality. The application structure includes multiple routes handled by separate JavaScript files. Key endpoints discovered include /register, /login, /forgot-password, /reset-password, and /dashboard. The admin user was identified as admin@hackthebox.com, and the flag is displayed on the dashboard when authenticated as admin.

Static analysis of the source code showed that the password reset token generation uses a predictable algorithm: const token = crypto.createHash('md5').update(email + currentTime.toString()).digest('hex'). This creates a deterministic token based on email and timestamp without any random components, making it vulnerable to timing attacks.

## Phase 3: Exploitation

### Solution Path

1. Identified the token generation vulnerability in ResetToken.js where tokens are created using MD5 hash of email concatenated with current timestamp in milliseconds
2. Attempted to calculate the exact timestamp by analyzing email headers from test password reset requests
3. Discovered timezone discrepancies between the server and local machine that complicated timestamp prediction
4. Implemented a live timing attack to measure server response times and estimate token generation timing
5. Developed brute force scripts to try tokens generated from timestamps in a ±60 second window around the request time
6. The exploitation strategy involved requesting a password reset for admin@hackthebox.com, then using the predictable algorithm to generate potential tokens based on estimated server processing time

The breakthrough insight was recognizing that the token generation is completely deterministic and based on server processing time, allowing for brute force attacks against the reset token validation. The lack of rate limiting on the reset-password endpoint made this approach feasible.

## Alternative Approaches

Several alternative approaches were considered but not fully implemented due to time constraints. These included analyzing server response headers for timing information, attempting to extract exact timestamps from email preview functionality, and using network packet analysis to precisely measure server processing time. Another potential approach was to register multiple test users to better calibrate the timing relationship between request sending and token generation.

## Toolchain

The exploitation utilized Python 3 with requests library for HTTP interactions, hashlib for MD5 token generation, and time module for precise timing measurements. Manual testing was conducted using curl and web browser developer tools to understand API endpoints and response formats. The challenge required careful timing analysis and brute force scripting due to the predictable nature of the token generation algorithm.
