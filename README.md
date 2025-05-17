# 🛡️ Ultimate Web Security Cheatsheet

## 🔐 1. Input-Based Attacks

### ✅ XSS (Cross-Site Scripting)
- **Types**: Stored, Reflected, DOM-based
- **Payload**: `<script>alert('XSS')</script>`
- **Mitigations**:
  - Escape output (HTML, JS, URL, attribute)
  - Use Content Security Policy (CSP)
  - Avoid `innerHTML`, `document.write`

---

### ✅ SQL Injection
- **Types**: Classic, Blind, Union-based, Time-based
- **Payload**: `' OR 1=1 --`
- **Mitigations**:
  - Use prepared statements / parameterized queries
  - Avoid dynamic SQL
  - Restrict DB permissions

---

### ✅ Command Injection
- **Payload**: `ping 127.0.0.1; rm -rf /`
- **Mitigations**:
  - Validate and sanitize input
  - Use `escapeshellarg()` and `escapeshellcmd()`
  - Avoid unsanitized shell access

---

### ✅ Path Traversal
- **Payload**: `../../../../etc/passwd`
- **Mitigations**:
  - Use `realpath()` validation
  - Restrict to allowlisted directories
  - Block `../`, `/`, `\` in inputs

---

## 🌍 2. Request-Based Attacks

### ✅ CSRF (Cross-Site Request Forgery)
- **Attack**: Tricking a logged-in user to make unintended requests
- **Mitigations**:
  - CSRF tokens
  - `SameSite=Strict` cookies
  - Action confirmations

---

### ✅ SSRF (Server-Side Request Forgery)
- **Payload**: `http://127.0.0.1:3306`
- **Mitigations**:
  - Validate and sanitize URLs
  - Block internal IPs (127.0.0.1, 169.254.x.x)
  - Allowlist domains

---

### ✅ Open Redirect
- **Payload**: `/redirect?to=http://evil.com`
- **Mitigations**:
  - Only allow internal redirects
  - Validate URLs before redirect

---

## 🧠 3. Logic Flaws & Abuse

### ✅ Business Logic Abuse
- **Examples**:
  - Reusing coupons
  - Bypassing payment calculation
- **Mitigations**:
  - Backend validation
  - Rate limiting
  - Security reviews

---

### ✅ Broken Access Control
- **Example**: Accessing `/admin?id=2` without permission
- **Mitigations**:
  - Role-based access checks on backend
  - Avoid relying on frontend auth

---

### ✅ Rate Limiting Bypass
- **Example**: Brute-force using rotated headers
- **Mitigations**:
  - Normalize IP headers (`X-Forwarded-For`)
  - Lockout, CAPTCHA

---

## 🔁 4. Session & Token Security

### ✅ Session Fixation
- **Mitigation**: Regenerate session ID on login

### ✅ JWT Pitfalls
- **Risks**:
  - Weak HMAC secrets
  - `alg=none` exploits
- **Mitigations**:
  - Enforce secure JWT validation
  - Use expiration, revocation strategies

---

## 🛠️ 5. Network-Level Attacks

### ✅ DDoS (Distributed Denial of Service)
- **Types**:
  - Volume: UDP/SYN floods
  - App-layer: Slowloris, expensive routes
- **Mitigations**:
  - WAF, CDN (Cloudflare)
  - Rate limiting
  - Auto-scaling

---

### ✅ DNS Spoofing
- **Mitigations**:
  - DNSSEC
  - TLS verification

### ✅ IP Spoofing
- **Mitigations**:
  - Don't rely on IP for auth
  - Use token-based access control

---

## 📤 6. Data Leakage & Injection

### ✅ Information Disclosure
- **Risks**: Error messages, `.env`, `.git/` files
- **Mitigations**:
  - Disable verbose errors in production
  - Block access to sensitive files

---

### ✅ File Upload Attacks
- **Risks**: RCE via fake image/PHP file
- **Mitigations**:
  - Check MIME type and extension
  - Store files outside web root
  - Sanitize filename and scan for viruses

---

### ✅ Log Injection
- **Payload**: `\n[ERROR] attacker input`
- **Mitigations**:
  - Sanitize log entries
  - Use structured logging

---

## 🕵️ 7. Scraping, Sniffing, Spoofing

### ✅ Web Scraping
- **Mitigations**:
  - Rate limit
  - CAPTCHA
  - API keys and request verification

---

### ✅ Packet Sniffing
- **Risk**: Data over HTTP
- **Mitigations**:
  - Enforce HTTPS
  - Use HSTS

---

### ✅ Spoofing (User-Agent, IP, identity)
- **Mitigations**:
  - Token-based verification
  - Device fingerprinting
  - Avoid trusting headers blindly

---

## 🔧 8. Secure Headers Checklist

| Header | Purpose |
|--------|---------|
| `X-Content-Type-Options: nosniff` | Block MIME sniffing |
| `X-Frame-Options: DENY` | Prevent clickjacking |
| `Strict-Transport-Security` | Force HTTPS |
| `Content-Security-Policy` | Block XSS |
| `Referrer-Policy: no-referrer` | Hide referer |

---

## 💾 9. Cryptography & Storage

- Use `bcrypt`, `argon2` for password hashing
- Avoid `md5`, `sha1`
- Use `openssl_random_pseudo_bytes()` or `random_bytes()` for secure tokens
- Never store secrets in code; use `.env` or secure vaults
- Always use HTTPS

---

## 🛠 Tools & Testing

| Tool | Purpose |
|------|---------|
| Burp Suite | Manual testing & interception |
| OWASP ZAP | Automated security scanner |
| sqlmap | SQL Injection testing |
| nmap | Port & network scanner |
| wpscan | WordPress vulnerability scanner |
| Nikto | Web server scanner |

---

## 🧠 Security Principles to Remember

- **Least Privilege**: Minimal access for users/processes
- **Defense in Depth**: Multiple security layers
- **Fail Securely**: Default to deny
- **Secure by Default**: Harden configs and remove dev artifacts
- **Don’t Roll Your Own Crypto**: Use tested libraries

---

> 🔒 Stay updated with OWASP Top 10 and CVEs relevant to your tech stack.
