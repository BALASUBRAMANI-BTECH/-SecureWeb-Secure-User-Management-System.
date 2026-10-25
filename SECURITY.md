# Security Policy – SecureWeb

This document outlines the security architecture, implemented defense mechanisms, threat model assumptions, known operational limitations, and production deployment recommendations for the **SecureWeb – Secure User Management System**.

---

## 1. Implemented Security Controls

### 1.1 Cryptographic Password Hashing
- **Algorithm**: Werkzeug's implementation of `scrypt` (or `pbkdf2:sha256` fallback).
- **Salt**: Cryptographically random salt generated per-user automatically.
- **Verification**: Constant-time string comparison (`hmac.compare_digest`) prevents timing attacks during authentication.
- **Rule**: Plaintext passwords are never logged, cached, transmitted unencrypted, or stored in any persistent medium.

### 1.2 Session Management & Anti-Session Fixation
- **Session Protection**: Flask-Login `session_protection = "strong"` binds active sessions to user agent and IP signatures.
- **Fixation Defense**: On successful authentication (`/login`), `session.clear()` is called to flush unauthenticated session attributes before initializing the authenticated session identity.
- **Cookie Security Attributes**:
  - `HttpOnly = True`: Prevents client-side JavaScript execution from accessing session cookies, neutralizing session theft via XSS.
  - `SameSite = 'Lax'`: Mitigates Cross-Site Request Forgery on top-level cross-site navigations.
  - `Secure = True`: Enforced in `ProductionConfig` to mandate TLS/HTTPS transmission.
  - `Lifetime`: Enforces a 30-minute idle expiration (`PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)`).

### 1.3 Cross-Site Request Forgery (CSRF) Protection
- **Mechanism**: Flask-WTF `CSRFProtect` validates cryptographically signed tokens on all state-changing HTTP requests (`POST`, `PUT`, `DELETE`).
- **Token Rotation**: State-changing operations include hidden tokens tied to the active session.
- **Logout Endpoint**: `/logout` mandates a valid CSRF token and rejects `GET` requests with HTTP 405 to prevent involuntary sign-out attacks.

### 1.4 Injection & SQL Injection Prevention
- **Database Abstraction**: Flask-SQLAlchemy ORM with parameterized queries.
- **Sanitization**: Form inputs are validated with WTForms regex and length constraints.
- **No Raw Concatenation**: Zero dynamic string interpolation in SQL statements.

### 1.5 Cross-Site Scripting (XSS) Defenses
- **Template Escaping**: Jinja2 auto-escapes all context variables by default.
- **Content-Security-Policy (CSP)**:
  ```http
  Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net; img-src 'self' data: https:; connect-src 'self'; frame-ancestors 'none'; form-action 'self';
  ```
- **Clickjacking Defense**: `X-Frame-Options: DENY` and `frame-ancestors 'none'` prevent embedding in malicious iframes.

### 1.6 Role-Based Access Control (RBAC) & IDOR Defenses
- **Server-Side Enforcement**: `@admin_required` and `@login_required` decorators verify roles strictly on the server; client-side checks are purely cosmetic.
- **Privilege Separation**:
  - `user`: Permitted to access personal dashboard and update own contact profile.
  - `admin`: Authorized to access administrative user directory and system audit logs.
- **Insecure Direct Object Reference (IDOR)**: User profile reads and updates are bound to `current_user.id`, ignoring arbitrary foreign user IDs in query parameters.
- **Self-Governance Locks**: Administrators cannot demote or delete their own accounts, preventing accidental lockouts or privilege loss.

### 1.7 Brute-Force & Credential Stuffing Throttling
- **Rate Limiting**:
  - `/login`: 5 attempts per minute per IP address.
  - `/register`: 10 attempts per minute per IP address.
- **Anti-Enumeration**: Authentication failures return a unified generic notice (`Invalid username/email or password.`).

### 1.8 Security Logging & Forensic Auditing
- **Audit Table**: `AuditLog` records timestamp, username, action (`LOGIN_SUCCESS`, `LOGIN_FAILED`, `ADMIN_ROLE_CHANGE`, etc.), status, remote IP, and details.
- **Suppressed Error Traces**: Custom error handlers (400, 403, 404, 429, 500) ensure internal stack traces are never exposed to end-users.

---

## 2. Threat Assumptions & Threat Model

1. **Untrusted Client Environment**: The client browser and network connection are considered hostile. All data originating from the client is treated as untrusted and re-validated server-side.
2. **Network Interception**: Plain HTTP traffic is vulnerable to eavesdropping and manipulation. Local testing runs on HTTP; production environments assume mandatory TLS/HTTPS encryption.
3. **Malicious Authenticated Principals**: Standard authenticated users are presumed capable of attempting horizontal (IDOR) and vertical (role tampering) privilege escalation.
4. **Automated Adversaries**: Credential stuffers and script-driven brute-forcers will target public authentication endpoints.

---

## 3. Known Limitations & Boundary Conditions

- **Single-Factor Authentication**: SecureWeb currently implements single-factor authentication (passwords). While fortified with `scrypt` and complexity checks, high-assurance production systems should implement Multi-Factor Authentication (MFA / TOTP / WebAuthn).
- **SQLite Concurrency**: SQLite is configured for local development and collegiate demonstrations. For concurrent high-traffic production workloads, PostgreSQL or MySQL with connection pooling should be deployed.
- **Rate Limiting Storage**: The default rate limiting backend uses in-memory storage (`memory://`), which resets upon process restart. Production multi-instance deployments require a shared Redis instance.
- **No Automated Account Recovery**: Password resets via email are omitted to avoid unauthenticated email enumeration or insecure reset token delivery in local testing.

---

## 4. Production Deployment Recommendations

When transitioning from local development to production:

1. **Mandatory HTTPS Enforcement**:
   - Terminate TLS 1.3 at a secure reverse proxy (Nginx, Caddy, or Cloudflare).
   - Set `SESSION_COOKIE_SECURE = True` in `.env`.
   - Add `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`.
2. **Cryptographic Secret Key**:
   - Never use development defaults. Generate a 256-bit entropy key:
     ```bash
     python -c "import secrets; print(secrets.token_hex(32))"
     ```
   - Store the key exclusively in environment variables or a secrets manager (HashiCorp Vault, AWS Secrets Manager).
3. **Database Migration**:
   - Use PostgreSQL (`postgresql://user:pass@host:5432/secureweb`).
   - Use `Flask-Migrate` (Alembic) for schema versioning.
4. **Redis for Rate Limiting**:
   - Configure `RATELIMIT_STORAGE_URI=redis://:password@redis-server:6379/0`.
5. **Least Privilege System Account**:
   - Run the WSGI worker (Gunicorn / uWSGI) under a dedicated non-root Linux user (`www-data`).

---

## 5. Vulnerability Reporting Protocol

If you discover a security vulnerability in this project, please follow responsible disclosure guidelines:
- Submit a detailed report explaining the reproduction steps, affected endpoint, and potential impact.
- Do not publicly disclose or exploit the vulnerability until a fix has been verified and deployed.
