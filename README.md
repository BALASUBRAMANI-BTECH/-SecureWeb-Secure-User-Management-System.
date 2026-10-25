# SecureWeb – Secure User Management System

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.1.3-emerald.svg)](https://flask.palletsprojects.com/)
[![Tests](https://img.shields.io/badge/Tests-27%20Passed-brightgreen.svg)]()
[![Security](https://img.shields.io/badge/OWASP-Top%2010%20Hardened-cyan.svg)](https://owasp.org/www-project-top-ten/)

A modern, functional, and production-grade reference web application demonstrating secure user registration, session authentication, role-based authorization (RBAC), parameterized data storage, security telemetry auditing, and defense-in-depth protection based on **OWASP Top 10** cybersecurity principles.

---

## 1. Project Introduction & Architecture

Modern web systems encounter persistent threats: credential stuffing, session hijacking, SQL injection, cross-site scripting (XSS), cross-site request forgery (CSRF), and privilege escalation. **SecureWeb** provides an end-to-end engineered implementation where security controls are actively enforced in application logic, rather than being cosmetic placeholders.

### Key Capabilities:
- **Zero Plaintext Storage**: Passwords hashed using Werkzeug's GPU-resistant `scrypt` key derivation function with unique salts.
- **Role-Based Access Control (RBAC)**: Distinct permissions for `user` and `admin` roles, enforcing strict HTTP 403 Forbidden boundaries and Anti-IDOR safeguards.
- **CSRF Tokenization**: State-changing operations (including user registration, login, logout, profile updates, and admin role actions) are validated via cryptographic tokens.
- **Anti-Enumeration Authentication**: Uniform generic response messaging prevents threat actors from harvesting valid usernames or emails.
- **Adaptive Rate Limiting**: Intelligent request throttling on authentication endpoints (`/login`, `/register`) to neutralize brute-force attacks.
- **Forensic Audit Logging**: Database-backed audit journal tracking all authentication, authorization, and administrative events with IP addresses and UTC timestamps.
- **Modern Cyber UI**: Responsive glassmorphism interface styled with a cybersecurity dark navy palette, live password complexity evaluation, and micro-interactions.

---

## 2. Technology Stack

- **Backend**: Python 3.10+, Flask 3.1.3 (Application Factory pattern with Blueprints)
- **Database & ORM**: SQLite (development) with Flask-SQLAlchemy 3.1.1 (Parameterized ORM queries)
- **Authentication**: Flask-Login 0.6.3 (Server-side session management with `session_protection="strong"`)
- **Password Hashing**: Werkzeug 3.1.8 (`scrypt` algorithm)
- **Form Protection & CSRF**: Flask-WTF 1.3.0 and WTForms 3.2.2
- **Rate Limiting**: Flask-Limiter 4.1.1
- **Frontend**: HTML5, CSS3, Vanilla JavaScript, Bootstrap 5.3.3, Bootstrap Icons 1.11.3
- **Testing Framework**: pytest 8.3.3 and Flask test client

---

## 3. Directory Structure

```text
secureweb/
├── app/
│   ├── __init__.py            # Application factory, security headers, CLI commands, error handlers
│   ├── extensions.py          # Extension instances (db, login_manager, csrf, limiter)
│   ├── models.py              # User and AuditLog database models
│   ├── forms.py               # Flask-WTF forms with server-side validation & complexity rules
│   ├── utils.py               # @admin_required decorator, is_safe_url, audit logging helper
│   ├── auth/                  # Authentication Blueprint
│   │   ├── __init__.py
│   │   └── routes.py          # /register, /login, /logout (CSRF POST)
│   ├── main/                  # Main Application Blueprint
│   │   ├── __init__.py
│   │   └── routes.py          # / (landing), /dashboard, /profile, /change-password
│   ├── admin/                 # Administrator Governance Blueprint
│   │   ├── __init__.py
│   │   └── routes.py          # /admin, /admin/users, toggle-role, toggle-status, delete, audit-logs
│   ├── templates/             # Jinja2 Security Templates
│   │   ├── base.html          # Base layout with navbar, alerts, footer, and CSRF logout
│   │   ├── index.html         # Landing page with live telemetry & OWASP defense matrix
│   │   ├── login.html         # Rate-limited login with password toggle
│   │   ├── register.html      # Registration with dynamic password strength meter
│   │   ├── dashboard.html     # User telemetry, active session flags, and personal audit trail
│   │   ├── profile.html       # Profile update (Anti-IDOR bound)
│   │   ├── change_password.html # Password rotation with complexity verification
│   │   ├── errors/            # Custom error pages (no stack trace leakage)
│   │   │   ├── 400.html       # Bad Request / CSRF verification failure
│   │   │   ├── 403.html       # Access Forbidden (RBAC violation)
│   │   │   ├── 404.html       # Resource not found
│   │   │   ├── 429.html       # Rate limit exceeded
│   │   │   └── 500.html       # Internal server error
│   │   └── admin/             # Admin portal templates
│   │       ├── dashboard.html # System governance control center
│   │       ├── users.html     # Directory management (role toggling, locking, deletion)
│   │       └── audit_logs.html # Forensic audit log journal with status filtering
│   └── static/
│       ├── css/
│       │   └── style.css      # Dark cyber theme, glassmorphism, responsive styles
│       └── js/
│           └── main.js        # Real-time password strength meter & action confirmations
├── tests/                     # Automated Automated Test Suite (27 Tests)
│   ├── __init__.py
│   ├── conftest.py            # Pytest fixtures, test database setup, CSRF extractor
│   ├── test_auth.py           # Registration, complexity, login, generic error, logout tests
│   ├── test_authorization.py  # RBAC, 403 checks, IDOR bounds, CLI admin bootstrapping
│   ├── test_csrf.py           # CSRF token validation, missing token rejection, invalid token
│   └── test_security.py       # SQLi prevention, XSS escaping, security headers, open redirect, rate limit
├── config.py                  # Development, Testing, and Production configuration classes
├── run.py                     # Local development launcher
├── pytest.ini                 # Pytest configuration
├── requirements.txt           # Python dependency specifications
├── .env.example               # Environment variables template
├── .gitignore                 # Git ignore rules for virtual environments, secrets, databases
├── README.md                  # Comprehensive documentation and OWASP mapping
└── SECURITY.md                # Security policy, threat model, and deployment guidelines
```

---

## 4. Installation & Setup Guide

### Prerequisites
- Python 3.10 or higher installed on your system (`python --version`).
- `pip` package manager installed (`pip --version`).

### Step 1: Clone or Navigate to Project
```bash
cd c:/Users/balav/Documents/codeec/prj2
```

### Step 2: (Optional but Recommended) Virtual Environment
Create and activate an isolated virtual environment:
```bash
# Windows PowerShell
python -m venv venv
.\venv\Scripts\Activate.ps1

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Required Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Configure Environment Variables
Copy the configuration template:
```bash
# Windows PowerShell
Copy-Item .env.example .env

# Linux / macOS
cp .env.example .env
```
Generate a strong random secret key:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```
Open `.env` and set `SECRET_KEY=<generated-key>`.

### Step 5: Initialize the Database
Execute the database initialization CLI command:
```bash
flask --app run:app init-db
```
Output:
```text
[+] Database schema created successfully.
```

### Step 6: Create the Initial Administrator Account
Bootstrap the first administrator account safely through the interactive CLI command without hardcoding credentials in source code:
```bash
flask --app run:app create-admin --username admin --email admin@secureweb.local --password "AdminMasterKey123!@#"
```
Output:
```text
[+] Administrator account 'admin' created successfully!
```

---

## 5. Running the Application Locally

Start the local development server:
```bash
python run.py
```
Output:
```text
[*] Starting SecureWeb on http://127.0.0.1:5000 (Environment: development)
 * Serving Flask app 'app'
 * Debug mode: on
 * Running on http://127.0.0.1:5000
```
Open your browser and navigate to:
**`http://127.0.0.1:5000`**

### Demonstration Walkthrough:
1. **Landing Page (`/`)**: View system statistics, architecture highlights, and OWASP defense grid.
2. **User Registration (`/register`)**: Register an account (`test_analyst`). Notice the real-time password strength meter enforcing minimum 8 characters, uppercase, lowercase, numbers, and symbols.
3. **Authentication (`/login`)**: Log in with either username or registered email.
4. **User Dashboard (`/dashboard`)**: Inspect your authenticated session flags, telemetry, and personal audit trail.
5. **Unauthorized Access Test**: As a regular user, attempt to navigate to `/admin`. Notice you receive an **HTTP 403 Forbidden** error page and a warning is written to the audit log.
6. **Administrator Portal (`/admin`)**: Log out and sign in using the administrator credentials created in Step 6 (`admin`). Navigate to the **Admin Portal** to govern users, promote/demote roles, lock accounts, and view the system-wide forensic audit trail.

---

## 6. Running Automated Tests

SecureWeb includes an automated test suite containing 27 unit and integration tests verifying all features and OWASP Top 10 defenses.

Run the entire test suite with verbose output:
```bash
python -m pytest -v
```

Execute a specific test file:
```bash
python -m pytest tests/test_auth.py -v
python -m pytest tests/test_authorization.py -v
python -m pytest tests/test_csrf.py -v
python -m pytest tests/test_security.py -v
```

### Test Suite Coverage Summary:
- **Authentication (`test_auth.py`)**: Valid registration, duplicate username/email rejection, OWASP password complexity enforcement, plaintext password rejection, login with username/email, anti-enumeration generic messaging, session fixation defense, CSRF logout, and GET logout rejection.
- **Authorization & RBAC (`test_authorization.py`)**: Unauthenticated page redirects, standard user 403 enforcement on admin endpoints, admin portal access, self-demotion/self-deletion safeguards, role toggling, privilege escalation prevention, and CLI admin creation.
- **CSRF Protection (`test_csrf.py`)**: Missing token rejection (400), tampered token rejection (400), valid token acceptance, and logout CSRF validation.
- **Security & Vulnerability Defenses (`test_security.py`)**: SQL injection payload rejection, HTML escaping of XSS payloads, Content-Security-Policy & security headers inspection, anti-cache directives, open redirect neutralization, rate limiting throttle (429), and production configuration validation.

---

## 7. OWASP Top 10 Mitigation Matrix

| OWASP Category | Vulnerability Description | SecureWeb Technical Mitigation | Mitigation Status | Production Considerations |
| :--- | :--- | :--- | :--- | :--- |
| **A01: Broken Access Control** | Unauthorized privilege escalation, viewing/modifying other users' records (IDOR), unauthorized admin access. | Server-side `@login_required` and `@admin_required` decorators return HTTP 403 Forbidden. Profile queries bound strictly to `current_user.id`. Registration and profile forms forbid setting `role`. Admin self-demotion/deletion prevented. | **Mitigated** | Implement fine-grained object-level access control lists (ACL) when multi-tenant organizations are introduced. |
| **A02: Cryptographic Failures** | Plaintext password exposure, weak hashing, unencrypted session cookies. | Passwords hashed using Werkzeug's memory-hard `scrypt` algorithm. Session cookies use `HttpOnly`, `SameSite=Lax`, and `Secure=True` in production. | **Mitigated** | Enforce TLS 1.3 / HTTPS at the reverse proxy (Nginx/Cloudflare) and enable HTTP Strict Transport Security (HSTS). |
| **A03: Injection** | SQL injection (SQLi) altering database queries, Cross-Site Scripting (XSS). | Full adoption of SQLAlchemy ORM parameterized queries eliminates dynamic SQL concatenation. Jinja2 context-aware HTML auto-escaping prevents script execution in inputs. | **Mitigated** | Maintain strict ORM query hygiene; never call `db.session.execute(text(f"...{user_input}..."))`. |
| **A04: Insecure Design** | Credential stuffing, brute-force attacks, missing rate limits. | Flask-Limiter enforces rate limits (5 attempts/min on login, 10/min on registration). Failed attempts return HTTP 429 Too Many Requests. | **Mitigated** | In production clusters, back Flask-Limiter with an external Redis instance and integrate CAPTCHA/WAF defenses. |
| **A05: Security Misconfiguration** | Missing security headers, exposed debugging stack traces, default secret keys. | Injects `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and `Referrer-Policy`. Custom error handlers (400, 403, 404, 429, 500) suppress stack traces. ProductionConfig halts on default keys. | **Mitigated** | Remove unnecessary server banners at the web server layer (e.g. `server_tokens off;` in Nginx). |
| **A06: Vulnerable & Outdated Components** | Compromised third-party packages with known CVEs. | Pinned dependencies in `requirements.txt` using stable, actively maintained libraries (Flask 3.1+, SQLAlchemy 2.0+, Werkzeug 3.1+). | **Partially Addressed** | Integrate automated dependency scanners (`pip-audit`, Dependabot, Snyk) in CI/CD pipeline. |
| **A07: Identification & Authentication Failures** | Username enumeration, credential harvesting, session fixation. | Unified generic error message (`Invalid username/email or password.`). Old session identifier invalidated upon login via `session.clear()` and refreshed. Session idle timeout enforced (30 mins). | **Mitigated** | Add multi-factor authentication (MFA/TOTP) for high-privilege administrative accounts. |
| **A08: Software & Data Integrity Failures** | Cross-Site Request Forgery (CSRF), untrusted deserialization. | Flask-WTF tokenizes all state-changing POST/PUT requests with per-session cryptographic CSRF tokens. Secure JSON serialization used exclusively. | **Mitigated** | Sign all deployment artifacts and verify integrity hashes in package installations. |
| **A09: Security Logging & Monitoring Failures** | Undetected intrusion attempts, missing audit trails. | Dedicated `AuditLog` database model logs every registration, login success/failure, role alteration, and password change with timestamps and IP addresses. Admin log viewer included. | **Mitigated** | Stream logs to a centralized SIEM (Splunk, Elastic, Datadog) with real-time alerting on repeated failed logins. |
| **A10: Server-Side Request Forgery (SSRF) & Open Redirect** | Malicious redirect parameters steering users to phishing domains (CWE-601). | `is_safe_url()` validates the `next` query parameter, blocking external hosts, backslash bypasses, and protocol-relative `//` URLs. | **Mitigated** | If server-side fetching is introduced, whitelist allowed destination IP ranges and block access to cloud metadata services (`169.254.169.254`). |

---

## 8. Troubleshooting Tips

1. **Flask CLI says `command not found` or `ModuleNotFoundError: No module named 'app'`:**
   Ensure you run commands from the project root (`prj2/`) and specify `--app run:app`:
   ```bash
   flask --app run:app init-db
   ```
2. **`429 Too Many Requests` during manual testing:**
   The authentication rate limiter throttles repeated requests from `127.0.0.1`. Wait 60 seconds or restart the local development server to clear the in-memory throttle cache.
3. **Database locked or schema updates:**
   If modifying models locally, delete the local `instance/secureweb.db` file and re-run `flask --app run:app init-db`.
4. **Pytest execution:**
   Run `python -m pytest -v` using the active Python interpreter to ensure local packages and dependencies are loaded into `sys.path`.
