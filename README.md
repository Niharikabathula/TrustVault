# TrustVault: Confidential Multi-Tenant Document Sharing Platform
**Snovasys Fresher Hiring Challenge 2026**

TrustVault is an enterprise-grade, secure, multi-tenant document-sharing platform engineered to enable organizations to upload, organize, share, and manage sensitive business documents with strict role-based access control, cryptographic isolation, and tamper-resistant audit accountability.

---

## 1. Project Overview & Problem Statement

### The Problem
Organizations face significant risks when sharing confidential documents (financial records, legal contracts, executive memos, HR data):
- **Cross-tenant data leaks**: Accidental cross-company access in multi-tenant SaaS.
- **Insecure Direct Object References (IDOR)**: Attackers guessing or altering document IDs in URLs.
- **Privilege Escalation**: Viewers gaining administrative or ownership rights by tampering with requests.
- **Unchecked Downloads**: Users retaining download access after permissions are revoked.
- **Malicious Uploads**: Attackers uploading web shells or executable polyglots disguised as documents.
- **Missing Non-Repudiation**: Absence of reliable, append-only audit trails.

### The Solution: TrustVault
TrustVault addresses these risks through **defense-in-depth security engineering**:
1. **Strict Multi-Tenancy**: Complete isolation between organizations. Company A users can never view, download, or discover Company B documents.
2. **Server-Derived Context**: Tenant identity is extracted exclusively from the authenticated session. Browser requests can never dictate tenant scope.
3. **Role-Based Access Control (RBAC)**: Centralized permissions for `ADMIN`, `OWNER`, and `VIEWER`.
4. **Dynamic Download Authorization**: Grants are validated live on every single download request. Revoking access immediately cuts off future downloads.
5. **Private Disk Storage**: Uploaded files are stored outside the web root with randomized UUID filenames, neutralizing path traversal and public URL exposure.
6. **Append-Only Audit Logging**: All security-relevant actions (login, upload, download, share, revoke, access denied) are recorded with actor and tenant context.

---

## 2. Technology Stack & Justification

| Layer | Technology | Justification |
| :--- | :--- | :--- |
| **Backend** | Python 3.13 + Flask 3.0 | Modular, beginner-friendly, and gives transparent, granular control over HTTP headers, session security, and middleware. |
| **ORM** | SQLAlchemy 2.0 | Automatically uses parameterized SQL queries, eliminating SQL injection by default. |
| **Dev Database** | SQLite 3 (WAL Mode) | Built into Python standard library, zero setup, enables isolated in-memory test suites. |
| **Production DB**| PostgreSQL 16+ | Evaluated for production multi-tenant concurrency; supports true row-level locking and simultaneous connections. |
| **Security** | Flask-WTF & Werkzeug | Automated CSRF token validation and modern salted password hashing (Scrypt / PBKDF2). |
| **Testing** | pytest 8.3 + pytest-cov | Automated fixture-driven testing for authentication, tenant isolation, and security boundaries. |
| **UI Design** | HTML5, CSS Tokens | Modern enterprise palette (Navy `#1e3a8a`, Steel Blue `#2563eb`), responsive mobile drawer, 44x44px touch targets. |

---

## 3. Database Schema

All database models use non-guessable UUID primary keys and strict tenant scoping:

```
TENANTS (id, name, slug, is_active, created_at, updated_at)
   │
   ├── USERS (id, tenant_id, email, password_hash, full_name, role, is_active, failed_login_attempts, locked_until)
   │     │
   │     └── DOCUMENTS (id, tenant_id, owner_id, title, description, category, original_filename, storage_key, file_size_bytes, mime_type, sha256_checksum, is_deleted)
   │           │
   │           └── DOCUMENT_ACCESS_GRANTS (id, tenant_id, document_id, granted_to_user_id, granted_by_user_id, permission_level, created_at, revoked_at)
   │
   └── AUDIT_EVENTS (id, tenant_id, actor_id, actor_email, actor_role, action, resource_type, resource_id, outcome, ip_address, user_agent, details_json, created_at)
```

---

## 4. Role & Permission Matrix (RBAC)

| Feature / Action | ADMIN | OWNER | VIEWER | Security Boundary Rule |
| :--- | :---: | :---: | :---: | :--- |
| **Tenant Onboarding** | Public Registration | ❌ | ❌ | Creates new Tenant and registers initial Admin only. |
| **User Provisioning & Roles** | ✅ | ❌ | ❌ | Admin provisions users within own tenant; assigns `OWNER` or `VIEWER`. Self-assignment is blocked. |
| **User Status (Deactivation)** | ✅ | ❌ | ❌ | Admin toggles active/inactive. Inactive accounts are blocked immediately at session level. |
| **Upload Document** | ❌ | ✅ | ❌ | Owner role uploads confidential files. |
| **Manage Access (Grant/Revoke)**| ✅ (Tenant-wide) | ✅ (Owned docs) | ❌ | **Admin & Owner only**. Grants only to active users in the same tenant. |
| **View Access Grants List** | ✅ (Tenant-wide) | ✅ (Owned docs) | ❌ | Inspect who has active/revoked access to a document. |
| **View Governance Metadata** | ✅ (Tenant-wide) | ✅ (Owned docs) | ✅ (Shared docs) | Minimal metadata shown to Admin (ID, Title, Owner, Category, Size). Sensitive description hidden. |
| **Download Document Content** | ❌ (Unless granted)| ✅ (Owned docs) | ✅ (Shared docs) | Dynamic re-check on every download request. Blocked immediately upon revocation. |
| **Edit Document Metadata** | ❌ | ✅ (Owned docs) | ❌ | Owner edits title, description, and category. |
| **Delete Document** | ❌ | ✅ (Owned docs) | ❌ | **Owner-only soft deletion**. Marks deleted and revokes grants; audit records preserved. |
| **View Tenant Audit Logs** | ✅ | ❌ | ❌ | Admin inspects append-only tenant audit events. Cross-tenant logs strictly inaccessible. |

---

## 5. Local Setup & Installation

### Prerequisites
- Python 3.11+ (Python 3.13 installed)
- Git 2.x

### Step 1: Clone or Navigate to Project
```bash
cd TrustVault_new
```

### Step 2: Configure Environment
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
*(On Windows PowerShell: `Copy-Item .env.example .env`)*

### Step 3: Install Dependencies
```bash
python -m pip install -r requirements.txt
```

### Step 4: Run the Application
```bash
python wsgi.py
```
Open your browser at `http://127.0.0.1:5000`.

---

## 6. How to Run the Test Suite

Execute the automated pytest suite:
```bash
python -m pytest tests/ -v
```

All 21 Phase 2 security, isolation, and regression tests will execute:
```
tests/test_auth.py::test_tenant_registration_success PASSED
tests/test_auth.py::test_tenant_registration_honeypot_bot_rejection PASSED
tests/test_auth.py::test_login_success_and_session_rotation PASSED
tests/test_auth.py::test_login_invalid_password_generic_error PASSED
tests/test_auth.py::test_login_brute_force_lockout PASSED
tests/test_auth.py::test_login_deactivated_account_blocked PASSED
tests/test_auth.py::test_logout_clears_session PASSED
tests/test_auth.py::test_security_headers_present PASSED
tests/test_auth.py::test_csrf_protection_enforced_when_enabled PASSED
tests/test_auth.py::test_login_ip_rate_limiting_unknown_emails PASSED
tests/test_auth.py::test_password_max_length_enforcement PASSED
tests/test_auth.py::test_audit_nested_metadata_sanitization PASSED
tests/test_tenant_isolation.py::test_user_strict_single_tenant_membership PASSED
tests/test_tenant_isolation.py::test_enforce_tenant_boundary_opaque_404 PASSED
tests/test_tenant_isolation.py::test_manage_document_access_permissions PASSED
tests/test_tenant_isolation.py::test_owner_only_document_deletion_policy PASSED
tests/test_tenant_isolation.py::test_download_authorization_and_revocation PASSED
tests/test_tenant_isolation.py::test_deactivated_user_immediate_session_kickout PASSED
tests/test_tenant_isolation.py::test_user_global_email_uniqueness PASSED
tests/test_tenant_isolation.py::test_deactivated_tenant_immediate_session_kickout PASSED
tests/test_tenant_isolation.py::test_sqlite_foreign_key_enforcement PASSED
```

---

## 7. Security Architecture & Threat Mitigations

See [THREATS.md](THREATS.md) for the detailed 15-threat analysis matrix covering STRIDE categories, mitigations, verification methods, and residual risks.

Key Highlights:
- **Global Identity Uniqueness**: `User.email` is globally unique, eliminating multi-tenant login collision.
- **Session Data Clearing**: `session.clear()` flushes untrusted pre-login attributes before issuing authenticated session cookies.
- **Two-Tier Brute-Force Rate Limiting**: IP-based sliding window rate limiter protects against unknown-email spraying; 5 failed password attempts locks the user account for 15 minutes.
- **Live CSRF Rejection**: Integration tests verify that forged POST requests without CSRF tokens are rejected with HTTP 400.
- **SQLite Foreign Key Enforcement**: `Engine.connect` event listener guarantees `PRAGMA foreign_keys = ON;` across all connections.
- **Recursive Audit Sanitization**: Deeply nested metadata dictionaries and lists have sensitive keys (`password`, `token`, `secret`, `api_key`) automatically redacted.
- **Opaque 404 Responses**: Unauthorized cross-tenant lookups return `404 Not Found` rather than `403 Forbidden` to prevent resource existence enumeration.
- **Immediate Deactivation Revocation**: Deactivated accounts and deactivated organizations have active sessions terminated on their very next request.

---

## 8. AI Assistance & Traceability

TrustVault is developed with full transparency regarding AI assistance. See [PROMPTS.md](PROMPTS.md) for detailed records of prompts, reviews, flaw identifications, and candidate corrections.
