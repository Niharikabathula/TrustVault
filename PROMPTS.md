# TrustVault: AI Interaction & Traceability Log (PROMPTS.md)
**Project**: TrustVault — Enterprise Confidential Document Sharing Platform  
**Participant**: Snovasys Fresher Hiring Challenge 2026 Candidate  
**Purpose**: Maintain genuine, transparent records of all AI-assisted engineering work, reviews, and corrections.

---

### Record 1: Project Audit & Phase 1 Proposal
- **Date**: 2026-10-24
- **Prompt/Request**: 
  > Comprehensive hackathon prompt instructing initial inspection of `c:\Users\NIHARIKA\OneDrive\ドキュメント\TrustVault_new`, environment audit, architecture design, threat modeling, RBAC permission matrix, and Phase 1 proposal generation without writing application code.
- **Tools Used**:
  - `run_command` (powershell directory inspection, python and pip version checks)
  - `write_file` (created `phase1_proposal.md` artifact)
- **Actual Result**:
  - Target directory was verified empty.
  - Python 3.13.1, pip 24.3.1, Git 2.56.0 identified.
  - Comprehensive Phase 1 proposal generated and saved to artifact directory.
- **Issue or Flaw Found During Review**:
  - The initial permission matrix incorrectly assigned ❌ to ADMIN for document sharing and access revocation, contradicting the challenge requirement that *both ADMIN and document OWNER may manage access*.
  - Admin view of document metadata was not clearly scoped regarding confidential descriptions vs. high-level inventory.
  - Document deletion permissions needed resolution (preferring Owner-only deletion to prevent administrative data destruction).
- **Candidate Review & Instruction**:
  - User instructed revisions: Clarify Admin & Owner access-management scope, ensure Owner-only soft-deletion, enforce strict tenant isolation, define defense-in-depth file validation beyond magic bytes, and address application-level audit immutability limitations.
- **Correction Made**:
  - Updated `phase1_proposal.md` with revised RBAC matrix: both Admin and Owner can manage access within their tenant; deletion is Owner-only; Admin metadata access is limited to governance fields (no file content download); defense-in-depth file pipeline defined; opaque 404s established for cross-tenant containment.

---

### Record 2: Phase 2 Foundation, Configuration & Authentication Implementation
- **Date**: 2026-10-24
- **Prompt/Request**:
  > User approved revised Phase 1 proposal and instructed execution of Phase 2 only in `C:\Users\NIHARIKA\OneDrive\ドキュメント\TrustVault_new`.
- **Tools Used**:
  - `write_file` (`.gitignore`, `requirements.txt`, `.env.example`, `.env`, `trustvault/config.py`, SQLAlchemy models, central authorization layer, auth forms, routes, Jinja templates, CSS design tokens, error handlers, `THREATS.md`, `PROMPTS.md`)
  - `run_command` (`pip install -r requirements.txt` background task)
- **Actual Result**:
  - Pinned dependencies installed successfully.
  - Modular Flask Application Factory implemented with CSRF protection, secure cookie configuration, and security headers.
  - Relational schema defined with UUID keys for `Tenant`, `User`, `Document`, `DocumentAccessGrant`, and `AuditEvent`.
  - Central authorization layer (`services/authz.py`) enforcing tenant context and permission rules.
  - Automated test suite created (`tests/conftest.py`, `tests/test_auth.py`, `tests/test_tenant_isolation.py`).
- **Issue or Flaw Found**:
  - Initial test run revealed two failures:
    1. `test_tenant_registration_honeypot_bot_rejection`: Form template did not render errors for hidden honeypot fields.
    2. `test_deactivated_user_immediate_session_kickout`: `get_current_user()` cached `None` on `flask.g` during the initial login check, which persisted across simulated requests due to the test fixture context wrapping.
- **Candidate Review & Correction Made**:
  - Rendered hidden field honeypot errors in `register_tenant.html`.
  - Refactored `get_current_user()` in `services/authz.py` to eliminate brittle manual `g` caching and rely on `db.session.get(User, user_id)` (which natively utilizes SQLAlchemy's Identity Map).
  - Streamlined `conftest.py` fixture lifecycle so `client` cleanly shares the isolated test database session.
- **Verification Result**:
  - Pytest re-run: 14 out of 14 tests **PASSED** (100% pass rate). Verified valid login, session rotation (fixation defense), brute-force lockout, deactivated account blocking, security response headers, strict single-tenant membership, opaque 404 cross-tenant containment, Admin & Owner access management permissions, Owner-only document deletion, dynamic download authorization & instant revocation, and mid-session deactivation kickout.
- **Git Preparation**:
  - Initialized local repository via `git init`.
  - Confirmed `.gitignore` successfully isolates `.env`, `instance/`, `storage/`, and `.pytest_cache/`. Ready for candidate review and approved commits.

---

### Record 3: Phase 2 Security Hardening Pass & Regression Suite
- **Date**: 2026-10-24
- **Prompt/Request**:
  > Candidate requested a read-only security review of Phase 2 implementation, followed by authorization to execute a targeted security-hardening pass: resolve cross-tenant email collision, enforce tenant deactivation mid-session, enable SQLite foreign key constraints, enforce 128-char max password length, add live CSRF rejection integration test, implement dependency-free IP rate limiting for unknown emails, sanitize nested audit metadata recursively, clarify Flask session fixation behavior, and add focused regression tests.
- **Tools Used**:
  - `read_file`, `write_file`, `edit_file`, `run_command` (pytest test execution).
- **Actual Result**:
  - Updated `User.email` to `unique=True` globally, eliminating multi-tenant email collision and non-deterministic login lookups.
  - Added `or not user.tenant.is_active` to `get_current_user()` to terminate sessions if a company is deactivated.
  - Registered SQLAlchemy `Engine.connect` event listener to enforce `PRAGMA foreign_keys = ON;` on SQLite.
  - Added 128-character upper password limit on `User.set_password`, `LoginForm`, `TenantRegistrationForm`, and `ChangePasswordForm`.
  - Created `IPRateLimiter` (`trustvault/services/rate_limiter.py`) providing in-memory sliding-window request throttling against unknown emails without external packages.
  - Implemented recursive `sanitize_audit_metadata()` in `trustvault/models/audit.py` to scrub sensitive keys from nested dicts and lists.
  - Clarified in documentation that Flask's default session mechanism provides client-side data clearance and re-signing rather than server-side session table revocation.
- **Issue or Flaw Found During Hardening**:
  - Two test failures occurred on first hardening run:
    1. `test_login_ip_rate_limiting_unknown_emails`: SQLite foreign key constraint failed on `AuditEvent.tenant_id = '00000000-0000-0000-0000-000000000000'` because that placeholder tenant does not exist. Fixed by making `tenant_id` nullable in `AuditEvent` to represent pre-authentication/unknown-tenant attempts as valid SQL `NULL` foreign keys.
    2. `test_audit_nested_metadata_sanitization`: Container key `"api_keys"` matched keyword `"api_key"` and redacted the list to a string, causing a TypeError when indexing nested elements. Fixed by checking if the value is a scalar before redacting; containers are recursed into instead.
- **Verification Result**:
  - Full pytest test suite re-run: 21 out of 21 tests **PASSED** (100% pass rate).
- **Git Status**:
  - Verified no commits executed. Uncommitted working tree ready for candidate inspection.

---

### Record 4: Phase 3 Document Management Pipeline, Secure Storage, Sharing & RBAC Implementation
- **Date**: 2026-10-24
- **Prompt/Request**:
  > Start Phase 3 of TrustVault. Phase 2 committed locally as b831520.
  > Implement essential document features:
  > 1. Owner uploads supported documents securely.
  > 2. Owner lists and manages their own documents.
  > 3. Owner shares documents with eligible users in the same tenant.
  > 4. Viewer sees and downloads only explicitly shared documents.
  > 5. Owner revokes grants; access stops immediately.
  > 6. Owner deletes their own documents; deleted documents cannot be downloaded.
  > 7. Record appropriate audit events.
  > Security requirements: server-side authz on every sensitive request, never trust client-supplied tenant/role IDs, keep files outside public/static roots, random storage keys, validate size/extension/content (reject unsupported formats), prevent path traversal, Admin must not read document contents without explicit grant, preserve audit records, do not claim malware scanning if absent. Add meaningful tests and run full test suite.
- **Tools Used**:
  - `read_file`, `write_file`, `edit_file`, `run_command` (pytest test suite execution via PowerShell).
- **Actual Result**:
  - Created `StorageService` (`trustvault/services/storage_service.py`):
    - Whitelist validation (`.pdf`, `.docx`, `.xlsx`, `.txt`, `.md`, `.png`, `.jpg`, `.jpeg`).
    - Magic byte header signature sniffing and OOXML ZIP structure verification.
    - Script and executable signature detection in text files (`MZ`, `ELF`, `#!`, `<?php`, `<script`, `<html`).
    - Files saved outside web root under unguessable UUID storage keys with strict path traversal containment checks.
    - SHA-256 integrity checksum calculation.
    - Explicit disclaimer stating antivirus/malware scanning is not implemented (honesty standard).
  - Created `documents` blueprint (`trustvault/blueprints/documents/`):
    - `forms.py`: `DocumentUploadForm` and `ShareDocumentForm`.
    - `routes.py`:
      - `GET /documents/`: Role-tailored lists (Owner sees owned + shared, Viewer sees only shared, Admin sees governance metadata).
      - `GET /documents/upload` & `POST /documents/upload`: Owner-only document upload with multi-stage validation.
      - `GET /documents/<doc_id>`: Document detail and metadata inspection with opaque 404 cross-tenant isolation.
      - `GET /documents/<doc_id>/download`: Live download authorization guard; blocks Admins without explicit grants (`403`); blocks deleted documents (`404`); sends attachment with `nosniff`.
      - `POST /documents/<doc_id>/share`: Admin & Owner access management; validates recipient is active member of same tenant; prevents self-sharing; reactivates revoked grants.
      - `POST /documents/<doc_id>/grants/<grant_id>/revoke`: Admin & Owner grant revocation; immediately terminates access while preserving history.
      - `POST /documents/<doc_id>/delete`: Owner-only soft-deletion; preserves DB record and audit trail while preventing future downloads.
  - Enhanced `AuditService` (`trustvault/services/audit_service.py`) with document action helpers (`DOC_UPLOAD`, `DOC_DOWNLOAD`, `DOC_SHARE`, `DOC_REVOKE`, `DOC_DELETE`, `ACCESS_DENIED`).
  - Created Jinja2 templates: `documents/list.html`, `documents/upload.html`, `documents/detail.html`.
  - Added CSS design tokens for responsive tables, category badges, and action bars in `style.css`.
  - Created automated test suite in `tests/test_documents.py` (11 comprehensive tests).
- **Issue or Flaw Found During Phase 3 Verification**:
  - In initial pytest run for `test_documents.py`, 5 tests failed because simulated user transitions used `client.post("/auth/login")` without logging out first. In TrustVault, `/auth/login` checks `if get_current_user(): return redirect(url_for('main.index'))`, preventing session hijacking. Because the previous user was still signed in, subsequent actions were executed under the wrong user identity.
  - Fixed by creating a `login_user(client, email)` test helper that cleanly calls `client.post("/auth/logout")` before establishing a new session.
- **Verification Result**:
  - Full pytest test suite: **32 passed in 33.83s (100% pass rate, 0 failed, 0 skipped)** across `test_auth.py`, `test_documents.py`, and `test_tenant_isolation.py`.
- **Git Status**:
  - Phase 2 commit `b831520` intact.
  - Phase 3 files ready for review; no deployment, publishing, or push executed.
