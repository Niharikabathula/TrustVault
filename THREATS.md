# TrustVault: Comprehensive Threat Model (THREATS.md)
**Project**: TrustVault — Enterprise Confidential Document Sharing Platform  
**Target**: Snovasys Fresher Hiring Challenge 2026  
**Security Standard**: OWASP Top 10, Defense-in-Depth Multi-Tenancy  

---

## 1. Threat Modeling Methodology
TrustVault employs the STRIDE and OWASP threat modeling methodologies to identify assets, adversary capabilities, potential threat scenarios, and layered technical mitigations.

### Primary Assets Protected:
1. **Confidential Customer Files**: Physical documents stored by corporate tenants.
2. **Document Metadata**: File names, descriptions, categories, checksums, and ownership records.
3. **Tenant Boundary Integrity**: Preventing cross-company data leakage or discovery.
4. **Access Grants**: Authorization records governing who can view and download documents.
5. **Audit Event Logs**: Forensic records required for compliance and non-repudiation.
6. **Authentication Credentials**: User passwords, session tokens, and cryptographic keys.

---

## 2. Threat Analysis Matrix

| Threat ID | Threat Name | Asset | Attacker Capability | Attack Scenario | Impact | Likelihood | Severity | Implemented Mitigation | Verification Test | Residual Risk |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **T-01** | Cross-Tenant Document Access | Confidential Documents | Authenticated user in Tenant A | Attacker in Company A probes URL `/documents/<id>` where ID belongs to Company B. | Critical | High | **CRITICAL** | Strict query scoping on `tenant_id` + opaque `404 Not Found` response (preventing existence disclosure) + security audit log. | `test_enforce_tenant_boundary_opaque_404` | Zero within app layer; assumes DB credentials uncompromised. |
| **T-02** | Insecure Direct Object References (IDOR) | Document Metadata & Files | Malicious authenticated user | Attacker changes document UUID in download/edit parameter to another user's document. | High | High | **HIGH** | Centralized permission checker (`can_download_document`, `can_manage_document_access`) verifies ownership or active grant before returning data. | `test_download_authorization_and_revocation` | Unguessable UUIDs ($2^{128}$) + explicit backend check. |
| **T-03** | Privilege Escalation (Viewer to Admin) | User Roles & Administration | Malicious Viewer | Viewer modifies role field in HTTP POST request to grant themselves `ADMIN` or `OWNER`. | High | Medium | **HIGH** | Roles are never accepted from public user inputs; only verified Tenant Admins can provision roles via dedicated server-side endpoints. | `test_manage_document_access_permissions` | Compromise of Admin credentials. |
| **T-04** | Malicious File Upload (Web Shell / Executable) | Server File System & OS | Malicious Owner | Attacker renames `shell.php` or `exploit.exe` to `invoice.pdf` and uploads. | Critical | Medium | **CRITICAL** | Multi-stage upload validation: extension whitelist, magic byte header verification, polyglot script inspection, and storage as pure UUID key outside web root. | `test_upload_invalid_file_rejected` | Zero-day OS parser vulnerabilities (mitigated by attachment-only headers). |
| **T-05** | Path Traversal File Access | Host Operating System | Malicious uploader | Attacker supplies filename `../../etc/passwd` or `..\\windows\\system32\\cmd.exe`. | Critical | Medium | **CRITICAL** | User-supplied filename is never used on disk; files are saved with generated UUIDv4 keys. Prefix containment (`target.startswith(base + sep)`) verifies storage path containment. | `test_storage_path_traversal_prevention` | None on disk storage paths. |
| **T-06** | Access Revocation Bypass | Confidential Documents | Previously authorized Viewer | Viewer retains direct download link and attempts to download file after Owner revoked access. | High | High | **HIGH** | Database grant state is checked dynamically on every single download request. If `revoked_at` is set, download immediately aborts. | `test_download_authorization_and_revocation` | Local browser cache if user downloaded prior to revocation. |
| **T-07** | Cross-Tenant Document Sharing | Confidential Documents | Malicious Owner in Tenant A | Owner in Tenant A attempts to grant document access to a user ID in Tenant B. | High | Medium | **HIGH** | Sharing service queries recipient user with `filter_by(id=recipient_id, tenant_id=current_user.tenant_id)`. Non-matching tenants reject grant and log security violation. | `test_manage_document_access_permissions` | None. |
| **T-08** | CSRF State Tampering | User Sessions & Data | Malicious third-party website | Attacker tricks logged-in Admin/Owner into visiting a malicious site that submits state-changing forms. | High | Medium | **HIGH** | Global Flask-WTF CSRF protection requires unique cryptographic CSRF token on all POST/PUT/DELETE forms. | `test_csrf_protection_enforced_when_enabled` | None for modern browsers supporting SameSite cookies. |
| **T-09** | Session Fixation & State Injection | User Session | Network / Physical Attacker | Attacker plants a pre-authentication cookie or session attributes before user logs in. | High | Medium | **HIGH** | `session.clear()` purges all pre-login state before setting authenticated keys; cookie is re-signed upon login. | `test_login_success_and_session_rotation` | Flask default sessions use client-side signed cookies; true server-side token blacklisting requires Redis/database session storage. |
| **T-10** | Audit Log Tampering | Audit Records | Malicious User or Admin | Attacker attempts to delete or alter audit logs to conceal unauthorized actions. | High | Low | **HIGH** | Application layer is strictly append-only with no update/delete routes or model methods. | `test_audit_nested_metadata_sanitization` | Direct database manipulation by root/DBA. |
| **T-11** | Brute-Force Authentication | User Passwords | Automated Attacker | Attacker scripts rapid password guessing against tenant admin or user accounts. | High | High | **HIGH** | Two-tier defense: Sliding-window IP rate limiter throttles excessive attempts (including unknown emails), while 5 failed password attempts locks the target user for 15 minutes. | `test_login_brute_force_lockout`, `test_login_ip_rate_limiting_unknown_emails` | Highly distributed botnets cycling thousands of unique IP addresses. |
| **T-12** | User Enumeration | User Privacy | External Attacker | Attacker attempts logins or registrations to map corporate email directories. | Low | High | **MEDIUM** | Generic error messages (*"Invalid email or password"*) for all authentication failures. | `test_login_invalid_password_generic_error` | Sub-millisecond timing side-channels in cryptographic hash comparison. |
| **T-13** | Sensitive Information in Logs | Credentials & Files | Log Viewer / Observer | Passwords, session cookies, or confidential file contents leak into application logs. | High | Medium | **HIGH** | Sanitized JSON audit schema explicitly redacts passwords, tokens, hashes, and binary payloads. | `test_tenant_registration_success` | Unsanitized reverse proxy web access logs. |
| **T-14** | Inactive User Access | Tenant Assets | Terminated Employee | Deactivated employee attempts to use existing session to access company assets. | High | Medium | **HIGH** | Authentication middleware validates `user.is_active` on every request. Deactivation terminates session immediately. | `test_deactivated_user_immediate_session_kickout` | None. |
| **T-15** | Cross-Tenant Existence Enumeration | Tenant Privacy | External Attacker | Attacker probes UUIDs to determine if other companies store specific document names or IDs. | Medium | High | **MEDIUM** | Cross-tenant lookups strictly return `404 Not Found` (never 403 Forbidden). | `test_enforce_tenant_boundary_opaque_404` | None ($2^{128}$ random UUID space). |

---

## 3. Immutability Limitations & Production Recommendations
1. **Application-Level Immutability**: Within TrustVault, application users and administrators cannot edit or delete audit events through the web UI or API.
2. **Storage-Level Limitation**: Application-level controls cannot prevent direct SQL manipulation by a database administrator (DBA) or an OS root compromise.
3. **Enterprise Hardening Roadmap**:
   - Stream audit logs in real-time to a Write-Once-Read-Many (WORM) target or remote SIEM (AWS CloudWatch, Datadog, Splunk).
   - Cryptographic Merkle tree hash chaining to detect any retroactively modified log records.
