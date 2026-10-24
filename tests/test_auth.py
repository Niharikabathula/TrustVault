import pytest
from trustvault.models import Tenant, User, UserRole, AuditEvent, AuditAction


def test_tenant_registration_success(client):
    """Test public onboarding creates a new tenant and sets the user as ADMIN."""
    response = client.post("/auth/register-tenant", data={
        "company_name": "Stark Industries",
        "full_name": "Tony Stark",
        "admin_email": "tony@stark.com",
        "password": "IronManPassword123!",
        "confirm_password": "IronManPassword123!",
        "website": "",  # Empty honeypot
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b"Stark Industries" in response.data or b"Please sign in" in response.data

    # Verify DB
    tenant = Tenant.query.filter_by(name="Stark Industries").first()
    assert tenant is not None
    assert tenant.slug == "stark-industries"

    user = User.query.filter_by(email="tony@stark.com").first()
    assert user is not None
    assert user.role == UserRole.ADMIN
    assert user.tenant_id == tenant.id
    assert user.check_password("IronManPassword123!") is True

    # Verify Audit log
    audit = AuditEvent.query.filter_by(action=AuditAction.TENANT_ONBOARD).first()
    assert audit is not None
    assert audit.tenant_id == tenant.id


def test_tenant_registration_honeypot_bot_rejection(client):
    """Test bot filling out hidden honeypot field is rejected."""
    response = client.post("/auth/register-tenant", data={
        "company_name": "Spam Corp",
        "full_name": "Spam Bot",
        "admin_email": "bot@spam.com",
        "password": "SpamPassword123!",
        "confirm_password": "SpamPassword123!",
        "website": "http://spambot.evil.com",  # Honeypot filled!
    })

    assert response.status_code == 200
    assert b"Automated bot submission detected" in response.data
    assert Tenant.query.filter_by(name="Spam Corp").first() is None


def test_login_success_and_session_rotation(client, users):
    """Test valid login sets session and rotates session identifiers (fixation defense)."""
    # 1. Establish initial session state
    with client.session_transaction() as sess:
        sess["pre_login_token"] = "initial_untrusted_session"

    # 2. Perform authentication
    response = client.post("/auth/login", data={
        "email": "owner@acme.com",
        "password": "Password123!",
    }, follow_redirects=False)

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/")

    # 3. Verify session was cleared and rotated
    with client.session_transaction() as sess:
        assert "pre_login_token" not in sess  # Cleaned by session.clear()
        assert sess.get("user_id") == users["owner_a"].id
        assert sess.get("tenant_id") == users["owner_a"].tenant_id
        assert sess.get("user_role") == UserRole.OWNER


def test_login_invalid_password_generic_error(client, users):
    """Test invalid password increments failed attempts and displays generic error."""
    response = client.post("/auth/login", data={
        "email": "owner@acme.com",
        "password": "WrongPassword!",
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b"Invalid email or password" in response.data

    user = User.query.filter_by(email="owner@acme.com").first()
    assert user.failed_login_attempts == 1


def test_login_brute_force_lockout(client, users):
    """Test 5 consecutive failed login attempts locks account for 15 minutes."""
    for i in range(5):
        client.post("/auth/login", data={
            "email": "owner@acme.com",
            "password": f"WrongAttempt{i}!",
        })

    user = User.query.filter_by(email="owner@acme.com").first()
    assert user.failed_login_attempts >= 5
    assert user.is_locked() is True

    # 6th attempt should return lockout message
    response = client.post("/auth/login", data={
        "email": "owner@acme.com",
        "password": "Password123!",  # Even correct password is now blocked
    }, follow_redirects=True)

    assert b"temporarily locked" in response.data


def test_login_deactivated_account_blocked(client, users):
    """Test deactivated account cannot log in."""
    user = users["viewer_a"]
    user.is_active = False
    from trustvault.models.base import db
    db.session.commit()

    response = client.post("/auth/login", data={
        "email": "viewer@acme.com",
        "password": "Password123!",
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b"deactivated" in response.data


def test_logout_clears_session(client, users):
    """Test logout clears session completely."""
    # Login first
    client.post("/auth/login", data={"email": "owner@acme.com", "password": "Password123!"})

    # Logout
    response = client.post("/auth/logout", follow_redirects=True)
    assert response.status_code == 200
    assert b"You have been securely logged out" in response.data

    # Verify session is empty
    with client.session_transaction() as sess:
        assert "user_id" not in sess


def test_security_headers_present(client):
    """Test enterprise security headers on every response."""
    response = client.get("/")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"


def test_csrf_protection_enforced_when_enabled(app):
    """
    Integration test verifying that when CSRF protection is active,
    a state-changing POST request without a valid CSRF token is rejected with HTTP 400.
    """
    app.config["WTF_CSRF_ENABLED"] = True
    with app.test_client() as csrf_client:
        # Submit POST without CSRF token
        response = csrf_client.post("/auth/login", data={
            "email": "owner@acme.com",
            "password": "Password123!",
        })
        assert response.status_code == 400
        assert b"CSRF" in response.data or b"Bad Request" in response.data
    # Re-disable for other unit tests
    app.config["WTF_CSRF_ENABLED"] = False


def test_login_ip_rate_limiting_unknown_emails(client):
    """
    Test that IP rate limiting blocks excessive failed attempts,
    even when an attacker scripts attacks using non-existent / random emails.
    """
    from trustvault.services.rate_limiter import login_rate_limiter
    login_rate_limiter.reset()

    # Perform 20 failed login attempts with random unknown emails from the same IP
    for i in range(20):
        client.post("/auth/login", data={
            "email": f"unknown_user_{i}@randomdomain.com",
            "password": "Password123!",
        })

    # The 21st attempt should be blocked by IP rate limiting with HTTP 429
    response = client.post("/auth/login", data={
        "email": "another_random@randomdomain.com",
        "password": "Password123!",
    })
    assert response.status_code == 429
    assert b"Too many login attempts from this network" in response.data

    # Cleanup singleton state after test
    login_rate_limiter.reset()


def test_password_max_length_enforcement(client, users):
    """
    Test that passwords exceeding 128 characters are rejected at both form
    and model validation to prevent hashing-based CPU exhaustion attacks.
    """
    user = users["owner_a"]
    excessive_password = "A" * 129

    # Model validation check
    with pytest.raises(ValueError, match="Password cannot exceed 128 characters"):
        user.set_password(excessive_password)

    # Form validation check on registration
    response = client.post("/auth/register-tenant", data={
        "company_name": "Test Co",
        "full_name": "Test Admin",
        "admin_email": "newadmin@testco.com",
        "password": excessive_password,
        "confirm_password": excessive_password,
        "website": "",
    })
    assert b"Password must be between 8 and 128 characters long" in response.data


def test_audit_nested_metadata_sanitization(db_session, tenants):
    """
    Test recursive sanitization in AuditEvent to guarantee that sensitive keys
    (e.g., password, token, secret) are redacted even when deeply nested in dicts/lists.
    """
    t_a = tenants["tenant_a"]
    event = AuditEvent(
        tenant_id=t_a.id,
        action=AuditAction.USER_CREATE,
        resource_type="USER",
        outcome="SUCCESS"
    )
    nested_details = {
        "user_email": "newbie@acme.com",
        "credentials": {
            "temporary_password": "super_secret_password",
            "session_token": "secret_session_token_xyz"
        },
        "tags": ["finance", "confidential"],
        "api_keys": [
            {"service": "cloud", "api_key": "12345-secret"},
            {"service": "analytics", "status": "active"}
        ]
    }
    event.set_details(nested_details)
    db_session.add(event)
    db_session.commit()

    saved_details = event.get_details()
    assert saved_details["credentials"]["temporary_password"] == "[REDACTED]"
    assert saved_details["credentials"]["session_token"] == "[REDACTED]"
    assert saved_details["api_keys"][0]["api_key"] == "[REDACTED]"
    assert saved_details["api_keys"][1]["status"] == "active"
    assert saved_details["user_email"] == "newbie@acme.com"


def test_temporary_password_user_redirected_to_profile_on_login(client, users, db_session):
    """
    Test that a user with must_change_password=True is immediately redirected
    to the profile password-change page upon login with a warning notice.
    """
    user = users["viewer_a"]
    user.must_change_password = True
    db_session.commit()

    client.post("/auth/logout")
    response = client.post("/auth/login", data={
        "email": "viewer@acme.com",
        "password": "Password123!",
    }, follow_redirects=False)

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/auth/profile")

    # Follow redirect to profile
    follow_resp = client.get(response.headers["Location"])
    assert follow_resp.status_code == 200
    assert b"temporary password" in follow_resp.data
    assert b"Action Required" in follow_resp.data


def test_temporary_password_user_redirected_away_from_protected_pages(client, users, db_session):
    """
    Test that users with must_change_password=True are blocked and redirected
    to /auth/profile whenever they attempt to access protected application endpoints.
    """
    viewer = users["viewer_a"]
    viewer.must_change_password = True
    db_session.commit()

    client.post("/auth/logout")
    client.post("/auth/login", data={"email": "viewer@acme.com", "password": "Password123!"})

    # Attempt to access dashboard (/)
    resp_dash = client.get("/")
    assert resp_dash.status_code == 302
    assert resp_dash.headers["Location"].endswith("/auth/profile")

    # Attempt to access document list (/documents/)
    resp_docs = client.get("/documents/")
    assert resp_docs.status_code == 302
    assert resp_docs.headers["Location"].endswith("/auth/profile")

    # Attempt to access document upload (/documents/upload)
    resp_upload = client.get("/documents/upload")
    assert resp_upload.status_code == 302
    assert resp_upload.headers["Location"].endswith("/auth/profile")

    # Test an Admin user with temporary password attempting to access admin portal
    admin = users["admin_a"]
    admin.must_change_password = True
    db_session.commit()

    client.post("/auth/logout")
    client.post("/auth/login", data={"email": "admin@acme.com", "password": "Password123!"})

    resp_admin_users = client.get("/admin/users")
    assert resp_admin_users.status_code == 302
    assert resp_admin_users.headers["Location"].endswith("/auth/profile")

    resp_admin_audit = client.get("/admin/audit-logs")
    assert resp_admin_audit.status_code == 302
    assert resp_admin_audit.headers["Location"].endswith("/auth/profile")

    # Attempting to visit /auth/login or /auth/register-tenant while authenticated redirects to profile
    resp_login = client.get("/auth/login")
    assert resp_login.status_code == 302
    assert resp_login.headers["Location"].endswith("/auth/profile")

    resp_reg = client.get("/auth/register-tenant")
    assert resp_reg.status_code == 302
    assert resp_reg.headers["Location"].endswith("/auth/profile")


def test_temporary_password_user_can_access_profile_and_logout_without_loop(client, users, db_session):
    """
    Test that users with must_change_password=True can safely view the profile page
    and perform sign-out without triggering redirect loops. Navigation links are suppressed.
    """
    viewer = users["viewer_a"]
    viewer.must_change_password = True
    db_session.commit()

    client.post("/auth/logout")
    client.post("/auth/login", data={"email": "viewer@acme.com", "password": "Password123!"})

    # GET /auth/profile returns 200 without loop
    resp_profile = client.get("/auth/profile")
    assert resp_profile.status_code == 200
    assert b"Update Password" in resp_profile.data
    assert b"Action Required:" in resp_profile.data
    assert b"temporary password" in resp_profile.data

    # Protected navigation links must be hidden from temporary password users
    assert b'href="/documents/"' not in resp_profile.data
    assert b'href="/admin/users"' not in resp_profile.data
    # But Sign Out and Profile are available
    assert b"Sign Out" in resp_profile.data
    assert b"Profile" in resp_profile.data

    # POST /auth/logout functions cleanly
    resp_logout = client.post("/auth/logout", follow_redirects=False)
    assert resp_logout.status_code == 302
    assert resp_logout.headers["Location"].endswith("/auth/login")

    # Unauthenticated user visiting /auth/profile now redirects to /auth/login
    resp_after_logout = client.get("/auth/profile")
    assert resp_after_logout.status_code == 302
    assert "/auth/login" in resp_after_logout.headers["Location"]


def test_incorrect_current_password_leaves_must_change_password_enabled(client, users, db_session):
    """
    Test that submitting an incorrect current password during password update
    fails validation and leaves must_change_password=True intact.
    """
    viewer = users["viewer_a"]
    viewer.must_change_password = True
    db_session.commit()

    client.post("/auth/logout")
    client.post("/auth/login", data={"email": "viewer@acme.com", "password": "Password123!"})

    # Submit wrong current password
    resp = client.post("/auth/profile", data={
        "current_password": "WrongPassword999!",
        "new_password": "NewValidPassword123!",
        "confirm_password": "NewValidPassword123!",
    })
    assert resp.status_code == 200
    assert b"Current password is incorrect." in resp.data

    # Verify database record
    db_session.refresh(viewer)
    assert viewer.must_change_password is True
    assert viewer.check_password("Password123!") is True
    assert viewer.check_password("NewValidPassword123!") is False

    # Still blocked from accessing protected pages
    resp_blocked = client.get("/documents/")
    assert resp_blocked.status_code == 302
    assert resp_blocked.headers["Location"].endswith("/auth/profile")


def test_successful_password_change_clears_must_change_password(client, users, db_session):
    """
    Test that a successful password update clears must_change_password to False,
    emits an audit event, unlocks full application access, and allows future logins.
    """
    viewer = users["viewer_a"]
    viewer.must_change_password = True
    db_session.commit()

    client.post("/auth/logout")
    client.post("/auth/login", data={"email": "viewer@acme.com", "password": "Password123!"})

    # Submit correct password change
    resp = client.post("/auth/profile", data={
        "current_password": "Password123!",
        "new_password": "SuperFreshPassword2026!",
        "confirm_password": "SuperFreshPassword2026!",
    }, follow_redirects=True)

    assert resp.status_code == 200
    assert b"Your password has been successfully updated." in resp.data

    # Verify database record
    db_session.refresh(viewer)
    assert viewer.must_change_password is False
    assert viewer.check_password("SuperFreshPassword2026!") is True

    # Audit event logged
    audit = AuditEvent.query.filter_by(
        action=AuditAction.USER_PASSWORD_CHANGE,
        resource_id=viewer.id
    ).first()
    assert audit is not None
    assert audit.tenant_id == viewer.tenant_id

    # Normal application access is now granted
    resp_docs = client.get("/documents/")
    assert resp_docs.status_code == 200
    assert b"Documents" in resp_docs.data

    resp_dash = client.get("/")
    assert resp_dash.status_code == 200

    # Log out and log in with new password -> redirects to dashboard (/), not forced to profile
    client.post("/auth/logout")
    resp_relogin = client.post("/auth/login", data={
        "email": "viewer@acme.com",
        "password": "SuperFreshPassword2026!",
    }, follow_redirects=False)
    assert resp_relogin.status_code == 302
    assert resp_relogin.headers["Location"].endswith("/")


def test_normal_user_unaffected_by_temporary_password_enforcement(client, users):
    """
    Test that standard users with must_change_password=False are never blocked
    or redirected to /auth/profile, and normal navigation items remain visible.
    """
    owner = users["owner_a"]
    assert owner.must_change_password is False

    client.post("/auth/logout")
    login_resp = client.post("/auth/login", data={
        "email": "owner@acme.com",
        "password": "Password123!",
    }, follow_redirects=False)

    # Standard redirect to dashboard
    assert login_resp.status_code == 302
    assert login_resp.headers["Location"].endswith("/")

    # Accessing dashboard works directly
    dash_resp = client.get("/")
    assert dash_resp.status_code == 200
    assert b"Dashboard" in dash_resp.data
    assert b'href="/documents/"' in dash_resp.data

    # Accessing documents works directly
    doc_resp = client.get("/documents/")
    assert doc_resp.status_code == 200