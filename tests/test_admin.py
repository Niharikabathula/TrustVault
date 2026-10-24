import pytest
from trustvault.models import (
    db,
    User,
    UserRole,
    Tenant,
    Document,
    AuditEvent,
    AuditAction,
    AuditOutcome,
)


def login_user(client, email: str, password: str = "Password123!"):
    """Helper to cleanly sign out existing session and log in as specified user."""
    client.post("/auth/logout")
    return client.post("/auth/login", data={"email": email, "password": password})


def test_admin_can_provision_owner(client, users):
    """Test that Admin can successfully provision a new OWNER in their tenant."""
    login_user(client, "admin@acme.com")

    response = client.post(
        "/admin/users/create",
        data={
            "full_name": "Alice Product Lead",
            "email": "alice.owner@acme.com",
            "role": UserRole.OWNER,
            "password": "TemporaryPass123!",
            "confirm_password": "TemporaryPass123!",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"provisioned successfully" in response.data

    # Verify Database record
    user = User.query.filter_by(email="alice.owner@acme.com").first()
    assert user is not None
    assert user.full_name == "Alice Product Lead"
    assert user.role == UserRole.OWNER
    assert user.tenant_id == users["admin_a"].tenant_id
    assert user.is_active is True
    assert user.must_change_password is True
    assert user.check_password("TemporaryPass123!") is True

    # Verify Audit log
    audit = AuditEvent.query.filter_by(
        action=AuditAction.USER_CREATE,
        resource_id=user.id
    ).first()
    assert audit is not None
    assert audit.tenant_id == users["admin_a"].tenant_id
    assert audit.actor_id == users["admin_a"].id
    assert audit.get_details()["assigned_role"] == UserRole.OWNER


def test_admin_can_provision_viewer(client, users):
    """Test that Admin can successfully provision a new VIEWER in their tenant."""
    login_user(client, "admin@acme.com")

    response = client.post(
        "/admin/users/create",
        data={
            "full_name": "Bob Analyst",
            "email": "bob.viewer@acme.com",
            "role": UserRole.VIEWER,
            "password": "TemporaryPass123!",
            "confirm_password": "TemporaryPass123!",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"provisioned successfully" in response.data

    # Verify Database record
    user = User.query.filter_by(email="bob.viewer@acme.com").first()
    assert user is not None
    assert user.role == UserRole.VIEWER
    assert user.tenant_id == users["admin_a"].tenant_id


def test_non_admin_cannot_provision_users(client, users):
    """Test that VIEWER, OWNER, and anonymous users cannot access user provisioning (HTTP 403 / 302)."""
    # 1. Anonymous user redirected to login
    client.post("/auth/logout")
    resp_anon = client.post("/admin/users/create", data={"email": "hacker@acme.com"})
    assert resp_anon.status_code == 302
    assert "/auth/login" in resp_anon.headers["Location"]

    # 2. Viewer gets 403 Forbidden
    login_user(client, "viewer@acme.com")
    resp_viewer = client.post("/admin/users/create", data={"email": "hacker@acme.com"})
    assert resp_viewer.status_code == 403

    # 3. Owner gets 403 Forbidden
    login_user(client, "owner@acme.com")
    resp_owner = client.post("/admin/users/create", data={"email": "hacker@acme.com"})
    assert resp_owner.status_code == 403


def test_forged_admin_role_assignment_rejected(client, users):
    """
    Security check: Ensure an attacker cannot forge a POST request with role=ADMIN
    to escalate privileges and create unauthorized administrators.
    """
    login_user(client, "admin@acme.com")

    # Attempt to post role=ADMIN
    response = client.post(
        "/admin/users/create",
        data={
            "full_name": "Forged Admin Attempt",
            "email": "rogue.admin@acme.com",
            "role": "ADMIN",  # Tampered role!
            "password": "Password123!",
            "confirm_password": "Password123!",
        },
    )

    # Server must reject invalid role with HTTP 400
    assert response.status_code == 400
    assert (
        b"Invalid role" in response.data
        or b"Privilege escalation blocked" in response.data
        or b"Not a valid choice" in response.data
    )

    # Verify database does not contain rogue admin
    rogue = User.query.filter_by(email="rogue.admin@acme.com").first()
    assert rogue is None


def test_provision_duplicate_email_handled_safely(client, users):
    """Test that provisioning a user with an already registered email fails safely with HTTP 400."""
    login_user(client, "admin@acme.com")

    # Attempt to provision with existing email
    response = client.post(
        "/admin/users/create",
        data={
            "full_name": "Duplicate User",
            "email": "owner@acme.com",  # Already exists in Acme Corp
            "role": UserRole.VIEWER,
            "password": "Password123!",
            "confirm_password": "Password123!",
        },
    )

    assert response.status_code == 400
    assert b"already exists" in response.data


def test_provisioned_user_belongs_strictly_to_admin_tenant(client, users):
    """Test that new accounts are strictly bound to the authenticated Admin's tenant."""
    login_user(client, "admin@acme.com")

    client.post(
        "/admin/users/create",
        data={
            "full_name": "Scoped User",
            "email": "scoped@acme.com",
            "role": UserRole.VIEWER,
            "password": "Password123!",
            "confirm_password": "Password123!",
        },
    )

    user = User.query.filter_by(email="scoped@acme.com").first()
    assert user is not None
    assert user.tenant_id == users["admin_a"].tenant_id
    assert user.tenant_id != users["admin_b"].tenant_id


def test_admin_cannot_modify_another_tenant_user(client, users):
    """
    Cross-tenant security check: Admin A cannot toggle the status of a user belonging to Tenant B.
    Lookups must return opaque 404 (anti-IDOR).
    """
    login_user(client, "admin@acme.com")

    # Admin A attempts to toggle status of Viewer B (Globex Corp)
    viewer_b_id = users["viewer_b"].id
    response = client.post(f"/admin/users/{viewer_b_id}/toggle-status")

    assert response.status_code == 404

    # Verify Viewer B's status was NOT altered
    db.session.refresh(users["viewer_b"])
    assert users["viewer_b"].is_active is True


def test_admin_cannot_deactivate_themselves(client, users):
    """Self-deactivation guard: Admin cannot deactivate their own account."""
    login_user(client, "admin@acme.com")

    admin_a_id = users["admin_a"].id
    response = client.post(f"/admin/users/{admin_a_id}/toggle-status", follow_redirects=True)

    assert response.status_code == 200
    assert b"cannot deactivate your own" in response.data

    # Verify Admin A remains active
    db.session.refresh(users["admin_a"])
    assert users["admin_a"].is_active is True


def test_admin_cannot_deactivate_another_admin(client, users, db_session):
    """Security guard: Administrator accounts cannot be deactivated via this route."""
    # Create a second admin in Tenant A
    admin_2 = User(
        tenant_id=users["admin_a"].tenant_id,
        email="admin2@acme.com",
        full_name="Acme Admin 2",
        role=UserRole.ADMIN,
        is_active=True,
    )
    admin_2.set_password("Password123!")
    db_session.add(admin_2)
    db_session.commit()

    login_user(client, "admin@acme.com")

    response = client.post(f"/admin/users/{admin_2.id}/toggle-status", follow_redirects=True)
    assert response.status_code == 200
    assert b"Administrator accounts cannot be deactivated" in response.data

    db.session.refresh(admin_2)
    assert admin_2.is_active is True


def test_deactivated_user_subsequent_requests_blocked(client, users):
    """
    Test that when an Admin deactivates a user, their active session
    is immediately invalidated on their very next request.
    """
    # 1. Viewer logs in and verifies active profile
    login_user(client, "viewer@acme.com")
    resp_profile = client.get("/auth/profile")
    assert resp_profile.status_code == 200

    # 2. Admin logs in and deactivates Viewer A
    login_user(client, "admin@acme.com")
    viewer_id = users["viewer_a"].id
    resp_deact = client.post(f"/admin/users/{viewer_id}/toggle-status", follow_redirects=True)
    assert resp_deact.status_code == 200
    assert b"has been deactivated" in resp_deact.data

    # Verify Viewer A status in DB
    db.session.refresh(users["viewer_a"])
    assert users["viewer_a"].is_active is False

    # Verify audit event
    audit = AuditEvent.query.filter_by(
        action=AuditAction.USER_STATUS_CHANGE,
        resource_id=viewer_id
    ).first()
    assert audit is not None
    assert audit.get_details()["new_status"] == "DEACTIVATED"

    # 3. Viewer attempts to access protected resource
    # Re-establish viewer session state
    login_user(client, "viewer@acme.com")  # Attempt login should be blocked
    resp_login_attempt = client.get("/auth/profile", follow_redirects=False)
    assert resp_login_attempt.status_code == 302
    assert "/auth/login" in resp_login_attempt.headers["Location"]


def test_admin_audit_viewer_only_returns_same_tenant_events(client, users, db_session):
    """
    Test that the audit log viewer strictly scopes results to the authenticated Admin's tenant.
    Events from Tenant B must never be visible to Admin A.
    """
    t_a = users["admin_a"].tenant
    t_b = users["admin_b"].tenant

    # Create event for Tenant A
    event_a = AuditEvent(
        tenant_id=t_a.id,
        action=AuditAction.DOC_UPLOAD,
        resource_type="DOCUMENT",
        actor_email="owner@acme.com",
        actor_role=UserRole.OWNER,
        outcome=AuditOutcome.SUCCESS,
    )
    event_a.set_details({"title": "Tenant A Secret File"})

    # Create event for Tenant B
    event_b = AuditEvent(
        tenant_id=t_b.id,
        action=AuditAction.DOC_UPLOAD,
        resource_type="DOCUMENT",
        actor_email="owner@globex.com",
        actor_role=UserRole.OWNER,
        outcome=AuditOutcome.SUCCESS,
    )
    event_b.set_details({"title": "Tenant B Top Secret"})

    db_session.add_all([event_a, event_b])
    db_session.commit()

    # Admin A inspects audit logs
    login_user(client, "admin@acme.com")
    resp = client.get("/admin/audit-logs")
    assert resp.status_code == 200

    # Tenant A data must be present
    assert b"Tenant A Secret File" in resp.data
    assert b"owner@acme.com" in resp.data

    # Tenant B data must NEVER be present
    assert b"Tenant B Top Secret" not in resp.data
    assert b"owner@globex.com" not in resp.data


def test_non_admin_cannot_access_admin_routes(client, users):
    """Test that VIEWER and OWNER roles receive HTTP 403 Forbidden when accessing Admin routes."""
    # Viewer tries to access users list
    login_user(client, "viewer@acme.com")
    assert client.get("/admin/users").status_code == 403
    assert client.get("/admin/audit-logs").status_code == 403

    # Owner tries to access users list
    login_user(client, "owner@acme.com")
    assert client.get("/admin/users").status_code == 403
    assert client.get("/admin/audit-logs").status_code == 403


def test_admin_csrf_protection_enforced(app, users):
    """
    Integration test verifying that Admin state-changing requests without
    valid CSRF tokens are rejected with HTTP 400 when CSRF is enabled.
    """
    app.config["WTF_CSRF_ENABLED"] = True

    with app.test_client() as csrf_client:
        # Sign in as Admin
        csrf_client.post("/auth/login", data={"email": "admin@acme.com", "password": "Password123!"})

        # Submit user provisioning without CSRF token
        response = csrf_client.post(
            "/admin/users/create",
            data={
                "full_name": "No CSRF User",
                "email": "nocsrf@acme.com",
                "role": UserRole.VIEWER,
                "password": "Password123!",
                "confirm_password": "Password123!",
            },
        )
        assert response.status_code == 400
        assert b"CSRF" in response.data or b"Bad Request" in response.data

    app.config["WTF_CSRF_ENABLED"] = False


def test_existing_document_permissions_still_work(client, users, db_session):
    """Regression test: Ensure existing document permission rules are unchanged by Phase 4."""
    t_a = users["owner_a"].tenant
    doc = Document(
        tenant_id=t_a.id,
        owner_id=users["owner_a"].id,
        title="Regression Test Doc",
        category="General",
        original_filename="regression.pdf",
        storage_key="dummy_regression_storage_key",
        file_size_bytes=100,
        mime_type="application/pdf",
        sha256_checksum="dummychecksum",
        is_deleted=False,
    )
    db_session.add(doc)
    db_session.commit()

    # Owner can view
    login_user(client, "owner@acme.com")
    resp_owner = client.get(f"/documents/{doc.id}")
    assert resp_owner.status_code == 200

    # Admin cannot download without explicit grant
    login_user(client, "admin@acme.com")
    resp_admin = client.get(f"/documents/{doc.id}/download")
    assert resp_admin.status_code == 403

    # Viewer without grant cannot download
    login_user(client, "viewer@acme.com")
    resp_viewer = client.get(f"/documents/{doc.id}/download")
    assert resp_viewer.status_code == 403
