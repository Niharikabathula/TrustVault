import pytest
from sqlalchemy.exc import IntegrityError
from trustvault.models.base import db
from trustvault.models import Document, DocumentAccessGrant, User, UserRole
from trustvault.services.authz import (
    enforce_tenant_boundary,
    can_manage_document_access,
    can_view_document_metadata,
    can_download_document,
    can_delete_document,
)
from werkzeug.exceptions import NotFound


def test_user_strict_single_tenant_membership(users, tenants):
    """Verify users strictly belong to their assigned tenant and cannot bleed across."""
    t_a = tenants["tenant_a"]
    t_b = tenants["tenant_b"]

    assert users["admin_a"].tenant_id == t_a.id
    assert users["owner_a"].tenant_id == t_a.id
    assert users["viewer_a"].tenant_id == t_a.id

    assert users["admin_b"].tenant_id == t_b.id
    assert users["owner_b"].tenant_id == t_b.id
    assert users["viewer_b"].tenant_id == t_b.id

    assert users["admin_a"].tenant_id != users["admin_b"].tenant_id


def test_enforce_tenant_boundary_opaque_404(app, users, tenants):
    """
    Test that cross-tenant resource lookups trigger HTTP 404 (Not Found).
    Returning 404 instead of 403 prevents attackers from enumerating whether
    a resource ID exists in another company (IDOR mitigation).
    """
    with app.test_request_context():
        from flask import session
        # Simulate User A logged in
        session["user_id"] = users["owner_a"].id
        session["tenant_id"] = tenants["tenant_a"].id

        # Dummy resource belonging to Tenant B
        class CrossTenantDoc:
            tenant_id = tenants["tenant_b"].id

        with pytest.raises(NotFound):
            enforce_tenant_boundary(CrossTenantDoc())


def test_manage_document_access_permissions(db_session, users, tenants):
    """
    Test that only ADMIN and document OWNER can manage access,
    and cross-tenant access management is completely blocked.
    """
    t_a = tenants["tenant_a"]
    t_b = tenants["tenant_b"]

    # Create document owned by Owner A in Tenant A
    doc_a = Document(
        tenant_id=t_a.id,
        owner_id=users["owner_a"].id,
        title="Q3 Strategy Plan",
        category="Executive",
        original_filename="strategy.pdf",
        storage_key="dummy-storage-key-1234",
        file_size_bytes=1024,
        mime_type="application/pdf",
        sha256_checksum="dummychecksum",
        is_deleted=False
    )
    db_session.add(doc_a)
    db_session.commit()

    # 1. Document Owner in Tenant A -> CAN manage access
    assert can_manage_document_access(doc_a, users["owner_a"]) is True

    # 2. Tenant Admin in Tenant A -> CAN manage access
    assert can_manage_document_access(doc_a, users["admin_a"]) is True

    # 3. Viewer in Tenant A -> CANNOT manage access
    assert can_manage_document_access(doc_a, users["viewer_a"]) is False

    # 4. Cross-tenant Admin B -> CANNOT manage access (Cross-tenant blocked)
    assert can_manage_document_access(doc_a, users["admin_b"]) is False

    # 5. Cross-tenant Owner B -> CANNOT manage access
    assert can_manage_document_access(doc_a, users["owner_b"]) is False


def test_owner_only_document_deletion_policy(db_session, users, tenants):
    """
    Test that only the document OWNER can delete their own documents.
    Admins, Viewers, and other tenants cannot delete the document.
    """
    t_a = tenants["tenant_a"]

    doc_a = Document(
        tenant_id=t_a.id,
        owner_id=users["owner_a"].id,
        title="Financial Statements 2026",
        category="Finance",
        original_filename="financials.xlsx",
        storage_key="dummy-storage-key-5678",
        file_size_bytes=2048,
        mime_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        sha256_checksum="dummychecksum2",
        is_deleted=False
    )
    db_session.add(doc_a)
    db_session.commit()

    # Owner can delete
    assert can_delete_document(doc_a, users["owner_a"]) is True

    # Admin CANNOT delete (Owner-only deletion policy to prevent administrative overreach)
    assert can_delete_document(doc_a, users["admin_a"]) is False

    # Viewer CANNOT delete
    assert can_delete_document(doc_a, users["viewer_a"]) is False

    # Cross-tenant Owner B CANNOT delete
    assert can_delete_document(doc_a, users["owner_b"]) is False


def test_download_authorization_and_revocation(db_session, users, tenants):
    """
    Test that download access requires ownership or an active grant.
    Revocation immediately terminates download permission.
    """
    t_a = tenants["tenant_a"]

    doc_a = Document(
        tenant_id=t_a.id,
        owner_id=users["owner_a"].id,
        title="Confidential Research",
        category="R&D",
        original_filename="research.pdf",
        storage_key="dummy-storage-key-9999",
        file_size_bytes=4096,
        mime_type="application/pdf",
        sha256_checksum="dummychecksum3",
        is_deleted=False
    )
    db_session.add(doc_a)
    db_session.commit()

    # 1. Owner can download
    assert can_download_document(doc_a, users["owner_a"]) is True

    # 2. Viewer has NO access initially
    assert can_download_document(doc_a, users["viewer_a"]) is False

    # 3. Grant access to Viewer A
    grant = DocumentAccessGrant(
        tenant_id=t_a.id,
        document_id=doc_a.id,
        granted_to_user_id=users["viewer_a"].id,
        granted_by_user_id=users["owner_a"].id,
        permission_level="VIEW_DOWNLOAD"
    )
    db_session.add(grant)
    db_session.commit()

    # 4. Viewer now CAN download
    assert can_download_document(doc_a, users["viewer_a"]) is True

    # 5. Revoke access
    grant.revoke()
    db_session.commit()

    # 6. Viewer is IMMEDIATELY blocked from downloading
    assert can_download_document(doc_a, users["viewer_a"]) is False


def test_deactivated_user_immediate_session_kickout(client, users):
    """
    Test that if an Admin deactivates a user, their next request
    immediately fails authentication and invalidates their session.
    """
    # 1. Log in Viewer A
    login_resp = client.post("/auth/login", data={"email": "viewer@acme.com", "password": "Password123!"})
    assert login_resp.status_code == 302

    # Verify session active
    response = client.get("/auth/profile")
    assert response.status_code == 200

    # 2. Admin deactivates Viewer A in database
    viewer = users["viewer_a"]
    viewer.is_active = False
    db.session.commit()

    # 3. Next request by Viewer A must immediately fail and redirect to login
    response = client.get("/auth/profile", follow_redirects=False)
    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]

    # Verify session was cleared
    with client.session_transaction() as sess:
        assert "user_id" not in sess


def test_user_global_email_uniqueness(db_session, tenants):
    """
    Test that email is globally unique across all organizations.
    Attempting to register the same email in Tenant B when already in Tenant A
    must raise an IntegrityError, preventing multi-tenant identity collision.
    """
    t_a = tenants["tenant_a"]
    t_b = tenants["tenant_b"]

    user_a = User(
        tenant_id=t_a.id,
        email="shared@enterprise.com",
        full_name="User A",
        role=UserRole.VIEWER
    )
    user_a.set_password("Password123!")
    db_session.add(user_a)
    db_session.commit()

    # Attempt to insert same email under a different tenant
    user_b = User(
        tenant_id=t_b.id,
        email="shared@enterprise.com",
        full_name="User B (Collision)",
        role=UserRole.VIEWER
    )
    user_b.set_password("Password123!")
    db_session.add(user_b)

    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_deactivated_tenant_immediate_session_kickout(client, users, tenants):
    """
    Test that if an entire organization/tenant is deactivated,
    any active sessions belonging to that tenant are immediately terminated.
    """
    # 1. Log in Owner A
    client.post("/auth/login", data={"email": "owner@acme.com", "password": "Password123!"})

    # Verify session active
    response = client.get("/auth/profile")
    assert response.status_code == 200

    # 2. Deactivate Tenant A
    t_a = tenants["tenant_a"]
    t_a.is_active = False
    db.session.commit()

    # 3. Next request by Owner A must fail and redirect to login
    response = client.get("/auth/profile", follow_redirects=False)
    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]

    # Verify session was cleared
    with client.session_transaction() as sess:
        assert "user_id" not in sess


def test_sqlite_foreign_key_enforcement(db_session, users):
    """
    Test that SQLite foreign key constraints are strictly enforced.
    Attempting to insert a document with a non-existent tenant_id must raise IntegrityError.
    """
    invalid_doc = Document(
        tenant_id="00000000-0000-0000-0000-nonexistent00",
        owner_id=users["owner_a"].id,
        title="Orphan Document",
        category="General",
        original_filename="orphan.pdf",
        storage_key="dummy-storage-orphan",
        file_size_bytes=100,
        mime_type="application/pdf",
        sha256_checksum="dummychecksum",
        is_deleted=False
    )
    db_session.add(invalid_doc)

    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()
