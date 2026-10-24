import io
import os
import pytest
from trustvault.models import (
    db,
    Document,
    DocumentAccessGrant,
    AuditEvent,
    AuditAction,
    UserRole,
)
from trustvault.services.storage_service import StorageService, ValidationError


@pytest.fixture(autouse=True)
def cleanup_temp_storage(app):
    """Clean up test storage folder after each test."""
    yield
    storage_path = app.config.get("STORAGE_PATH")
    if storage_path and os.path.exists(storage_path) and "test" in storage_path.lower():
        import shutil
        try:
            shutil.rmtree(storage_path)
        except Exception:
            pass


def login_user(client, email: str, password: str = "Password123!"):
    """Helper to cleanly sign out any existing session and log in as specified user."""
    client.post("/auth/logout")
    return client.post("/auth/login", data={"email": email, "password": password})


def create_dummy_pdf():
    """Create a minimal valid PDF byte stream for upload tests."""
    content = b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj 2 0 obj<</Type/Pages/Count 0>>endobj\nxref\n0 3\n0000000000 65535 f\n0000000009 00000 n\n0000000052 00000 n\ntrailer<</Size 3/Root 1 0 R>>\nstartxref\n99\n%%EOF\n"
    return io.BytesIO(content), "confidential_plan.pdf"


def test_owner_upload_document_success(client, users, app):
    """Test that document Owner can securely upload a supported PDF document."""
    # Log in as Owner A
    login_user(client, "owner@acme.com")

    pdf_stream, filename = create_dummy_pdf()

    response = client.post(
        "/documents/upload",
        data={
            "title": "Acme Q3 Strategic Plan",
            "category": "Confidential",
            "description": "Board-only confidential strategy document.",
            "file": (pdf_stream, filename),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"uploaded successfully" in response.data
    assert b"Acme Q3 Strategic Plan" in response.data

    # Verify Database record
    doc = Document.query.filter_by(title="Acme Q3 Strategic Plan").first()
    assert doc is not None
    assert doc.tenant_id == users["owner_a"].tenant_id
    assert doc.owner_id == users["owner_a"].id
    assert doc.category == "Confidential"
    assert doc.original_filename == "confidential_plan.pdf"
    assert doc.mime_type == "application/pdf"
    assert doc.file_size_bytes > 0
    assert len(doc.sha256_checksum) == 64
    assert doc.is_deleted is False

    # Verify physical file exists on disk outside web root
    storage_root = app.config["STORAGE_PATH"]
    physical_path = StorageService.get_file_path(storage_root, doc.tenant_id, doc.storage_key)
    assert os.path.isfile(physical_path)
    assert doc.storage_key not in doc.original_filename  # Physical filename is pure random key

    # Verify Audit log
    audit = AuditEvent.query.filter_by(
        action=AuditAction.DOC_UPLOAD,
        resource_id=doc.id
    ).first()
    assert audit is not None
    assert audit.tenant_id == users["owner_a"].tenant_id
    assert audit.actor_id == users["owner_a"].id


def test_upload_invalid_file_rejected(client, users):
    """Test that malicious, unsupported, or spoofed files are rejected with HTTP 400."""
    login_user(client, "owner@acme.com")

    # 1. Disallowed extension (.exe)
    response = client.post(
        "/documents/upload",
        data={
            "title": "Malicious Payload",
            "category": "General",
            "file": (io.BytesIO(b"MZ\x90\x00executable content"), "malware.exe"),
        },
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    assert b"Unsupported file format" in response.data

    # 2. Magic byte mismatch (claimed PDF but fake content)
    response = client.post(
        "/documents/upload",
        data={
            "title": "Spoofed PDF",
            "category": "General",
            "file": (io.BytesIO(b"NOT A REAL PDF HEADER"), "fake.pdf"),
        },
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    assert b"does not match the expected format" in response.data

    # 3. Text file with executable script signature
    response = client.post(
        "/documents/upload",
        data={
            "title": "PHP Shell",
            "category": "General",
            "file": (io.BytesIO(b"<?php system($_GET['cmd']); ?>"), "shell.txt"),
        },
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    assert b"executable or script signatures" in response.data

    # 4. Empty file
    response = client.post(
        "/documents/upload",
        data={
            "title": "Empty File",
            "category": "General",
            "file": (io.BytesIO(b""), "empty.pdf"),
        },
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    assert b"Empty file" in response.data or b"Empty files" in response.data


def test_non_owner_upload_blocked(client, users):
    """Test that VIEWER role is blocked from uploading documents (HTTP 403)."""
    login_user(client, "viewer@acme.com")

    pdf_stream, filename = create_dummy_pdf()
    response = client.post(
        "/documents/upload",
        data={
            "title": "Unauthorized Upload",
            "category": "General",
            "file": (pdf_stream, filename),
        },
        content_type="multipart/form-data",
    )
    assert response.status_code == 403


def test_document_list_role_based_visibility(client, users, db_session):
    """
    Test role-based document list:
    - Owner sees owned documents.
    - Viewer does NOT see unshared documents.
    - Admin sees organization registry metadata.
    """
    t_a = users["owner_a"].tenant
    doc = Document(
        tenant_id=t_a.id,
        owner_id=users["owner_a"].id,
        title="Restricted Blueprint",
        category="Engineering",
        original_filename="blueprint.pdf",
        storage_key="dummy_blueprint_storage_key",
        file_size_bytes=1024,
        mime_type="application/pdf",
        sha256_checksum="dummychecksum",
        is_deleted=False,
    )
    db_session.add(doc)
    db_session.commit()

    # 1. Owner A logs in -> sees document
    login_user(client, "owner@acme.com")
    resp = client.get("/documents/")
    assert resp.status_code == 200
    assert b"Restricted Blueprint" in resp.data

    # 2. Viewer A logs in -> does NOT see document (not shared yet)
    login_user(client, "viewer@acme.com")
    resp = client.get("/documents/")
    assert resp.status_code == 200
    assert b"Restricted Blueprint" not in resp.data
    assert b"No documents have been shared" in resp.data

    # 3. Admin A logs in -> sees document in organization registry
    login_user(client, "admin@acme.com")
    resp = client.get("/documents/")
    assert resp.status_code == 200
    assert b"Restricted Blueprint" in resp.data
    assert b"Tenant Document Registry" in resp.data


def test_document_sharing_and_viewer_download(client, users, app, db_session):
    """
    Test complete sharing lifecycle:
    1. Owner uploads file
    2. Owner shares with Viewer A
    3. Viewer A downloads file successfully
    4. Audit events DOC_SHARE and DOC_DOWNLOAD are recorded
    """
    # 1. Owner logs in and uploads
    login_user(client, "owner@acme.com")
    pdf_stream, filename = create_dummy_pdf()
    client.post(
        "/documents/upload",
        data={"title": "Shared Contract", "category": "Legal", "file": (pdf_stream, filename)},
        content_type="multipart/form-data",
    )
    doc = Document.query.filter_by(title="Shared Contract").first()
    assert doc is not None

    # 2. Owner shares with Viewer A
    share_resp = client.post(
        f"/documents/{doc.id}/share",
        data={
            "recipient_email": "viewer@acme.com",
            "permission_level": "VIEW_DOWNLOAD",
        },
        follow_redirects=True,
    )
    assert share_resp.status_code == 200
    assert b"Access granted successfully" in share_resp.data

    # Verify Grant in DB
    grant = DocumentAccessGrant.query.filter_by(
        document_id=doc.id,
        granted_to_user_id=users["viewer_a"].id
    ).first()
    assert grant is not None
    assert grant.is_active is True

    # Verify DOC_SHARE audit event
    audit_share = AuditEvent.query.filter_by(
        action=AuditAction.DOC_SHARE,
        resource_id=doc.id
    ).first()
    assert audit_share is not None
    assert audit_share.actor_id == users["owner_a"].id

    # 3. Viewer A logs in and accesses document
    login_user(client, "viewer@acme.com")
    
    # Viewer sees in list
    list_resp = client.get("/documents/")
    assert b"Shared Contract" in list_resp.data

    # Viewer downloads file
    download_resp = client.get(f"/documents/{doc.id}/download")
    assert download_resp.status_code == 200
    assert download_resp.headers["Content-Disposition"].startswith("attachment")
    assert "confidential_plan.pdf" in download_resp.headers["Content-Disposition"]
    assert download_resp.headers["X-Content-Type-Options"] == "nosniff"
    assert download_resp.data.startswith(b"%PDF-")

    # 4. Verify DOC_DOWNLOAD audit event
    audit_dl = AuditEvent.query.filter_by(
        action=AuditAction.DOC_DOWNLOAD,
        resource_id=doc.id,
        actor_id=users["viewer_a"].id
    ).first()
    assert audit_dl is not None


def test_cross_tenant_sharing_prevented(client, users, db_session):
    """Test that Owner A cannot share documents with a user in Tenant B."""
    t_a = users["owner_a"].tenant
    doc = Document(
        tenant_id=t_a.id,
        owner_id=users["owner_a"].id,
        title="Tenant A Secrets",
        category="Confidential",
        original_filename="secrets.pdf",
        storage_key="storage_key_tenant_a_doc",
        file_size_bytes=500,
        mime_type="application/pdf",
        sha256_checksum="dummychecksum",
        is_deleted=False,
    )
    db_session.add(doc)
    db_session.commit()

    login_user(client, "owner@acme.com")

    # Attempt to share with viewer from Tenant B (Globex Corp)
    response = client.post(
        f"/documents/{doc.id}/share",
        data={
            "recipient_email": "viewer@globex.com",
            "permission_level": "VIEW_DOWNLOAD",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"User not found within your organization" in response.data

    # Verify no grant was created
    grant = DocumentAccessGrant.query.filter_by(document_id=doc.id).first()
    assert grant is None


def test_cross_tenant_access_and_download_opaque_404(client, users, db_session):
    """
    Test that users from Tenant B get opaque HTTP 404 when querying
    Tenant A's document details or download routes (preventing IDOR enumeration).
    """
    t_a = users["owner_a"].tenant
    doc_a = Document(
        tenant_id=t_a.id,
        owner_id=users["owner_a"].id,
        title="Confidential A Document",
        category="General",
        original_filename="confidential_a.pdf",
        storage_key="storage_key_doc_a_unique",
        file_size_bytes=500,
        mime_type="application/pdf",
        sha256_checksum="dummychecksum",
        is_deleted=False,
    )
    db_session.add(doc_a)
    db_session.commit()

    # Log in as Owner B from Tenant B
    login_user(client, "owner@globex.com")

    # Detail route must return 404
    resp_detail = client.get(f"/documents/{doc_a.id}")
    assert resp_detail.status_code == 404

    # Download route must return 404
    resp_download = client.get(f"/documents/{doc_a.id}/download")
    assert resp_download.status_code == 404


def test_admin_cannot_download_without_explicit_grant(client, users, app, db_session):
    """
    Security check: Admin can inspect document metadata for governance,
    but CANNOT read or download document contents without explicit grant.
    Attempts must return 403 and log an ACCESS_DENIED audit event.
    """
    # 1. Owner A logs in and uploads
    login_user(client, "owner@acme.com")
    pdf_stream, filename = create_dummy_pdf()
    client.post(
        "/documents/upload",
        data={"title": "Trade Secrets", "category": "Engineering", "file": (pdf_stream, filename)},
        content_type="multipart/form-data",
    )
    doc = Document.query.filter_by(title="Trade Secrets").first()

    # 2. Admin A logs in
    login_user(client, "admin@acme.com")

    # Metadata view works
    resp_detail = client.get(f"/documents/{doc.id}")
    assert resp_detail.status_code == 200
    assert b"Download Restricted" in resp_detail.data

    # Download attempt is rejected with 403
    resp_download = client.get(f"/documents/{doc.id}/download")
    assert resp_download.status_code == 403

    # Audit event ACCESS_DENIED is recorded
    audit = AuditEvent.query.filter_by(
        action=AuditAction.ACCESS_DENIED,
        resource_id=doc.id,
        actor_id=users["admin_a"].id
    ).first()
    assert audit is not None


def test_grant_revocation_immediate_cutoff(client, users, app, db_session):
    """Test that revoking an access grant immediately terminates download ability."""
    # 1. Owner A uploads and shares with Viewer A
    login_user(client, "owner@acme.com")
    pdf_stream, filename = create_dummy_pdf()
    client.post(
        "/documents/upload",
        data={"title": "Audit Review", "category": "General", "file": (pdf_stream, filename)},
        content_type="multipart/form-data",
    )
    doc = Document.query.filter_by(title="Audit Review").first()
    client.post(
        f"/documents/{doc.id}/share",
        data={"recipient_email": "viewer@acme.com", "permission_level": "VIEW_DOWNLOAD"},
    )
    grant = DocumentAccessGrant.query.filter_by(document_id=doc.id, granted_to_user_id=users["viewer_a"].id).first()

    # 2. Viewer A can download
    login_user(client, "viewer@acme.com")
    dl_resp = client.get(f"/documents/{doc.id}/download")
    assert dl_resp.status_code == 200

    # 3. Owner A revokes grant
    login_user(client, "owner@acme.com")
    revoke_resp = client.post(f"/documents/{doc.id}/grants/{grant.id}/revoke", follow_redirects=True)
    assert revoke_resp.status_code == 200
    assert b"Access revoked" in revoke_resp.data

    assert grant.is_active is False
    assert grant.revoked_at is not None

    # Verify DOC_REVOKE audit event
    audit_revoke = AuditEvent.query.filter_by(action=AuditAction.DOC_REVOKE, resource_id=doc.id).first()
    assert audit_revoke is not None

    # 4. Viewer A immediately blocked from downloading
    login_user(client, "viewer@acme.com")
    blocked_dl = client.get(f"/documents/{doc.id}/download")
    assert blocked_dl.status_code == 403


def test_owner_soft_delete_prevents_downloads(client, users, db_session):
    """
    Test that only the owner can delete their document,
    and soft-deleted documents immediately block all downloads.
    """
    # 1. Owner A uploads
    login_user(client, "owner@acme.com")
    pdf_stream, filename = create_dummy_pdf()
    client.post(
        "/documents/upload",
        data={"title": "To Be Deleted", "category": "General", "file": (pdf_stream, filename)},
        content_type="multipart/form-data",
    )
    doc = Document.query.filter_by(title="To Be Deleted").first()

    # 2. Viewer A cannot delete (403)
    login_user(client, "viewer@acme.com")
    resp_viewer_del = client.post(f"/documents/{doc.id}/delete")
    assert resp_viewer_del.status_code == 403

    # 3. Admin A cannot delete (403 - Owner-only deletion policy)
    login_user(client, "admin@acme.com")
    resp_admin_del = client.post(f"/documents/{doc.id}/delete")
    assert resp_admin_del.status_code == 403

    # 4. Owner A deletes document
    login_user(client, "owner@acme.com")
    resp_del = client.post(f"/documents/{doc.id}/delete", follow_redirects=True)
    assert resp_del.status_code == 200
    assert b"has been deleted" in resp_del.data

    # Verify is_deleted in DB
    db.session.refresh(doc)
    assert doc.is_deleted is True
    assert doc.deleted_at is not None

    # Verify DOC_DELETE audit event
    audit_del = AuditEvent.query.filter_by(action=AuditAction.DOC_DELETE, resource_id=doc.id).first()
    assert audit_del is not None

    # 5. Subsequent download attempt returns 404
    resp_dl = client.get(f"/documents/{doc.id}/download")
    assert resp_dl.status_code == 404


def test_storage_path_traversal_prevention(app):
    """Test that StorageService rejects malicious path traversal keys and characters."""
    storage_root = app.config["STORAGE_PATH"]
    tenant_id = "tenant-1234"

    # Malicious traversal keys
    traversal_keys = [
        "../../etc/passwd",
        "..\\..\\windows\\system32",
        "nested/path/key",
        "key with spaces",
        "",
        None,
        "a" * 65,  # Exceeds max length
    ]

    for bad_key in traversal_keys:
        with pytest.raises(ValueError):
            StorageService.get_file_path(storage_root, tenant_id, bad_key)
