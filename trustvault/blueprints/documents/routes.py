from flask import (
    Blueprint,
    render_template,
    redirect,
    url_for,
    flash,
    request,
    send_file,
    abort,
    current_app,
)
from trustvault.models import (
    db,
    Document,
    DocumentAccessGrant,
    User,
    UserRole,
    utc_now,
)
from trustvault.blueprints.documents.forms import DocumentUploadForm, ShareDocumentForm
from trustvault.services.authz import (
    get_current_user,
    login_required,
    require_role,
    enforce_tenant_boundary,
    can_manage_document_access,
    can_view_document_metadata,
    can_download_document,
    can_delete_document,
)
from trustvault.services.storage_service import StorageService, ValidationError
from trustvault.services.audit_service import AuditService

documents_bp = Blueprint("documents", __name__, url_prefix="/documents")


@documents_bp.route("/", methods=["GET"])
@login_required
def document_list():
    """
    List accessible documents scoped strictly to the user's role and tenant:
    - OWNER: Sees owned documents + documents shared with them.
    - VIEWER: Sees only documents explicitly shared with them via an active grant.
    - ADMIN: Sees organization document metadata registry for governance/audit.
    """
    user = get_current_user()
    search_query = request.args.get("q", "").strip()
    category_filter = request.args.get("category", "").strip()

    if user.is_owner:
        # Owned documents
        owned_query = Document.query.filter_by(
            tenant_id=user.tenant_id,
            owner_id=user.id,
            is_deleted=False
        )
        if search_query:
            owned_query = owned_query.filter(Document.title.ilike(f"%{search_query}%"))
        if category_filter:
            owned_query = owned_query.filter_by(category=category_filter)
        owned_docs = owned_query.order_by(Document.created_at.desc()).all()

        # Shared with owner by others
        shared_grants_query = (
            DocumentAccessGrant.query.join(Document)
            .filter(
                DocumentAccessGrant.tenant_id == user.tenant_id,
                DocumentAccessGrant.granted_to_user_id == user.id,
                DocumentAccessGrant.revoked_at.is_(None),
                Document.is_deleted.is_(False),
                Document.owner_id != user.id,
            )
        )
        if search_query:
            shared_grants_query = shared_grants_query.filter(Document.title.ilike(f"%{search_query}%"))
        if category_filter:
            shared_grants_query = shared_grants_query.filter(Document.category == category_filter)
        shared_grants = shared_grants_query.all()
        shared_docs = [grant.document for grant in shared_grants]

        return render_template(
            "documents/list.html",
            user=user,
            owned_docs=owned_docs,
            shared_docs=shared_docs,
            search_query=search_query,
            category_filter=category_filter,
        )

    elif user.is_viewer:
        # Viewer sees ONLY documents explicitly granted to them
        shared_grants_query = (
            DocumentAccessGrant.query.join(Document)
            .filter(
                DocumentAccessGrant.tenant_id == user.tenant_id,
                DocumentAccessGrant.granted_to_user_id == user.id,
                DocumentAccessGrant.revoked_at.is_(None),
                Document.is_deleted.is_(False),
            )
        )
        if search_query:
            shared_grants_query = shared_grants_query.filter(Document.title.ilike(f"%{search_query}%"))
        if category_filter:
            shared_grants_query = shared_grants_query.filter(Document.category == category_filter)
        shared_grants = shared_grants_query.all()
        shared_docs = [grant.document for grant in shared_grants]

        return render_template(
            "documents/list.html",
            user=user,
            owned_docs=[],
            shared_docs=shared_docs,
            search_query=search_query,
            category_filter=category_filter,
        )

    else:
        # ADMIN: Governance metadata list
        admin_query = Document.query.filter_by(
            tenant_id=user.tenant_id,
            is_deleted=False
        )
        if search_query:
            admin_query = admin_query.filter(Document.title.ilike(f"%{search_query}%"))
        if category_filter:
            admin_query = admin_query.filter_by(category=category_filter)
        admin_docs = admin_query.order_by(Document.created_at.desc()).all()

        return render_template(
            "documents/list.html",
            user=user,
            admin_docs=admin_docs,
            search_query=search_query,
            category_filter=category_filter,
        )


@documents_bp.route("/upload", methods=["GET", "POST"])
@login_required
@require_role(UserRole.OWNER)
def upload():
    """
    Owner uploads confidential document into the tenant vault.
    Validates file format, magic bytes, size limits, and sanitizes storage key.
    """
    user = get_current_user()
    form = DocumentUploadForm()

    if form.validate_on_submit():
        file_obj = form.file.data
        storage_root = current_app.config["STORAGE_PATH"]
        max_size = current_app.config.get("MAX_CONTENT_LENGTH", 10 * 1024 * 1024)

        try:
            save_result = StorageService.save_file(
                storage_root=storage_root,
                tenant_id=user.tenant_id,
                file_storage=file_obj,
                max_size_bytes=max_size,
            )
        except ValidationError as e:
            flash(str(e), "danger")
            return render_template("documents/upload.html", form=form), 400
        except Exception as e:
            flash("An unexpected error occurred while saving the file. Please try again.", "danger")
            return render_template("documents/upload.html", form=form), 500

        doc = Document(
            tenant_id=user.tenant_id,
            owner_id=user.id,
            title=form.title.data.strip(),
            description=form.description.data.strip() if form.description.data else None,
            category=form.category.data,
            original_filename=save_result["original_filename"],
            storage_key=save_result["storage_key"],
            file_size_bytes=save_result["file_size_bytes"],
            mime_type=save_result["mime_type"],
            sha256_checksum=save_result["sha256_checksum"],
            is_deleted=False,
        )

        db.session.add(doc)
        db.session.commit()

        # Audit Event
        AuditService.log_doc_upload(doc, user)

        flash(f"Document '{doc.title}' uploaded successfully.", "success")
        return redirect(url_for("documents.document_detail", doc_id=doc.id))

    return render_template("documents/upload.html", form=form)


@documents_bp.route("/<doc_id>", methods=["GET"])
@login_required
def document_detail(doc_id: str):
    """
    View document metadata and sharing management:
    - Owner can view and manage access grants.
    - Admin can view metadata and manage access.
    - Viewer can view metadata only if explicitly granted active access.
    - Cross-tenant requests trigger opaque 404 (IDOR mitigation).
    """
    user = get_current_user()
    doc = Document.query.filter_by(id=doc_id, is_deleted=False).first()
    if not doc:
        abort(404)

    enforce_tenant_boundary(doc)

    if not can_view_document_metadata(doc, user):
        abort(404)

    can_manage = can_manage_document_access(doc, user)
    can_download = can_download_document(doc, user)
    can_delete = can_delete_document(doc, user)

    share_form = ShareDocumentForm() if can_manage else None
    active_grants = []
    if can_manage:
        active_grants = (
            DocumentAccessGrant.query.filter_by(
                document_id=doc.id,
                tenant_id=user.tenant_id,
                revoked_at=None
            )
            .order_by(DocumentAccessGrant.created_at.desc())
            .all()
        )

    return render_template(
        "documents/detail.html",
        doc=doc,
        user=user,
        can_manage=can_manage,
        can_download=can_download,
        can_delete=can_delete,
        share_form=share_form,
        active_grants=active_grants,
    )


@documents_bp.route("/<doc_id>/download", methods=["GET"])
@login_required
def download(doc_id: str):
    """
    Secure document download endpoint:
    - Server verifies tenant isolation and active download authorization.
    - Admin without explicit grant cannot read or download file contents.
    - Deleted documents cannot be downloaded.
    - Protects against path traversal and force-serves as attachment with nosniff.
    """
    user = get_current_user()
    doc = Document.query.filter_by(id=doc_id, is_deleted=False).first()
    if not doc:
        abort(404)

    enforce_tenant_boundary(doc)

    if not can_download_document(doc, user):
        AuditService.log_access_denied(
            actor=user,
            action="DOC_DOWNLOAD",
            resource_type="DOCUMENT",
            resource_id=doc.id,
            reason="User does not possess active download authorization.",
        )
        abort(403)

    storage_root = current_app.config["STORAGE_PATH"]
    try:
        file_path = StorageService.get_file_path(storage_root, doc.tenant_id, doc.storage_key)
    except (ValueError, FileNotFoundError):
        abort(404)

    # Audit download event
    AuditService.log_doc_download(doc, user)

    response = send_file(
        file_path,
        as_attachment=True,
        download_name=doc.original_filename,
        mimetype=doc.mime_type,
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@documents_bp.route("/<doc_id>/share", methods=["POST"])
@login_required
def share(doc_id: str):
    """
    Share document with an eligible user in the same tenant.
    Only authorized Admin or document Owner can manage access.
    """
    user = get_current_user()
    doc = Document.query.filter_by(id=doc_id, is_deleted=False).first_or_404()
    enforce_tenant_boundary(doc)

    if not can_manage_document_access(doc, user):
        AuditService.log_access_denied(
            actor=user,
            action="DOC_SHARE",
            resource_type="DOCUMENT",
            resource_id=doc.id,
            reason="User not authorized to manage access grants.",
        )
        abort(403)

    form = ShareDocumentForm()
    if form.validate_on_submit():
        recipient_email = form.recipient_email.data.strip().lower()

        # Strict tenant boundary on recipient lookup
        recipient = User.query.filter_by(email=recipient_email, tenant_id=user.tenant_id).first()
        if not recipient:
            flash("User not found within your organization.", "danger")
            return redirect(url_for("documents.document_detail", doc_id=doc.id))

        if recipient.id == doc.owner_id:
            flash("The document owner already has full access to this document.", "info")
            return redirect(url_for("documents.document_detail", doc_id=doc.id))

        if recipient.id == user.id:
            flash("You cannot grant access to yourself.", "warning")
            return redirect(url_for("documents.document_detail", doc_id=doc.id))

        if not recipient.is_active:
            flash("Cannot grant access to a deactivated user account.", "danger")
            return redirect(url_for("documents.document_detail", doc_id=doc.id))

        # Check existing grant
        existing_grant = DocumentAccessGrant.query.filter_by(
            document_id=doc.id,
            granted_to_user_id=recipient.id,
        ).first()

        if existing_grant and existing_grant.is_active:
            flash(f"Document is already actively shared with {recipient.full_name}.", "info")
            return redirect(url_for("documents.document_detail", doc_id=doc.id))

        if existing_grant and not existing_grant.is_active:
            existing_grant.reactivate(actor_user_id=user.id)
        else:
            grant = DocumentAccessGrant(
                tenant_id=user.tenant_id,
                document_id=doc.id,
                granted_to_user_id=recipient.id,
                granted_by_user_id=user.id,
                permission_level=form.permission_level.data,
            )
            db.session.add(grant)

        db.session.commit()
        AuditService.log_doc_share(doc, user, recipient)

        flash(f"Access granted successfully to {recipient.full_name} ({recipient.email}).", "success")
        return redirect(url_for("documents.document_detail", doc_id=doc.id))

    for field, errors in form.errors.items():
        for error in errors:
            flash(f"{field}: {error}", "danger")

    return redirect(url_for("documents.document_detail", doc_id=doc.id))


@documents_bp.route("/<doc_id>/grants/<grant_id>/revoke", methods=["POST"])
@login_required
def revoke_grant(doc_id: str, grant_id: str):
    """
    Revoke a document access grant immediately.
    Preserves audit history while terminating access.
    """
    user = get_current_user()
    doc = Document.query.filter_by(id=doc_id, is_deleted=False).first_or_404()
    enforce_tenant_boundary(doc)

    if not can_manage_document_access(doc, user):
        AuditService.log_access_denied(
            actor=user,
            action="DOC_REVOKE",
            resource_type="DOCUMENT",
            resource_id=doc.id,
            reason="User not authorized to revoke access grants.",
        )
        abort(403)

    grant = DocumentAccessGrant.query.filter_by(
        id=grant_id,
        document_id=doc.id,
        tenant_id=user.tenant_id,
    ).first_or_404()

    if not grant.is_active:
        flash("Access grant is already revoked.", "info")
        return redirect(url_for("documents.document_detail", doc_id=doc.id))

    target_user = grant.granted_to
    grant.revoke()
    db.session.commit()

    AuditService.log_doc_revoke(doc, user, target_user)

    flash(f"Access revoked for {target_user.full_name} ({target_user.email}).", "info")
    return redirect(url_for("documents.document_detail", doc_id=doc.id))


@documents_bp.route("/<doc_id>/delete", methods=["POST"])
@login_required
def delete(doc_id: str):
    """
    Soft-delete document (Owner-only deletion policy).
    Preserves database record and audit history while immediately blocking downloads.
    """
    user = get_current_user()
    doc = Document.query.filter_by(id=doc_id, is_deleted=False).first_or_404()
    enforce_tenant_boundary(doc)

    if not can_delete_document(doc, user):
        AuditService.log_access_denied(
            actor=user,
            action="DOC_DELETE",
            resource_type="DOCUMENT",
            resource_id=doc.id,
            reason="Only the document owner can delete this document.",
        )
        abort(403)

    doc.is_deleted = True
    doc.deleted_at = utc_now()
    db.session.commit()

    AuditService.log_doc_delete(doc, user)

    flash(f"Document '{doc.title}' has been deleted.", "success")
    return redirect(url_for("documents.document_list"))
