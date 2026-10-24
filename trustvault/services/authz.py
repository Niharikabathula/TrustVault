from functools import wraps
from typing import Optional, List, Callable, Any
from flask import session, redirect, url_for, request, abort, g, flash, has_request_context, current_app
from trustvault.models import db, User, Tenant, Document, DocumentAccessGrant, UserRole


def get_client_ip() -> Optional[str]:
    """
    Safely extract the client IP address.

    Security Boundary:
    By default, uses direct request.remote_addr to prevent IP spoofing attacks via
    unverified client-supplied headers (e.g. X-Forwarded-For).

    Forwarded headers are evaluated ONLY if TRUST_PROXY_HEADERS is explicitly enabled
    in the application configuration for trusted reverse-proxy deployments.
    When enabled, the leftmost client IP from X-Forwarded-For is extracted.
    """
    if not has_request_context():
        return None

    if current_app and current_app.config.get("TRUST_PROXY_HEADERS"):
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()

    return request.remote_addr


def get_current_user() -> Optional[User]:
    """
    Retrieve and validate the active authenticated user from server session.
    Derives identity exclusively from server session, never from browser parameters.
    Invalidates session immediately if user or tenant has been deactivated.
    """
    user_id = session.get("user_id")
    if not user_id:
        return None

    user = db.session.get(User, user_id)
    if not user or not user.is_active or not user.tenant or not user.tenant.is_active:
        # User or Tenant was deleted or deactivated: invalidate session immediately
        session.clear()
        return None

    return user


def get_current_tenant() -> Optional[Tenant]:
    """Retrieve the active tenant for the currently authenticated user."""
    user = get_current_user()
    if not user:
        return None
    return user.tenant


def login_required(f: Callable) -> Callable:
    """Decorator ensuring request has a valid, active authenticated session."""
    @wraps(f)
    def decorated_function(*args: Any, **kwargs: Any) -> Any:
        user = get_current_user()
        if not user:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("auth.login", next=request.path))

        # Central temporary password enforcement: block access until password is changed
        if user.must_change_password and request.endpoint not in ("auth.profile", "auth.logout"):
            flash("You must update your temporary password before accessing other features.", "warning")
            return redirect(url_for("auth.profile"))

        return f(*args, **kwargs)
    return decorated_function


def require_role(*allowed_roles: str) -> Callable:
    """Decorator restricting access to specified roles within the user's tenant."""
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args: Any, **kwargs: Any) -> Any:
            user = get_current_user()
            if not user:
                flash("Please log in to continue.", "warning")
                return redirect(url_for("auth.login"))

            # Central temporary password enforcement: block access until password is changed
            if user.must_change_password and request.endpoint not in ("auth.profile", "auth.logout"):
                flash("You must update your temporary password before accessing other features.", "warning")
                return redirect(url_for("auth.profile"))

            if user.role not in allowed_roles:
                # Role not authorized: return 403 Forbidden
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def enforce_tenant_boundary(resource: Any) -> None:
    """
    Enforce strict tenant isolation on any tenant-owned resource.
    If resource belongs to a different tenant, return 404 Not Found to prevent
    information enumeration (attacker cannot verify if ID exists in another company).
    """
    user = get_current_user()
    if not user or not hasattr(resource, "tenant_id"):
        abort(404)

    if resource.tenant_id != user.tenant_id:
        # Cross-tenant boundary violation attempt!
        abort(404)


def can_manage_document_access(document: Document, user: User) -> bool:
    """
    Per challenge requirements:
    Only ADMIN and document OWNER may manage access, subject to tenant boundaries.
    """
    if document.tenant_id != user.tenant_id or document.is_deleted:
        return False
    
    # OWNER manages access for their own document
    if document.owner_id == user.id:
        return True
    
    # ADMIN manages access for documents within their tenant (for governance/handover)
    if user.role == UserRole.ADMIN:
        return True
    
    return False


def can_view_document_metadata(document: Document, user: User) -> bool:
    """
    Check if user is authorized to view document metadata.
    - Owner can view
    - Admin can view tenant metadata for governance
    - Viewer can view ONLY if granted active access
    """
    if document.tenant_id != user.tenant_id or document.is_deleted:
        return False

    if user.role == UserRole.ADMIN or document.owner_id == user.id:
        return True

    # Check active grant for VIEWER
    grant = DocumentAccessGrant.query.filter_by(
        document_id=document.id,
        granted_to_user_id=user.id,
        revoked_at=None
    ).first()
    return grant is not None


def can_download_document(document: Document, user: User) -> bool:
    """
    Strict per-request download authorization guard.
    - Owner can download
    - Viewer can download ONLY if actively granted access
    - Admin cannot download confidential files by default unless granted or is owner
    """
    if document.tenant_id != user.tenant_id or document.is_deleted:
        return False

    if document.owner_id == user.id:
        return True

    # Check active grant
    grant = DocumentAccessGrant.query.filter_by(
        document_id=document.id,
        granted_to_user_id=user.id,
        revoked_at=None
    ).first()
    return grant is not None


def can_delete_document(document: Document, user: User) -> bool:
    """
    Consistent deletion policy:
    Only the document OWNER can soft-delete their own documents.
    """
    if document.tenant_id != user.tenant_id or document.is_deleted:
        return False
    return document.owner_id == user.id
