from flask import Blueprint, render_template, redirect, url_for, flash, request, abort
from trustvault.models import db, User, UserRole, AuditEvent, AuditAction
from trustvault.services.authz import get_current_user, login_required, require_role
from trustvault.services.audit_service import AuditService
from trustvault.blueprints.admin.forms import UserProvisionForm

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.route("/users", methods=["GET"])
@login_required
@require_role(UserRole.ADMIN)
def users_list():
    """
    List all users belonging strictly to the authenticated Admin's tenant.
    Displays user roles, account activation status, and last login dates.
    """
    admin = get_current_user()
    form = UserProvisionForm()
    tenant_users = (
        User.query.filter_by(tenant_id=admin.tenant_id)
        .order_by(User.created_at.asc())
        .all()
    )
    return render_template("admin/users.html", users=tenant_users, form=form, admin=admin)


@admin_bp.route("/users/create", methods=["POST"])
@login_required
@require_role(UserRole.ADMIN)
def provision_user():
    """
    Provision an OWNER or VIEWER account within the Admin's tenant.
    Server derives tenant strictly from authenticated Admin.
    Rejects unauthorized roles (e.g. forged ADMIN role assignment).
    """
    admin = get_current_user()
    form = UserProvisionForm()

    if form.validate_on_submit():
        role = form.role.data
        if role not in (UserRole.OWNER, UserRole.VIEWER):
            flash("Privilege escalation blocked: Only OWNER and VIEWER accounts may be provisioned.", "danger")
            tenant_users = User.query.filter_by(tenant_id=admin.tenant_id).order_by(User.created_at.asc()).all()
            return render_template("admin/users.html", users=tenant_users, form=form, admin=admin), 400

        email = form.email.data.strip().lower()

        # Enforce global email uniqueness
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash(f"An account with email '{email}' already exists. Please choose a different corporate email.", "danger")
            tenant_users = User.query.filter_by(tenant_id=admin.tenant_id).order_by(User.created_at.asc()).all()
            return render_template("admin/users.html", users=tenant_users, form=form, admin=admin), 400

        # Create new user in Admin's tenant with temporary password
        new_user = User(
            tenant_id=admin.tenant_id,
            email=email,
            full_name=form.full_name.data.strip(),
            role=role,
            is_active=True,
            must_change_password=True,
        )
        new_user.set_password(form.password.data)

        db.session.add(new_user)
        db.session.commit()

        # Audit event
        AuditService.log_user_create(admin, new_user)

        flash(f"User account '{new_user.full_name}' ({new_user.role}) provisioned successfully.", "success")
        return redirect(url_for("admin.users_list"))

    # Form validation errors
    tenant_users = User.query.filter_by(tenant_id=admin.tenant_id).order_by(User.created_at.asc()).all()
    return render_template("admin/users.html", users=tenant_users, form=form, admin=admin), 400


@admin_bp.route("/users/<user_id>/toggle-status", methods=["POST"])
@login_required
@require_role(UserRole.ADMIN)
def toggle_user_status(user_id: str):
    """
    Activate or deactivate an account within the Admin's tenant.
    Never permits cross-tenant modification or self-deactivation.
    Deactivation immediately blocks future requests via get_current_user().
    """
    admin = get_current_user()

    # Scope lookup strictly to Admin's tenant (returns 404 if user belongs to another company)
    target_user = User.query.filter_by(id=user_id, tenant_id=admin.tenant_id).first_or_404()

    # Prevent Admin from deactivating their own account
    if target_user.id == admin.id:
        flash("Action blocked: You cannot deactivate your own administrative account.", "danger")
        return redirect(url_for("admin.users_list"))

    # Prevent unauthorized deactivation of other Admin accounts
    if target_user.is_admin:
        flash("Action blocked: Administrator accounts cannot be deactivated through this interface.", "warning")
        return redirect(url_for("admin.users_list"))

    # Toggle status
    target_user.is_active = not target_user.is_active
    db.session.commit()

    # Audit event
    AuditService.log_user_status_change(admin, target_user, target_user.is_active)

    status_str = "activated" if target_user.is_active else "deactivated"
    flash(f"Account for '{target_user.full_name}' has been {status_str}.", "info")
    return redirect(url_for("admin.users_list"))


@admin_bp.route("/audit-logs", methods=["GET"])
@login_required
@require_role(UserRole.ADMIN)
def audit_logs():
    """
    Append-only audit event log viewer strictly scoped to the Admin's tenant.
    Does not expose sensitive credentials, password values, or file bytes.
    No editing or deleting of records is permitted.
    """
    admin = get_current_user()
    action_filter = request.args.get("action", "").strip()

    query = AuditEvent.query.filter_by(tenant_id=admin.tenant_id)
    if action_filter:
        query = query.filter_by(action=action_filter)

    # Bounded query: latest 100 events
    logs = query.order_by(AuditEvent.created_at.desc()).limit(100).all()

    # Distinct actions for filter dropdown
    distinct_actions = [
        AuditAction.AUTH_LOGIN_SUCCESS,
        AuditAction.AUTH_LOGIN_FAILURE,
        AuditAction.AUTH_LOGOUT,
        AuditAction.TENANT_ONBOARD,
        AuditAction.USER_CREATE,
        AuditAction.USER_STATUS_CHANGE,
        AuditAction.DOC_UPLOAD,
        AuditAction.DOC_DOWNLOAD,
        AuditAction.DOC_SHARE,
        AuditAction.DOC_REVOKE,
        AuditAction.DOC_DELETE,
        AuditAction.ACCESS_DENIED,
    ]

    return render_template(
        "admin/audit_logs.html",
        logs=logs,
        action_filter=action_filter,
        distinct_actions=distinct_actions,
        admin=admin,
    )
