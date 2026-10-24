import re
from datetime import datetime, timedelta, timezone
from flask import Blueprint, render_template, redirect, url_for, flash, request, session, abort
from trustvault.models import db, Tenant, User, UserRole, AuditAction, utc_now
from trustvault.blueprints.auth.forms import LoginForm, TenantRegistrationForm, ChangePasswordForm
from trustvault.services.authz import get_current_user, login_required, get_client_ip
from trustvault.services.audit_service import AuditService
from trustvault.services.rate_limiter import login_rate_limiter

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


def slugify(text: str) -> str:
    """Generate a clean, URL-safe tenant slug from company name."""
    text = text.lower().strip()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"[\s_-]+", "-", text)
    return text.strip("-") or "company"


@auth_bp.route("/register-tenant", methods=["GET", "POST"])
def register_tenant():
    """
    Public onboarding: Creates a brand-new Tenant and registers its first Admin.
    Users cannot use this route to join an existing tenant or self-assign roles.
    """
    logged_user = get_current_user()
    if logged_user:
        if logged_user.must_change_password:
            return redirect(url_for("auth.profile"))
        return redirect(url_for("main.index"))

    form = TenantRegistrationForm()
    if form.validate_on_submit():
        company_name = form.company_name.data.strip()
        admin_email = form.admin_email.data.strip().lower()
        full_name = form.full_name.data.strip()
        password = form.password.data

        # Generate unique tenant slug
        base_slug = slugify(company_name)
        slug = base_slug
        counter = 1
        while Tenant.query.filter_by(slug=slug).first():
            slug = f"{base_slug}-{counter}"
            counter += 1

        # Check if an admin with this email already exists in a tenant with this slug
        existing_user = User.query.filter_by(email=admin_email).first()
        if existing_user:
            flash("An account with this email is already registered. Please sign in or use a different email.", "danger")
            return render_template("auth/register_tenant.html", form=form)

        # 1. Create Tenant
        tenant = Tenant(name=company_name, slug=slug, is_active=True)
        db.session.add(tenant)
        db.session.flush()  # Populates tenant.id

        # 2. Create Initial Admin User
        admin_user = User(
            tenant_id=tenant.id,
            email=admin_email,
            full_name=full_name,
            role=UserRole.ADMIN,
            is_active=True,
            must_change_password=False
        )
        admin_user.set_password(password)
        db.session.add(admin_user)
        db.session.commit()

        # 3. Log Audit Event
        AuditService.log_tenant_onboard(tenant, admin_user)

        flash(f"Organization '{company_name}' successfully registered! Please sign in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register_tenant.html", form=form)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """
    Secure login with IP and account rate-limiting, generic error messages,
    and session fixation defense (session rotation).
    """
    logged_user = get_current_user()
    if logged_user:
        if logged_user.must_change_password:
            return redirect(url_for("auth.profile"))
        return redirect(url_for("main.index"))

    client_ip = get_client_ip()

    form = LoginForm()

    if request.method == "POST":
        if login_rate_limiter.is_rate_limited(client_ip):
            AuditService.log_login_failure("IP_RATE_LIMITED", None, reason="IP rate limit exceeded")
            flash("Too many login attempts from this network. Please try again later.", "danger")
            return render_template("auth/login.html", form=form), 429

    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        password = form.password.data

        user = User.query.filter_by(email=email).first()

        # Check if account is temporarily locked
        if user and user.is_locked():
            login_rate_limiter.record_attempt(client_ip)
            AuditService.log_login_failure(email, user.tenant_id, reason="Account temporarily locked")
            flash("Account is temporarily locked due to multiple failed login attempts. Please try again in 15 minutes.", "danger")
            return render_template("auth/login.html", form=form)

        # Authenticate user credentials
        if not user or not user.check_password(password):
            login_rate_limiter.record_attempt(client_ip)
            if user:
                user.failed_login_attempts += 1
                if user.failed_login_attempts >= 5:
                    user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)
                db.session.commit()
                AuditService.log_login_failure(email, user.tenant_id, reason="Invalid password")
            else:
                AuditService.log_login_failure(email, None, reason="User does not exist")

            # Generic error message to prevent user enumeration
            flash("Invalid email or password.", "danger")
            return render_template("auth/login.html", form=form)

        # Check account active status
        if not user.is_active or not user.tenant.is_active:
            login_rate_limiter.record_attempt(client_ip)
            AuditService.log_login_failure(email, user.tenant_id, reason="Account or tenant deactivated")
            flash("This account or organization has been deactivated. Please contact your administrator.", "danger")
            return render_template("auth/login.html", form=form)

        # Authentication Successful: Reset lockouts & update timestamps
        user.failed_login_attempts = 0
        user.locked_until = None
        user.last_login_at = utc_now()
        db.session.commit()
        login_rate_limiter.reset(client_ip)

        # Session Fixation Defense: Invalidate existing session and issue fresh identifiers
        session.clear()
        session["user_id"] = user.id
        session["tenant_id"] = user.tenant_id
        session["user_role"] = user.role
        session.permanent = True

        AuditService.log_login_success(user)

        if user.must_change_password:
            flash(f"Welcome back, {user.full_name}! You are using a temporary password. Please update your password to continue.", "warning")
            return redirect(url_for("auth.profile"))

        flash(f"Welcome back, {user.full_name}!", "success")
        next_page = request.args.get("next")
        # Validate that redirect target is safe (relative URL only)
        if next_page and next_page.startswith("/"):
            return redirect(next_page)
        return redirect(url_for("main.index"))

    return render_template("auth/login.html", form=form)


@auth_bp.route("/logout", methods=["POST"])
def logout():
    """Secure logout requiring CSRF-validated POST request."""
    user = get_current_user()
    if user:
        AuditService.log_logout(user)
    session.clear()
    flash("You have been securely logged out.", "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    """User profile overview and password change."""
    user = get_current_user()
    form = ChangePasswordForm()

    if form.validate_on_submit():
        if not user.check_password(form.current_password.data):
            flash("Current password is incorrect.", "danger")
            return render_template("auth/profile.html", user=user, form=form)

        user.set_password(form.new_password.data)
        user.must_change_password = False
        db.session.commit()

        AuditService.log(
            action=AuditAction.USER_PASSWORD_CHANGE,
            resource_type="USER",
            actor=user,
            resource_id=user.id,
            details={"email": user.email}
        )

        flash("Your password has been successfully updated.", "success")
        return redirect(url_for("auth.profile"))

    return render_template("auth/profile.html", user=user, form=form)
