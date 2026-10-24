from flask import Blueprint, render_template, redirect, url_for
from trustvault.services.authz import get_current_user

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def index():
    """Main route: displays landing page or dashboard overview depending on session."""
    user = get_current_user()
    if not user:
        return render_template("index.html")
    return render_template("dashboard.html", user=user, tenant=user.tenant)


@main_bp.route("/health")
def health():
    """Opaque healthcheck endpoint for monitoring and uptime probes."""
    return {"status": "healthy", "service": "trustvault"}, 200
