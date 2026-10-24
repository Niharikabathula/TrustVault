import json
from typing import Any, Dict, Optional
from trustvault.models.base import db, generate_uuid, utc_now


class AuditAction:
    AUTH_LOGIN_SUCCESS = "AUTH_LOGIN_SUCCESS"
    AUTH_LOGIN_FAILURE = "AUTH_LOGIN_FAILURE"
    AUTH_LOGOUT = "AUTH_LOGOUT"
    TENANT_ONBOARD = "TENANT_ONBOARD"
    USER_CREATE = "USER_CREATE"
    USER_STATUS_CHANGE = "USER_STATUS_CHANGE"
    USER_ROLE_CHANGE = "USER_ROLE_CHANGE"
    DOC_UPLOAD = "DOC_UPLOAD"
    DOC_DOWNLOAD = "DOC_DOWNLOAD"
    DOC_SHARE = "DOC_SHARE"
    DOC_REVOKE = "DOC_REVOKE"
    DOC_DELETE = "DOC_DELETE"
    ACCESS_DENIED = "ACCESS_DENIED"


class AuditOutcome:
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    DENIED = "DENIED"


def sanitize_audit_metadata(data: Any) -> Any:
    """
    Recursively sanitize metadata dictionary, list, or primitive values.
    Redacts any sensitive keys (case-insensitive match) in nested structures.
    """
    if data is None:
        return None

    SENSITIVE_KEYS = {
        "password", "password_hash", "token", "secret", "csrf_token",
        "file_bytes", "api_key", "authorization", "private_key", "credit_card"
    }

    if isinstance(data, dict):
        sanitized = {}
        for key, val in data.items():
            key_lower = str(key).lower().replace("-", "_")
            if any(s in key_lower for s in SENSITIVE_KEYS) and not isinstance(val, (dict, list, tuple)):
                sanitized[key] = "[REDACTED]"
            else:
                sanitized[key] = sanitize_audit_metadata(val)
        return sanitized
    elif isinstance(data, (list, tuple)):
        return [sanitize_audit_metadata(item) for item in data]
    else:
        return data


class AuditEvent(db.Model):
    """
    Append-only tamper-resistant audit event record.
    Application-level code provides no update or delete routes.
    All events are strictly scoped to a tenant.
    """
    __tablename__ = "audit_events"

    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    tenant_id = db.Column(db.String(36), db.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True, index=True)
    actor_id = db.Column(db.String(36), db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    actor_email = db.Column(db.String(255), nullable=True)
    actor_role = db.Column(db.String(20), nullable=True)
    action = db.Column(db.String(50), nullable=False, index=True)
    resource_type = db.Column(db.String(50), nullable=False)
    resource_id = db.Column(db.String(36), nullable=True, index=True)
    outcome = db.Column(db.String(20), nullable=False, default=AuditOutcome.SUCCESS)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)
    details_json = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False, index=True)

    # Relationship
    tenant = db.relationship("Tenant", back_populates="audit_events")
    actor = db.relationship("User", foreign_keys=[actor_id])

    def get_details(self) -> Dict[str, Any]:
        """Safely deserialize stored JSON details."""
        if not self.details_json:
            return {}
        try:
            return json.loads(self.details_json)
        except Exception:
            return {}

    def set_details(self, details: Optional[Dict[str, Any]]) -> None:
        """Serialize details dictionary into sanitized JSON, excluding sensitive fields recursively."""
        if not details:
            self.details_json = None
            return
        sanitized = sanitize_audit_metadata(details)
        self.details_json = json.dumps(sanitized)

    def __repr__(self) -> str:
        return f"<AuditEvent {self.action} by {self.actor_email} outcome={self.outcome} ({self.created_at})>"
