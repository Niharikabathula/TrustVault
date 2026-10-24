from datetime import datetime
from trustvault.models.base import db, generate_uuid, utc_now


class Tenant(db.Model):
    """
    Represents an organization / company tenant in TrustVault.
    All confidential assets, users, and audit records belong strictly to one tenant.
    """
    __tablename__ = "tenants"

    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    name = db.Column(db.String(100), nullable=False)
    slug = db.Column(db.String(100), unique=True, nullable=False, index=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False)
    updated_at = db.Column(db.DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    # Relationships
    users = db.relationship("User", back_populates="tenant", cascade="all, delete-orphan")
    documents = db.relationship("Document", back_populates="tenant", cascade="all, delete-orphan")
    audit_events = db.relationship("AuditEvent", back_populates="tenant", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Tenant {self.name} ({self.id})>"
