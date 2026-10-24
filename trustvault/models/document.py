from trustvault.models.base import db, generate_uuid, utc_now


class Document(db.Model):
    """
    Represents a confidential document owned by an OWNER within a tenant.
    Physical file content is stored outside the web root under storage_key.
    """
    __tablename__ = "documents"

    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    tenant_id = db.Column(db.String(36), db.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    owner_id = db.Column(db.String(36), db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    category = db.Column(db.String(50), nullable=False, default="General")
    original_filename = db.Column(db.String(255), nullable=False)
    storage_key = db.Column(db.String(100), unique=True, nullable=False, index=True)
    file_size_bytes = db.Column(db.Integer, nullable=False)
    mime_type = db.Column(db.String(100), nullable=False)
    sha256_checksum = db.Column(db.String(64), nullable=False)
    is_deleted = db.Column(db.Boolean, default=False, nullable=False, index=True)
    deleted_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False)
    updated_at = db.Column(db.DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    # Relationships
    tenant = db.relationship("Tenant", back_populates="documents")
    owner = db.relationship("User", back_populates="owned_documents", foreign_keys=[owner_id])
    access_grants = db.relationship("DocumentAccessGrant", back_populates="document", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Document {self.title} (Tenant={self.tenant_id}, Owner={self.owner_id})>"
