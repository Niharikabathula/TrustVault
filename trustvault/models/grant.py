from trustvault.models.base import db, generate_uuid, utc_now


class DocumentAccessGrant(db.Model):
    """
    Explicit document access grant for a user within the same tenant.
    Only ADMIN and document OWNER can manage access.
    Revocation immediately invalidates access while preserving history.
    """
    __tablename__ = "document_access_grants"
    __table_args__ = (
        db.Index("ix_grant_doc_user", "document_id", "granted_to_user_id"),
    )

    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    tenant_id = db.Column(db.String(36), db.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    document_id = db.Column(db.String(36), db.ForeignKey("documents.id", ondelete="CASCADE"), nullable=False, index=True)
    granted_to_user_id = db.Column(db.String(36), db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    granted_by_user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False)
    permission_level = db.Column(db.String(20), default="VIEW_DOWNLOAD", nullable=False)
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False)
    revoked_at = db.Column(db.DateTime, nullable=True, index=True)

    # Relationships
    document = db.relationship("Document", back_populates="access_grants")
    granted_to = db.relationship("User", back_populates="received_grants", foreign_keys=[granted_to_user_id])
    granted_by = db.relationship("User", back_populates="issued_grants", foreign_keys=[granted_by_user_id])

    @property
    def is_active(self) -> bool:
        """True if the access grant is currently active (not revoked)."""
        return self.revoked_at is None

    def revoke(self) -> None:
        """Mark access grant as revoked immediately."""
        self.revoked_at = utc_now()

    def reactivate(self, actor_user_id: str) -> None:
        """Reactivate a previously revoked grant."""
        self.revoked_at = None
        self.granted_by_user_id = actor_user_id
        self.created_at = utc_now()

    def __repr__(self) -> str:
        status = "ACTIVE" if self.is_active else "REVOKED"
        return f"<AccessGrant Doc={self.document_id} To={self.granted_to_user_id} Status={status}>"
