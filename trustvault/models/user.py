from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from trustvault.models.base import db, generate_uuid, utc_now


class UserRole:
    ADMIN = "ADMIN"
    OWNER = "OWNER"
    VIEWER = "VIEWER"
    ALL_ROLES = [ADMIN, OWNER, VIEWER]


class User(db.Model):
    """
    Represents an authorized user within a specific tenant.
    A user belongs strictly to one tenant (strict 1-tenant membership).
    Email is globally unique across the system to eliminate multi-tenant login ambiguity.
    """
    __tablename__ = "users"

    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    tenant_id = db.Column(db.String(36), db.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False, default=UserRole.VIEWER)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    must_change_password = db.Column(db.Boolean, default=False, nullable=False)
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)
    last_login_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False)
    updated_at = db.Column(db.DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    # Relationships
    tenant = db.relationship("Tenant", back_populates="users")
    owned_documents = db.relationship("Document", back_populates="owner", foreign_keys="Document.owner_id", cascade="all, delete-orphan")
    received_grants = db.relationship("DocumentAccessGrant", back_populates="granted_to", foreign_keys="DocumentAccessGrant.granted_to_user_id", cascade="all, delete-orphan")
    issued_grants = db.relationship("DocumentAccessGrant", back_populates="granted_by", foreign_keys="DocumentAccessGrant.granted_by_user_id")

    def set_password(self, password: str) -> None:
        """Hash and salt the password using Werkzeug's default modern hashing (Scrypt or PBKDF2)."""
        if not password or len(password) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        if len(password) > 128:
            raise ValueError("Password cannot exceed 128 characters.")
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """Securely verify password against stored salted hash."""
        if not self.password_hash or not password:
            return False
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self) -> bool:
        return self.role == UserRole.ADMIN

    @property
    def is_owner(self) -> bool:
        return self.role == UserRole.OWNER

    @property
    def is_viewer(self) -> bool:
        return self.role == UserRole.VIEWER

    def is_locked(self) -> bool:
        """Check if account is currently temporarily locked due to failed login attempts."""
        if self.locked_until:
            now = datetime.now(timezone.utc)
            locked_until_utc = self.locked_until.replace(tzinfo=timezone.utc) if self.locked_until.tzinfo is None else self.locked_until
            return now < locked_until_utc
        return False

    def __repr__(self) -> str:
        return f"<User {self.email} ({self.role}) Tenant={self.tenant_id}>"
