from typing import Optional, Dict, Any
from flask import request, has_request_context
from trustvault.models import db, AuditEvent, AuditAction, AuditOutcome, User, Tenant


class AuditService:
    """
    Append-only audit logging service for compliance and security forensics.
    Application features provide no update or delete routes for audit records.
    """

    @staticmethod
    def log(
        action: str,
        resource_type: str,
        outcome: str = AuditOutcome.SUCCESS,
        tenant_id: Optional[str] = None,
        actor: Optional[User] = None,
        resource_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Create and commit a persistent audit record."""
        ip_address = None
        user_agent = None

        if has_request_context():
            ip_address = request.headers.get("X-Forwarded-For", request.remote_addr)
            if ip_address and "," in ip_address:
                ip_address = ip_address.split(",")[0].strip()
            user_agent = request.user_agent.string[:255] if request.user_agent else None

        actor_id = actor.id if actor else None
        actor_email = actor.email if actor else None
        actor_role = actor.role if actor else None
        
        # If tenant_id not passed explicitly, infer from actor
        if not tenant_id and actor and actor.tenant_id:
            tenant_id = actor.tenant_id

        # If tenant_id cannot be resolved (e.g. pre-auth unknown user failure), tenant_id is None (valid NULL FK)

        event = AuditEvent(
            tenant_id=tenant_id,
            actor_id=actor_id,
            actor_email=actor_email,
            actor_role=actor_role,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            outcome=outcome,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        event.set_details(details)

        db.session.add(event)
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise

        return event

    @classmethod
    def log_login_success(cls, user: User) -> AuditEvent:
        return cls.log(
            action=AuditAction.AUTH_LOGIN_SUCCESS,
            resource_type="AUTH",
            outcome=AuditOutcome.SUCCESS,
            tenant_id=user.tenant_id,
            actor=user,
            resource_id=user.id,
            details={"email": user.email, "role": user.role},
        )

    @classmethod
    def log_login_failure(cls, email: str, tenant_id: Optional[str] = None, reason: str = "Invalid credentials") -> AuditEvent:
        return cls.log(
            action=AuditAction.AUTH_LOGIN_FAILURE,
            resource_type="AUTH",
            outcome=AuditOutcome.FAILURE,
            tenant_id=tenant_id,
            actor=None,
            resource_id=None,
            details={"attempted_email": email, "reason": reason},
        )

    @classmethod
    def log_logout(cls, user: User) -> AuditEvent:
        return cls.log(
            action=AuditAction.AUTH_LOGOUT,
            resource_type="AUTH",
            outcome=AuditOutcome.SUCCESS,
            tenant_id=user.tenant_id,
            actor=user,
            resource_id=user.id,
        )

    @classmethod
    def log_tenant_onboard(cls, tenant: Tenant, admin_user: User) -> AuditEvent:
        return cls.log(
            action=AuditAction.TENANT_ONBOARD,
            resource_type="TENANT",
            outcome=AuditOutcome.SUCCESS,
            tenant_id=tenant.id,
            actor=admin_user,
            resource_id=tenant.id,
            details={"tenant_name": tenant.name, "admin_email": admin_user.email},
        )

    @classmethod
    def log_access_denied(
        cls,
        actor: Optional[User],
        action: str,
        resource_type: str,
        resource_id: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> AuditEvent:
        return cls.log(
            action=AuditAction.ACCESS_DENIED,
            resource_type=resource_type,
            outcome=AuditOutcome.DENIED,
            tenant_id=actor.tenant_id if actor else None,
            actor=actor,
            resource_id=resource_id,
            details={"attempted_action": action, "reason": reason or "Unauthorized access attempt"},
        )
