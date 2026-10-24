import pytest
from trustvault import create_app
from trustvault.models.base import db
from trustvault.models import Tenant, User, UserRole


@pytest.fixture(scope="session")
def app():
    """Create and configure a clean Flask app for the entire test session."""
    flask_app = create_app("testing")
    return flask_app


@pytest.fixture(scope="function")
def db_session(app):
    """Provide clean isolated database session per test."""
    with app.app_context():
        db.create_all()
        yield db.session
        db.session.remove()
        db.drop_all()


@pytest.fixture(scope="function")
def client(app, db_session):
    """A test client for the app sharing the test db_session."""
    with app.test_client() as test_client:
        yield test_client


@pytest.fixture
def tenants(db_session):
    """Seed two distinct tenants: Acme Corp (Tenant A) and Globex Corp (Tenant B)."""
    tenant_a = Tenant(name="Acme Corp", slug="acme-corp", is_active=True)
    tenant_b = Tenant(name="Globex Corp", slug="globex-corp", is_active=True)
    db_session.add_all([tenant_a, tenant_b])
    db_session.commit()
    return {"tenant_a": tenant_a, "tenant_b": tenant_b}


@pytest.fixture
def users(db_session, tenants):
    """Seed users with all three roles in both tenants."""
    t_a = tenants["tenant_a"]
    t_b = tenants["tenant_b"]

    # Tenant A Users
    admin_a = User(tenant_id=t_a.id, email="admin@acme.com", full_name="Acme Admin", role=UserRole.ADMIN, is_active=True)
    admin_a.set_password("Password123!")

    owner_a = User(tenant_id=t_a.id, email="owner@acme.com", full_name="Acme Owner", role=UserRole.OWNER, is_active=True)
    owner_a.set_password("Password123!")

    viewer_a = User(tenant_id=t_a.id, email="viewer@acme.com", full_name="Acme Viewer", role=UserRole.VIEWER, is_active=True)
    viewer_a.set_password("Password123!")

    # Tenant B Users
    admin_b = User(tenant_id=t_b.id, email="admin@globex.com", full_name="Globex Admin", role=UserRole.ADMIN, is_active=True)
    admin_b.set_password("Password123!")

    owner_b = User(tenant_id=t_b.id, email="owner@globex.com", full_name="Globex Owner", role=UserRole.OWNER, is_active=True)
    owner_b.set_password("Password123!")

    viewer_b = User(tenant_id=t_b.id, email="viewer@globex.com", full_name="Globex Viewer", role=UserRole.VIEWER, is_active=True)
    viewer_b.set_password("Password123!")

    db_session.add_all([admin_a, owner_a, viewer_a, admin_b, owner_b, viewer_b])
    db_session.commit()

    return {
        "admin_a": admin_a,
        "owner_a": owner_a,
        "viewer_a": viewer_a,
        "admin_b": admin_b,
        "owner_b": owner_b,
        "viewer_b": viewer_b,
    }
