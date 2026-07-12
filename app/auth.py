from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from . import database as database_module
from .models_db import Organization, User
from .security import ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER, get_password_hash, verify_password


VALID_ROLES = {ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER}


def normalize_role(role: str | None) -> str:
    """Normalize and validate user roles."""
    candidate = (role or ROLE_VIEWER).strip().lower()
    if candidate not in VALID_ROLES:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid role")
    return candidate


def register_user(
    db: Session,
    *,
    email: str,
    password: str,
    full_name: str | None = None,
    organization_name: str,
    role: str | None = None,
) -> User:
    """Create a new user account in an organization."""
    normalized_email = (email or "").strip().lower()
    if not normalized_email:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Email is required")
    if not password or len(password) < 8:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Password must be at least 8 characters")

    existing = database_module.get_user_by_email(db, normalized_email)
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

    org = database_module.get_or_create_organization(db, organization_name)
    user = database_module.create_user(
        db,
        email=normalized_email,
        password_hash=get_password_hash(password),
        full_name=full_name,
        role=normalize_role(role),
        organization_id=org.id,
    )
    return user


def authenticate_user(db: Session, *, email: str, password: str) -> User:
    """Authenticate a user by email/password."""
    normalized_email = (email or "").strip().lower()
    user = database_module.get_user_by_email(db, normalized_email)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if int(user.is_active or 0) != 1:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User inactive")
    if not verify_password(password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    return user


def serialize_user(user: User, organization: Organization | None = None) -> dict:
    """Convert a user model into a safe API payload."""
    org_name = organization.name if organization else (user.organization.name if user.organization else "")
    return {
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name or "",
        "role": (user.role or ROLE_VIEWER).lower(),
        "organization_id": user.organization_id,
        "organization_name": org_name,
        "is_active": bool(user.is_active),
    }
