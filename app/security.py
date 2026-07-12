import os
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import Depends, HTTPException, Request, status
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from . import database as database_module
from .models_db import User


SECRET_KEY = os.getenv("AUTH_SECRET_KEY", "dev-only-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("AUTH_ACCESS_TOKEN_EXPIRE_MINUTES", "240"))

ROLE_VIEWER = "viewer"
ROLE_ANALYST = "analyst"
ROLE_ADMIN = "admin"
ROLE_ORDER = {
    ROLE_VIEWER: 1,
    ROLE_ANALYST: 2,
    ROLE_ADMIN: 3,
}

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Validate plaintext password against a hash."""
    if not plain_password or not hashed_password:
        return False
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception:
        return False


def get_password_hash(password: str) -> str:
    """Create a password hash for storage."""
    return pwd_context.hash(password)


def create_access_token(subject: str, expires_minutes: int | None = None, extra: dict[str, Any] | None = None) -> str:
    """Create a signed JWT access token."""
    expire_delta = timedelta(minutes=expires_minutes or ACCESS_TOKEN_EXPIRE_MINUTES)
    payload: dict[str, Any] = {
        "sub": subject,
        "exp": datetime.now(timezone.utc) + expire_delta,
        "iat": datetime.now(timezone.utc),
        "type": "access",
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict[str, Any]:
    """Decode and validate a signed JWT token."""
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])


def _extract_bearer_token(request: Request) -> str | None:
    auth_header = request.headers.get("Authorization", "")
    if auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()
    return None


def _extract_request_token(request: Request) -> str | None:
    cookie_token = request.cookies.get("access_token")
    if cookie_token:
        return cookie_token
    return _extract_bearer_token(request)


def get_current_user(request: Request, db: Session = Depends(database_module.get_db)) -> User:
    """Resolve the authenticated user from cookie or bearer token."""
    token = _extract_request_token(request)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")

    try:
        payload = decode_access_token(token)
        subject = payload.get("sub")
        if subject is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        user_id = int(subject)
    except (JWTError, ValueError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    user = db.query(User).filter(User.id == user_id).first()
    if not user or int(user.is_active or 0) != 1:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")
    return user


def require_roles(*allowed_roles: str):
    """Build a dependency that enforces one of the allowed roles."""
    normalized = {role.strip().lower() for role in allowed_roles if role}

    def _dependency(current_user: User = Depends(get_current_user)) -> User:
        if not normalized:
            return current_user
        if (current_user.role or "").strip().lower() not in normalized:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return current_user

    return _dependency


def require_min_role(role: str):
    """Build a dependency that enforces a minimum role level."""
    minimum = ROLE_ORDER.get((role or "").strip().lower(), 999)

    def _dependency(current_user: User = Depends(get_current_user)) -> User:
        current = ROLE_ORDER.get((current_user.role or "").strip().lower(), 0)
        if current < minimum:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return current_user

    return _dependency
