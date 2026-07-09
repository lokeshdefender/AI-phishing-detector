import os
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker

from .models_db import Base


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = BASE_DIR / "investigations.db"
DEFAULT_DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DEFAULT_DB_PATH}")


def get_engine(database_url: str | None = None) -> Engine:
    """Create a SQLAlchemy engine for the configured database URL."""
    resolved_url = database_url or DEFAULT_DATABASE_URL
    connect_args = {"check_same_thread": False} if resolved_url.startswith("sqlite") else {}
    return create_engine(resolved_url, connect_args=connect_args)


engine = get_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def init_db(database_url: str | None = None) -> Engine:
    """Create database tables for the current models."""
    resolved_engine = get_engine(database_url)
    Base.metadata.create_all(bind=resolved_engine)
    return resolved_engine


def get_db():
    """Yield a database session for FastAPI request lifecycle management."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
