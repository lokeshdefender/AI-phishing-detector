from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy ORM models."""


class Investigation(Base):
    """Persisted phishing investigation case record."""

    __tablename__ = "investigations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    case_id: Mapped[str] = mapped_column(String(20), unique=True, index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False, default="Phishing Investigation")
    submitted_text: Mapped[str] = mapped_column(Text, nullable=False, default="")
    sender: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    urls: Mapped[Optional[str]] = mapped_column(Text, nullable=True, default="[]")
    phishing_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    confidence: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    threat_level: Mapped[str] = mapped_column(String(20), nullable=False, default="MINIMAL")
    analyst_report: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    analyst_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True, default="")
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="Open")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
