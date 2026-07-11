from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


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
    investigation_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True, default="email")
    pipeline_stage: Mapped[Optional[str]] = mapped_column(String(30), nullable=True, default="New")
    timeline: Mapped[Optional[str]] = mapped_column(Text, nullable=True, default="[]")
    graph: Mapped[Optional[str]] = mapped_column(Text, nullable=True, default="[]")
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True, default="")
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True, default="[]")
    assigned_to: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, default="")
    tags: Mapped[Optional[str]] = mapped_column(Text, nullable=True, default="[]")
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

    threat_intel_indicators: Mapped[list["ThreatIntelIndicator"]] = relationship(
        back_populates="investigation",
        cascade="all, delete-orphan",
    )


class ThreatIntelIndicator(Base):
    """Persisted extraction and enrichment output for a single investigation IOC."""

    __tablename__ = "threat_intel_indicators"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id"), index=True, nullable=False)
    ioc_value: Mapped[str] = mapped_column(String(1024), nullable=False, index=True)
    ioc_type: Mapped[str] = mapped_column(String(50), nullable=False, default="Unknown")
    source_providers: Mapped[Optional[str]] = mapped_column(Text, nullable=True, default="[]")
    reputation: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    confidence: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    detection_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True, default="")
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True, default="[]")
    provider_responses: Mapped[Optional[str]] = mapped_column(Text, nullable=True, default="{}")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    investigation: Mapped[Investigation] = relationship(back_populates="threat_intel_indicators")


class ThreatIntelCache(Base):
    """Simple cache table for provider results to avoid repeated external queries."""

    __tablename__ = "threat_intel_cache"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    provider_name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    ioc_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    ioc_value: Mapped[str] = mapped_column(String(1024), nullable=False, index=True)
    response_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ttl_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=86400)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
