from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy ORM models."""


class Organization(Base):
    """Tenant organization that owns users and investigations."""

    __tablename__ = "organizations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    users: Mapped[list["User"]] = relationship(back_populates="organization")
    investigations: Mapped[list["Investigation"]] = relationship(back_populates="organization")


class User(Base):
    """Authenticated platform user belonging to an organization."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    full_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False, default="viewer")
    is_active: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    organization: Mapped[Organization] = relationship(back_populates="users")
    investigations: Mapped[list["Investigation"]] = relationship(
        back_populates="creator",
        foreign_keys="Investigation.creator_user_id",
    )
    assigned_investigations: Mapped[list["Investigation"]] = relationship(
        back_populates="assigned_user",
        foreign_keys="Investigation.assigned_user_id",
    )
    assignment_changes: Mapped[list["Investigation"]] = relationship(
        back_populates="assigned_by_user",
        foreign_keys="Investigation.assigned_by",
    )
    comments: Mapped[list["InvestigationComment"]] = relationship(back_populates="author")


class Investigation(Base):
    """Persisted phishing investigation case record."""

    __tablename__ = "investigations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    case_id: Mapped[str] = mapped_column(String(20), unique=True, index=True, nullable=False)
    organization_id: Mapped[Optional[int]] = mapped_column(ForeignKey("organizations.id"), index=True, nullable=True)
    creator_user_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), index=True, nullable=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False, default="Phishing Investigation")
    submitted_text: Mapped[str] = mapped_column(Text, nullable=False, default="")
    sender: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    subject: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    recipients: Mapped[Optional[str]] = mapped_column(Text, nullable=True, default="[]")
    message_id: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    attachment_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
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
    mitre_mappings: Mapped[Optional[str]] = mapped_column(Text, nullable=True, default="{}")
    assigned_to: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, default="")
    assigned_user_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), index=True, nullable=True)
    assigned_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    assigned_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), index=True, nullable=True)
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
    chat_messages: Mapped[list["InvestigationChatMessage"]] = relationship(
        back_populates="investigation",
        cascade="all, delete-orphan",
    )
    organization: Mapped[Optional[Organization]] = relationship(back_populates="investigations")
    creator: Mapped[Optional[User]] = relationship(
        back_populates="investigations",
        foreign_keys=[creator_user_id],
    )
    assigned_user: Mapped[Optional[User]] = relationship(
        back_populates="assigned_investigations",
        foreign_keys=[assigned_user_id],
    )
    assigned_by_user: Mapped[Optional[User]] = relationship(
        back_populates="assignment_changes",
        foreign_keys=[assigned_by],
    )
    comments: Mapped[list["InvestigationComment"]] = relationship(
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


class InvestigationTimeline(Base):
    """Immutable audit trail events for investigations."""

    __tablename__ = "investigation_timeline"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    event_id: Mapped[str] = mapped_column(String(36), unique=True, nullable=False, index=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id"), index=True, nullable=False)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    title: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    metadata_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )


class InvestigationChatMessage(Base):
    """Persisted copilot chat messages scoped to a single investigation."""

    __tablename__ = "investigation_chat_messages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    message_id: Mapped[str] = mapped_column(String(36), unique=True, nullable=False, index=True)
    case_id: Mapped[str] = mapped_column(String(20), index=True, nullable=False)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id"), index=True, nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    investigation: Mapped[Investigation] = relationship(back_populates="chat_messages")


class InvestigationComment(Base):
    """Collaboration comment message for a single investigation."""

    __tablename__ = "investigation_comments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    comment_id: Mapped[str] = mapped_column(String(36), unique=True, nullable=False, index=True)
    case_id: Mapped[str] = mapped_column(String(20), index=True, nullable=False)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id"), index=True, nullable=False)
    author_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True, nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    investigation: Mapped[Investigation] = relationship(back_populates="comments")
    author: Mapped[User] = relationship(back_populates="comments")

