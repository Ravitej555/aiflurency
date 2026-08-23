"""ThreatLens AI — Threat Event ORM Model"""

import enum
from datetime import datetime
from sqlalchemy import (
    Boolean, DateTime, Enum, Float, ForeignKey,
    Integer, String, Text, func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


class ThreatSeverity(str, enum.Enum):
    """CVSS-aligned severity levels."""
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class ThreatStatus(str, enum.Enum):
    """Lifecycle status of a detected threat."""
    OPEN        = "open"
    INVESTIGATING = "investigating"
    CONTAINED   = "contained"
    RESOLVED    = "resolved"
    FALSE_POSITIVE = "false_positive"


class ThreatEvent(Base):
    """
    Represents a detected cybersecurity threat or indicator of compromise (IoC).
    """
    __tablename__ = "threat_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    # Classification
    title: Mapped[str] = mapped_column(String(500), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    severity: Mapped[ThreatSeverity] = mapped_column(
        Enum(ThreatSeverity), nullable=False, index=True
    )
    status: Mapped[ThreatStatus] = mapped_column(
        Enum(ThreatStatus), default=ThreatStatus.OPEN, nullable=False, index=True
    )

    # Threat Intelligence Fields
    threat_type: Mapped[str] = mapped_column(String(100), nullable=True)   # e.g., "ransomware", "phishing"
    source_ip: Mapped[str] = mapped_column(String(45), nullable=True)      # IPv4 or IPv6
    destination_ip: Mapped[str] = mapped_column(String(45), nullable=True)
    affected_asset: Mapped[str] = mapped_column(String(255), nullable=True)
    cve_id: Mapped[str] = mapped_column(String(30), nullable=True, index=True)  # e.g., CVE-2024-1234
    cvss_score: Mapped[float] = mapped_column(Float, nullable=True)        # 0.0 – 10.0

    # AI Analysis
    ai_confidence: Mapped[float] = mapped_column(Float, nullable=True)     # Model confidence 0.0-1.0
    ai_recommendation: Mapped[str] = mapped_column(Text, nullable=True)

    # Ownership
    reported_by_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    assigned_to_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    is_resolved: Mapped[bool] = mapped_column(Boolean, default=False)

    # Audit Timestamps
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    resolved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    reported_by = relationship("User", foreign_keys=[reported_by_id])
    assigned_to  = relationship("User", foreign_keys=[assigned_to_id])

    def __repr__(self) -> str:
        return f"<ThreatEvent id={self.id} severity={self.severity.value!r} title={self.title[:40]!r}>"
