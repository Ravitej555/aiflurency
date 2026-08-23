"""ThreatLens AI — Threat Event Pydantic Schemas"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field
from app.models.threat import ThreatSeverity, ThreatStatus


class ThreatBase(BaseModel):
    title: str = Field(..., min_length=5, max_length=500)
    description: Optional[str] = None
    severity: ThreatSeverity
    threat_type: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    affected_asset: Optional[str] = None
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)


class ThreatCreate(ThreatBase):
    """Schema for creating a new threat event."""
    pass


class ThreatUpdate(BaseModel):
    """Partial update — analysts update status, assignments, and AI fields."""
    status: Optional[ThreatStatus] = None
    assigned_to_id: Optional[int] = None
    ai_confidence: Optional[float] = Field(None, ge=0.0, le=1.0)
    ai_recommendation: Optional[str] = None
    is_resolved: Optional[bool] = None


class ThreatRead(ThreatBase):
    id: int
    status: ThreatStatus
    ai_confidence: Optional[float] = None
    ai_recommendation: Optional[str] = None
    is_resolved: bool
    reported_by_id: Optional[int] = None
    assigned_to_id: Optional[int] = None
    detected_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class ThreatListResponse(BaseModel):
    """Paginated list response."""
    items: list[ThreatRead]
    total: int
    page: int
    size: int
    pages: int


class ScanRequest(BaseModel):
    scan_type: str = Field(..., description="'file' or 'url'")
    target_input: str = Field(..., min_length=1, max_length=1000)


class IncidentReport(BaseModel):
    timestamp: str
    target_name: str
    classification: str
    confidence: str
    action_taken: str
    status: str
    md5_hash: Optional[str] = None
    sha256_hash: Optional[str] = None
    risk_score: Optional[int] = None
    detected_indicators: Optional[list[str]] = None
    file_size: Optional[str] = None  # e.g. "48,312 bytes" — only for real file uploads


class ScanResultResponse(BaseModel):
    alert_message: str
    notification_sent: bool
    analyst_response: str
    incident_report: IncidentReport
    threat_event: ThreatRead
