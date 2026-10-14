"""
Pydantic API request and response schemas for FastAPI endpoints.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field

from analyst_core.state import (
    ContainmentAction,
    InvestigationHypothesis,
    MitreTechnique,
    Severity,
    TriageVerdict,
)


class AlertIngestRequest(BaseModel):
    """Payload for submitting security alerts for autonomous investigation."""

    telemetry: Union[Dict[str, Any], List[Dict[str, Any]]] = Field(
        ...,
        description="Raw alert payload (Sysmon, CloudTrail, Zeek, or envelope containing list of events)",
    )
    investigation_id: Optional[str] = Field(
        default=None,
        description="Optional custom identifier for the investigation tracking receipt",
    )
    reasoning_provider: Optional[str] = Field(
        default="mock",
        description="Reasoning engine: 'mock' (offline determinism) or 'ollama' (local LLM)",
    )


class TriageSummaryResponse(BaseModel):
    """High-level triage receipt returned immediately upon investigation completion."""

    investigation_id: str
    status: str = "COMPLETED"
    verdict: TriageVerdict
    confidence_score: int
    severity: Severity
    correlated_events: int
    mitre_techniques_count: int
    containment_actions_count: int
    executive_summary: Optional[str]
    created_at: datetime


class InvestigationDetailResponse(BaseModel):
    """Complete investigation record with graph correlation, hypotheses, and containment."""

    investigation_id: str
    verdict: TriageVerdict
    confidence_score: int
    severity: Severity
    executive_summary: Optional[str]
    root_cause_analysis: Optional[str]
    correlated_alerts_count: int
    mitre_techniques: List[MitreTechnique]
    hypotheses: List[InvestigationHypothesis]
    containment_playbook: List[ContainmentAction]
    report_markdown: str
    created_at: datetime


class EnrichRequest(BaseModel):
    """Request schema for standalone observable enrichment."""

    indicator: str
    ioc_type: Optional[str] = "ip"


class EnrichResponse(BaseModel):
    """CTI lookup response for single indicator."""

    indicator: str
    ioc_type: str
    malicious: bool
    threat_score: int
    tags: List[str]
    description: Optional[str]


class HealthResponse(BaseModel):
    """Service health and operational status."""

    status: str = "HEALTHY"
    version: str = "1.0.0"
    engine: str = "Autonomous Tier-1 AI SOC Analyst"
    active_provider: str
