"""
Investigation state models and schemas using Pydantic v2.
Tracks normalized alerts, extracted observables, CTI context,
attack graph causality, hypotheses, reasoning results, and containment playbooks.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ObservableType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    HASH_SHA256 = "hash_sha256"
    HASH_MD5 = "hash_md5"
    PROCESS_NAME = "process_name"
    COMMAND_LINE = "command_line"
    FILE_PATH = "file_path"
    USER = "user"
    HOST = "host"
    IAM_ROLE = "iam_role"
    ACCESS_KEY_ID = "access_key_id"
    PORT = "port"


class AlertSource(str, Enum):
    SYSMON = "sysmon"
    CLOUDTRAIL = "cloudtrail"
    ZEEK = "zeek"
    GENERIC = "generic"


class TriageVerdict(str, Enum):
    TRUE_POSITIVE = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    SUSPICIOUS_BENIGN = "SUSPICIOUS_BENIGN"
    INCONCLUSIVE = "INCONCLUSIVE"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class Observable(BaseModel):
    obs_type: ObservableType
    value: str
    context: Optional[str] = None
    reputation: Optional[str] = "UNKNOWN"
    tags: List[str] = Field(default_factory=list)


class NormalizedAlert(BaseModel):
    alert_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: AlertSource
    raw_event: Dict[str, Any] = Field(default_factory=dict)
    host: Optional[str] = None
    user: Optional[str] = None
    process_name: Optional[str] = None
    pid: Optional[int] = None
    ppid: Optional[int] = None
    parent_process_name: Optional[str] = None
    command_line: Optional[str] = None
    file_path: Optional[str] = None
    file_hash: Optional[str] = None
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    query: Optional[str] = None
    api_call: Optional[str] = None
    request_parameters: Optional[Dict[str, Any]] = None
    observables: List[Observable] = Field(default_factory=list)


class CTIIndicator(BaseModel):
    indicator: str
    ioc_type: ObservableType
    malicious: bool
    threat_score: int = Field(ge=0, le=100, default=0)
    sources: Dict[str, Any] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)
    description: Optional[str] = None


class AssetContext(BaseModel):
    identifier: str
    asset_tier: str = "Tier-2"
    is_critical: bool = False
    owner: str = "Unassigned"
    department: str = "Corporate IT"
    environment: str = "Production"
    tags: List[str] = Field(default_factory=list)


class UserContext(BaseModel):
    username: str
    role: str = "Standard User"
    is_privileged: bool = False
    department: str = "Corporate"
    normal_working_hours: str = "09:00-17:00 UTC"


class MitreTechnique(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    description: str
    observed_indicators: List[str] = Field(default_factory=list)


class ContainmentAction(BaseModel):
    action_type: str
    target: str
    description: str
    urgency: Severity = Severity.HIGH
    automation_ready: bool = True
    cli_command: Optional[str] = None


class InvestigationHypothesis(BaseModel):
    hypothesis: str
    likelihood: str
    supporting_evidence: List[str] = Field(default_factory=list)
    contradicting_evidence: List[str] = Field(default_factory=list)


class GraphSummary(BaseModel):
    total_nodes: int = 0
    total_edges: int = 0
    suspicious_chains: List[str] = Field(default_factory=list)
    root_nodes: List[str] = Field(default_factory=list)
    leaf_nodes: List[str] = Field(default_factory=list)
    node_types: Dict[str, int] = Field(default_factory=dict)


class InvestigationState(BaseModel):
    investigation_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    alerts: List[NormalizedAlert] = Field(default_factory=list)
    observables: List[Observable] = Field(default_factory=list)
    enriched_cti: Dict[str, CTIIndicator] = Field(default_factory=dict)
    internal_assets: Dict[str, AssetContext] = Field(default_factory=dict)
    internal_users: Dict[str, UserContext] = Field(default_factory=dict)
    graph_summary: Optional[GraphSummary] = None
    mitre_techniques: List[MitreTechnique] = Field(default_factory=list)
    hypotheses: List[InvestigationHypothesis] = Field(default_factory=list)
    root_cause_analysis: Optional[str] = None
    verdict: TriageVerdict = TriageVerdict.INCONCLUSIVE
    confidence_score: int = Field(ge=0, le=100, default=0)
    severity: Severity = Severity.INFORMATIONAL
    containment_playbook: List[ContainmentAction] = Field(default_factory=list)
    executive_summary: Optional[str] = None
    raw_reasoning_output: Optional[str] = None
