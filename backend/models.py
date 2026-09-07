"""Pydantic models for SOCPilot AI."""
import uuid
from typing import Optional, List, Any
from pydantic import BaseModel, Field, EmailStr, ConfigDict
from datetime import datetime, timezone


def _uid() -> str:
    return str(uuid.uuid4())


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ----- Auth / Users -----
class UserRole:
    ADMIN = "Admin"
    SOC_MANAGER = "SOC Manager"
    L1 = "L1"
    L2 = "L2"
    L3 = "L3"
    READONLY = "ReadOnly"

    ALL = [ADMIN, SOC_MANAGER, L1, L2, L3, READONLY]


class UserPublic(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    email: EmailStr
    name: str
    role: str
    active: bool = True
    tenant_ids: List[str] = Field(default_factory=list)
    must_reset_password: bool = False
    created_at: str = Field(default_factory=_now)


class UserCreate(BaseModel):
    email: EmailStr
    name: str
    password: str
    role: str = UserRole.L1
    tenant_ids: List[str] = Field(default_factory=list)


class UserUpdate(BaseModel):
    name: Optional[str] = None
    role: Optional[str] = None
    active: Optional[bool] = None
    password: Optional[str] = None
    tenant_ids: Optional[List[str]] = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserPublic


# ----- Clients (Tenants) -----
class Client(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=_uid)
    name: str
    code: str
    industry: str = ""
    contact_email: str = ""
    description: str = ""
    active: bool = True
    created_at: str = Field(default_factory=_now)


class ClientCreate(BaseModel):
    name: str
    code: str
    industry: str = ""
    contact_email: str = ""
    description: str = ""


# ----- Offenses -----
class Offense(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=_uid)
    qradar_offense_id: Optional[int] = None
    client_id: str
    description: str
    magnitude: int = 0
    credibility: int = 0
    severity: int = 0  # 0-10
    relevance: int = 0
    severity_label: str = "Low"  # Critical | High | Medium | Low
    status: str = "OPEN"  # OPEN | INVESTIGATING | PENDING_APPROVAL | RESOLVED | CLOSED
    assigned_user: Optional[str] = None
    start_time: str = Field(default_factory=_now)
    last_updated: str = Field(default_factory=_now)
    categories: List[str] = Field(default_factory=list)
    source_count: int = 0
    destination_count: int = 0
    username_count: int = 0
    event_count: int = 0
    flow_count: int = 0
    network: str = ""
    domain_id: Optional[int] = None
    closing_reason: Optional[str] = None
    offense_type: str = ""
    rules: List[str] = Field(default_factory=list)
    source_ips: List[str] = Field(default_factory=list)
    destination_ips: List[str] = Field(default_factory=list)
    usernames: List[str] = Field(default_factory=list)
    events: List[dict] = Field(default_factory=list)
    ai_analysis: Optional[dict] = None
    risk_score: int = 0
    mitre_techniques: List[dict] = Field(default_factory=list)
    iocs: dict = Field(default_factory=dict)
    recommendation: Optional[str] = None
    confidence: int = 0
    similar_incidents: List[dict] = Field(default_factory=list)
    kb_matches: List[dict] = Field(default_factory=list)
    merged_into: Optional[str] = None
    merged_from: List[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=_now)


class OffenseActionRequest(BaseModel):
    action: str  # approve | reject | escalate | close | modify
    reason: Optional[str] = None
    modified_recommendation: Optional[str] = None


# ----- Knowledge Base -----
class KBEntry(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=_uid)
    client_id: str
    kb_type: str  # network_hierarchy | use_case | historical_incident | asset | playbook
    filename: str
    content_summary: str = ""
    document_count: int = 0
    status: str = "PROCESSING"  # PROCESSING | READY | FAILED
    error: Optional[str] = None
    file_size_bytes: int = 0
    uploaded_by: str = ""
    uploaded_at: str = Field(default_factory=_now)
    completed_at: Optional[str] = None
    # Manual "historical data" entries (entry_kind="manual") carry structured fields
    entry_kind: str = "file"  # file | manual | analyst_feedback
    alert_name: Optional[str] = None
    analysis: Optional[str] = None
    impact: Optional[str] = None
    ioc_enrichment: bool = False  # if true, IOC Enrichment section is generated live from VirusTotal
    verdict: Optional[str] = None  # TP | FP | Suspicious
    recommendations: List[str] = Field(default_factory=list)
    rag_source: Optional[str] = None


# ----- Settings -----
class QRadarSettings(BaseModel):
    host: str = ""
    api_token: str = ""
    api_version: str = "12.0"
    domain_id: Optional[int] = None
    processor_id: Optional[int] = None
    verify_ssl: bool = True


class LLMSettings(BaseModel):
    provider: str = "local"  # local | huggingface | ollama
    model_name: str = "Qwen/Qwen2.5-0.5B-Instruct"
    analysis_mode: str = "kb"  # kb (deterministic template) | llm (local Qwen)
    endpoint_url: str = ""
    api_token: str = ""
    max_tokens: int = 512
    temperature: float = 0.3
    enable_llm: bool = False  # legacy flag; analysis_mode drives behaviour
    llm_step_timeout_seconds: int = 90  # per-step timeout for LLM inference (CPU)


class IntegrationCred(BaseModel):
    enabled: bool = False
    url: str = ""
    token: str = ""
    username: str = ""
    project_key: str = ""
    webhook_url: str = ""


class ThreatIntelSettings(BaseModel):
    virustotal_enabled: bool = False
    virustotal_api_key: str = ""  # legacy single key — kept for back-compat
    virustotal_api_keys: str = ""  # multiline: one API key per line (rotated with failover)
    abuseipdb_enabled: bool = False
    abuseipdb_api_key: str = ""
    misp_enabled: bool = False
    misp_url: str = ""
    misp_api_key: str = ""
    misp_verify_ssl: bool = True


class Settings(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default="global")
    qradar: QRadarSettings = Field(default_factory=QRadarSettings)
    llm: LLMSettings = Field(default_factory=LLMSettings)
    threat_intel: ThreatIntelSettings = Field(default_factory=ThreatIntelSettings)
    xsoar: IntegrationCred = Field(default_factory=IntegrationCred)
    servicenow: IntegrationCred = Field(default_factory=IntegrationCred)
    jira: IntegrationCred = Field(default_factory=IntegrationCred)
    freshservice: IntegrationCred = Field(default_factory=IntegrationCred)
    slack: IntegrationCred = Field(default_factory=IntegrationCred)
    teams: IntegrationCred = Field(default_factory=IntegrationCred)
    email: IntegrationCred = Field(default_factory=IntegrationCred)
    updated_at: str = Field(default_factory=_now)


# ----- Tickets -----
class Ticket(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=_uid)
    client_id: str
    offense_ids: List[str] = Field(default_factory=list)
    title: str
    executive_summary: str = ""
    root_cause: str = ""
    timeline: List[dict] = Field(default_factory=list)
    affected_assets: List[str] = Field(default_factory=list)
    mitre: List[dict] = Field(default_factory=list)
    iocs: dict = Field(default_factory=dict)
    evidence: str = ""
    recommended_action: str = ""
    risk_score: int = 0
    mssp_report: Optional[dict] = None
    status: str = "PENDING_APPROVAL"  # PENDING_APPROVAL | APPROVED | REJECTED | PUSHED
    destination: str = "internal"  # xsoar | servicenow | jira | freshservice | slack | teams | email | internal
    approver: Optional[str] = None
    approved_at: Optional[str] = None
    external_ref: Optional[str] = None
    created_by: str = ""
    created_at: str = Field(default_factory=_now)


class TicketCreate(BaseModel):
    offense_id: str
    destination: str = "internal"


class TicketApproval(BaseModel):
    approved: bool
    reason: Optional[str] = None


class TicketMerge(BaseModel):
    ticket_ids: List[str]
    title: Optional[str] = None


# ----- Audit -----
class AuditLog(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=_uid)
    user_email: str
    action: str
    resource: str
    resource_id: Optional[str] = None
    details: dict = Field(default_factory=dict)
    timestamp: str = Field(default_factory=_now)
