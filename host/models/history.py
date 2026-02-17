"""
History Models
===============

Pydantic-Modelle für die 3 neuen Tracking-Tabellen:
  1. FlowHistoryRead   — Audit-Trail aller Genesis/Switch/Backup Flows
  2. IPHistoryRead     — IP-Tracking pro Identität/Profil
  3. AuditHistoryRead  — Audit-Ergebnis-Verlauf

SQL-Schema: Siehe database.py
"""

from __future__ import annotations

from datetime import datetime

from host.config import LOCAL_TZ
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# =============================================================================
# Enums
# =============================================================================

class FlowType(str, Enum):
    """Typ des ausgeführten Flows."""
    GENESIS = "genesis"
    SWITCH = "switch"
    BACKUP = "backup"


class FlowStatus(str, Enum):
    """Ausführungsstatus des Flows."""
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    ABORTED = "aborted"


class ConnectionType(str, Enum):
    """Verbindungstyp beim IP-Check."""
    MOBILE_O2 = "mobile_o2"
    WIFI = "wifi"
    HOTSPOT = "hotspot"
    UNKNOWN = "unknown"


# =============================================================================
# Flow History
# =============================================================================

class FlowHistoryCreate(BaseModel):
    """Input zum Starten eines neuen Flow-History Eintrags."""
    identity_id: Optional[int] = None
    profile_id: Optional[int] = None
    flow_type: FlowType
    started_at: str = Field(
        default_factory=lambda: datetime.now(LOCAL_TZ).strftime("%Y-%m-%dT%H:%M:%SZ")
    )


class FlowHistoryRead(BaseModel):
    """Vollständiger Flow-History Eintrag."""
    id: int
    identity_id: Optional[int] = None
    profile_id: Optional[int] = None
    flow_type: FlowType
    status: FlowStatus = Field(default=FlowStatus.RUNNING)
    started_at: str
    finished_at: Optional[str] = None
    duration_ms: Optional[int] = None

    # Genesis-spezifisch
    generated_serial: Optional[str] = None
    generated_imei: Optional[str] = None

    # Netzwerk
    public_ip: Optional[str] = None
    ip_service: Optional[str] = None

    # Audit
    audit_score: Optional[int] = None
    audit_detail: Optional[str] = None

    # Schritte & Fehler
    steps_json: Optional[str] = None
    error: Optional[str] = None

    created_at: str = ""

    model_config = {"from_attributes": True}


class FlowHistoryUpdate(BaseModel):
    """Partielle Updates für einen laufenden Flow."""
    status: Optional[FlowStatus] = None
    finished_at: Optional[str] = None
    duration_ms: Optional[int] = None
    generated_serial: Optional[str] = None
    generated_imei: Optional[str] = None
    public_ip: Optional[str] = None
    ip_service: Optional[str] = None
    audit_score: Optional[int] = None
    audit_detail: Optional[str] = None
    steps_json: Optional[str] = None
    error: Optional[str] = None


# =============================================================================
# IP History
# =============================================================================

class IPHistoryCreate(BaseModel):
    """Input zum Protokollieren einer erkannten IP."""
    identity_id: Optional[int] = None
    profile_id: Optional[int] = None
    public_ip: str
    ip_service: Optional[str] = None
    connection_type: ConnectionType = Field(default=ConnectionType.UNKNOWN)
    flow_type: Optional[str] = None


class IPHistoryRead(BaseModel):
    """Vollständiger IP-History Eintrag."""
    id: int
    identity_id: Optional[int] = None
    profile_id: Optional[int] = None
    public_ip: str
    ip_service: Optional[str] = None
    connection_type: ConnectionType = Field(default=ConnectionType.UNKNOWN)
    flow_type: Optional[str] = None
    detected_at: str = ""

    model_config = {"from_attributes": True}


# =============================================================================
# Audit History
# =============================================================================

class AuditHistoryCreate(BaseModel):
    """Input zum Protokollieren eines Audit-Ergebnisses."""
    identity_id: Optional[int] = None
    flow_id: Optional[int] = None
    score_percent: int
    total_checks: int
    passed_checks: int
    failed_checks: int
    checks_json: str
    error: Optional[str] = None


class AuditHistoryRead(BaseModel):
    """Vollständiger Audit-History Eintrag."""
    id: int
    identity_id: Optional[int] = None
    flow_id: Optional[int] = None
    score_percent: int
    total_checks: int
    passed_checks: int
    failed_checks: int
    checks_json: str
    error: Optional[str] = None
    created_at: str = ""

    model_config = {"from_attributes": True}
