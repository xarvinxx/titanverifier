"""
Project Titan — Account / Profile Models
==========================================

Pydantic-Modelle für das "Vault" (Account-Management).

Ein Profile verknüpft:
  - Eine Identity (Hardware-DNA)
  - TikTok Account Credentials
  - Proxy-Konfiguration
  - App-Data Backup (tar-Archiv Pfad)

SQL-Schema: Siehe database.py → CREATE TABLE profiles
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# =============================================================================
# Enums
# =============================================================================

class ProfileStatus(str, Enum):
    """Lifecycle-Status eines TikTok-Profils."""
    WARMUP = "warmup"           # Frisch erstellt, wird "aufgewärmt"
    ACTIVE = "active"           # Aktiv, funktionsfähig
    COOLDOWN = "cooldown"       # Temporär pausiert (Rate-Limiting)
    BANNED = "banned"           # Gesperrt
    SUSPENDED = "suspended"     # Vorübergehend eingeschränkt
    ARCHIVED = "archived"       # Manuell archiviert


class BackupStatus(str, Enum):
    """Status des App-Data Backups."""
    NONE = "none"               # Kein Backup vorhanden
    VALID = "valid"             # Backup vorhanden und intakt
    CORRUPTED = "corrupted"     # tar-Stream abgebrochen
    RESTORING = "restoring"     # Wird gerade wiederhergestellt


# =============================================================================
# Create Model
# =============================================================================

class ProfileCreate(BaseModel):
    """Input zum Erstellen eines neuen Profils."""
    name: str = Field(..., min_length=1, max_length=64,
                      description="Anzeigename (z.B. 'TikTok_DE_001')")
    identity_id: int = Field(..., description="FK → identities.id")

    # TikTok Credentials (optional beim Erstellen)
    tiktok_username: Optional[str] = Field(default=None, max_length=128)
    tiktok_email: Optional[str] = Field(default=None, max_length=256)
    tiktok_password: Optional[str] = Field(default=None, max_length=256)

    # Proxy
    proxy_ip: Optional[str] = Field(default=None, max_length=256,
                                    description="SOCKS5/HTTP Proxy (ip:port)")

    notes: Optional[str] = Field(default=None, max_length=1000)


# =============================================================================
# Read Model (Full DB Response)
# =============================================================================

class ProfileRead(BaseModel):
    """Vollständiges Profil inkl. DB-Metadaten."""
    id: int
    name: str
    identity_id: int
    status: ProfileStatus = Field(default=ProfileStatus.WARMUP)

    # TikTok Credentials
    tiktok_username: Optional[str] = None
    tiktok_email: Optional[str] = None
    tiktok_password: Optional[str] = None

    # Proxy
    proxy_ip: Optional[str] = None

    # Backup
    backup_status: BackupStatus = Field(default=BackupStatus.NONE)
    backup_path: Optional[str] = Field(default=None,
                                       description="Relativer Pfad zum tar-Archiv")
    backup_size_bytes: Optional[int] = Field(default=None)
    backup_created_at: Optional[datetime] = Field(default=None)

    # Metadata
    notes: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: Optional[datetime] = None
    last_switch_at: Optional[datetime] = Field(
        default=None,
        description="Letzter Zeitpunkt, zu dem dieses Profil auf das Gerät geladen wurde"
    )
    switch_count: int = Field(default=0,
                              description="Wie oft dieses Profil geladen wurde")

    model_config = {"from_attributes": True}


# =============================================================================
# Update Model (Partial)
# =============================================================================

class ProfileUpdate(BaseModel):
    """Partielle Updates für ein bestehendes Profil."""
    name: Optional[str] = Field(default=None, min_length=1, max_length=64)
    status: Optional[ProfileStatus] = None
    tiktok_username: Optional[str] = None
    tiktok_email: Optional[str] = None
    tiktok_password: Optional[str] = None
    proxy_ip: Optional[str] = None
    notes: Optional[str] = None
