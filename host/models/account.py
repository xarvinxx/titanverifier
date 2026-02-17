"""
Account / Profile Models (v2.0)
=================================

Pydantic-Modelle für das "Vault" (Account-Management).

Ein Profile verknüpft:
  - Eine Identity (Hardware-DNA)
  - TikTok Account Credentials + Stats
  - Google Account Credentials
  - Proxy-Konfiguration (SOCKS5/HTTP)
  - Backup-Status: TikTok, GMS, Account-DBs (separat getrackt)

SQL-Schema: Siehe database.py → CREATE TABLE profiles
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


class ProxyType(str, Enum):
    """Proxy-Typen."""
    NONE = "none"
    SOCKS5 = "socks5"
    HTTP = "http"
    SOCKS4 = "socks4"


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

    # Instagram Credentials (optional)
    instagram_username: Optional[str] = Field(default=None, max_length=128)
    instagram_email: Optional[str] = Field(default=None, max_length=256)
    instagram_password: Optional[str] = Field(default=None, max_length=256)

    # YouTube Credentials (optional)
    youtube_username: Optional[str] = Field(default=None, max_length=128)
    youtube_email: Optional[str] = Field(default=None, max_length=256)
    youtube_password: Optional[str] = Field(default=None, max_length=256)

    # Snapchat Credentials (optional)
    snapchat_username: Optional[str] = Field(default=None, max_length=128)
    snapchat_email: Optional[str] = Field(default=None, max_length=256)
    snapchat_password: Optional[str] = Field(default=None, max_length=256)

    # Google Account (optional)
    google_email: Optional[str] = Field(default=None, max_length=256)
    google_password: Optional[str] = Field(default=None, max_length=256)

    # General Contact Email (optional)
    contact_email: Optional[str] = Field(default=None, max_length=256)
    contact_password: Optional[str] = Field(default=None, max_length=256)

    # Proxy
    proxy_ip: Optional[str] = Field(default=None, max_length=256,
                                    description="SOCKS5/HTTP Proxy (ip:port)")
    proxy_type: ProxyType = Field(default=ProxyType.NONE)
    proxy_username: Optional[str] = Field(default=None, max_length=128)
    proxy_password: Optional[str] = Field(default=None, max_length=256)

    notes: Optional[str] = Field(default=None, max_length=1000)


# =============================================================================
# Read Model (Full DB Response)
# =============================================================================

class ProfileRead(BaseModel):
    """Vollständiges Profil inkl. DB-Metadaten und aller Tracking-Felder."""
    id: int
    name: str
    identity_id: int
    status: ProfileStatus = Field(default=ProfileStatus.WARMUP)

    # --- TikTok Credentials ---
    tiktok_username: Optional[str] = None
    tiktok_email: Optional[str] = None
    tiktok_password: Optional[str] = None

    # --- TikTok Stats ---
    tiktok_followers: int = Field(default=0)
    tiktok_following: int = Field(default=0)
    tiktok_likes: int = Field(default=0)

    # --- Instagram Credentials ---
    instagram_username: Optional[str] = None
    instagram_email: Optional[str] = None
    instagram_password: Optional[str] = None

    # --- YouTube Credentials ---
    youtube_username: Optional[str] = None
    youtube_email: Optional[str] = None
    youtube_password: Optional[str] = None

    # --- Snapchat Credentials ---
    snapchat_username: Optional[str] = None
    snapchat_email: Optional[str] = None
    snapchat_password: Optional[str] = None

    # --- Google Account ---
    google_email: Optional[str] = None
    google_password: Optional[str] = None

    # --- General Contact ---
    contact_email: Optional[str] = None
    contact_password: Optional[str] = None

    # --- Proxy ---
    proxy_ip: Optional[str] = None
    proxy_type: ProxyType = Field(default=ProxyType.NONE)
    proxy_username: Optional[str] = None
    proxy_password: Optional[str] = None

    # --- Backup: TikTok ---
    backup_status: BackupStatus = Field(default=BackupStatus.NONE)
    backup_path: Optional[str] = Field(default=None,
                                       description="Relativer Pfad zum TikTok tar-Archiv")
    backup_size_bytes: Optional[int] = Field(default=None)
    backup_created_at: Optional[str] = Field(default=None)

    # --- Backup: GMS (Full-State) ---
    gms_backup_status: BackupStatus = Field(default=BackupStatus.NONE)
    gms_backup_path: Optional[str] = Field(default=None)
    gms_backup_size: Optional[int] = Field(default=None)
    gms_backup_at: Optional[str] = Field(default=None)

    # --- Backup: Account-DBs ---
    accounts_backup_status: BackupStatus = Field(default=BackupStatus.NONE)
    accounts_backup_path: Optional[str] = Field(default=None)
    accounts_backup_at: Optional[str] = Field(default=None)

    # --- Metadata ---
    notes: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(LOCAL_TZ))
    updated_at: Optional[datetime] = None

    # --- Activity Tracking ---
    last_switch_at: Optional[str] = Field(
        default=None,
        description="Letzter Zeitpunkt, zu dem dieses Profil auf das Gerät geladen wurde"
    )
    switch_count: int = Field(default=0,
                              description="Wie oft dieses Profil geladen wurde")
    last_active_at: Optional[str] = Field(
        default=None,
        description="Letzter Zeitpunkt, zu dem das Profil aktiv war"
    )

    model_config = {"from_attributes": True}


# =============================================================================
# Update Model (Partial)
# =============================================================================

class ProfileUpdate(BaseModel):
    """Partielle Updates für ein bestehendes Profil."""
    name: Optional[str] = Field(default=None, min_length=1, max_length=64)
    status: Optional[ProfileStatus] = None

    # TikTok
    tiktok_username: Optional[str] = None
    tiktok_email: Optional[str] = None
    tiktok_password: Optional[str] = None
    tiktok_followers: Optional[int] = None
    tiktok_following: Optional[int] = None
    tiktok_likes: Optional[int] = None

    # Instagram
    instagram_username: Optional[str] = None
    instagram_email: Optional[str] = None
    instagram_password: Optional[str] = None

    # YouTube
    youtube_username: Optional[str] = None
    youtube_email: Optional[str] = None
    youtube_password: Optional[str] = None

    # Snapchat
    snapchat_username: Optional[str] = None
    snapchat_email: Optional[str] = None
    snapchat_password: Optional[str] = None

    # Google
    google_email: Optional[str] = None
    google_password: Optional[str] = None

    # Contact
    contact_email: Optional[str] = None
    contact_password: Optional[str] = None

    # Proxy
    proxy_ip: Optional[str] = None
    proxy_type: Optional[ProxyType] = None
    proxy_username: Optional[str] = None
    proxy_password: Optional[str] = None

    notes: Optional[str] = None
