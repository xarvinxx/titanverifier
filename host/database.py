"""
Project Titan — SQLite Database Engine (v2.0)
================================================

Vollständige Datenbank für eine Farm mit 1000+ Identitäten.

5 Tabellen:
  1. identities      — Hardware-DNA (gespooftes Geräteprofil)
  2. profiles         — TikTok/Google Account Management (Vault)
  3. flow_history     — Audit-Trail aller Genesis/Switch/Backup Flows
  4. ip_history       — IP-Tracking pro Identität/Profil
  5. audit_history    — Audit-Ergebnis-Verlauf

Features:
  - Async SQLite via aiosqlite (WAL-Mode)
  - Automatische Schema-Migration (ALTER TABLE für neue Spalten)
  - Atomare Transaktionen
  - UNIQUE Constraints auf imei1, widevine_id
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import aiosqlite

from host.config import DATABASE_PATH

logger = logging.getLogger("titan.database")


# =============================================================================
# SQL Schema: Tabelle 1 — identities (Hardware-DNA)
# =============================================================================

_SQL_CREATE_IDENTITIES = """
CREATE TABLE IF NOT EXISTS identities (
    -- Primary Key
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Metadaten
    name                TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'ready'
                            CHECK (status IN ('ready', 'active', 'retired', 'corrupted')),
    notes               TEXT,

    -- Core Hardware (Bridge-Felder)
    serial              TEXT NOT NULL,
    boot_serial         TEXT NOT NULL,
    imei1               TEXT NOT NULL UNIQUE,
    imei2               TEXT NOT NULL,
    gsf_id              TEXT NOT NULL,
    android_id          TEXT NOT NULL,
    wifi_mac            TEXT NOT NULL,
    widevine_id         TEXT NOT NULL UNIQUE,
    imsi                TEXT NOT NULL,
    sim_serial          TEXT NOT NULL,
    operator_name       TEXT NOT NULL DEFAULT 'o2-de',
    phone_number        TEXT NOT NULL,
    sim_operator        TEXT NOT NULL DEFAULT '26207',
    sim_operator_name   TEXT NOT NULL DEFAULT 'o2 - de',
    voicemail_number    TEXT NOT NULL DEFAULT '+4917610',

    -- Build Fingerprint
    build_id            TEXT,
    build_fingerprint   TEXT,
    security_patch      TEXT,

    -- Netzwerk-Tracking
    last_public_ip      TEXT,
    last_ip_service     TEXT,
    last_ip_at          TEXT,

    -- Audit-Tracking
    last_audit_score    INTEGER,
    last_audit_at       TEXT,
    last_audit_detail   TEXT,
    total_audits        INTEGER NOT NULL DEFAULT 0,

    -- Timestamps & Counters
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at          TEXT,
    last_used_at        TEXT,
    usage_count         INTEGER NOT NULL DEFAULT 0
);
"""

# =============================================================================
# SQL Schema: Tabelle 2 — profiles (Vault / Account Management)
# =============================================================================

_SQL_CREATE_PROFILES = """
CREATE TABLE IF NOT EXISTS profiles (
    -- Primary Key
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Beziehung
    identity_id             INTEGER NOT NULL REFERENCES identities(id) ON DELETE RESTRICT,

    -- Metadaten
    name                    TEXT NOT NULL,
    status                  TEXT NOT NULL DEFAULT 'warmup'
                                CHECK (status IN (
                                    'warmup', 'active', 'cooldown',
                                    'banned', 'suspended', 'archived'
                                )),
    notes                   TEXT,

    -- TikTok Credentials
    tiktok_username         TEXT,
    tiktok_email            TEXT,
    tiktok_password         TEXT,
    tiktok_followers        INTEGER NOT NULL DEFAULT 0,
    tiktok_following        INTEGER NOT NULL DEFAULT 0,
    tiktok_likes            INTEGER NOT NULL DEFAULT 0,

    -- Google Account
    google_email            TEXT,
    google_password         TEXT,

    -- Proxy
    proxy_ip                TEXT,
    proxy_type              TEXT NOT NULL DEFAULT 'none'
                                CHECK (proxy_type IN ('none', 'socks5', 'http', 'socks4')),
    proxy_username          TEXT,
    proxy_password          TEXT,

    -- Backup: TikTok
    backup_status           TEXT NOT NULL DEFAULT 'none'
                                CHECK (backup_status IN ('none', 'valid', 'corrupted', 'restoring')),
    backup_path             TEXT,
    backup_size_bytes       INTEGER,
    backup_created_at       TEXT,

    -- Backup: GMS (Full-State)
    gms_backup_status       TEXT NOT NULL DEFAULT 'none'
                                CHECK (gms_backup_status IN ('none', 'valid', 'corrupted')),
    gms_backup_path         TEXT,
    gms_backup_size         INTEGER,
    gms_backup_at           TEXT,

    -- Backup: Account-DBs
    accounts_backup_status  TEXT NOT NULL DEFAULT 'none'
                                CHECK (accounts_backup_status IN ('none', 'valid', 'corrupted')),
    accounts_backup_path    TEXT,
    accounts_backup_at      TEXT,

    -- Timestamps & Counters
    created_at              TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at              TEXT,
    last_switch_at          TEXT,
    switch_count            INTEGER NOT NULL DEFAULT 0,
    last_active_at          TEXT
);
"""

# =============================================================================
# SQL Schema: Tabelle 3 — flow_history (Audit-Trail)
# =============================================================================

_SQL_CREATE_FLOW_HISTORY = """
CREATE TABLE IF NOT EXISTS flow_history (
    -- Primary Key
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Beziehungen
    identity_id         INTEGER REFERENCES identities(id),
    profile_id          INTEGER REFERENCES profiles(id),

    -- Flow-Info
    flow_type           TEXT NOT NULL
                            CHECK (flow_type IN ('genesis', 'switch', 'backup')),
    status              TEXT NOT NULL DEFAULT 'running'
                            CHECK (status IN ('running', 'success', 'failed', 'aborted')),
    started_at          TEXT NOT NULL,
    finished_at         TEXT,
    duration_ms         INTEGER,

    -- Genesis-spezifisch
    generated_serial    TEXT,
    generated_imei      TEXT,

    -- Netzwerk
    public_ip           TEXT,
    ip_service          TEXT,

    -- Audit
    audit_score         INTEGER,
    audit_detail        TEXT,

    -- Schritte & Fehler
    steps_json          TEXT,
    error               TEXT,

    -- Auto-Timestamp
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
"""

# =============================================================================
# SQL Schema: Tabelle 4 — ip_history (IP-Tracking)
# =============================================================================

_SQL_CREATE_IP_HISTORY = """
CREATE TABLE IF NOT EXISTS ip_history (
    -- Primary Key
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Beziehungen
    identity_id         INTEGER REFERENCES identities(id),
    profile_id          INTEGER REFERENCES profiles(id),

    -- IP-Daten
    public_ip           TEXT NOT NULL,
    ip_service          TEXT,
    connection_type     TEXT DEFAULT 'unknown'
                            CHECK (connection_type IN ('mobile_o2', 'wifi', 'hotspot', 'unknown')),
    flow_type           TEXT,

    -- Auto-Timestamp
    detected_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
"""

# =============================================================================
# SQL Schema: Tabelle 5 — audit_history (Audit-Verlauf)
# =============================================================================

_SQL_CREATE_AUDIT_HISTORY = """
CREATE TABLE IF NOT EXISTS audit_history (
    -- Primary Key
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Beziehungen
    identity_id         INTEGER REFERENCES identities(id),
    flow_id             INTEGER REFERENCES flow_history(id),

    -- Ergebnis
    score_percent       INTEGER NOT NULL,
    total_checks        INTEGER NOT NULL,
    passed_checks       INTEGER NOT NULL,
    failed_checks       INTEGER NOT NULL,
    checks_json         TEXT NOT NULL,
    error               TEXT,

    -- Auto-Timestamp
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
"""

# =============================================================================
# Indizes für Performance
# =============================================================================

_SQL_CREATE_INDEXES = """
-- Identities
CREATE INDEX IF NOT EXISTS idx_identities_status        ON identities(status);
CREATE INDEX IF NOT EXISTS idx_identities_name          ON identities(name);
CREATE INDEX IF NOT EXISTS idx_identities_last_ip       ON identities(last_public_ip);

-- Profiles
CREATE INDEX IF NOT EXISTS idx_profiles_status          ON profiles(status);
CREATE INDEX IF NOT EXISTS idx_profiles_identity        ON profiles(identity_id);
CREATE INDEX IF NOT EXISTS idx_profiles_name            ON profiles(name);
CREATE INDEX IF NOT EXISTS idx_profiles_backup          ON profiles(backup_status);

-- Flow History
CREATE INDEX IF NOT EXISTS idx_flow_type_status         ON flow_history(flow_type, status);
CREATE INDEX IF NOT EXISTS idx_flow_identity            ON flow_history(identity_id);
CREATE INDEX IF NOT EXISTS idx_flow_time                ON flow_history(started_at DESC);

-- IP History
CREATE INDEX IF NOT EXISTS idx_ip_ip                    ON ip_history(public_ip);
CREATE INDEX IF NOT EXISTS idx_ip_identity              ON ip_history(identity_id);
CREATE INDEX IF NOT EXISTS idx_ip_time                  ON ip_history(detected_at DESC);

-- Audit History
CREATE INDEX IF NOT EXISTS idx_audit_identity           ON audit_history(identity_id);
CREATE INDEX IF NOT EXISTS idx_audit_score              ON audit_history(score_percent);
CREATE INDEX IF NOT EXISTS idx_audit_time               ON audit_history(created_at DESC);
"""

# =============================================================================
# Schema-Migration: Neue Spalten zu bestehenden Tabellen hinzufügen
# =============================================================================

_SQL_MIGRATIONS = [
    # identities: Netzwerk-Tracking
    "ALTER TABLE identities ADD COLUMN last_public_ip TEXT",
    "ALTER TABLE identities ADD COLUMN last_ip_service TEXT",
    "ALTER TABLE identities ADD COLUMN last_ip_at TEXT",
    # identities: Audit-Tracking
    "ALTER TABLE identities ADD COLUMN last_audit_score INTEGER",
    "ALTER TABLE identities ADD COLUMN last_audit_at TEXT",
    "ALTER TABLE identities ADD COLUMN last_audit_detail TEXT",
    "ALTER TABLE identities ADD COLUMN total_audits INTEGER NOT NULL DEFAULT 0",
    # identities: Usage Counter
    "ALTER TABLE identities ADD COLUMN usage_count INTEGER NOT NULL DEFAULT 0",
    # profiles: TikTok Stats
    "ALTER TABLE profiles ADD COLUMN tiktok_followers INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE profiles ADD COLUMN tiktok_following INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE profiles ADD COLUMN tiktok_likes INTEGER NOT NULL DEFAULT 0",
    # profiles: Google Account
    "ALTER TABLE profiles ADD COLUMN google_email TEXT",
    "ALTER TABLE profiles ADD COLUMN google_password TEXT",
    # profiles: Proxy Details
    "ALTER TABLE profiles ADD COLUMN proxy_type TEXT NOT NULL DEFAULT 'none'",
    "ALTER TABLE profiles ADD COLUMN proxy_username TEXT",
    "ALTER TABLE profiles ADD COLUMN proxy_password TEXT",
    # profiles: GMS Backup
    "ALTER TABLE profiles ADD COLUMN gms_backup_status TEXT NOT NULL DEFAULT 'none'",
    "ALTER TABLE profiles ADD COLUMN gms_backup_path TEXT",
    "ALTER TABLE profiles ADD COLUMN gms_backup_size INTEGER",
    "ALTER TABLE profiles ADD COLUMN gms_backup_at TEXT",
    # profiles: Account-DB Backup
    "ALTER TABLE profiles ADD COLUMN accounts_backup_status TEXT NOT NULL DEFAULT 'none'",
    "ALTER TABLE profiles ADD COLUMN accounts_backup_path TEXT",
    "ALTER TABLE profiles ADD COLUMN accounts_backup_at TEXT",
    # profiles: Activity Tracking
    "ALTER TABLE profiles ADD COLUMN last_active_at TEXT",
]


# =============================================================================
# Database Engine
# =============================================================================

class TitanDatabase:
    """
    Async SQLite Database Engine für Project Titan.

    Unterstützt automatische Schema-Migration: Wenn die DB bereits existiert
    und neue Spalten hinzugekommen sind, werden sie via ALTER TABLE ergänzt.

    Usage:
        db = TitanDatabase()
        await db.initialize()           # Tabellen erstellen / migrieren

        async with db.connection() as conn:
            cursor = await conn.execute("SELECT * FROM identities")
            rows = await cursor.fetchall()

        await db.close()
    """

    def __init__(self, db_path: str | None = None):
        self._db_path = str(db_path or DATABASE_PATH)
        self._connection: aiosqlite.Connection | None = None

    async def initialize(self) -> None:
        """
        Initialisiert die Datenbank:
          1. Verbindung herstellen
          2. WAL-Mode + Foreign Keys aktivieren
          3. Tabellen erstellen (IF NOT EXISTS)
          4. Schema-Migration ausführen (ALTER TABLE für neue Spalten)
          5. Indizes erstellen
        """
        logger.info("Initialisiere Datenbank: %s", self._db_path)

        self._connection = await aiosqlite.connect(self._db_path)
        self._connection.row_factory = aiosqlite.Row

        # Performance & Integrität
        await self._connection.execute("PRAGMA journal_mode=WAL")
        await self._connection.execute("PRAGMA foreign_keys=ON")
        await self._connection.execute("PRAGMA busy_timeout=5000")

        # Schema erstellen (IF NOT EXISTS — sicher für bestehende DBs)
        # WICHTIG: Indizes werden NACH den Migrationen erstellt,
        # da einige Indizes auf Spalten verweisen, die erst durch
        # Migrationen hinzugefügt werden (z.B. last_public_ip).
        await self._connection.executescript(
            _SQL_CREATE_IDENTITIES
            + _SQL_CREATE_PROFILES
            + _SQL_CREATE_FLOW_HISTORY
            + _SQL_CREATE_IP_HISTORY
            + _SQL_CREATE_AUDIT_HISTORY
        )
        await self._connection.commit()

        # Schema-Migration: Neue Spalten zu bestehenden Tabellen
        await self._run_migrations()

        # Indizes erstellen (nach Migrationen, da Spalten jetzt existieren)
        await self._connection.executescript(_SQL_CREATE_INDEXES)
        await self._connection.commit()

        # Tabellen verifizieren
        cursor = await self._connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name IN ('identities', 'profiles', 'flow_history', "
            "'ip_history', 'audit_history')"
        )
        tables = [row[0] for row in await cursor.fetchall()]
        logger.info("Tabellen bereit: %s", ", ".join(sorted(tables)))

    async def _run_migrations(self) -> None:
        """
        Führt ALTER TABLE Migrationen aus.

        Jede Migration wird einzeln versucht — wenn die Spalte
        bereits existiert, wird der Fehler stillschweigend ignoriert.
        Das macht die Migration idempotent.
        """
        migrated = 0
        for sql in _SQL_MIGRATIONS:
            try:
                await self._connection.execute(sql)
                migrated += 1
            except Exception:
                # Spalte existiert bereits — OK
                pass

        if migrated > 0:
            await self._connection.commit()
            logger.info("Schema-Migration: %d neue Spalten hinzugefügt", migrated)

    @asynccontextmanager
    async def connection(self) -> AsyncGenerator[aiosqlite.Connection, None]:
        """Context-Manager für eine Datenbankverbindung (read)."""
        if self._connection is None:
            raise RuntimeError("Datenbank nicht initialisiert — await db.initialize() zuerst!")
        yield self._connection

    @asynccontextmanager
    async def transaction(self) -> AsyncGenerator[aiosqlite.Connection, None]:
        """
        Atomare Transaktion (write).

        Bei Exception: Rollback.
        Bei Erfolg: Commit.
        """
        if self._connection is None:
            raise RuntimeError("Datenbank nicht initialisiert!")
        try:
            await self._connection.execute("BEGIN")
            yield self._connection
            await self._connection.commit()
        except Exception:
            await self._connection.rollback()
            raise

    async def close(self) -> None:
        """Schliesst die Datenbankverbindung."""
        if self._connection:
            await self._connection.close()
            self._connection = None
            logger.info("Datenbank geschlossen.")

    @staticmethod
    def row_to_dict(row: aiosqlite.Row) -> dict:
        """Konvertiert eine aiosqlite.Row in ein dict."""
        return dict(row)


# =============================================================================
# Globale Singleton-Instanz
# =============================================================================

db = TitanDatabase()
