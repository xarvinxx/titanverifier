"""
Project Titan — SQLite Database Engine
========================================

Async SQLite via aiosqlite für FastAPI-Kompatibilität.

Features:
  - Automatische Tabellen-Erstellung beim Start (idempotent)
  - WAL-Mode für bessere Concurrent-Read Performance
  - Atomare Transaktionen für kritische Operationen
  - UNIQUE Constraints auf imei1, widevine_id (wie in TITAN_CONTEXT.md)

Tabellen:
  - identities: Hardware-DNA (O2-DE Pixel 6 Identitäten)
  - profiles:   TikTok Account Management (Vault)
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import aiosqlite

from host.config import DATABASE_PATH

logger = logging.getLogger("titan.database")


# =============================================================================
# SQL Schema Definitionen
# =============================================================================

_SQL_CREATE_IDENTITIES = """
CREATE TABLE IF NOT EXISTS identities (
    -- Primary Key
    id              INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Metadaten
    name            TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'ready'
                        CHECK (status IN ('ready', 'active', 'retired', 'corrupted')),
    notes           TEXT,

    -- Core Hardware (Bridge-Felder)
    serial          TEXT NOT NULL,
    boot_serial     TEXT NOT NULL,
    imei1           TEXT NOT NULL UNIQUE,
    imei2           TEXT NOT NULL,
    gsf_id          TEXT NOT NULL,
    android_id      TEXT NOT NULL,
    wifi_mac        TEXT NOT NULL,
    widevine_id     TEXT NOT NULL UNIQUE,
    imsi            TEXT NOT NULL,
    sim_serial      TEXT NOT NULL,
    operator_name   TEXT NOT NULL DEFAULT 'o2-de',
    phone_number    TEXT NOT NULL,
    sim_operator    TEXT NOT NULL DEFAULT '26207',
    sim_operator_name TEXT NOT NULL DEFAULT 'o2 - de',
    voicemail_number  TEXT NOT NULL DEFAULT '+4917610',

    -- Build Fingerprint (konsistent!)
    build_id        TEXT,
    build_fingerprint TEXT,
    security_patch  TEXT,

    -- Timestamps
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at      TEXT,
    last_used_at    TEXT
);
"""

_SQL_CREATE_PROFILES = """
CREATE TABLE IF NOT EXISTS profiles (
    -- Primary Key
    id              INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Beziehung
    identity_id     INTEGER NOT NULL REFERENCES identities(id) ON DELETE RESTRICT,

    -- Metadaten
    name            TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'warmup'
                        CHECK (status IN (
                            'warmup', 'active', 'cooldown',
                            'banned', 'suspended', 'archived'
                        )),
    notes           TEXT,

    -- TikTok Credentials
    tiktok_username TEXT,
    tiktok_email    TEXT,
    tiktok_password TEXT,

    -- Proxy
    proxy_ip        TEXT,

    -- Backup
    backup_status   TEXT NOT NULL DEFAULT 'none'
                        CHECK (backup_status IN ('none', 'valid', 'corrupted', 'restoring')),
    backup_path     TEXT,
    backup_size_bytes INTEGER,
    backup_created_at TEXT,

    -- Timestamps
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at      TEXT,
    last_switch_at  TEXT,
    switch_count    INTEGER NOT NULL DEFAULT 0
);
"""

# Indizes für schnelle Lookups
_SQL_CREATE_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_identities_status  ON identities(status);
CREATE INDEX IF NOT EXISTS idx_identities_name    ON identities(name);
CREATE INDEX IF NOT EXISTS idx_profiles_status    ON profiles(status);
CREATE INDEX IF NOT EXISTS idx_profiles_identity  ON profiles(identity_id);
CREATE INDEX IF NOT EXISTS idx_profiles_name      ON profiles(name);
"""


# =============================================================================
# Database Engine
# =============================================================================

class TitanDatabase:
    """
    Async SQLite Database Engine für Project Titan.

    Usage:
        db = TitanDatabase()
        await db.initialize()           # Tabellen erstellen

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
          2. WAL-Mode aktivieren (bessere Read-Performance)
          3. Foreign Keys aktivieren
          4. Tabellen erstellen (idempotent via IF NOT EXISTS)
        """
        logger.info("Initialisiere Datenbank: %s", self._db_path)

        self._connection = await aiosqlite.connect(self._db_path)
        self._connection.row_factory = aiosqlite.Row

        # Performance & Integrität
        await self._connection.execute("PRAGMA journal_mode=WAL")
        await self._connection.execute("PRAGMA foreign_keys=ON")
        await self._connection.execute("PRAGMA busy_timeout=5000")

        # Schema erstellen
        await self._connection.executescript(
            _SQL_CREATE_IDENTITIES
            + _SQL_CREATE_PROFILES
            + _SQL_CREATE_INDEXES
        )
        await self._connection.commit()

        # Tabellen zählen zur Bestätigung
        cursor = await self._connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name IN ('identities', 'profiles')"
        )
        tables = [row[0] for row in await cursor.fetchall()]
        logger.info("Tabellen bereit: %s", ", ".join(tables))

    @asynccontextmanager
    async def connection(self) -> AsyncGenerator[aiosqlite.Connection, None]:
        """
        Context-Manager für eine Datenbankverbindung.

        Nutzt die geteilte Verbindung (SQLite hat sowieso nur einen Writer).
        Für atomare Writes: Nutze `async with db.transaction()`.
        """
        if self._connection is None:
            raise RuntimeError("Datenbank nicht initialisiert — await db.initialize() zuerst!")
        yield self._connection

    @asynccontextmanager
    async def transaction(self) -> AsyncGenerator[aiosqlite.Connection, None]:
        """
        Atomare Transaktion.

        Bei Exception: Automatischer Rollback.
        Bei Erfolg: Automatischer Commit.

        Usage:
            async with db.transaction() as conn:
                await conn.execute("INSERT INTO ...")
                await conn.execute("UPDATE ...")
                # Auto-Commit bei Erfolg
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

    # =========================================================================
    # Convenience: Row → Dict
    # =========================================================================

    @staticmethod
    def row_to_dict(row: aiosqlite.Row) -> dict:
        """Konvertiert eine aiosqlite.Row in ein dict."""
        return dict(row)


# =============================================================================
# Globale Singleton-Instanz
# =============================================================================

# Wird von main.py initialisiert und in allen Modulen importiert
db = TitanDatabase()
