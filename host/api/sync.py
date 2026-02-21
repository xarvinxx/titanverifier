"""
Supabase Sync API v1.0
=======================

Endpoints für Cloud-Synchronisation:
  POST /api/sync/full     — Kompletter Sync aller Tabellen → Supabase
  POST /api/sync/identity — Einzelne Identität synchro
  POST /api/sync/profile  — Einzelnes Profil synchro
  GET  /api/sync/status   — Sync-Status und Konfiguration
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException

from host.database import db
from host.engine import supabase_sync as sync

logger = logging.getLogger("host.api.sync")

router = APIRouter(prefix="/api/sync", tags=["Cloud-Sync"])


@router.get("/status")
async def sync_status():
    """Zeigt ob Supabase konfiguriert ist und den letzten Sync-Status."""
    from host.config import SUPABASE_URL
    return {
        "enabled": sync.is_enabled(),
        "supabase_url": SUPABASE_URL[:40] + "..." if SUPABASE_URL else None,
    }


@router.post("/full")
async def full_sync():
    """Synchronisiert alle Tabellen von SQLite → Supabase."""
    if not sync.is_enabled():
        raise HTTPException(
            status_code=400,
            detail="Supabase nicht konfiguriert. "
                   "Setze SUPABASE_URL und SUPABASE_KEY Umgebungsvariablen.",
        )

    async with db.connection() as conn:
        stats = await sync.full_sync_from_sqlite(conn)

    return {"status": "ok", "synced": stats}


@router.post("/identity/{identity_id}")
async def sync_single_identity(identity_id: int):
    """Synchronisiert eine einzelne Identität."""
    if not sync.is_enabled():
        raise HTTPException(status_code=400, detail="Supabase nicht konfiguriert")

    async with db.connection() as conn:
        cursor = await conn.execute(
            "SELECT * FROM identities WHERE id = ?", (identity_id,),
        )
        row = await cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"Identität #{identity_id} nicht gefunden")

        ok = await sync.sync_identity(dict(row))
        return {"status": "ok" if ok else "failed", "identity_id": identity_id}


@router.post("/profile/{profile_id}")
async def sync_single_profile(profile_id: int):
    """Synchronisiert ein einzelnes Profil."""
    if not sync.is_enabled():
        raise HTTPException(status_code=400, detail="Supabase nicht konfiguriert")

    async with db.connection() as conn:
        cursor = await conn.execute(
            "SELECT * FROM profiles WHERE id = ?", (profile_id,),
        )
        row = await cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"Profil #{profile_id} nicht gefunden")

        ok = await sync.sync_profile(dict(row))
        return {"status": "ok" if ok else "failed", "profile_id": profile_id}


# =========================================================================
# Auto-Sync Helper: Wird von Flows nach Abschluss aufgerufen
# =========================================================================

async def auto_sync_after_flow(
    identity_id: int | None = None,
    profile_id: int | None = None,
    flow_id: int | None = None,
) -> None:
    """
    Wird nach Genesis/Switch/Backup aufgerufen.
    Pusht die betroffenen Datensätze an Supabase (fire-and-forget).
    """
    if not sync.is_enabled():
        return

    try:
        async with db.connection() as conn:
            if identity_id:
                cursor = await conn.execute(
                    "SELECT * FROM identities WHERE id = ?", (identity_id,),
                )
                row = await cursor.fetchone()
                if row:
                    await sync.sync_identity(dict(row))

            if profile_id:
                cursor = await conn.execute(
                    "SELECT * FROM profiles WHERE id = ?", (profile_id,),
                )
                row = await cursor.fetchone()
                if row:
                    await sync.sync_profile(dict(row))

            if flow_id:
                cursor = await conn.execute(
                    "SELECT * FROM flow_history WHERE id = ?", (flow_id,),
                )
                row = await cursor.fetchone()
                if row:
                    await sync.sync_flow_history(dict(row))

    except Exception as e:
        logger.warning("Auto-Sync fehlgeschlagen: %s", e)
