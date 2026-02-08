"""
Project Titan — Vault API (Account Manager CRUD)
===================================================

REST-Endpoints für die Verwaltung der Profiles-Tabelle.

Endpoints:
  GET    /api/vault                      — Alle Profile (mit Identity-Join)
  POST   /api/vault                      — Neues Profil erstellen
  GET    /api/vault/{id}                 — Einzelnes Profil laden
  PUT    /api/vault/{id}                 — Profil komplett aktualisieren
  PUT    /api/vault/{id}/credentials     — TikTok Credentials updaten
  PUT    /api/vault/{id}/status          — Status ändern (warmup/active/banned/...)
  DELETE /api/vault/{id}                 — Profil + zugehörige Identität löschen
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from host.database import db

logger = logging.getLogger("titan.api.vault")

router = APIRouter(prefix="/api/vault", tags=["Vault"])


# =============================================================================
# Request Models
# =============================================================================

class VaultCreateRequest(BaseModel):
    """Neues Profil anlegen."""
    name: str = Field(..., min_length=1, max_length=64)
    identity_id: int = Field(..., description="FK → identities.id")
    tiktok_username: Optional[str] = Field(default=None, max_length=128)
    tiktok_email: Optional[str] = Field(default=None, max_length=256)
    tiktok_password: Optional[str] = Field(default=None, max_length=256)
    proxy_ip: Optional[str] = Field(default=None, max_length=256)
    notes: Optional[str] = Field(default=None, max_length=1000)


class VaultCredentialsRequest(BaseModel):
    """TikTok Credentials aktualisieren."""
    tiktok_username: Optional[str] = Field(default=None, max_length=128)
    tiktok_email: Optional[str] = Field(default=None, max_length=256)
    tiktok_password: Optional[str] = Field(default=None, max_length=256)


class VaultUpdateRequest(BaseModel):
    """Profil-Felder aktualisieren (partial)."""
    name: Optional[str] = Field(default=None, min_length=1, max_length=64)
    tiktok_username: Optional[str] = Field(default=None, max_length=128)
    tiktok_email: Optional[str] = Field(default=None, max_length=256)
    tiktok_password: Optional[str] = Field(default=None, max_length=256)
    proxy_ip: Optional[str] = Field(default=None, max_length=256)
    notes: Optional[str] = Field(default=None, max_length=1000)
    status: Optional[str] = Field(default=None)


class VaultStatusRequest(BaseModel):
    """Status ändern."""
    status: str = Field(
        ...,
        description="Neuer Status: warmup, active, cooldown, banned, suspended, archived",
    )


# =============================================================================
# GET /api/vault — Alle Profile
# =============================================================================

@router.get("")
async def list_profiles():
    """
    Liefert alle Profile mit verknüpfter Identity-Info.

    Sortiert nach ID absteigend (neueste zuerst).
    """
    try:
        async with db.connection() as conn:
            cursor = await conn.execute("""
                SELECT
                    p.id, p.name, p.identity_id, p.status,
                    p.tiktok_username, p.tiktok_email, p.tiktok_password,
                    p.proxy_ip, p.notes,
                    p.backup_status, p.backup_path, p.backup_size_bytes,
                    p.created_at, p.updated_at, p.last_switch_at, p.switch_count,
                    i.name        AS identity_name,
                    i.serial      AS identity_serial,
                    i.imei1       AS identity_imei1,
                    i.phone_number AS identity_phone,
                    i.wifi_mac    AS identity_mac,
                    i.status      AS identity_status
                FROM profiles p
                LEFT JOIN identities i ON p.identity_id = i.id
                ORDER BY p.id DESC
            """)
            rows = await cursor.fetchall()
            return {"profiles": [dict(r) for r in rows]}
    except Exception as e:
        logger.error("Vault list error: %s", e)
        return {"profiles": [], "error": str(e)}


# =============================================================================
# POST /api/vault — Neues Profil
# =============================================================================

@router.post("", status_code=201)
async def create_profile(req: VaultCreateRequest):
    """
    Erstellt ein neues Profil, verknüpft mit einer existierenden Identität.
    """
    async with db.connection() as conn:
        # Prüfe ob Identity existiert
        cursor = await conn.execute(
            "SELECT id, name FROM identities WHERE id = ?", (req.identity_id,),
        )
        identity = await cursor.fetchone()
        if not identity:
            raise HTTPException(
                status_code=404,
                detail=f"Identität #{req.identity_id} nicht gefunden",
            )

    now = datetime.now(timezone.utc).isoformat()

    async with db.transaction() as conn:
        cursor = await conn.execute(
            """INSERT INTO profiles (
                name, identity_id, status,
                tiktok_username, tiktok_email, tiktok_password,
                proxy_ip, notes, created_at
            ) VALUES (?, ?, 'warmup', ?, ?, ?, ?, ?, ?)""",
            (
                req.name, req.identity_id,
                req.tiktok_username, req.tiktok_email, req.tiktok_password,
                req.proxy_ip, req.notes, now,
            ),
        )
        profile_id = cursor.lastrowid

    logger.info("Profil erstellt: #%d '%s' → Identity #%d", profile_id, req.name, req.identity_id)
    return {
        "id": profile_id,
        "name": req.name,
        "identity_id": req.identity_id,
        "message": f"Profil '{req.name}' erstellt.",
    }


# =============================================================================
# GET /api/vault/{id} — Einzelnes Profil
# =============================================================================

@router.get("/{profile_id}")
async def get_profile(profile_id: int):
    """Liefert ein einzelnes Profil mit Identity-Details."""
    async with db.connection() as conn:
        cursor = await conn.execute(
            """SELECT
                p.*,
                i.name AS identity_name, i.serial AS identity_serial,
                i.imei1 AS identity_imei1, i.phone_number AS identity_phone
            FROM profiles p
            LEFT JOIN identities i ON p.identity_id = i.id
            WHERE p.id = ?""",
            (profile_id,),
        )
        row = await cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"Profil #{profile_id} nicht gefunden")
        return dict(row)


# =============================================================================
# PUT /api/vault/{id} — Profil aktualisieren
# =============================================================================

@router.put("/{profile_id}")
async def update_profile(profile_id: int, req: VaultUpdateRequest):
    """Aktualisiert beliebige Felder eines Profils."""
    # Nur gesetzte Felder updaten
    updates = req.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(status_code=400, detail="Keine Felder zum Aktualisieren")

    # Status validieren
    if "status" in updates:
        valid = {"warmup", "active", "cooldown", "banned", "suspended", "archived"}
        if updates["status"] not in valid:
            raise HTTPException(
                status_code=400,
                detail=f"Ungültiger Status: '{updates['status']}'. Erlaubt: {valid}",
            )

    updates["updated_at"] = datetime.now(timezone.utc).isoformat()

    set_clause = ", ".join(f"{k} = ?" for k in updates)
    values = list(updates.values()) + [profile_id]

    async with db.transaction() as conn:
        cursor = await conn.execute(
            f"UPDATE profiles SET {set_clause} WHERE id = ?",
            values,
        )
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail=f"Profil #{profile_id} nicht gefunden")

    logger.info("Profil #%d aktualisiert: %s", profile_id, list(updates.keys()))
    return {"id": profile_id, "updated": list(updates.keys()), "message": "Profil aktualisiert."}


# =============================================================================
# PUT /api/vault/{id}/credentials — TikTok Credentials
# =============================================================================

@router.put("/{profile_id}/credentials")
async def update_credentials(profile_id: int, req: VaultCredentialsRequest):
    """
    Aktualisiert die TikTok-Zugangsdaten eines Profils.

    Felder: tiktok_username, tiktok_email, tiktok_password
    """
    now = datetime.now(timezone.utc).isoformat()

    async with db.transaction() as conn:
        cursor = await conn.execute(
            """UPDATE profiles SET
                tiktok_username = COALESCE(?, tiktok_username),
                tiktok_email    = COALESCE(?, tiktok_email),
                tiktok_password = COALESCE(?, tiktok_password),
                updated_at      = ?
            WHERE id = ?""",
            (req.tiktok_username, req.tiktok_email, req.tiktok_password, now, profile_id),
        )
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail=f"Profil #{profile_id} nicht gefunden")

    logger.info("Credentials aktualisiert: Profil #%d", profile_id)
    return {"id": profile_id, "message": "Credentials aktualisiert."}


# =============================================================================
# PUT /api/vault/{id}/status — Status ändern
# =============================================================================

@router.put("/{profile_id}/status")
async def update_status(profile_id: int, req: VaultStatusRequest):
    """Ändert den Profil-Status (warmup/active/banned/...)."""
    valid = {"warmup", "active", "cooldown", "banned", "suspended", "archived"}
    if req.status not in valid:
        raise HTTPException(
            status_code=400,
            detail=f"Ungültiger Status: '{req.status}'. Erlaubt: {valid}",
        )

    now = datetime.now(timezone.utc).isoformat()

    async with db.transaction() as conn:
        cursor = await conn.execute(
            "UPDATE profiles SET status = ?, updated_at = ? WHERE id = ?",
            (req.status, now, profile_id),
        )
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail=f"Profil #{profile_id} nicht gefunden")

    logger.info("Status geändert: Profil #%d → %s", profile_id, req.status)
    return {"id": profile_id, "status": req.status, "message": f"Status auf '{req.status}' geändert."}


# =============================================================================
# DELETE /api/vault/{id} — Profil + Identität löschen
# =============================================================================

@router.delete("/{profile_id}")
async def delete_profile(profile_id: int):
    """
    Löscht ein Profil und (optional) die zugehörige Identität.

    Die Identität wird nur gelöscht, wenn kein anderes Profil sie referenziert.
    Andernfalls wird nur das Profil gelöscht und die Identität auf 'retired' gesetzt.
    """
    async with db.connection() as conn:
        # Profil laden
        cursor = await conn.execute(
            "SELECT id, name, identity_id FROM profiles WHERE id = ?",
            (profile_id,),
        )
        profile = await cursor.fetchone()
        if not profile:
            raise HTTPException(status_code=404, detail=f"Profil #{profile_id} nicht gefunden")

        identity_id = profile["identity_id"]

        # Prüfe ob andere Profile diese Identität nutzen
        cursor = await conn.execute(
            "SELECT COUNT(*) FROM profiles WHERE identity_id = ? AND id != ?",
            (identity_id, profile_id),
        )
        other_count = (await cursor.fetchone())[0]

    now = datetime.now(timezone.utc).isoformat()

    async with db.transaction() as conn:
        # Profil löschen
        await conn.execute("DELETE FROM profiles WHERE id = ?", (profile_id,))

        identity_deleted = False
        if other_count == 0:
            # Keine anderen Profile → Identität auch löschen
            await conn.execute("DELETE FROM identities WHERE id = ?", (identity_id,))
            identity_deleted = True
        else:
            # Identität auf retired setzen
            await conn.execute(
                "UPDATE identities SET status = 'retired', updated_at = ? WHERE id = ?",
                (now, identity_id),
            )

    action = "gelöscht (inkl. Identität)" if identity_deleted else "gelöscht (Identität behalten)"
    logger.info("Profil #%d %s: '%s'", profile_id, action, profile["name"])

    return {
        "id": profile_id,
        "identity_deleted": identity_deleted,
        "message": f"Profil '{profile['name']}' {action}.",
    }
