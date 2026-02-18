"""
Vault API (Account Manager CRUD) v2.0
======================================

REST-Endpoints für die Verwaltung der Profiles-Tabelle.

Endpoints:
  GET    /api/vault                      — Alle Profile (mit Identity-Join + alle Felder)
  POST   /api/vault                      — Neues Profil erstellen (erweitert)
  GET    /api/vault/{id}                 — Einzelnes Profil laden
  PUT    /api/vault/{id}                 — Profil komplett aktualisieren (erweitert)
  PUT    /api/vault/{id}/credentials     — TikTok + Google Credentials updaten
  PUT    /api/vault/{id}/status          — Status ändern (warmup/active/banned/...)
  DELETE /api/vault/{id}                 — Profil + zugehörige Identität löschen
"""

from __future__ import annotations

import logging
from datetime import datetime

from host.config import LOCAL_TZ
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from host.database import db

logger = logging.getLogger("host.api.vault")

router = APIRouter(prefix="/api/vault", tags=["Vault"])


# =============================================================================
# Request Models (Erweitert für v2.0)
# =============================================================================

class VaultCreateRequest(BaseModel):
    """Neues Profil anlegen."""
    name: str = Field(..., min_length=1, max_length=64)
    identity_id: int = Field(..., description="FK → identities.id")

    # TikTok
    tiktok_username: Optional[str] = Field(default=None, max_length=128)
    tiktok_email: Optional[str] = Field(default=None, max_length=256)
    tiktok_password: Optional[str] = Field(default=None, max_length=256)

    # Instagram
    instagram_username: Optional[str] = Field(default=None, max_length=128)
    instagram_email: Optional[str] = Field(default=None, max_length=256)
    instagram_password: Optional[str] = Field(default=None, max_length=256)

    # YouTube
    youtube_username: Optional[str] = Field(default=None, max_length=128)
    youtube_email: Optional[str] = Field(default=None, max_length=256)
    youtube_password: Optional[str] = Field(default=None, max_length=256)

    # Snapchat
    snapchat_username: Optional[str] = Field(default=None, max_length=128)
    snapchat_email: Optional[str] = Field(default=None, max_length=256)
    snapchat_password: Optional[str] = Field(default=None, max_length=256)

    # Google Account
    google_email: Optional[str] = Field(default=None, max_length=256)
    google_password: Optional[str] = Field(default=None, max_length=256)

    # General Contact Email
    contact_email: Optional[str] = Field(default=None, max_length=256)
    contact_password: Optional[str] = Field(default=None, max_length=256)

    # Proxy
    proxy_ip: Optional[str] = Field(default=None, max_length=256)
    proxy_type: str = Field(default="none")
    proxy_username: Optional[str] = Field(default=None, max_length=128)
    proxy_password: Optional[str] = Field(default=None, max_length=256)

    notes: Optional[str] = Field(default=None, max_length=1000)


class VaultCredentialsRequest(BaseModel):
    """TikTok + Google Credentials aktualisieren."""
    tiktok_username: Optional[str] = Field(default=None, max_length=128)
    tiktok_email: Optional[str] = Field(default=None, max_length=256)
    tiktok_password: Optional[str] = Field(default=None, max_length=256)
    google_email: Optional[str] = Field(default=None, max_length=256)
    google_password: Optional[str] = Field(default=None, max_length=256)


class VaultUpdateRequest(BaseModel):
    """Profil-Felder aktualisieren (partial)."""
    name: Optional[str] = Field(default=None, min_length=1, max_length=64)
    status: Optional[str] = Field(default=None)

    # TikTok
    tiktok_username: Optional[str] = Field(default=None, max_length=128)
    tiktok_email: Optional[str] = Field(default=None, max_length=256)
    tiktok_password: Optional[str] = Field(default=None, max_length=256)
    tiktok_followers: Optional[int] = None
    tiktok_following: Optional[int] = None
    tiktok_likes: Optional[int] = None

    # Instagram
    instagram_username: Optional[str] = Field(default=None, max_length=128)
    instagram_email: Optional[str] = Field(default=None, max_length=256)
    instagram_password: Optional[str] = Field(default=None, max_length=256)

    # YouTube
    youtube_username: Optional[str] = Field(default=None, max_length=128)
    youtube_email: Optional[str] = Field(default=None, max_length=256)
    youtube_password: Optional[str] = Field(default=None, max_length=256)

    # Snapchat
    snapchat_username: Optional[str] = Field(default=None, max_length=128)
    snapchat_email: Optional[str] = Field(default=None, max_length=256)
    snapchat_password: Optional[str] = Field(default=None, max_length=256)

    # Google
    google_email: Optional[str] = Field(default=None, max_length=256)
    google_password: Optional[str] = Field(default=None, max_length=256)

    # Contact
    contact_email: Optional[str] = Field(default=None, max_length=256)
    contact_password: Optional[str] = Field(default=None, max_length=256)

    # Proxy
    proxy_ip: Optional[str] = Field(default=None, max_length=256)
    proxy_type: Optional[str] = None
    proxy_username: Optional[str] = Field(default=None, max_length=128)
    proxy_password: Optional[str] = Field(default=None, max_length=256)

    notes: Optional[str] = Field(default=None, max_length=1000)


class VaultStatusRequest(BaseModel):
    """Status ändern."""
    status: str = Field(
        ...,
        description="Neuer Status: warmup, active, cooldown, banned, suspended, archived",
    )


class BulkActionRequest(BaseModel):
    """Bulk-Aktion auf mehrere Profile."""
    profile_ids: list[int] = Field(..., min_length=1, description="Liste der Profil-IDs")


class BulkStatusRequest(BaseModel):
    """Bulk-Status-Änderung."""
    profile_ids: list[int] = Field(..., min_length=1)
    status: str = Field(..., description="Neuer Status für alle Profile")


# =============================================================================
# GET /api/vault — Alle Profile (Erweitert)
# =============================================================================

@router.get("")
async def list_profiles():
    """
    Liefert alle Profile mit verknüpfter Identity-Info.

    Enthält jetzt: TikTok Stats, Google-Info, Proxy-Details,
    GMS/Accounts Backup-Status und Activity-Tracking.
    """
    try:
        async with db.connection() as conn:
            cursor = await conn.execute("""
                SELECT
                    p.id, p.name, p.identity_id, p.status,
                    p.tiktok_username, p.tiktok_email, p.tiktok_password,
                    p.tiktok_followers, p.tiktok_following, p.tiktok_likes,
                    p.instagram_username, p.instagram_email, p.instagram_password,
                    p.youtube_username, p.youtube_email, p.youtube_password,
                    p.snapchat_username, p.snapchat_email, p.snapchat_password,
                    p.google_email, p.google_password,
                    p.contact_email, p.contact_password,
                    p.proxy_ip, p.proxy_type, p.proxy_username, p.proxy_password,
                    p.backup_status, p.backup_path, p.backup_size_bytes, p.backup_created_at,
                    p.gms_backup_status, p.gms_backup_path, p.gms_backup_size, p.gms_backup_at,
                    p.accounts_backup_status, p.accounts_backup_path, p.accounts_backup_at,
                    p.tiktok_install_id,
                    p.notes, p.created_at, p.updated_at,
                    p.last_switch_at, p.switch_count, p.last_active_at,
                    i.name          AS identity_name,
                    i.serial        AS identity_serial,
                    i.imei1         AS identity_imei1,
                    i.phone_number  AS identity_phone,
                    i.wifi_mac      AS identity_mac,
                    i.status        AS identity_status,
                    i.last_public_ip    AS identity_last_ip,
                    i.last_audit_score  AS identity_audit_score,
                    i.usage_count       AS identity_usage_count
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
# POST /api/vault — Neues Profil (Erweitert)
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

    now = datetime.now(LOCAL_TZ).isoformat()

    async with db.transaction() as conn:
        cursor = await conn.execute(
            """INSERT INTO profiles (
                name, identity_id, status,
                tiktok_username, tiktok_email, tiktok_password,
                instagram_username, instagram_email, instagram_password,
                youtube_username, youtube_email, youtube_password,
                snapchat_username, snapchat_email, snapchat_password,
                google_email, google_password,
                contact_email, contact_password,
                proxy_ip, proxy_type, proxy_username, proxy_password,
                notes, created_at
            ) VALUES (?, ?, 'warmup', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                req.name, req.identity_id,
                req.tiktok_username, req.tiktok_email, req.tiktok_password,
                req.instagram_username, req.instagram_email, req.instagram_password,
                req.youtube_username, req.youtube_email, req.youtube_password,
                req.snapchat_username, req.snapchat_email, req.snapchat_password,
                req.google_email, req.google_password,
                req.contact_email, req.contact_password,
                req.proxy_ip, req.proxy_type, req.proxy_username, req.proxy_password,
                req.notes, now,
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
                i.imei1 AS identity_imei1, i.phone_number AS identity_phone,
                i.wifi_mac AS identity_mac, i.status AS identity_status,
                i.last_public_ip AS identity_last_ip,
                i.last_audit_score AS identity_audit_score,
                i.last_audit_at AS identity_audit_at,
                i.total_audits AS identity_total_audits,
                i.usage_count AS identity_usage_count
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
# PUT /api/vault/{id} — Profil aktualisieren (Erweitert)
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

    # Proxy-Type validieren
    if "proxy_type" in updates:
        valid_types = {"none", "socks5", "http", "socks4"}
        if updates["proxy_type"] not in valid_types:
            raise HTTPException(
                status_code=400,
                detail=f"Ungültiger Proxy-Typ: '{updates['proxy_type']}'. Erlaubt: {valid_types}",
            )

    updates["updated_at"] = datetime.now(LOCAL_TZ).isoformat()

    set_clause = ", ".join(f"{k} = ?" for k in updates)
    values = list(updates.values()) + [profile_id]

    async with db.transaction() as conn:
        cursor = await conn.execute(
            f"UPDATE profiles SET {set_clause} WHERE id = ?",
            values,
        )
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail=f"Profil #{profile_id} nicht gefunden")

        # Name-Sync: Wenn der Profilname geändert wird, auch die verknüpfte
        # Identity umbenennen, damit Dashboard und Vault synchron bleiben.
        if "name" in updates:
            await conn.execute(
                """UPDATE identities SET name = ?, updated_at = ?
                   WHERE id = (SELECT identity_id FROM profiles WHERE id = ?)""",
                (updates["name"], updates["updated_at"], profile_id),
            )
            logger.info("Identity für Profil #%d ebenfalls umbenannt → '%s'", profile_id, updates["name"])

    logger.info("Profil #%d aktualisiert: %s", profile_id, list(updates.keys()))
    return {"id": profile_id, "updated": list(updates.keys()), "message": "Profil aktualisiert."}


# =============================================================================
# FIX-27: PUT /api/vault/{id}/credentials ENTFERNT
# (redundant — bereits über PUT /api/vault/{id} (Edit) abgedeckt)
# =============================================================================

# =============================================================================
# FIX-27: PUT /api/vault/{id}/status ENTFERNT
# (redundant — bereits über Edit oder Bulk-Status abgedeckt)
# =============================================================================


# =============================================================================
# Helper: FK-Referenzen in History-Tabellen auflösen
# =============================================================================

async def _nullify_fk_refs(conn, *, profile_id: int = None, identity_id: int = None):
    """
    Setzt Foreign-Key-Referenzen in History-Tabellen auf NULL,
    damit Profile und Identitäten gelöscht werden können.

    Die History-Einträge bleiben erhalten (für Audit-Trail),
    aber der Link zum gelöschten Profil/Identity wird gelöst.
    """
    if profile_id is not None:
        await conn.execute(
            "UPDATE flow_history SET profile_id = NULL WHERE profile_id = ?",
            (profile_id,),
        )
        await conn.execute(
            "UPDATE ip_history SET profile_id = NULL WHERE profile_id = ?",
            (profile_id,),
        )

    if identity_id is not None:
        await conn.execute(
            "UPDATE flow_history SET identity_id = NULL WHERE identity_id = ?",
            (identity_id,),
        )
        await conn.execute(
            "UPDATE ip_history SET identity_id = NULL WHERE identity_id = ?",
            (identity_id,),
        )
        await conn.execute(
            "UPDATE audit_history SET identity_id = NULL WHERE identity_id = ?",
            (identity_id,),
        )


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

    now = datetime.now(LOCAL_TZ).isoformat()

    async with db.transaction() as conn:
        # FK-Referenzen in History-Tabellen auflösen
        await _nullify_fk_refs(conn, profile_id=profile_id)

        # Profil löschen
        await conn.execute("DELETE FROM profiles WHERE id = ?", (profile_id,))

        identity_deleted = False
        if other_count == 0:
            # Keine anderen Profile → FK-Refs der Identity auflösen + löschen
            await _nullify_fk_refs(conn, identity_id=identity_id)
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


# =============================================================================
# PUT /api/vault/{id}/archive — Profil archivieren
# =============================================================================

@router.put("/{profile_id}/archive")
async def archive_profile(profile_id: int):
    """
    Archiviert ein Profil (Status → 'archived').
    Die Identität bleibt erhalten, wird aber auf 'retired' gesetzt.
    """
    now = datetime.now(LOCAL_TZ).isoformat()

    async with db.connection() as conn:
        cursor = await conn.execute(
            "SELECT id, name, identity_id, status FROM profiles WHERE id = ?",
            (profile_id,),
        )
        profile = await cursor.fetchone()
        if not profile:
            raise HTTPException(status_code=404, detail=f"Profil #{profile_id} nicht gefunden")

        if profile["status"] == "archived":
            return {"id": profile_id, "message": "Profil ist bereits archiviert."}

    async with db.transaction() as conn:
        await conn.execute(
            "UPDATE profiles SET status = 'archived', updated_at = ? WHERE id = ?",
            (now, profile_id),
        )
        # Identität auf retired setzen wenn keine aktiven Profile mehr
        cursor = await conn.execute(
            """SELECT COUNT(*) FROM profiles
               WHERE identity_id = ? AND id != ? AND status NOT IN ('archived', 'banned')""",
            (profile["identity_id"], profile_id),
        )
        active_count = (await cursor.fetchone())[0]
        if active_count == 0:
            await conn.execute(
                "UPDATE identities SET status = 'retired', updated_at = ? WHERE id = ?",
                (now, profile["identity_id"]),
            )

    logger.info("Profil #%d archiviert: '%s'", profile_id, profile["name"])
    return {"id": profile_id, "status": "archived", "message": f"Profil '{profile['name']}' archiviert."}


# =============================================================================
# PUT /api/vault/{id}/unarchive — Profil wiederherstellen
# =============================================================================

@router.put("/{profile_id}/unarchive")
async def unarchive_profile(profile_id: int):
    """Stellt ein archiviertes Profil wieder her (Status → 'cooldown')."""
    now = datetime.now(LOCAL_TZ).isoformat()

    async with db.connection() as conn:
        cursor = await conn.execute(
            "SELECT id, name, status FROM profiles WHERE id = ?",
            (profile_id,),
        )
        profile = await cursor.fetchone()
        if not profile:
            raise HTTPException(status_code=404, detail=f"Profil #{profile_id} nicht gefunden")
        if profile["status"] != "archived":
            raise HTTPException(status_code=400, detail="Profil ist nicht archiviert")

    async with db.transaction() as conn:
        await conn.execute(
            "UPDATE profiles SET status = 'cooldown', updated_at = ? WHERE id = ?",
            (now, profile_id),
        )

    logger.info("Profil #%d wiederhergestellt: '%s'", profile_id, profile["name"])
    return {"id": profile_id, "status": "cooldown", "message": f"Profil '{profile['name']}' wiederhergestellt."}


# =============================================================================
# GET /api/vault/{id}/detail — Vollständige Details (Identity + History)
# =============================================================================

@router.get("/{profile_id}/detail")
async def get_profile_detail(profile_id: int):
    """
    Liefert ALLE Details zu einem Profil:
      - Profil-Daten inkl. aller Credentials
      - Vollständige Identity-Hardware (IMEI, GSF, Android ID, etc.)
      - IP-History (letzte 10)
      - Flow-History (letzte 10)
      - Audit-History (letzte 5)
      - Backup-Info (Pfade, Größen, Timestamps)
    """
    async with db.connection() as conn:
        # Profil + Identity (ALLE Felder)
        cursor = await conn.execute(
            """SELECT
                p.*,
                i.name AS identity_name,
                i.serial, i.boot_serial, i.imei1, i.imei2,
                i.gsf_id, i.android_id, i.wifi_mac, i.widevine_id,
                i.advertising_id, i.bluetooth_mac,
                i.imsi, i.sim_serial, i.operator_name, i.phone_number,
                i.sim_operator, i.sim_operator_name, i.voicemail_number,
                i.build_id, i.build_fingerprint, i.security_patch,
                i.last_public_ip AS identity_last_ip,
                i.last_ip_service AS identity_last_ip_service,
                i.last_ip_at AS identity_last_ip_at,
                i.last_audit_score AS identity_audit_score,
                i.last_audit_at AS identity_audit_at,
                i.last_audit_detail AS identity_audit_detail,
                i.total_audits AS identity_total_audits,
                i.status AS identity_status,
                i.created_at AS identity_created_at,
                i.updated_at AS identity_updated_at,
                i.last_used_at AS identity_last_used_at,
                i.usage_count AS identity_usage_count
            FROM profiles p
            LEFT JOIN identities i ON p.identity_id = i.id
            WHERE p.id = ?""",
            (profile_id,),
        )
        row = await cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"Profil #{profile_id} nicht gefunden")

        profile = dict(row)
        identity_id = profile.get("identity_id")

        # IP-History (letzte 10 für diese Identity)
        ip_rows = []
        if identity_id:
            cursor = await conn.execute(
                """SELECT public_ip, ip_service, connection_type, flow_type, detected_at
                   FROM ip_history WHERE identity_id = ?
                   ORDER BY detected_at DESC LIMIT 10""",
                (identity_id,),
            )
            ip_rows = [dict(r) for r in await cursor.fetchall()]

        # Flow-History (letzte 10 für diese Identity)
        flow_rows = []
        if identity_id:
            cursor = await conn.execute(
                """SELECT id, flow_type, status, started_at, finished_at,
                          duration_ms, public_ip, audit_score, error
                   FROM flow_history WHERE identity_id = ?
                   ORDER BY started_at DESC LIMIT 10""",
                (identity_id,),
            )
            flow_rows = [dict(r) for r in await cursor.fetchall()]

        # Audit-History (letzte 5 für diese Identity)
        audit_rows = []
        if identity_id:
            cursor = await conn.execute(
                """SELECT score_percent, total_checks, passed_checks,
                          failed_checks, checks_json, created_at, error
                   FROM audit_history WHERE identity_id = ?
                   ORDER BY created_at DESC LIMIT 5""",
                (identity_id,),
            )
            audit_rows = [dict(r) for r in await cursor.fetchall()]

        # Profile Logs (Live Monitor + HookGuard Snapshots, letzte 10)
        log_rows = []
        try:
            cursor = await conn.execute(
                """SELECT id, trigger, live_summary_json, live_api_count, live_spoofed_pct,
                          hookguard_json, hook_count, bridge_intact, heartbeat_ok, leaks_detected,
                          kill_events_json, kill_event_count, captured_at
                   FROM profile_logs WHERE profile_id = ?
                   ORDER BY captured_at DESC LIMIT 10""",
                (profile_id,),
            )
            log_rows = [dict(r) for r in await cursor.fetchall()]
        except Exception:
            pass

    return {
        "profile": profile,
        "ip_history": ip_rows,
        "flow_history": flow_rows,
        "audit_history": audit_rows,
        "profile_logs": log_rows,
    }


# =============================================================================
# POST /api/vault/{id}/capture — Manueller Log-Snapshot
# =============================================================================

@router.post("/{profile_id}/capture")
async def capture_profile_snapshot(profile_id: int):
    """
    Erstellt einen manuellen Snapshot der Live-Monitor- und HookGuard-Daten.
    Liest die aktuellen Daten vom Gerät und speichert sie in der DB.
    """
    import dataclasses
    import json as _json

    from host.adb.client import ADBClient
    from host.engine.db_ops import capture_profile_log

    # Identity-ID für dieses Profil ermitteln
    async with db.connection() as conn:
        cursor = await conn.execute(
            "SELECT identity_id FROM profiles WHERE id = ?", (profile_id,),
        )
        row = await cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"Profil #{profile_id} nicht gefunden")
        identity_id = row["identity_id"]

    adb = ADBClient()

    # Live Monitor Summary
    live_summary = None
    for pkg in ("com.zhiliaoapp.musically", "com.ss.android.ugc.trill"):
        try:
            result = await adb.shell(
                f"cat /data/data/{pkg}/files/.titan_access_summary.json 2>/dev/null",
                root=True, timeout=5,
            )
            if result.success and result.output.strip().startswith("{"):
                live_summary = _json.loads(result.output.strip())
                break
        except Exception:
            pass

    # HookGuard State
    hookguard_dict = None
    kill_events = None
    try:
        import host.main as _main
        guard = getattr(_main, "_hookguard", None)
        if guard and guard.is_running:
            hookguard_dict = dataclasses.asdict(guard.state)
            hookguard_dict["status"] = guard.state.status.value
            kill_events = hookguard_dict.pop("device_kill_events", [])
    except Exception:
        pass

    log_id = await capture_profile_log(
        profile_id=profile_id,
        identity_id=identity_id,
        trigger="manual",
        live_summary=live_summary,
        hookguard_state=hookguard_dict,
        kill_events=kill_events,
    )

    return {
        "log_id": log_id,
        "message": f"Snapshot gespeichert (log #{log_id})",
        "apis": len(live_summary.get("apis", {})) if live_summary else 0,
        "hookguard": bool(hookguard_dict),
    }


# =============================================================================
# POST /api/vault/bulk/archive — Mehrere Profile archivieren
# =============================================================================

@router.post("/bulk/archive")
async def bulk_archive(req: BulkActionRequest):
    """Archiviert mehrere Profile auf einmal."""
    now = datetime.now(LOCAL_TZ).isoformat()
    archived = 0
    skipped = 0

    async with db.transaction() as conn:
        for pid in req.profile_ids:
            cursor = await conn.execute(
                "SELECT id, identity_id, status FROM profiles WHERE id = ?",
                (pid,),
            )
            profile = await cursor.fetchone()
            if not profile:
                skipped += 1
                continue
            if profile["status"] == "archived":
                skipped += 1
                continue

            await conn.execute(
                "UPDATE profiles SET status = 'archived', updated_at = ? WHERE id = ?",
                (now, pid),
            )
            archived += 1

            # Identität auf retired setzen wenn keine aktiven Profile mehr
            cursor = await conn.execute(
                """SELECT COUNT(*) FROM profiles
                   WHERE identity_id = ? AND id != ? AND status NOT IN ('archived', 'banned')""",
                (profile["identity_id"], pid),
            )
            active_count = (await cursor.fetchone())[0]
            if active_count == 0:
                await conn.execute(
                    "UPDATE identities SET status = 'retired', updated_at = ? WHERE id = ?",
                    (now, profile["identity_id"]),
                )

    logger.info("Bulk-Archive: %d archiviert, %d übersprungen", archived, skipped)
    return {
        "archived": archived,
        "skipped": skipped,
        "message": f"{archived} Profile archiviert" + (f", {skipped} übersprungen" if skipped else ""),
    }


# =============================================================================
# POST /api/vault/bulk/unarchive — Mehrere Profile wiederherstellen
# =============================================================================

@router.post("/bulk/unarchive")
async def bulk_unarchive(req: BulkActionRequest):
    """Stellt mehrere archivierte Profile wieder her (→ cooldown)."""
    now = datetime.now(LOCAL_TZ).isoformat()
    restored = 0
    skipped = 0

    async with db.transaction() as conn:
        for pid in req.profile_ids:
            cursor = await conn.execute(
                "SELECT id, status FROM profiles WHERE id = ?", (pid,),
            )
            profile = await cursor.fetchone()
            if not profile or profile["status"] != "archived":
                skipped += 1
                continue

            await conn.execute(
                "UPDATE profiles SET status = 'cooldown', updated_at = ? WHERE id = ?",
                (now, pid),
            )
            restored += 1

    logger.info("Bulk-Unarchive: %d wiederhergestellt, %d übersprungen", restored, skipped)
    return {
        "restored": restored,
        "skipped": skipped,
        "message": f"{restored} Profile wiederhergestellt" + (f", {skipped} übersprungen" if skipped else ""),
    }


# =============================================================================
# POST /api/vault/bulk/delete — Mehrere Profile löschen
# =============================================================================

@router.post("/bulk/delete")
async def bulk_delete(req: BulkActionRequest):
    """
    Löscht mehrere Profile und (optional) ihre Identitäten.
    Identitäten werden nur gelöscht, wenn kein anderes Profil sie referenziert.
    FK-Referenzen in History-Tabellen werden auf NULL gesetzt (History bleibt).
    """
    now = datetime.now(LOCAL_TZ).isoformat()
    deleted = 0
    identities_deleted = 0
    skipped = 0

    async with db.transaction() as conn:
        for pid in req.profile_ids:
            cursor = await conn.execute(
                "SELECT id, name, identity_id FROM profiles WHERE id = ?",
                (pid,),
            )
            profile = await cursor.fetchone()
            if not profile:
                skipped += 1
                continue

            identity_id = profile["identity_id"]

            # FK-Referenzen in History-Tabellen auflösen
            await _nullify_fk_refs(conn, profile_id=pid)

            # Profil löschen
            await conn.execute("DELETE FROM profiles WHERE id = ?", (pid,))
            deleted += 1

            # Prüfe ob andere Profile diese Identität noch nutzen
            cursor = await conn.execute(
                "SELECT COUNT(*) FROM profiles WHERE identity_id = ?",
                (identity_id,),
            )
            remaining = (await cursor.fetchone())[0]

            if remaining == 0:
                # FK-Refs der Identity auflösen + löschen
                await _nullify_fk_refs(conn, identity_id=identity_id)
                await conn.execute("DELETE FROM identities WHERE id = ?", (identity_id,))
                identities_deleted += 1
            else:
                await conn.execute(
                    "UPDATE identities SET status = 'retired', updated_at = ? WHERE id = ?",
                    (now, identity_id),
                )

    logger.info(
        "Bulk-Delete: %d Profile gelöscht, %d Identitäten gelöscht, %d übersprungen",
        deleted, identities_deleted, skipped,
    )
    return {
        "deleted": deleted,
        "identities_deleted": identities_deleted,
        "skipped": skipped,
        "message": f"{deleted} Profile gelöscht" + (f" ({identities_deleted} Identitäten entfernt)" if identities_deleted else ""),
    }


# =============================================================================
# POST /api/vault/bulk/status — Status für mehrere Profile ändern
# =============================================================================

@router.post("/bulk/status")
async def bulk_status(req: BulkStatusRequest):
    """Ändert den Status mehrerer Profile auf einmal."""
    valid = {"warmup", "active", "cooldown", "banned", "suspended", "archived"}
    if req.status not in valid:
        raise HTTPException(
            status_code=400,
            detail=f"Ungültiger Status: '{req.status}'. Erlaubt: {valid}",
        )

    now = datetime.now(LOCAL_TZ).isoformat()
    updated = 0

    async with db.transaction() as conn:
        for pid in req.profile_ids:
            cursor = await conn.execute(
                "UPDATE profiles SET status = ?, updated_at = ? WHERE id = ?",
                (req.status, now, pid),
            )
            if cursor.rowcount > 0:
                updated += 1

    logger.info("Bulk-Status: %d Profile → '%s'", updated, req.status)
    return {
        "updated": updated,
        "status": req.status,
        "message": f"{updated} Profile auf '{req.status}' gesetzt.",
    }


# =============================================================================
# GET /api/vault/{profile_id}/backups — Backups eines Profils auflisten
# =============================================================================

@router.get("/{profile_id}/backups")
async def list_profile_backups(profile_id: int):
    """
    Listet alle Backups eines Profils (Dual-Path: app_data + sandbox).

    Scannt das Backup-Verzeichnis nach tar-Dateien und gibt
    Metadaten (Größe, Datum, Pfad, Typ) zurück.
    """
    from host.config import BACKUP_DIR, BACKUP_TIKTOK_SUBDIR, BACKUP_SANDBOX_SUBDIR
    from pathlib import Path

    # Profil-Name aus DB holen
    async with db.connection() as conn:
        cursor = await conn.execute(
            "SELECT name FROM profiles WHERE id = ?", (profile_id,),
        )
        row = await cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Profil nicht gefunden")
        profile_name = row["name"]

    profile_dir = BACKUP_DIR / profile_name
    backups = []

    # Scanne Backup-Unterordner
    for subdir, backup_type in [
        (BACKUP_TIKTOK_SUBDIR, "app_data"),
        (BACKUP_SANDBOX_SUBDIR, "sandbox"),
        ("gms", "gms"),
        ("accounts", "accounts"),
    ]:
        target_dir = profile_dir / subdir
        if target_dir.exists():
            for tar_file in sorted(
                target_dir.glob("*.tar"),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            ):
                stat = tar_file.stat()
                backups.append({
                    "type": backup_type,
                    "filename": tar_file.name,
                    "path": str(tar_file),
                    "size_bytes": stat.st_size,
                    "size_mb": round(stat.st_size / (1024 * 1024), 2),
                    "created_at": datetime.fromtimestamp(
                        stat.st_mtime, tz=LOCAL_TZ
                    ).isoformat(),
                })

    return {
        "profile_id": profile_id,
        "profile_name": profile_name,
        "backups": backups,
        "total": len(backups),
    }


# =============================================================================
# POST /api/vault/{profile_id}/backup — Manuelles Dual-Path Backup auslösen
# =============================================================================

@router.post("/{profile_id}/backup")
async def trigger_profile_backup(profile_id: int):
    """
    Löst ein manuelles Dual-Path TikTok Backup für ein Profil aus.

    Sichert:
      A) App-Daten (/data/data/com.zhiliaoapp.musically/)
      B) Sandbox  (/sdcard/Android/data/com.zhiliaoapp.musically/)
    """
    from host.adb.client import ADBClient
    from host.engine.shifter import AppShifter

    # Profil-Name aus DB
    async with db.connection() as conn:
        cursor = await conn.execute(
            "SELECT name FROM profiles WHERE id = ?", (profile_id,),
        )
        row = await cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Profil nicht gefunden")
        profile_name = row["name"]

    try:
        adb = ADBClient()
        shifter = AppShifter(adb)

        result = await shifter.backup_tiktok_dual(profile_name)

        saved = sum(1 for v in result.values() if v is not None)
        paths = {k: str(v) if v else None for k, v in result.items()}

        return {
            "profile_id": profile_id,
            "profile_name": profile_name,
            "success": saved > 0,
            "components_saved": saved,
            "paths": paths,
            "message": f"Dual-Path Backup: {saved}/2 Komponenten gesichert",
        }
    except Exception as e:
        logger.error("Backup fehlgeschlagen für Profil %d: %s", profile_id, e)
        raise HTTPException(
            status_code=500,
            detail=f"Backup fehlgeschlagen: {e}",
        )
