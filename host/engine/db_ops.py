"""
Project Titan — Database Operations Layer
============================================

Zentralisierte DB-Operationen für alle Flows.
Jede Funktion ist eine atomare Transaktion.

Verwendung:
  - GenesisFlow   → create_flow_history, update_flow_history, create_profile_auto,
                     record_ip, record_audit, update_identity_network, update_identity_audit
  - SwitchFlow    → create_flow_history, update_flow_history,
                     record_ip, record_audit, update_profile_activity
  - BackupFlow    → update_profile_backup, update_profile_gms_backup, update_profile_accounts_backup
  - Auditor       → record_audit, update_identity_audit
  - NetworkChecker→ record_ip, update_identity_network
"""

from __future__ import annotations

import json
import logging
from datetime import datetime

from host.config import LOCAL_TZ
from pathlib import Path
from typing import Any, Optional

from host.database import db

logger = logging.getLogger("titan.db_ops")


def _now() -> str:
    """ISO-Timestamp in Europe/Berlin (CET/CEST)."""
    return datetime.now(LOCAL_TZ).strftime("%Y-%m-%dT%H:%M:%S")


# =============================================================================
# Flow History
# =============================================================================

async def create_flow_history(
    flow_type: str,
    identity_id: Optional[int] = None,
    profile_id: Optional[int] = None,
) -> int:
    """
    Erstellt einen neuen Flow-History Eintrag (Status: 'running').

    Returns:
        Die ID des neuen Eintrags.
    """
    async with db.transaction() as conn:
        cursor = await conn.execute(
            """INSERT INTO flow_history (
                identity_id, profile_id, flow_type, status, started_at
            ) VALUES (?, ?, ?, 'running', ?)""",
            (identity_id, profile_id, flow_type, _now()),
        )
        flow_id = cursor.lastrowid
        logger.debug("Flow-History erstellt: id=%d, type=%s", flow_id, flow_type)
        return flow_id


async def update_flow_history(
    flow_id: int,
    *,
    status: Optional[str] = None,
    duration_ms: Optional[int] = None,
    generated_serial: Optional[str] = None,
    generated_imei: Optional[str] = None,
    public_ip: Optional[str] = None,
    ip_service: Optional[str] = None,
    audit_score: Optional[int] = None,
    audit_detail: Optional[str] = None,
    steps_json: Optional[str] = None,
    error: Optional[str] = None,
) -> None:
    """Aktualisiert einen bestehenden Flow-History Eintrag."""
    updates: list[str] = []
    values: list[Any] = []

    if status is not None:
        updates.append("status = ?")
        values.append(status)
        if status in ("success", "failed", "aborted"):
            updates.append("finished_at = ?")
            values.append(_now())
    if duration_ms is not None:
        updates.append("duration_ms = ?")
        values.append(duration_ms)
    if generated_serial is not None:
        updates.append("generated_serial = ?")
        values.append(generated_serial)
    if generated_imei is not None:
        updates.append("generated_imei = ?")
        values.append(generated_imei)
    if public_ip is not None:
        updates.append("public_ip = ?")
        values.append(public_ip)
    if ip_service is not None:
        updates.append("ip_service = ?")
        values.append(ip_service)
    if audit_score is not None:
        updates.append("audit_score = ?")
        values.append(audit_score)
    if audit_detail is not None:
        updates.append("audit_detail = ?")
        values.append(audit_detail)
    if steps_json is not None:
        updates.append("steps_json = ?")
        values.append(steps_json)
    if error is not None:
        updates.append("error = ?")
        values.append(error)

    if not updates:
        return

    values.append(flow_id)
    sql = f"UPDATE flow_history SET {', '.join(updates)} WHERE id = ?"

    async with db.transaction() as conn:
        await conn.execute(sql, tuple(values))


# =============================================================================
# IP History
# =============================================================================

async def record_ip(
    public_ip: str,
    *,
    identity_id: Optional[int] = None,
    profile_id: Optional[int] = None,
    ip_service: Optional[str] = None,
    connection_type: str = "unknown",
    flow_type: Optional[str] = None,
) -> int:
    """
    Protokolliert eine erkannte öffentliche IP.

    Returns:
        Die ID des neuen Eintrags.
    """
    async with db.transaction() as conn:
        cursor = await conn.execute(
            """INSERT INTO ip_history (
                identity_id, profile_id, public_ip, ip_service,
                connection_type, flow_type
            ) VALUES (?, ?, ?, ?, ?, ?)""",
            (identity_id, profile_id, public_ip, ip_service,
             connection_type, flow_type),
        )
        ip_id = cursor.lastrowid
        logger.debug("IP-History: %s (id=%d, service=%s)", public_ip, ip_id, ip_service)
        return ip_id


# =============================================================================
# Audit History
# =============================================================================

async def record_audit(
    *,
    identity_id: Optional[int] = None,
    flow_id: Optional[int] = None,
    score_percent: int,
    total_checks: int,
    passed_checks: int,
    failed_checks: int,
    checks_json: str,
    error: Optional[str] = None,
) -> int:
    """
    Protokolliert ein Audit-Ergebnis.

    Returns:
        Die ID des neuen Eintrags.
    """
    async with db.transaction() as conn:
        cursor = await conn.execute(
            """INSERT INTO audit_history (
                identity_id, flow_id, score_percent, total_checks,
                passed_checks, failed_checks, checks_json, error
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (identity_id, flow_id, score_percent, total_checks,
             passed_checks, failed_checks, checks_json, error),
        )
        audit_id = cursor.lastrowid
        logger.debug(
            "Audit-History: score=%d%% (id=%d, identity=%s)",
            score_percent, audit_id, identity_id,
        )
        return audit_id


# =============================================================================
# Identity Updates
# =============================================================================

async def update_identity_network(
    identity_id: int,
    public_ip: str,
    ip_service: str,
) -> None:
    """Aktualisiert die Netzwerk-Tracking Felder einer Identität."""
    async with db.transaction() as conn:
        await conn.execute(
            """UPDATE identities SET
                last_public_ip = ?,
                last_ip_service = ?,
                last_ip_at = ?,
                updated_at = ?
            WHERE id = ?""",
            (public_ip, ip_service, _now(), _now(), identity_id),
        )


async def update_identity_audit(
    identity_id: int,
    score: int,
    detail: str,
) -> None:
    """Aktualisiert die Audit-Tracking Felder einer Identität."""
    async with db.transaction() as conn:
        await conn.execute(
            """UPDATE identities SET
                last_audit_score = ?,
                last_audit_at = ?,
                last_audit_detail = ?,
                total_audits = total_audits + 1,
                updated_at = ?
            WHERE id = ?""",
            (score, _now(), detail, _now(), identity_id),
        )


async def increment_identity_usage(identity_id: int) -> None:
    """Erhöht den usage_count einer Identität."""
    async with db.transaction() as conn:
        await conn.execute(
            """UPDATE identities SET
                usage_count = usage_count + 1,
                last_used_at = ?,
                updated_at = ?
            WHERE id = ?""",
            (_now(), _now(), identity_id),
        )


# =============================================================================
# Profile: Auto-Create (Genesis)
# =============================================================================

async def create_profile_auto(
    identity_id: int,
    name: str,
) -> int:
    """
    Erstellt automatisch ein Profil nach einem erfolgreichen Genesis-Flow.

    Returns:
        Die ID des neuen Profils.
    """
    async with db.transaction() as conn:
        cursor = await conn.execute(
            """INSERT INTO profiles (
                identity_id, name, status, created_at
            ) VALUES (?, ?, 'warmup', ?)""",
            (identity_id, name, _now()),
        )
        profile_id = cursor.lastrowid
        logger.info("Auto-Profil erstellt: id=%d, name=%s", profile_id, name)
        return profile_id


# =============================================================================
# Profile: Activity & Switch Tracking
# =============================================================================

async def update_profile_activity(
    profile_id: int,
) -> None:
    """Aktualisiert switch_count, last_switch_at und last_active_at."""
    async with db.transaction() as conn:
        await conn.execute(
            """UPDATE profiles SET
                switch_count = switch_count + 1,
                last_switch_at = ?,
                last_active_at = ?,
                updated_at = ?
            WHERE id = ?""",
            (_now(), _now(), _now(), profile_id),
        )


# =============================================================================
# Profile: Backup Status Updates
# =============================================================================

async def update_profile_tiktok_backup(
    profile_id: int,
    backup_path: str,
    backup_size_bytes: int,
) -> None:
    """Aktualisiert den TikTok-Backup-Status eines Profils."""
    async with db.transaction() as conn:
        await conn.execute(
            """UPDATE profiles SET
                backup_status = 'valid',
                backup_path = ?,
                backup_size_bytes = ?,
                backup_created_at = ?,
                updated_at = ?
            WHERE id = ?""",
            (backup_path, backup_size_bytes, _now(), _now(), profile_id),
        )


async def update_profile_gms_backup(
    profile_id: int,
    gms_path: str,
    gms_size: int,
) -> None:
    """Aktualisiert den GMS-Backup-Status eines Profils."""
    async with db.transaction() as conn:
        await conn.execute(
            """UPDATE profiles SET
                gms_backup_status = 'valid',
                gms_backup_path = ?,
                gms_backup_size = ?,
                gms_backup_at = ?,
                updated_at = ?
            WHERE id = ?""",
            (gms_path, gms_size, _now(), _now(), profile_id),
        )


async def update_profile_accounts_backup(
    profile_id: int,
    accounts_path: str,
) -> None:
    """Aktualisiert den Account-DB-Backup-Status eines Profils."""
    async with db.transaction() as conn:
        await conn.execute(
            """UPDATE profiles SET
                accounts_backup_status = 'valid',
                accounts_backup_path = ?,
                accounts_backup_at = ?,
                updated_at = ?
            WHERE id = ?""",
            (accounts_path, _now(), _now(), profile_id),
        )


async def mark_profile_backup_corrupted(
    profile_id: int,
    component: str = "tiktok",
) -> None:
    """Markiert ein Profil-Backup-Komponent als corrupted."""
    col = {
        "tiktok": "backup_status",
        "gms": "gms_backup_status",
        "accounts": "accounts_backup_status",
    }.get(component, "backup_status")

    async with db.transaction() as conn:
        await conn.execute(
            f"UPDATE profiles SET {col} = 'corrupted', updated_at = ? WHERE id = ?",
            (_now(), profile_id),
        )
    logger.warning("Profil %d: %s-Backup als corrupted markiert", profile_id, component)


# =============================================================================
# Lookup Helpers
# =============================================================================

async def find_profile_by_identity(identity_id: int) -> Optional[int]:
    """Findet die Profil-ID für eine Identität (die neueste)."""
    async with db.connection() as conn:
        cursor = await conn.execute(
            "SELECT id FROM profiles WHERE identity_id = ? "
            "ORDER BY created_at DESC LIMIT 1",
            (identity_id,),
        )
        row = await cursor.fetchone()
        return row[0] if row else None


async def find_profile_by_name(name: str) -> Optional[dict]:
    """Findet ein Profil per Name."""
    async with db.connection() as conn:
        cursor = await conn.execute(
            "SELECT * FROM profiles WHERE name = ? LIMIT 1",
            (name,),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None


async def get_flow_history(
    limit: int = 50,
    flow_type: Optional[str] = None,
) -> list[dict]:
    """Holt die letzten Flow-History Einträge."""
    async with db.connection() as conn:
        if flow_type:
            cursor = await conn.execute(
                "SELECT * FROM flow_history WHERE flow_type = ? "
                "ORDER BY started_at DESC LIMIT ?",
                (flow_type, limit),
            )
        else:
            cursor = await conn.execute(
                "SELECT * FROM flow_history ORDER BY started_at DESC LIMIT ?",
                (limit,),
            )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def get_ip_history(
    identity_id: Optional[int] = None,
    limit: int = 50,
) -> list[dict]:
    """Holt die letzten IP-History Einträge."""
    async with db.connection() as conn:
        if identity_id:
            cursor = await conn.execute(
                "SELECT * FROM ip_history WHERE identity_id = ? "
                "ORDER BY detected_at DESC LIMIT ?",
                (identity_id, limit),
            )
        else:
            cursor = await conn.execute(
                "SELECT * FROM ip_history ORDER BY detected_at DESC LIMIT ?",
                (limit,),
            )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def get_audit_history(
    identity_id: Optional[int] = None,
    limit: int = 50,
) -> list[dict]:
    """Holt die letzten Audit-History Einträge."""
    async with db.connection() as conn:
        if identity_id:
            cursor = await conn.execute(
                "SELECT * FROM audit_history WHERE identity_id = ? "
                "ORDER BY created_at DESC LIMIT ?",
                (identity_id, limit),
            )
        else:
            cursor = await conn.execute(
                "SELECT * FROM audit_history ORDER BY created_at DESC LIMIT ?",
                (limit,),
            )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def get_dashboard_stats() -> dict:
    """Aggregierte Statistiken für das Dashboard."""
    async with db.connection() as conn:
        # Identitäten
        cur = await conn.execute("SELECT COUNT(*) FROM identities")
        total_identities = (await cur.fetchone())[0]

        cur = await conn.execute("SELECT COUNT(*) FROM identities WHERE status = 'active'")
        active_identities = (await cur.fetchone())[0]

        cur = await conn.execute("SELECT COUNT(*) FROM identities WHERE status = 'corrupted'")
        corrupted_identities = (await cur.fetchone())[0]

        # Profile
        cur = await conn.execute("SELECT COUNT(*) FROM profiles")
        total_profiles = (await cur.fetchone())[0]

        cur = await conn.execute("SELECT COUNT(*) FROM profiles WHERE status = 'active'")
        active_profiles = (await cur.fetchone())[0]

        cur = await conn.execute("SELECT COUNT(*) FROM profiles WHERE status = 'banned'")
        banned_profiles = (await cur.fetchone())[0]

        cur = await conn.execute("SELECT COUNT(*) FROM profiles WHERE backup_status = 'valid'")
        backed_up_profiles = (await cur.fetchone())[0]

        # Flows
        cur = await conn.execute("SELECT COUNT(*) FROM flow_history")
        total_flows = (await cur.fetchone())[0]

        cur = await conn.execute("SELECT COUNT(*) FROM flow_history WHERE status = 'success'")
        success_flows = (await cur.fetchone())[0]

        cur = await conn.execute("SELECT COUNT(*) FROM flow_history WHERE status = 'failed'")
        failed_flows = (await cur.fetchone())[0]

        # IPs
        cur = await conn.execute("SELECT COUNT(DISTINCT public_ip) FROM ip_history")
        unique_ips = (await cur.fetchone())[0]

        # Audits
        cur = await conn.execute("SELECT AVG(score_percent) FROM audit_history")
        avg_audit = (await cur.fetchone())[0]

        return {
            "identities": {
                "total": total_identities,
                "active": active_identities,
                "corrupted": corrupted_identities,
            },
            "profiles": {
                "total": total_profiles,
                "active": active_profiles,
                "banned": banned_profiles,
                "backed_up": backed_up_profiles,
            },
            "flows": {
                "total": total_flows,
                "success": success_flows,
                "failed": failed_flows,
                "success_rate": round(success_flows / total_flows * 100, 1) if total_flows > 0 else 0,
            },
            "network": {
                "unique_ips": unique_ips,
            },
            "audits": {
                "average_score": round(avg_audit, 1) if avg_audit else 0,
            },
        }
