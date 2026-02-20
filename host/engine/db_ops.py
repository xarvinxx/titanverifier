"""
Database Operations Layer
==========================

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

logger = logging.getLogger("host.db_ops")


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
# Genesis Frequency Guard
# =============================================================================

GENESIS_COOLDOWN_MINUTES = 0
GENESIS_MAX_PER_2H = 9999
GENESIS_MAX_PER_24H = 9999

async def check_genesis_frequency() -> dict:
    """
    Prüft ob zu viele Genesis Flows in kurzer Zeit gelaufen sind.

    TikTok rate-limitet auf Carrier/ASN-Ebene. Zu viele Account-Erstellungen
    vom selben Carrier-Subnet lösen "Zu viele Versuche" aus.

    Returns:
        Dict mit:
          - allowed: bool
          - cooldown_remaining_s: Sekunden bis nächster Flow erlaubt
          - reason: Menschenlesbare Begründung
          - stats: Dict mit Frequenz-Statistiken
    """
    from datetime import timezone, timedelta

    now_utc = datetime.now(timezone.utc)
    result = {
        "allowed": True,
        "cooldown_remaining_s": 0,
        "reason": "",
        "stats": {},
    }

    async with db.connection() as conn:
        cursor = await conn.execute(
            """SELECT started_at FROM flow_history
               WHERE flow_type = 'genesis'
               ORDER BY started_at DESC LIMIT 1""",
        )
        last_row = await cursor.fetchone()

        cutoff_2h = (now_utc - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%S")
        cursor = await conn.execute(
            """SELECT COUNT(*) FROM flow_history
               WHERE flow_type = 'genesis' AND started_at > ?""",
            (cutoff_2h,),
        )
        count_2h = (await cursor.fetchone())[0]

        cutoff_24h = (now_utc - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S")
        cursor = await conn.execute(
            """SELECT COUNT(*) FROM flow_history
               WHERE flow_type = 'genesis' AND started_at > ?""",
            (cutoff_24h,),
        )
        count_24h = (await cursor.fetchone())[0]

        cursor = await conn.execute(
            "SELECT COUNT(*) FROM flow_history WHERE flow_type = 'genesis'",
        )
        count_total = (await cursor.fetchone())[0]

    result["stats"] = {
        "last_2h": count_2h,
        "last_24h": count_24h,
        "total": count_total,
        "limits": {
            "cooldown_min": GENESIS_COOLDOWN_MINUTES,
            "max_2h": GENESIS_MAX_PER_2H,
            "max_24h": GENESIS_MAX_PER_24H,
        },
    }

    if last_row and last_row[0]:
        try:
            last_ts = last_row[0].replace("Z", "+00:00")
            if "+" not in last_ts and not last_ts.endswith("Z"):
                from zoneinfo import ZoneInfo
                last_dt = datetime.fromisoformat(last_ts).replace(
                    tzinfo=ZoneInfo("Europe/Berlin"),
                )
            else:
                last_dt = datetime.fromisoformat(last_ts)
            elapsed = (now_utc - last_dt.astimezone(timezone.utc)).total_seconds()
            cooldown_s = GENESIS_COOLDOWN_MINUTES * 60
            if elapsed < cooldown_s:
                remaining = int(cooldown_s - elapsed)
                result["allowed"] = False
                result["cooldown_remaining_s"] = remaining
                result["reason"] = (
                    f"Cooldown: {remaining // 60}min {remaining % 60}s verbleibend "
                    f"(Minimum {GENESIS_COOLDOWN_MINUTES}min zwischen Genesis Flows)"
                )
                return result
        except (ValueError, TypeError):
            pass

    if count_2h >= GENESIS_MAX_PER_2H:
        result["allowed"] = False
        result["reason"] = (
            f"Rate-Limit: {count_2h}/{GENESIS_MAX_PER_2H} Genesis Flows "
            f"in 2h (TikTok rate-limitet auf Carrier/ASN-Ebene)"
        )
        return result

    if count_24h >= GENESIS_MAX_PER_24H:
        result["allowed"] = False
        result["reason"] = (
            f"Tages-Limit: {count_24h}/{GENESIS_MAX_PER_24H} Genesis Flows "
            f"in 24h (zu viele Accounts vom selben Carrier)"
        )
        return result

    return result


# =============================================================================
# FIX-18: IP-Collision Detection
# =============================================================================

async def check_ip_collision(
    public_ip: str,
    current_profile_id: Optional[int] = None,
) -> dict:
    """
    Prüft ob eine IP bereits von einem anderen Profil benutzt wurde.

    FIX-18: Cross-Profile IP-Korrelation erkennen.

    Returns:
        Dict mit:
          - collision: bool (True wenn IP von anderem Profil benutzt)
          - severity: "none" | "warning" | "critical"
          - profiles: Liste der betroffenen Profile
          - message: Menschenlesbare Meldung
    """
    result = {
        "collision": False,
        "severity": "none",
        "profiles": [],
        "message": "",
        "total_uses": 0,
    }

    async with db.connection() as conn:
        # Prüfe ob diese IP jemals von einem ANDEREN Profil benutzt wurde
        if current_profile_id:
            cursor = await conn.execute(
                """SELECT DISTINCT ip.profile_id, p.name, ip.flow_type,
                          ip.detected_at
                   FROM ip_history ip
                   LEFT JOIN profiles p ON ip.profile_id = p.id
                   WHERE ip.public_ip = ?
                     AND ip.profile_id IS NOT NULL
                     AND ip.profile_id != ?
                   ORDER BY ip.detected_at DESC
                   LIMIT 10""",
                (public_ip, current_profile_id),
            )
        else:
            cursor = await conn.execute(
                """SELECT DISTINCT ip.profile_id, p.name, ip.flow_type,
                          ip.detected_at
                   FROM ip_history ip
                   LEFT JOIN profiles p ON ip.profile_id = p.id
                   WHERE ip.public_ip = ?
                     AND ip.profile_id IS NOT NULL
                   ORDER BY ip.detected_at DESC
                   LIMIT 10""",
                (public_ip,),
            )

        rows = await cursor.fetchall()

        if not rows:
            result["message"] = f"IP {public_ip} ist neu — keine Collision"
            return result

        # Unique Profile zählen
        unique_profiles = {r["profile_id"] for r in rows if r["profile_id"]}
        result["collision"] = True
        result["total_uses"] = len(rows)
        result["profiles"] = [
            {
                "profile_id": r["profile_id"],
                "name": r["name"] or f"Profil #{r['profile_id']}",
                "flow_type": r["flow_type"],
                "detected_at": r["detected_at"],
            }
            for r in rows[:5]
        ]

        n_profiles = len(unique_profiles)
        if n_profiles >= 3:
            result["severity"] = "critical"
            result["message"] = (
                f"IP {public_ip} wurde von {n_profiles} verschiedenen Profilen benutzt! "
                f"Cross-Profile Korrelation HOCH. Empfehlung: Wartezeit erhöhen."
            )
            logger.error("IP-COLLISION CRITICAL: %s", result["message"])
        else:
            result["severity"] = "warning"
            profile_names = ", ".join(
                r["name"] or f"#{r['profile_id']}" for r in rows[:3]
            )
            result["message"] = (
                f"IP {public_ip} wurde bereits von Profil(en) {profile_names} benutzt. "
                f"Cross-Profile Korrelation möglich."
            )
            logger.warning("IP-COLLISION WARNING: %s", result["message"])

    return result


async def check_subnet_saturation(
    public_ip: str,
    hours: int = 24,
) -> dict:
    """
    Prüft wie viele Genesis Flows vom selben /16 Subnet gelaufen sind.

    TikTok rate-limitet nicht nur per IP, sondern auf Carrier/ASN-Ebene.
    Alle O2 DE Mobilfunk-IPs fallen unter 176.6.0.0/16.
    """
    from datetime import timezone, timedelta

    parts = public_ip.split(".")
    if len(parts) != 4:
        return {"warning": False, "message": "Ungültige IP"}

    subnet_prefix = f"{parts[0]}.{parts[1]}."

    cutoff = (
        datetime.now(timezone.utc) - timedelta(hours=hours)
    ).strftime("%Y-%m-%dT%H:%M:%S")

    async with db.connection() as conn:
        cursor = await conn.execute(
            """SELECT COUNT(DISTINCT identity_id) as unique_ids,
                      COUNT(*) as total
               FROM ip_history
               WHERE public_ip LIKE ? AND detected_at > ?""",
            (subnet_prefix + "%", cutoff),
        )
        row = await cursor.fetchone()
        unique_ids = row["unique_ids"] if row else 0
        total = row["total"] if row else 0

    if unique_ids >= 5:
        return {
            "warning": True,
            "severity": "critical",
            "message": (
                f"SUBNET SÄTTIGUNG: {unique_ids} verschiedene Identitäten "
                f"von {subnet_prefix}x.x in {hours}h — "
                f"TikTok rate-limitet auf Carrier/ASN-Ebene!"
            ),
            "unique_identities": unique_ids,
            "total_entries": total,
        }
    elif unique_ids >= 3:
        return {
            "warning": True,
            "severity": "warning",
            "message": (
                f"Subnet-Warnung: {unique_ids} Identitäten von "
                f"{subnet_prefix}x.x in {hours}h — Vorsicht empfohlen"
            ),
            "unique_identities": unique_ids,
            "total_entries": total,
        }
    return {
        "warning": False,
        "severity": "none",
        "message": f"Subnet OK: {unique_ids} Identitäten von {subnet_prefix}x.x in {hours}h",
        "unique_identities": unique_ids,
        "total_entries": total,
    }


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


async def sync_backup_status_from_disk() -> int:
    """Scannt das Backup-Verzeichnis und aktualisiert die DB für alle Profile.

    Wird beim Server-Start aufgerufen, damit bestehende Backups, die
    vor dem DB-Tracking erstellt wurden, korrekt in der Vault angezeigt werden.

    Returns:
        Anzahl aktualisierter Profile.
    """
    from host.config import (
        BACKUP_DIR,
        BACKUP_TIKTOK_SUBDIR,
        BACKUP_GMS_SUBDIR,
        BACKUP_ACCOUNTS_SUBDIR,
    )

    MIN_VALID_SIZE = 50 * 1024  # 50 KB — gleicher Schwellenwert wie beim Backup

    updated = 0
    async with db.connection() as conn:
        cursor = await conn.execute(
            "SELECT id, name, backup_status FROM profiles",
        )
        profiles = await cursor.fetchall()

    for row in profiles:
        pid, name, current_status = row["id"], row["name"], row["backup_status"]
        profile_dir = BACKUP_DIR / name

        # TikTok Backup
        tt_dir = profile_dir / BACKUP_TIKTOK_SUBDIR
        if tt_dir.exists():
            tars = sorted(
                (p for p in tt_dir.glob("*.tar") if p.stat().st_size >= MIN_VALID_SIZE),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            if tars and current_status != "valid":
                best = tars[0]
                await update_profile_tiktok_backup(
                    pid, str(best), best.stat().st_size,
                )
                updated += 1

        # GMS Backup
        gms_dir = profile_dir / BACKUP_GMS_SUBDIR
        if gms_dir.exists():
            gms_tars = sorted(
                (p for p in gms_dir.glob("*.tar") if p.stat().st_size >= MIN_VALID_SIZE),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            if gms_tars:
                async with db.connection() as conn:
                    c = await conn.execute(
                        "SELECT gms_backup_status FROM profiles WHERE id = ?", (pid,),
                    )
                    r = await c.fetchone()
                if r and r["gms_backup_status"] != "valid":
                    best = gms_tars[0]
                    await update_profile_gms_backup(
                        pid, str(best), best.stat().st_size,
                    )
                    updated += 1

        # Accounts Backup
        acc_dir = profile_dir / BACKUP_ACCOUNTS_SUBDIR
        if acc_dir.exists():
            acc_tars = sorted(
                (p for p in acc_dir.glob("*.tar") if p.stat().st_size >= 1024),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            if acc_tars:
                async with db.connection() as conn:
                    c = await conn.execute(
                        "SELECT accounts_backup_status FROM profiles WHERE id = ?", (pid,),
                    )
                    r = await c.fetchone()
                if r and r["accounts_backup_status"] != "valid":
                    best = acc_tars[0]
                    await update_profile_accounts_backup(pid, str(best))
                    updated += 1

    if updated > 0:
        logger.info(
            "Backup-Sync: %d Profil(e) aus Dateisystem aktualisiert", updated,
        )
    return updated


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


# =============================================================================
# DNA Fingerprint — Automatische Identity-Erkennung via Bridge-Datei
# =============================================================================

# Die Bridge-Datei enthält die aktuell auf dem Gerät gespooften Werte
# im Key=Value Format. Diese Werte sind identisch mit dem, was die
# Verifier-App auf allen Ebenen (Java/Native/Root) sieht — die "DNA" des Geräts.
#
# Matching-Strategie (abgestuft):
#   1. serial + imei1 + android_id  → Exakt (3/3 Treffer)
#   2. serial + imei1               → Stark  (2/3 Treffer)
#   3. serial allein                → Mittel (1/3 Treffer)
#   4. imei1 allein                 → Schwach
#   5. android_id allein            → Schwach

# Bridge-Felder die für DNA-Matching genutzt werden:
_DNA_FIELDS = ("serial", "imei1", "android_id", "wifi_mac", "gsf_id")

_IDENTITY_SELECT_COLS = """
    id, name, serial, boot_serial, android_id, imei1, imei2, phone_number,
    operator_name, sim_operator, sim_operator_name, voicemail_number,
    wifi_mac, gsf_id, widevine_id, imsi, sim_serial,
    advertising_id, bluetooth_mac,
    build_id, build_fingerprint, security_patch,
    build_incremental, build_description,
    status, created_at, last_used_at,
    last_public_ip, last_ip_service, last_ip_at,
    last_audit_score, last_audit_at, total_audits, usage_count
"""


def parse_bridge_file(content: str) -> dict[str, str]:
    """
    Parst den Inhalt einer Bridge-Datei (Key=Value Format).

    Ignoriert Kommentare (#) und leere Zeilen.
    Keys werden lowercase normalisiert.
    """
    result: dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        result[key.strip().lower()] = value.strip()
    return result


async def detect_identity_by_dna(
    bridge_values: Optional[dict[str, str]] = None,
) -> Optional[dict]:
    """
    Erkennt die aktuell auf dem Gerät geladene Identität anhand der
    Bridge-Datei-Werte (= gespooften Hardware-DNA).

    Args:
        bridge_values: Geparstes dict aus der Bridge-Datei (Key→Value).
                       Relevante Keys: serial, imei1, android_id, wifi_mac, gsf_id.

    Matching-Logik (abgestuft nach Trefferanzahl):
      - 3+ Felder stimmen überein → 'exact'
      - 2 Felder                  → 'strong'
      - 1 Feld                    → 'partial'
      - 0 Felder                  → None (kein Treffer)

    Auto-Sync: Bei Treffer wird die Identity automatisch als 'active'
    markiert, falls sie es nicht schon ist.

    Returns:
        dict mit Identity-Daten + 'dna_confidence', 'dna_synced',
        'dna_matched_fields' Feldern, oder None.
    """
    if not bridge_values:
        return None

    # Relevante Felder aus der Bridge extrahieren
    b_serial = bridge_values.get("serial", "").strip()
    b_imei1 = bridge_values.get("imei1", "").strip()
    b_android_id = bridge_values.get("android_id", "").strip()
    b_wifi_mac = bridge_values.get("wifi_mac", "").strip()
    b_gsf_id = bridge_values.get("gsf_id", "").strip()

    if not any([b_serial, b_imei1, b_android_id]):
        logger.debug("DNA: Keine relevanten Bridge-Felder vorhanden")
        return None

    async with db.connection() as conn:
        # Alle nicht-retired Identitäten laden (in der Regel < 100 Zeilen)
        cursor = await conn.execute(
            f"SELECT {_IDENTITY_SELECT_COLS} FROM identities "
            "WHERE status != 'retired' ORDER BY last_used_at DESC"
        )
        rows = await cursor.fetchall()

        if not rows:
            return None

        # Scoring: Für jede Identity zählen wie viele Felder übereinstimmen
        best_match: Optional[dict] = None
        best_score: int = 0
        matched_fields: list[str] = []

        for row in rows:
            identity = dict(row)
            score = 0
            fields: list[str] = []

            if b_serial and identity.get("serial") == b_serial:
                score += 3  # Serial hat höchstes Gewicht
                fields.append("serial")
            if b_imei1 and identity.get("imei1") == b_imei1:
                score += 3  # IMEI ebenso hoch
                fields.append("imei1")
            if b_android_id and identity.get("android_id") == b_android_id:
                score += 2
                fields.append("android_id")
            if b_wifi_mac and identity.get("wifi_mac") == b_wifi_mac:
                score += 1
                fields.append("wifi_mac")
            if b_gsf_id and identity.get("gsf_id") == b_gsf_id:
                score += 1
                fields.append("gsf_id")

            if score > best_score:
                best_score = score
                best_match = identity
                matched_fields = fields

        if not best_match or best_score == 0:
            return None

        # Confidence-Level bestimmen
        n_fields = len(matched_fields)
        if n_fields >= 3 or best_score >= 7:
            confidence = "exact"
        elif n_fields >= 2 or best_score >= 4:
            confidence = "strong"
        else:
            confidence = "partial"

        # --- Auto-Sync: Identity + verknüpftes Profil als 'active' markieren ---
        dna_synced = False
        now = _now()

        if best_match["status"] != "active":
            async with db.transaction() as tx:
                # Alle anderen Identitäten deaktivieren
                await tx.execute(
                    "UPDATE identities SET status = 'ready', updated_at = ? "
                    "WHERE status = 'active'",
                    (now,),
                )
                # Erkannte Identity aktivieren
                await tx.execute(
                    "UPDATE identities SET status = 'active', "
                    "last_used_at = ?, updated_at = ? WHERE id = ?",
                    (now, now, best_match["id"]),
                )
            best_match["status"] = "active"
            dna_synced = True
            logger.info(
                "DNA-Match: Identity #%d '%s' automatisch aktiviert "
                "(confidence=%s, score=%d, fields=%s)",
                best_match["id"], best_match["name"],
                confidence, best_score, "+".join(matched_fields),
            )
        else:
            logger.debug(
                "DNA-Match: Identity #%d '%s' bereits aktiv "
                "(confidence=%s, fields=%s)",
                best_match["id"], best_match["name"],
                confidence, "+".join(matched_fields),
            )

        # --- Auto-Sync: Verknüpftes Profil ebenfalls auf 'active' setzen ---
        # Wenn ein DNA-Match besteht (partial+), muss das Profil im Vault
        # automatisch als 'active' angezeigt werden.
        async with db.transaction() as tx:
            # Alle Profile die aktuell 'active' sind aber NICHT zu dieser
            # Identity gehören → zurück auf 'cooldown'
            # WICHTIG: profiles erlaubt NICHT 'ready' — nur identities!
            # Gültige profile-Status: warmup, active, cooldown, banned, suspended, archived
            await tx.execute(
                "UPDATE profiles SET status = 'cooldown', updated_at = ? "
                "WHERE status = 'active' AND identity_id != ?",
                (now, best_match["id"]),
            )
            # Profil(e) dieser Identity auf 'active' setzen
            # (nur wenn noch nicht active und nicht archived/banned)
            cursor = await tx.execute(
                "UPDATE profiles SET status = 'active', updated_at = ? "
                "WHERE identity_id = ? AND status NOT IN ('active', 'archived', 'banned')",
                (now, best_match["id"]),
            )
            if cursor.rowcount and cursor.rowcount > 0:
                dna_synced = True
                logger.info(
                    "DNA-Sync: %d Profil(e) für Identity #%d auf 'active' gesetzt",
                    cursor.rowcount, best_match["id"],
                )

        best_match["dna_confidence"] = confidence
        best_match["dna_synced"] = dna_synced
        best_match["dna_matched_fields"] = matched_fields
        best_match["dna_score"] = best_score
        return best_match


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


# =============================================================================
# v6.2: TikTok install_id Operationen
# =============================================================================

async def save_tiktok_install_id(
    profile_id: int,
    install_id: str,
) -> None:
    """
    Speichert die TikTok install_id für ein Profil.

    Args:
        profile_id: Profil-DB-ID
        install_id: UUID-String der install_id
    """
    async with db.transaction() as conn:
        await conn.execute(
            "UPDATE profiles SET tiktok_install_id = ?, updated_at = ? WHERE id = ?",
            (install_id, _now(), profile_id),
        )
    logger.info(
        "TikTok install_id gespeichert: Profil #%d → %s…%s",
        profile_id, install_id[:8], install_id[-4:],
    )


async def check_install_id_collision(
    install_id: str,
    exclude_profile_id: Optional[int] = None,
) -> dict:
    """
    Prüft ob eine install_id bereits in der DB existiert (Collision-Detection).

    Args:
        install_id:         Die zu prüfende install_id
        exclude_profile_id: Eigenes Profil ausschließen (bei Re-Check)

    Returns:
        {
            "collision": bool,
            "existing_profile_id": int | None,
            "existing_profile_name": str | None,
            "message": str
        }
    """
    async with db.connection() as conn:
        if exclude_profile_id:
            cursor = await conn.execute(
                "SELECT id, name FROM profiles "
                "WHERE tiktok_install_id = ? AND id != ? LIMIT 1",
                (install_id, exclude_profile_id),
            )
        else:
            cursor = await conn.execute(
                "SELECT id, name FROM profiles "
                "WHERE tiktok_install_id = ? LIMIT 1",
                (install_id,),
            )
        row = await cursor.fetchone()

    if row:
        return {
            "collision": True,
            "existing_profile_id": row["id"],
            "existing_profile_name": row["name"],
            "message": (
                f"install_id Collision! '{install_id[:8]}…' gehört bereits "
                f"zu Profil '{row['name']}' (#{row['id']})"
            ),
        }

    return {
        "collision": False,
        "existing_profile_id": None,
        "existing_profile_name": None,
        "message": "install_id ist unique",
    }


# =============================================================================
# Profile Logs — Live Monitor + HookGuard Snapshots
# =============================================================================

async def capture_profile_log(
    profile_id: int,
    identity_id: Optional[int],
    trigger: str,
    live_summary: Optional[dict] = None,
    hookguard_state: Optional[dict] = None,
    kill_events: Optional[list] = None,
) -> int:
    """
    Speichert einen Snapshot der Live-Monitor- und HookGuard-Daten
    für ein bestimmtes Profil.

    Args:
        profile_id:     Profil-ID
        identity_id:    Identity-ID
        trigger:        Auslöser ('genesis_end', 'switch_in', 'switch_out', 'manual', 'periodic')
        live_summary:   Parsed .titan_access_summary.json (Dict mit 'apis', 'hooks', etc.)
        hookguard_state: HookState als Dict (dataclasses.asdict)
        kill_events:    Liste von Kill-Switch Events

    Returns:
        ID des erstellten Log-Eintrags
    """
    live_api_count = 0
    live_spoofed_pct = None
    if live_summary:
        apis = live_summary.get("apis", {})
        live_api_count = len(apis)
        if live_api_count > 0:
            spoofed = sum(1 for a in apis.values() if a.get("spoofed"))
            live_spoofed_pct = round(spoofed / live_api_count * 100, 1)

    hook_count = None
    bridge_intact = None
    heartbeat_ok = None
    leaks = 0
    if hookguard_state:
        nh = hookguard_state.get("native_hooks", 0)
        ah = hookguard_state.get("art_hooks", 0)
        en = hookguard_state.get("expected_native", 13)
        ea = hookguard_state.get("expected_art", 8)
        hook_count = f"{nh}+{ah}/{en}+{ea}"
        bridge_intact = 1 if hookguard_state.get("bridge_intact") else 0
        heartbeat_ok = 1 if hookguard_state.get("guard_loaded") and hookguard_state.get("heartbeat_counter", 0) > 0 else 0
        leaks = 0 if hookguard_state.get("lsplant_ok") and hookguard_state.get("bridge_loaded") else 1

    kill_count = len(kill_events) if kill_events else 0

    now = _now()
    async with db.connection() as conn:
        cursor = await conn.execute(
            """INSERT INTO profile_logs (
                profile_id, identity_id, trigger,
                live_summary_json, live_api_count, live_spoofed_pct,
                hookguard_json, hook_count, bridge_intact, heartbeat_ok, leaks_detected,
                kill_events_json, kill_event_count,
                captured_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                profile_id, identity_id, trigger,
                json.dumps(live_summary) if live_summary else None,
                live_api_count, live_spoofed_pct,
                json.dumps(hookguard_state) if hookguard_state else None,
                hook_count, bridge_intact, heartbeat_ok, leaks,
                json.dumps(kill_events) if kill_events else None,
                kill_count,
                now,
            ),
        )
        await conn.commit()
        log_id = cursor.lastrowid
        logger.info(
            "Profile log captured: profile=%d trigger=%s apis=%d spoofed=%.1f%% hooks=%s leaks=%d kills=%d",
            profile_id, trigger, live_api_count,
            live_spoofed_pct or 0, hook_count or "?", leaks, kill_count,
        )
        return log_id


async def get_profile_logs(profile_id: int, limit: int = 20) -> list[dict]:
    """Gibt alle Log-Snapshots für ein Profil zurück (neueste zuerst)."""
    async with db.connection() as conn:
        cursor = await conn.execute(
            """SELECT id, profile_id, identity_id, trigger,
                      live_summary_json, live_api_count, live_spoofed_pct,
                      hookguard_json, hook_count, bridge_intact, heartbeat_ok, leaks_detected,
                      kill_events_json, kill_event_count,
                      captured_at
               FROM profile_logs
               WHERE profile_id = ?
               ORDER BY captured_at DESC
               LIMIT ?""",
            (profile_id, limit),
        )
        return [dict(r) for r in await cursor.fetchall()]
