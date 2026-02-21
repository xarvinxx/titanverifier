"""
Supabase Cloud-Sync Engine v1.0
================================

Synchronisiert lokale SQLite-Daten mit Supabase PostgreSQL.
Die lokale DB bleibt die Single Source of Truth — Supabase ist
ein Online-Spiegel zum Einsehen von überall.

Sync-Strategie: Push-after-Write
  → Nach jedem Genesis/Switch/Backup wird der betroffene Datensatz
    an Supabase gepusht (upsert). Kein Polling, kein Cron.

Verwendet die Supabase REST API (PostgREST) via httpx.
Keine zusätzlichen Dependencies nötig.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any, Optional

import httpx

from host.config import SUPABASE_KEY, SUPABASE_URL

logger = logging.getLogger("host.supabase")

_client: Optional[httpx.AsyncClient] = None


def is_enabled() -> bool:
    return bool(SUPABASE_URL and SUPABASE_KEY)


def _get_client() -> httpx.AsyncClient:
    global _client
    if _client is None or _client.is_closed:
        _client = httpx.AsyncClient(
            base_url=SUPABASE_URL,
            headers={
                "apikey": SUPABASE_KEY,
                "Authorization": f"Bearer {SUPABASE_KEY}",
                "Content-Type": "application/json",
                "Prefer": "resolution=merge-duplicates",
            },
            timeout=15.0,
        )
    return _client


async def _upsert(table: str, data: dict[str, Any]) -> bool:
    """Upsert (INSERT ... ON CONFLICT UPDATE) via PostgREST."""
    if not is_enabled():
        return False

    clean = {k: v for k, v in data.items() if v is not None}
    try:
        resp = await _get_client().post(
            f"/rest/v1/{table}",
            json=clean,
        )
        if resp.status_code in (200, 201):
            logger.debug("Supabase upsert %s OK", table)
            return True
        else:
            logger.warning(
                "Supabase upsert %s: %d — %s",
                table, resp.status_code, resp.text[:200],
            )
            return False
    except Exception as e:
        logger.warning("Supabase upsert %s fehlgeschlagen: %s", table, e)
        return False


async def _upsert_batch(table: str, rows: list[dict[str, Any]]) -> bool:
    if not is_enabled() or not rows:
        return False
    all_keys = set()
    for r in rows:
        all_keys.update(r.keys())
    uniform_rows = [{k: r.get(k) for k in all_keys} for r in rows]
    try:
        resp = await _get_client().post(
            f"/rest/v1/{table}",
            json=uniform_rows,
        )
        if resp.status_code in (200, 201):
            logger.debug("Supabase batch upsert %s: %d rows", table, len(rows))
            return True
        else:
            logger.warning(
                "Supabase batch %s: %d — %s",
                table, resp.status_code, resp.text[:200],
            )
            return False
    except Exception as e:
        logger.warning("Supabase batch %s fehlgeschlagen: %s", table, e)
        return False


# =========================================================================
# High-Level Sync Funktionen
# =========================================================================

async def sync_identity(identity: dict) -> bool:
    """Synchronisiert eine Identität nach Supabase."""
    return await _upsert("identities", identity)


async def sync_profile(profile: dict) -> bool:
    """Synchronisiert ein Profil nach Supabase."""
    return await _upsert("profiles", profile)


async def sync_flow_history(flow: dict) -> bool:
    """Synchronisiert einen Flow-History Eintrag."""
    return await _upsert("flow_history", flow)


async def sync_profile_log(log_entry: dict) -> bool:
    """Synchronisiert einen Profile-Log Eintrag."""
    return await _upsert("profile_logs", log_entry)


async def sync_ip_history(ip_entry: dict) -> bool:
    """Synchronisiert einen IP-History Eintrag."""
    return await _upsert("ip_history", ip_entry)


async def sync_audit(audit: dict) -> bool:
    """Synchronisiert ein Audit-Ergebnis."""
    return await _upsert("audit_history", audit)


async def full_sync_from_sqlite(db_conn) -> dict:
    """
    Vollständiger Sync: Liest alle Daten aus SQLite und pusht sie an Supabase.
    Nützlich für den initialen Sync oder nach manuellem DB-Edit.

    Returns:
        {"identities": n, "profiles": n, "flow_history": n, ...}
    """
    if not is_enabled():
        return {"error": "Supabase nicht konfiguriert"}

    stats = {}

    for table in ["identities", "profiles", "flow_history",
                   "ip_history", "audit_history", "profile_logs"]:
        try:
            cursor = await db_conn.execute(f"SELECT * FROM {table}")
            rows = await cursor.fetchall()
            dicts = [dict(r) for r in rows]

            if dicts:
                ok = await _upsert_batch(table, dicts)
                stats[table] = len(dicts) if ok else f"FAILED ({len(dicts)} rows)"
            else:
                stats[table] = 0
        except Exception as e:
            stats[table] = f"ERROR: {e}"
            logger.warning("Full-Sync %s fehlgeschlagen: %s", table, e)

    logger.info("Full-Sync abgeschlossen: %s", stats)
    return stats


async def close():
    """Schliesst den HTTP-Client."""
    global _client
    if _client and not _client.is_closed:
        await _client.aclose()
        _client = None
