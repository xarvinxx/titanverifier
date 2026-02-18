"""
Dashboard API ("The Monitor") v2.0
====================================

Live-Daten, Echtzeit-Logs und History-Endpoints.

Endpoints:
  GET  /api/dashboard/stats       — Device-Info, ADB-Status, erweiterte DB-Stats
  GET  /api/dashboard/identities  — Alle Identitäten (mit IP/Audit Tracking)
  GET  /api/dashboard/profiles    — Alle Profile
  GET  /api/dashboard/flow-history — Flow-History (letzte 50)
  GET  /api/dashboard/ip-history  — IP-History (letzte 50)
  GET  /api/dashboard/audit-history — Audit-History (letzte 50)
  GET  /api/dashboard/farm-stats  — Aggregierte Farm-Statistiken
  WS   /ws/logs                   — Echtzeit Log-Stream via WebSocket
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections import deque
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect

from host.adb.client import ADBClient, ADBError
from host.config import LOCAL_TZ
from host.database import db
from host.config import BRIDGE_FILE_PATH
from host.engine.db_ops import (
    detect_identity_by_dna,
    get_audit_history,
    get_flow_history,
    get_ip_history,
    parse_bridge_file,
)

logger = logging.getLogger("host.api.dashboard")


# =============================================================================
# ADB Stats Cache — Verhindert ADB-Spam wenn kein Flow läuft
# =============================================================================
# Bei jedem Poll (~3s) werden sonst 6-7 ADB-Befehle gefeuert.
# Cache hält die Ergebnisse für IDLE_CACHE_TTL Sekunden, solange
# kein Flow aktiv ist. Während eines Flows wird NICHT gecacht.
# =============================================================================

_IDLE_CACHE_TTL = 30  # Sekunden — ADB-Daten cachen wenn kein Flow läuft

_adb_cache: dict = {
    "data": None,          # Gecachte ADB-Ergebnisse
    "timestamp": 0.0,      # Wann zuletzt gefetcht
    "bridge_values": {},   # Gecachte Bridge-Werte
}


def _is_flow_running() -> bool:
    """Prüft ob gerade ein Flow läuft (Zugriff auf den Flow-Controller)."""
    try:
        from host.api.control import _state
        return _state.running
    except (ImportError, AttributeError):
        return False


def _cache_valid() -> bool:
    """Prüft ob der ADB-Cache noch gültig ist."""
    import time
    if _adb_cache["data"] is None:
        return False
    if _is_flow_running():
        return False  # Während Flow: immer frisch fetchen
    age = time.time() - _adb_cache["timestamp"]
    return age < _IDLE_CACHE_TTL

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


# =============================================================================
# WebSocket Log-Handler (fängt Host-Logs ab und broadcastet sie)
# =============================================================================

class WebSocketLogHandler(logging.Handler):
    """
    Custom Log-Handler der Nachrichten in einen Ring-Buffer schreibt
    und alle verbundenen WebSocket-Clients benachrichtigt.
    """

    def __init__(self, buffer_size: int = 500):
        super().__init__()
        self.buffer: deque[dict] = deque(maxlen=buffer_size)
        self.clients: set[WebSocket] = set()
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def emit(self, record: logging.LogRecord) -> None:
        entry = {
            "ts": datetime.fromtimestamp(record.created, tz=LOCAL_TZ).strftime("%H:%M:%S"),
            "level": record.levelname,
            "name": record.name,
            "msg": self.format(record),
        }
        self.buffer.append(entry)

        # Async broadcast an alle Clients
        if self.clients:
            if self._loop is None or self._loop.is_closed():
                try:
                    self._loop = asyncio.get_running_loop()
                except RuntimeError:
                    return
            self._loop.create_task(self._broadcast(entry))

    async def _broadcast(self, entry: dict) -> None:
        dead: set[WebSocket] = set()
        msg = json.dumps(entry, ensure_ascii=False)
        for ws in self.clients:
            try:
                await ws.send_text(msg)
            except Exception:
                dead.add(ws)
        self.clients -= dead

    def get_history(self) -> list[dict]:
        """Gibt den gesamten Buffer als Liste zurück."""
        return list(self.buffer)


# Globale Instanz — wird in main.py an den Logger gehängt
ws_log_handler = WebSocketLogHandler(buffer_size=500)
ws_log_handler.setFormatter(logging.Formatter("%(message)s"))
ws_log_handler.setLevel(logging.INFO)


# =============================================================================
# WebSocket /ws/logs
# =============================================================================

async def websocket_logs(ws: WebSocket) -> None:
    """
    Echtzeit Log-Stream via WebSocket.

    Bei Verbindung: Sendet den kompletten Log-Buffer (History).
    Danach: Jede neue Log-Nachricht wird sofort gepusht.
    """
    await ws.accept()
    logger.info("WebSocket Client verbunden: %s", ws.client)

    # Sende History
    for entry in ws_log_handler.get_history():
        try:
            await ws.send_text(json.dumps(entry, ensure_ascii=False))
        except Exception:
            return

    # Registriere Client für Live-Updates
    ws_log_handler.clients.add(ws)

    try:
        # Halte die Verbindung offen (Client kann Ping/Pong senden)
        while True:
            # Warte auf Nachrichten vom Client (keep-alive)
            data = await ws.receive_text()
            # Client kann "ping" senden
            if data == "ping":
                await ws.send_text(json.dumps({"type": "pong"}))
    except WebSocketDisconnect:
        logger.info("WebSocket Client getrennt: %s", ws.client)
    except Exception as e:
        logger.debug("WebSocket Fehler: %s", e)
    finally:
        ws_log_handler.clients.discard(ws)


# =============================================================================
# GET /api/dashboard/stats (Erweitert)
# =============================================================================

@router.get("/stats")
async def dashboard_stats():
    """
    Liefert den aktuellen Systemstatus für das Dashboard.

    v5.0 ANTI-SPAM:
      - ADB-Daten (Serial, Bridge, Root, interne IP) werden für 30s gecacht
        wenn KEIN Flow läuft. Bei laufendem Flow: immer frisch.
      - Public IP wird NICHT mehr gepollt! Die letzte bekannte IP kommt
        aus der DB (identities.last_public_ip). Frische IP-Checks passieren
        NUR innerhalb der Flows (Genesis/Switch).
      - Das reduziert ADB-Befehle von ~7 pro Poll auf 1 (is_connected).
    """
    import time as _time

    flow_active = _is_flow_running()

    # ── Cache Check: Wenn idle + Cache gültig → sofort zurückgeben ──
    if _cache_valid():
        cached = _adb_cache["data"]
        # Nur DB-Counts + active_identity frisch holen (kein ADB nötig)
        await _refresh_db_stats(cached, _adb_cache["bridge_values"])
        cached["flow_active"] = flow_active
        return cached

    # ── Frische ADB-Daten holen ──
    adb = ADBClient()
    stats: dict = {
        "adb_connected": False,
        "device_serial": None,
        "device_ip": None,
        "public_ip": None,
        "public_ip_service": None,
        "root_access": False,
        "active_identity": None,
        "dna_match": None,
        "dna_synced": False,
        "dna_matched_fields": [],
        "bridge_loaded": False,
        "bridge_values": {},
        "flow_active": flow_active,
        "counts": {
            "identities": 0,
            "profiles": 0,
            "flows_total": 0,
            "flows_success": 0,
            "unique_ips": 0,
        },
    }

    bridge_values: dict[str, str] = {}
    try:
        # 1 ADB-Befehl: Verbindungscheck (leichtgewichtig)
        stats["adb_connected"] = await adb.is_connected()

        if stats["adb_connected"]:
            # Serial vom Gerät (1 Befehl)
            result = await adb.shell("getprop ro.serialno", timeout=5)
            if result.success:
                stats["device_serial"] = result.output.strip()

            # Bridge-Datei lesen (1 Befehl mit root)
            try:
                result = await adb.shell(
                    f"cat {BRIDGE_FILE_PATH}", root=True, timeout=5,
                )
                if result.success and result.output.strip():
                    bridge_values = parse_bridge_file(result.output)
                    stats["bridge_loaded"] = bool(bridge_values)
                    stats["bridge_values"] = {
                        k: bridge_values.get(k, "")
                        for k in ("serial", "imei1", "android_id",
                                  "wifi_mac", "gsf_id", "phone_number",
                                  "operator_name")
                        if bridge_values.get(k)
                    }
            except Exception as e:
                logger.debug("Bridge-Datei nicht lesbar: %s", e)

            # Root-Check (1 Befehl)
            stats["root_access"] = await adb.has_root()

            # Interne IP: NUR wenn Flow aktiv (sonst unnötig)
            if flow_active:
                try:
                    result = await adb.shell(
                        "ip -4 route get 1.1.1.1 2>/dev/null | head -1",
                        timeout=5,
                    )
                    if result.success and "src " in result.stdout:
                        src_part = result.stdout.split("src ")[1]
                        ip_candidate = src_part.split()[0].strip()
                        if ip_candidate and ip_candidate != "127.0.0.1":
                            stats["device_ip"] = ip_candidate
                except (ADBError, Exception):
                    pass

            # ═══════════════════════════════════════════════════════════
            # PUBLIC IP: NICHT MEHR VIA ADB GEPOLLT!
            # ═══════════════════════════════════════════════════════════
            # Die öffentliche IP wird NUR innerhalb der Flows ermittelt
            # (Genesis Schritt 6, nach dem Flugmodus-Cycle).
            # Hier zeigen wir die letzte bekannte IP aus der DB.
            # Das spart ~1 ADB-Befehl + 1 HTTP-Request pro Poll.
            # ═══════════════════════════════════════════════════════════

    except (ADBError, Exception) as e:
        logger.debug("ADB Stats Fehler: %s", e)

    # ── DB Stats + DNA Matching ──
    await _refresh_db_stats(stats, bridge_values)

    # ── Cache aktualisieren (nur im Idle-Modus) ──
    if not flow_active:
        _adb_cache["data"] = stats.copy()
        _adb_cache["timestamp"] = _time.time()
        _adb_cache["bridge_values"] = bridge_values

    return stats


async def _refresh_db_stats(
    stats: dict,
    bridge_values: dict[str, str],
) -> None:
    """
    Holt DB-Counts, DNS-Match und die letzte bekannte Public IP.
    Wird sowohl frisch als auch für Cache-Refreshes aufgerufen.
    """
    try:
        async with db.connection() as conn:
            cursor = await conn.execute("SELECT COUNT(*) FROM identities")
            stats["counts"]["identities"] = (await cursor.fetchone())[0]

            cursor = await conn.execute("SELECT COUNT(*) FROM profiles")
            stats["counts"]["profiles"] = (await cursor.fetchone())[0]

            cursor = await conn.execute("SELECT COUNT(*) FROM flow_history")
            stats["counts"]["flows_total"] = (await cursor.fetchone())[0]

            cursor = await conn.execute(
                "SELECT COUNT(*) FROM flow_history WHERE status = 'success'"
            )
            stats["counts"]["flows_success"] = (await cursor.fetchone())[0]

            cursor = await conn.execute(
                "SELECT COUNT(DISTINCT public_ip) FROM ip_history"
            )
            stats["counts"]["unique_ips"] = (await cursor.fetchone())[0]

            # ── DNA-Fingerprint: Identity-Erkennung via Bridge ──
            if bridge_values:
                dna_result = await detect_identity_by_dna(
                    bridge_values=bridge_values,
                )
                if dna_result:
                    stats["active_identity"] = dna_result
                    stats["dna_match"] = dna_result.pop("dna_confidence", None)
                    stats["dna_synced"] = dna_result.pop("dna_synced", False)
                    stats["dna_matched_fields"] = dna_result.pop("dna_matched_fields", [])
                    dna_result.pop("dna_score", None)

            # Fallback: DB-Status wenn kein Bridge-Match
            if not stats["active_identity"]:
                cursor = await conn.execute(
                    """SELECT id, name, serial, android_id, imei1, imei2,
                       phone_number, operator_name, sim_operator,
                       wifi_mac, gsf_id, widevine_id,
                       status, created_at, last_used_at,
                       last_public_ip, last_ip_service, last_ip_at,
                       last_audit_score, last_audit_at, total_audits, usage_count
                    FROM identities WHERE status = 'active' LIMIT 1"""
                )
                row = await cursor.fetchone()
                if row:
                    stats["active_identity"] = dict(row)
                    stats["dna_match"] = "db_only"

            # ── Public IP aus der DB (letzte bekannte) ──
            # Kein ADB-Call nötig! Die IP wurde beim letzten Flow gespeichert.
            if stats["active_identity"] and not stats["public_ip"]:
                ip = stats["active_identity"].get("last_public_ip")
                svc = stats["active_identity"].get("last_ip_service")
                if ip:
                    stats["public_ip"] = ip
                    stats["public_ip_service"] = svc

    except Exception as e:
        logger.debug("DB Stats Fehler: %s", e)


# =============================================================================
# GET /api/dashboard/identities (Erweitert)
# =============================================================================

@router.get("/identities")
async def list_identities():
    """Alle Identitäten aus dem Vault mit IP/Audit-Tracking + Profil-Status."""
    try:
        async with db.connection() as conn:
            cursor = await conn.execute(
                """SELECT
                       i.id, i.name, i.serial, i.boot_serial,
                       i.imei1, i.imei2, i.android_id, i.gsf_id,
                       i.wifi_mac, i.widevine_id,
                       i.imsi, i.sim_serial,
                       i.phone_number, i.operator_name,
                       i.sim_operator, i.sim_operator_name, i.voicemail_number,
                       i.build_id, i.build_fingerprint, i.security_patch,
                       i.status, i.created_at, i.last_used_at,
                       i.last_public_ip, i.last_ip_service, i.last_ip_at,
                       i.last_audit_score, i.last_audit_at, i.total_audits, i.usage_count,
                       p.id          AS profile_id,
                       p.status      AS profile_status,
                       p.name        AS profile_name,
                       p.backup_status,
                       p.backup_created_at,
                       p.gms_backup_status,
                       p.gms_backup_at,
                       p.accounts_backup_status,
                       p.accounts_backup_at
                   FROM identities i
                   INNER JOIN profiles p ON p.identity_id = i.id
                       AND p.status != 'archived'
                   ORDER BY i.id DESC"""
            )
            rows = await cursor.fetchall()

            # Deduplizieren: Falls mehrere Profile pro Identity existieren,
            # bevorzuge das aktive Profil (oder das erste nicht-archivierte)
            seen: dict[int, dict] = {}
            for row in rows:
                r = dict(row)
                iid = r["id"]
                if iid not in seen:
                    seen[iid] = r
                elif r.get("profile_status") == "active":
                    seen[iid] = r

            return {"identities": list(seen.values())}
    except Exception as e:
        return {"identities": [], "error": str(e)}


# =============================================================================
# FIX-27: GET /api/dashboard/profiles ENTFERNT (redundant mit /api/vault)
# =============================================================================

# =============================================================================
# GET /api/dashboard/flow-history — Flow-Verlauf
# =============================================================================

@router.get("/flow-history")
async def flow_history(
    limit: int = Query(default=50, ge=1, le=200),
    flow_type: Optional[str] = Query(default=None),
):
    """Liefert die letzten Flow-History Einträge."""
    try:
        rows = await get_flow_history(limit=limit, flow_type=flow_type)
        return {"flows": rows, "count": len(rows)}
    except Exception as e:
        logger.error("Flow-History Fehler: %s", e)
        return {"flows": [], "error": str(e)}


# =============================================================================
# GET /api/dashboard/ip-history — IP-Verlauf
# =============================================================================

@router.get("/ip-history")
async def ip_history(
    limit: int = Query(default=50, ge=1, le=200),
    identity_id: Optional[int] = Query(default=None),
):
    """Liefert die letzten IP-History Einträge."""
    try:
        rows = await get_ip_history(identity_id=identity_id, limit=limit)
        return {"ips": rows, "count": len(rows)}
    except Exception as e:
        logger.error("IP-History Fehler: %s", e)
        return {"ips": [], "error": str(e)}


# =============================================================================
# GET /api/dashboard/audit-history — Audit-Verlauf
# =============================================================================

@router.get("/audit-history")
async def audit_history(
    limit: int = Query(default=50, ge=1, le=200),
    identity_id: Optional[int] = Query(default=None),
):
    """Liefert die letzten Audit-History Einträge."""
    try:
        rows = await get_audit_history(identity_id=identity_id, limit=limit)
        return {"audits": rows, "count": len(rows)}
    except Exception as e:
        logger.error("Audit-History Fehler: %s", e)
        return {"audits": [], "error": str(e)}


# =============================================================================
# FIX-27: GET /api/dashboard/farm-stats ENTFERNT (redundant mit /stats)
# =============================================================================


# ── HookGuard Endpoints ─────────────────────────────────────────

def _get_hookguard():
    """Get the global HookGuard instance (lazy init)."""
    import host.main as _main
    return getattr(_main, "_hookguard", None)


@router.get("/hookguard")
async def hookguard_status():
    """Current HookGuard state including hook status, kill history, etc."""
    from host.engine.hookguard import HookGuard
    guard = _get_hookguard()
    if not guard:
        return {"status": "unavailable", "message": "HookGuard not initialized"}
    import dataclasses
    state_dict = dataclasses.asdict(guard.state)
    state_dict["status"] = guard.state.status.value
    state_dict["is_running"] = guard.is_running
    return state_dict


@router.post("/hookguard/toggle")
async def hookguard_toggle():
    """Start or stop the HookGuard monitor."""
    guard = _get_hookguard()
    if not guard:
        return {"error": "HookGuard not initialized"}
    if guard.is_running:
        await guard.stop()
        return {"status": "stopped"}
    else:
        await guard.start()
        return {"status": "started"}


@router.post("/hookguard/reactivate")
async def hookguard_reactivate():
    """After kill-switch: re-enable TikTok, disable airplane mode."""
    guard = _get_hookguard()
    if not guard:
        return {"error": "HookGuard not initialized"}
    await guard.reactivate()
    return {"status": "reactivated"}
