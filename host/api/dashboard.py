"""
Project Titan — Dashboard API ("The Monitor") v2.0
====================================================

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
from host.engine.db_ops import (
    get_audit_history,
    get_dashboard_stats,
    get_flow_history,
    get_ip_history,
)

logger = logging.getLogger("titan.api.dashboard")

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


# =============================================================================
# WebSocket Log-Handler (fängt Titan-Logs ab und broadcastet sie)
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

    Returns:
        adb_connected: bool
        device_serial: str (aktuell auf dem Gerät)
        device_ip: str (WiFi IP)
        active_identity: dict (aktuell aktive Identität aus DB)
        counts: dict (Identitäten, Profile, Flows, IPs)
    """
    adb = ADBClient()
    stats: dict = {
        "adb_connected": False,
        "device_serial": None,
        "device_ip": None,
        "root_access": False,
        "active_identity": None,
        "counts": {
            "identities": 0,
            "profiles": 0,
            "flows_total": 0,
            "flows_success": 0,
            "unique_ips": 0,
        },
    }

    # --- ADB Status ---
    try:
        stats["adb_connected"] = await adb.is_connected()

        if stats["adb_connected"]:
            # Serial vom Gerät lesen
            result = await adb.shell("getprop ro.serialno", timeout=5)
            if result.success:
                stats["device_serial"] = result.output.strip()

            # Mobilfunk-IP (rmnet) oder WiFi-IP (wlan0)
            for iface in ("rmnet_data0", "rmnet0", "wlan0"):
                try:
                    result = await adb.shell(
                        f"ip -4 addr show {iface} 2>/dev/null",
                        timeout=3,
                    )
                    if result.success and "inet " in result.stdout:
                        for line in result.stdout.split("\n"):
                            line = line.strip()
                            if line.startswith("inet "):
                                ip = line.split()[1].split("/")[0]
                                stats["device_ip"] = ip
                                break
                    if stats["device_ip"]:
                        break
                except ADBError:
                    continue

            # Root-Check
            stats["root_access"] = await adb.has_root()

    except (ADBError, Exception) as e:
        logger.debug("ADB Stats Fehler: %s", e)

    # --- DB Counts (erweitert) ---
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

            # Aktive Identität (erweitert mit IP/Audit)
            cursor = await conn.execute(
                """SELECT id, name, serial, imei1, phone_number, operator_name,
                   sim_operator, wifi_mac, status, created_at, last_used_at,
                   last_public_ip, last_ip_service, last_ip_at,
                   last_audit_score, last_audit_at, total_audits, usage_count
                FROM identities WHERE status = 'active' LIMIT 1"""
            )
            row = await cursor.fetchone()
            if row:
                stats["active_identity"] = dict(row)

    except Exception as e:
        logger.debug("DB Stats Fehler: %s", e)

    return stats


# =============================================================================
# GET /api/dashboard/identities (Erweitert)
# =============================================================================

@router.get("/identities")
async def list_identities():
    """Alle Identitäten aus dem Vault mit IP/Audit-Tracking."""
    try:
        async with db.connection() as conn:
            cursor = await conn.execute(
                """SELECT id, name, serial, imei1, phone_number, wifi_mac,
                   operator_name, sim_operator, status, build_id,
                   created_at, last_used_at,
                   last_public_ip, last_ip_service, last_ip_at,
                   last_audit_score, last_audit_at, total_audits, usage_count
                FROM identities ORDER BY id DESC"""
            )
            rows = await cursor.fetchall()
            return {"identities": [dict(r) for r in rows]}
    except Exception as e:
        return {"identities": [], "error": str(e)}


# =============================================================================
# GET /api/dashboard/profiles
# =============================================================================

@router.get("/profiles")
async def list_profiles():
    """Alle Profile mit verknüpfter Identität."""
    try:
        async with db.connection() as conn:
            cursor = await conn.execute(
                """SELECT p.*, i.name as identity_name, i.serial as identity_serial,
                   i.last_public_ip as identity_last_ip
                FROM profiles p
                LEFT JOIN identities i ON p.identity_id = i.id
                ORDER BY p.id DESC"""
            )
            rows = await cursor.fetchall()
            return {"profiles": [dict(r) for r in rows]}
    except Exception as e:
        return {"profiles": [], "error": str(e)}


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
# GET /api/dashboard/farm-stats — Aggregierte Farm-Statistiken
# =============================================================================

@router.get("/farm-stats")
async def farm_stats():
    """
    Liefert aggregierte Statistiken für die gesamte Farm.

    Beinhaltet:
      - Identitäten: Total, Active, Corrupted
      - Profile: Total, Active, Banned, Backed-up
      - Flows: Total, Success, Failed, Success-Rate
      - Netzwerk: Unique IPs
      - Audits: Durchschnitts-Score
    """
    try:
        stats = await get_dashboard_stats()
        return stats
    except Exception as e:
        logger.error("Farm-Stats Fehler: %s", e)
        return {"error": str(e)}
