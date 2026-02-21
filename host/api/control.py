"""
Control API ("The Trigger") v2.0
==================================

REST-Endpoints zum Starten und Überwachen der Orchestrator-Flows.

Endpoints:
  POST /api/control/genesis          — Startet GenesisFlow als BackgroundTask
  POST /api/control/switch/{id}      — Startet SwitchFlow als BackgroundTask (Full-State!)
  POST /api/control/backup           — Full-State Backup (GMS + TikTok + Account-DBs)
  GET  /api/control/status           — Gibt aktuellen Flow-Status zurück
  POST /api/control/abort            — Setzt den Flow-Lock zurück (Emergency)

DB-Tracking (v2.0):
  - Backup-Flow: Aktualisiert profiles-Tabelle mit Backup-Status/Pfad/Size
  - Flow-History: Backup-Flow wird in flow_history protokolliert
"""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime

from host.config import LOCAL_TZ
from typing import Any, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel, Field

from host.config import create_adb_client
from host.engine.db_ops import (
    check_genesis_frequency,
    create_flow_history,
    find_profile_by_name,
    update_flow_history,
    update_profile_accounts_backup,
    update_profile_gms_backup,
    update_profile_tiktok_backup,
)
from host.engine.shifter import AppShifter
from host.flows.genesis import GenesisFlow, GenesisResult
from host.flows.switch import SwitchFlow, SwitchResult

logger = logging.getLogger("host.api.control")

router = APIRouter(prefix="/api/control", tags=["Control"])


# =============================================================================
# Flow State (Singleton — Global Lock + Ergebnis-Cache)
# =============================================================================

@dataclass
class FlowState:
    """Globaler State für den aktuell laufenden Flow."""
    running: bool = False
    flow_type: str = ""           # "genesis" | "switch" | "backup" | ""
    flow_name: str = ""           # Name/Label des Flows
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    result: Optional[dict] = None  # Letztes Ergebnis als dict
    error: Optional[str] = None


_state = FlowState()
_lock = asyncio.Lock()


# =============================================================================
# Request Models
# =============================================================================

class GenesisRequest(BaseModel):
    """Request-Body für den Genesis-Flow."""
    name: str = Field(
        ..., min_length=1, max_length=64,
        description="Anzeigename für die neue Identität",
        json_schema_extra={"example": "DE_Berlin_001"},
    )
    notes: Optional[str] = Field(
        default=None, max_length=500,
        description="Optionale Notizen",
    )
    backup_before: bool = Field(
        default=False,
        description="Aktives Profil vor Genesis automatisch sichern (Dual-Path Backup)",
    )


class SwitchRequest(BaseModel):
    """Request-Body für den Switch-Flow."""
    profile_name: Optional[str] = Field(
        default=None,
        description="Profil-Name für Full-State Restore (GMS + TikTok + Accounts)",
    )
    backup_path: Optional[str] = Field(
        default=None,
        description="Legacy: Pfad zum TikTok tar-Backup (nur wenn kein profile_name)",
    )


class BackupRequest(BaseModel):
    """Request-Body für Full-State Backup."""
    profile_name: str = Field(
        ..., min_length=1, max_length=64,
        description="Name des Profils das gesichert werden soll",
        json_schema_extra={"example": "DE_Berlin_001"},
    )


# =============================================================================
# POST /api/control/genesis
# =============================================================================

@router.post("/genesis")
async def start_genesis(
    req: GenesisRequest,
    background_tasks: BackgroundTasks,
):
    """
    Startet den Genesis-Flow (Cold Start — neue Identität).

    Der Flow läuft im Hintergrund. Status abrufbar via GET /api/control/status.
    """
    global _state

    if _state.running:
        raise HTTPException(
            status_code=409,
            detail=f"Flow '{_state.flow_type}' läuft bereits seit {_state.started_at}",
        )

    # Pre-Check: Genesis Frequency Guard
    try:
        freq = await check_genesis_frequency()
        if not freq["allowed"]:
            raise HTTPException(
                status_code=429,
                detail=freq["reason"],
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.warning("Frequency pre-check fehlgeschlagen: %s", e)

    # Lock setzen BEVOR der Background-Task startet
    _state = FlowState(
        running=True,
        flow_type="genesis",
        flow_name=req.name,
        started_at=datetime.now(LOCAL_TZ).isoformat(),
    )

    background_tasks.add_task(_run_genesis, req.name, req.notes, req.backup_before)

    logger.info("Genesis-Flow gestartet: %s", req.name)
    return {
        "status": "started",
        "flow": "genesis",
        "name": req.name,
        "message": f"Genesis-Flow '{req.name}' wurde gestartet.",
    }


async def _run_genesis(name: str, notes: Optional[str], backup_before: bool = False) -> None:
    """Background-Task: Führt den GenesisFlow aus."""
    global _state
    async with _lock:
        try:
            adb = create_adb_client()
            flow = GenesisFlow(adb)
            result = await flow.execute(name, notes=notes, backup_before=backup_before)

            _state.result = _safe_dict(result)
            _state.error = result.error

            # Cloud-Sync: Betroffene Daten an Supabase pushen
            try:
                from host.api.sync import auto_sync_after_flow
                r = _safe_dict(result)
                await auto_sync_after_flow(
                    identity_id=r.get("identity_id"),
                    profile_id=r.get("profile_id"),
                    flow_id=r.get("flow_id"),
                )
            except Exception:
                pass

        except Exception as e:
            logger.error("Genesis Background-Task Fehler: %s", e, exc_info=True)
            _state.error = str(e)
            _state.result = {"success": False, "error": str(e)}

        finally:
            _state.running = False
            _state.finished_at = datetime.now(LOCAL_TZ).isoformat()


# =============================================================================
# POST /api/control/switch/{identity_id}
# =============================================================================

@router.post("/switch/{identity_id}")
async def start_switch(
    identity_id: int,
    req: SwitchRequest,
    background_tasks: BackgroundTasks,
):
    """
    Startet den Switch-Flow (Warm Switch — existierendes Profil).

    Der Flow läuft im Hintergrund. Status abrufbar via GET /api/control/status.
    """
    global _state

    if _state.running:
        raise HTTPException(
            status_code=409,
            detail=f"Flow '{_state.flow_type}' läuft bereits seit {_state.started_at}",
        )

    _state = FlowState(
        running=True,
        flow_type="switch",
        flow_name=f"switch-{identity_id}",
        started_at=datetime.now(LOCAL_TZ).isoformat(),
    )

    background_tasks.add_task(
        _run_switch, identity_id, req.profile_name, req.backup_path,
    )

    mode = "Full-State" if req.profile_name else "Legacy"
    logger.info(
        "Switch-Flow gestartet: identity_id=%d [%s]", identity_id, mode,
    )
    return {
        "status": "started",
        "flow": "switch",
        "identity_id": identity_id,
        "mode": mode,
        "message": (
            f"Switch-Flow für Identity #{identity_id} wurde gestartet "
            f"({mode}: {req.profile_name or req.backup_path or 'no restore'})."
        ),
    }


async def _run_switch(
    identity_id: int,
    profile_name: Optional[str],
    backup_path: Optional[str],
) -> None:
    """Background-Task: Führt den SwitchFlow aus."""
    global _state
    async with _lock:
        try:
            adb = create_adb_client()
            flow = SwitchFlow(adb)
            result = await flow.execute(
                identity_id=identity_id,
                profile_name=profile_name,
                backup_path=backup_path,
            )

            _state.result = _safe_dict(result)
            _state.error = result.error

            try:
                from host.api.sync import auto_sync_after_flow
                r = _safe_dict(result)
                await auto_sync_after_flow(
                    identity_id=r.get("identity_id") or identity_id,
                    profile_id=r.get("profile_id"),
                    flow_id=r.get("flow_id"),
                )
            except Exception:
                pass

        except Exception as e:
            logger.error("Switch Background-Task Fehler: %s", e, exc_info=True)
            _state.error = str(e)
            _state.result = {"success": False, "error": str(e)}

        finally:
            _state.running = False
            _state.finished_at = datetime.now(LOCAL_TZ).isoformat()


# =============================================================================
# POST /api/control/backup (Full-State Backup mit DB-Tracking)
# =============================================================================

@router.post("/backup")
async def start_backup(
    req: BackupRequest,
    background_tasks: BackgroundTasks,
):
    """
    Startet ein Full-State Backup (GMS + TikTok + Account-DBs).

    Sichert den kompletten Session-State eines Profils, damit beim
    nächsten Switch der Google-Login erhalten bleibt.

    WICHTIG: Erst nach manuellem Google- und TikTok-Login ausführen!
    """
    global _state

    if _state.running:
        raise HTTPException(
            status_code=409,
            detail=f"Flow '{_state.flow_type}' läuft bereits seit {_state.started_at}",
        )

    _state = FlowState(
        running=True,
        flow_type="backup",
        flow_name=f"backup-{req.profile_name}",
        started_at=datetime.now(LOCAL_TZ).isoformat(),
    )

    background_tasks.add_task(_run_backup, req.profile_name)

    logger.info("Full-State Backup gestartet: %s", req.profile_name)
    return {
        "status": "started",
        "flow": "backup",
        "profile_name": req.profile_name,
        "message": (
            f"Full-State Backup für '{req.profile_name}' wurde gestartet. "
            f"Sichert GMS + TikTok + Account-DBs."
        ),
    }


async def _run_backup(profile_name: str) -> None:
    """Background-Task: Führt Full-State Backup aus + aktualisiert profiles-Tabelle."""
    global _state
    async with _lock:
        flow_history_id: Optional[int] = None

        try:
            # Flow-History: Eintrag erstellen
            try:
                # Profil finden
                profile_data = await find_profile_by_name(profile_name)
                profile_id = profile_data["id"] if profile_data else None
                identity_id = profile_data["identity_id"] if profile_data else None

                flow_history_id = await create_flow_history(
                    flow_type="backup",
                    identity_id=identity_id,
                    profile_id=profile_id,
                )
            except Exception as e:
                profile_id = None
                identity_id = None
                logger.warning("Flow-History für Backup fehlgeschlagen: %s", e)

            adb = create_adb_client()
            shifter = AppShifter(adb)
            results = await shifter.backup_full_state(profile_name)

            # Ergebnis für API
            backup_summary = {
                component: str(path) if path else None
                for component, path in results.items()
            }
            success_count = sum(1 for v in results.values() if v is not None)

            _state.result = {
                "success": success_count > 0,
                "profile_name": profile_name,
                "components": backup_summary,
                "components_saved": success_count,
                "components_total": len(results),
            }

            # DB: Profile Backup-Status aktualisieren
            if profile_id:
                try:
                    # TikTok Backup
                    tiktok_path = results.get("tiktok")
                    if tiktok_path:
                        tiktok_size = os.path.getsize(tiktok_path) if tiktok_path.exists() else 0
                        await update_profile_tiktok_backup(
                            profile_id, str(tiktok_path), tiktok_size,
                        )

                    # GMS Backup
                    gms_path = results.get("gms")
                    if gms_path:
                        gms_size = os.path.getsize(gms_path) if gms_path.exists() else 0
                        await update_profile_gms_backup(
                            profile_id, str(gms_path), gms_size,
                        )

                    # Account-DBs Backup
                    accounts_path = results.get("accounts")
                    if accounts_path:
                        await update_profile_accounts_backup(
                            profile_id, str(accounts_path),
                        )

                    logger.info(
                        "Profile %d Backup-Status aktualisiert: %d/%d Komponenten",
                        profile_id, success_count, len(results),
                    )
                except Exception as e:
                    logger.warning("Profile Backup-Status Update fehlgeschlagen: %s", e)

            # Flow-History: Finalize
            if flow_history_id:
                await update_flow_history(
                    flow_history_id,
                    status="success" if success_count > 0 else "failed",
                    duration_ms=int(
                        (datetime.now(LOCAL_TZ).timestamp() -
                         datetime.fromisoformat(_state.started_at).timestamp()) * 1000
                    ) if _state.started_at else 0,
                )

        except Exception as e:
            logger.error("Backup Background-Task Fehler: %s", e, exc_info=True)
            _state.error = str(e)
            _state.result = {"success": False, "error": str(e)}

            if flow_history_id:
                try:
                    await update_flow_history(
                        flow_history_id,
                        status="failed",
                        error=str(e),
                    )
                except Exception:
                    pass

        finally:
            _state.running = False
            _state.finished_at = datetime.now(LOCAL_TZ).isoformat()


# =============================================================================
# GET /api/control/status
# =============================================================================

@router.get("/status")
async def flow_status():
    """
    Gibt den aktuellen Flow-Status zurück.

    Returns:
        running: bool — Läuft gerade ein Flow?
        flow_type: str — "genesis" | "switch" | "backup" | ""
        result: dict — Letztes Ergebnis (wenn fertig)
    """
    return {
        "running": _state.running,
        "flow_type": _state.flow_type,
        "flow_name": _state.flow_name,
        "started_at": _state.started_at,
        "finished_at": _state.finished_at,
        "error": _state.error,
        "result": _state.result,
    }


# =============================================================================
# POST /api/control/abort (Emergency Reset)
# =============================================================================

@router.post("/abort")
async def abort_flow():
    """
    Emergency: Setzt den Flow-Lock zurück.

    ACHTUNG: Dies stoppt den laufenden Flow NICHT sofort —
    es gibt nur den Lock frei, damit ein neuer Flow gestartet werden kann.
    """
    global _state
    was_running = _state.running
    _state.running = False
    _state.finished_at = datetime.now(LOCAL_TZ).isoformat()
    _state.error = "Manuell abgebrochen" if was_running else None

    logger.warning("Flow-Lock manuell zurückgesetzt (war_aktiv=%s)", was_running)
    return {
        "status": "aborted" if was_running else "no_flow_running",
        "message": "Flow-Lock zurückgesetzt.",
    }


# =============================================================================
# SCRCPY: Screen Mirroring via Web UI
# =============================================================================

import shutil
import signal
import subprocess

_scrcpy_process: Optional[subprocess.Popen] = None


@router.post("/scrcpy/start")
async def start_scrcpy():
    """
    Startet scrcpy als Desktop-Fenster.

    Scrcpy muss auf dem Host installiert sein (brew install scrcpy).
    Das Fenster öffnet sich auf dem Desktop und zeigt den Geräte-Screen.
    """
    global _scrcpy_process

    # Prüfe ob scrcpy installiert ist
    scrcpy_path = shutil.which("scrcpy")
    if not scrcpy_path:
        raise HTTPException(
            status_code=500,
            detail="scrcpy ist nicht installiert. Installiere mit: brew install scrcpy",
        )

    # Prüfe ob bereits eine Instanz läuft
    if _scrcpy_process is not None and _scrcpy_process.poll() is None:
        return {
            "status": "already_running",
            "pid": _scrcpy_process.pid,
            "message": "scrcpy läuft bereits.",
        }

    try:
        _scrcpy_process = subprocess.Popen(
            [
                scrcpy_path,
                "--window-title", "Titan Device Mirror",
                "--stay-awake",
                "--turn-screen-off",
                "--no-audio",
                "--max-size", "1024",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        logger.info("scrcpy gestartet (PID: %d)", _scrcpy_process.pid)
        return {
            "status": "started",
            "pid": _scrcpy_process.pid,
            "message": "scrcpy wurde gestartet. Fenster öffnet sich auf dem Desktop.",
        }

    except Exception as e:
        logger.error("scrcpy Start fehlgeschlagen: %s", e)
        raise HTTPException(
            status_code=500,
            detail=f"scrcpy konnte nicht gestartet werden: {e}",
        )


@router.post("/scrcpy/stop")
async def stop_scrcpy():
    """Stoppt die laufende scrcpy-Instanz."""
    global _scrcpy_process

    if _scrcpy_process is None or _scrcpy_process.poll() is not None:
        _scrcpy_process = None
        return {
            "status": "not_running",
            "message": "scrcpy läuft nicht.",
        }

    try:
        pid = _scrcpy_process.pid
        _scrcpy_process.send_signal(signal.SIGTERM)
        _scrcpy_process.wait(timeout=5)
        _scrcpy_process = None

        logger.info("scrcpy gestoppt (PID: %d)", pid)
        return {
            "status": "stopped",
            "message": "scrcpy wurde gestoppt.",
        }

    except subprocess.TimeoutExpired:
        _scrcpy_process.kill()
        _scrcpy_process = None
        return {
            "status": "killed",
            "message": "scrcpy wurde erzwungen beendet.",
        }

    except Exception as e:
        _scrcpy_process = None
        logger.error("scrcpy Stop Fehler: %s", e)
        return {
            "status": "error",
            "message": f"Fehler beim Stoppen: {e}",
        }


@router.post("/adb/reconnect")
async def adb_reconnect():
    """
    Simuliert ein USB-Kabel raus-/reinstecken — komplett vom Mac aus.

    Ablauf (alles Host-seitig, kein Geräte-Zugriff nötig):
      1. `adb disconnect` — Trennt aktive USB-Transports (= Kabel raus)
      2. `adb kill-server` — ADB-Daemon komplett beenden
      3. Warte 2s — Wie physisches Rausziehen
      4. `adb start-server` — ADB-Daemon neu starten (= Kabel rein)
      5. `adb reconnect offline` — Offline-Geräte reaktivieren
      6. `adb wait-for-device` — Warten bis Gerät wieder da ist
      7. Verify — Serial auslesen als Bestätigung
    """

    async def _run_adb(*args: str, timeout: int = 10) -> tuple[int, str]:
        """Führt einen ADB-Befehl aus und gibt (returncode, stdout) zurück."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "adb", *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout,
            )
            return proc.returncode, stdout.decode().strip()
        except asyncio.TimeoutError:
            return -1, "timeout"
        except OSError as e:
            return -1, str(e)

    # ── Phase 1: USB trennen (Kabel raus) ──
    logger.info("USB-Cycle: Phase 1 — Trenne USB-Transport...")
    await _run_adb("disconnect", timeout=5)

    # ── Phase 2: ADB-Daemon komplett killen ──
    logger.info("USB-Cycle: Phase 2 — ADB-Daemon stoppen...")
    await _run_adb("kill-server", timeout=5)

    # ── Phase 3: Pause (simuliert physisches Kabel-Rausziehen) ──
    logger.info("USB-Cycle: Phase 3 — USB getrennt, warte 2s...")
    await asyncio.sleep(2)

    # ── Phase 4: ADB-Daemon neu starten (Kabel rein) ──
    logger.info("USB-Cycle: Phase 4 — ADB-Daemon starten (= Kabel rein)...")
    rc, out = await _run_adb("start-server", timeout=10)
    if rc != 0:
        logger.warning("USB-Cycle: start-server Fehler: %s", out)

    await asyncio.sleep(1)

    # ── Phase 5: Offline-Geräte reaktivieren ──
    logger.info("USB-Cycle: Phase 5 — Reconnect offline Geräte...")
    await _run_adb("reconnect", "offline", timeout=5)

    await asyncio.sleep(1)

    # ── Phase 6: Auf Gerät warten ──
    logger.info("USB-Cycle: Phase 6 — wait-for-device (max 15s)...")
    rc, _ = await _run_adb("wait-for-device", timeout=15)

    # ── Phase 7: Verbindung verifizieren ──
    await asyncio.sleep(1)
    adb = create_adb_client()

    if rc != 0 or not await adb.is_connected():
        # USB hat nicht geklappt — versuche wadbd Wireless Fallback
        logger.warning("USB-Cycle: Kein USB-Gerät — versuche wadbd Wireless Fallback...")
        try:
            wadbd = await adb.check_wadbd_available()
            if wadbd["available"]:
                logger.info("USB-Cycle: wadbd gefunden: %s", wadbd["detail"])
                connected = await adb.connect_wireless(wadbd["ip"], wadbd["port"])
                if connected:
                    result = await adb.shell("getprop ro.serialno", timeout=5)
                    serial = result.output.strip() if result.success else "?"
                    return {
                        "status": "connected",
                        "serial": serial,
                        "connection": "wireless",
                        "message": f"Wireless ADB verbunden (wadbd): {serial} @ {wadbd['ip']}:{wadbd['port']}",
                    }
        except Exception as e:
            logger.debug("wadbd Fallback fehlgeschlagen: %s", e)

        return {
            "status": "failed",
            "message": "USB-Cycle: Kein Gerät gefunden (USB + Wireless). Kabel prüfen!",
        }

    try:
        result = await adb.shell("getprop ro.serialno", timeout=5)
        serial = result.output.strip() if result.success else "?"

        logger.info("USB-Cycle erfolgreich — Gerät: %s", serial)
        return {
            "status": "connected",
            "serial": serial,
            "connection": "usb",
            "message": f"USB-Reconnect erfolgreich! Gerät: {serial}",
        }
    except Exception as e:
        logger.error("USB-Cycle: Verifikation fehlgeschlagen: %s", e)
        return {
            "status": "error",
            "message": f"USB-Cycle Fehler bei Verifikation: {e}",
        }


@router.get("/scrcpy/status")
async def scrcpy_status():
    """Gibt den aktuellen scrcpy-Status zurück."""
    global _scrcpy_process

    if _scrcpy_process is not None and _scrcpy_process.poll() is not None:
        _scrcpy_process = None

    running = _scrcpy_process is not None and _scrcpy_process.poll() is None
    return {
        "running": running,
        "pid": _scrcpy_process.pid if running else None,
    }


# =============================================================================
# v6.1: ADB Input Guard — Behavioral Analysis Protection
# =============================================================================
# Standard `adb shell input tap/swipe` erzeugt Events über /dev/input/
# die NICHT vom Touchscreen-Treiber kommen. Anti-Cheat-Systeme (TikTok
# libsscronet.so, Snapchat) erkennen das sofort:
#   - EV_SYN Source ist "adb" statt "fts_ts" (Touchscreen HAL)
#   - Timing ist perfekt (0ms Jitter) statt menschlich (5-30ms)
#   - Kein EV_ABS Pressure (Druckstärke fehlt komplett)
#
# LÖSUNG: Wenn ein Kernel-Input-Binary vorhanden ist (/data/local/tmp/
# hydra_input), wird es bevorzugt. Es injiziert Events direkt in den
# Touchscreen-Treiber-Node, was von echtem Touch ununterscheidbar ist.
# =============================================================================

HYDRA_INPUT_PATH = "/data/local/tmp/hydra_input"


@router.post("/input/tap")
async def safe_input_tap(x: int, y: int):
    """
    Führt einen Touch-Tap aus — bevorzugt über Kernel-Input-Driver.

    Standard `input tap` wird BLOCKIERT wenn ein Target-App-Prozess
    läuft, da es sofort als Bot-Input erkannt wird.
    """
    adb = create_adb_client()

    # Prüfe ob Kernel-Input-Binary vorhanden
    hydra_check = await adb.shell(
        f"test -x {HYDRA_INPUT_PATH} && echo OK", root=True, timeout=3,
    )
    if hydra_check.success and "OK" in hydra_check.output:
        # Kernel-Driver Tap (nicht von adb input unterscheidbar)
        result = await adb.shell(
            f"{HYDRA_INPUT_PATH} tap {x} {y}", root=True, timeout=5,
        )
        logger.info("[InputGuard] Kernel-Tap: (%d, %d) — hydra_input", x, y)
        return {
            "status": "ok",
            "method": "kernel_driver",
            "x": x, "y": y,
        }

    # Fallback: Standard input — MIT fetter Warnung
    logger.warning(
        "⚠ UNSAFE INPUT DETECTED — USE KERNEL DRIVER! "
        "adb shell input tap %d %d wird von Anti-Cheat erkannt. "
        "Pushe hydra_input nach %s für sicheren Input.",
        x, y, HYDRA_INPUT_PATH,
    )
    result = await adb.shell(
        f"input tap {x} {y}", root=False, timeout=5,
    )
    return {
        "status": "warning",
        "method": "adb_input_UNSAFE",
        "warning": (
            "Standard adb input ist von Anti-Cheat-Systemen erkennbar! "
            f"Installiere {HYDRA_INPUT_PATH} für Kernel-Level Input."
        ),
        "x": x, "y": y,
    }


@router.post("/input/swipe")
async def safe_input_swipe(x1: int, y1: int, x2: int, y2: int, duration_ms: int = 300):
    """
    Führt einen Swipe aus — bevorzugt über Kernel-Input-Driver.
    """
    adb = create_adb_client()

    hydra_check = await adb.shell(
        f"test -x {HYDRA_INPUT_PATH} && echo OK", root=True, timeout=3,
    )
    if hydra_check.success and "OK" in hydra_check.output:
        result = await adb.shell(
            f"{HYDRA_INPUT_PATH} swipe {x1} {y1} {x2} {y2} {duration_ms}",
            root=True, timeout=max(5, duration_ms // 1000 + 3),
        )
        logger.info(
            "[InputGuard] Kernel-Swipe: (%d,%d)→(%d,%d) %dms — hydra_input",
            x1, y1, x2, y2, duration_ms,
        )
        return {
            "status": "ok",
            "method": "kernel_driver",
        }

    logger.warning(
        "⚠ UNSAFE INPUT DETECTED — USE KERNEL DRIVER! "
        "adb shell input swipe wird von Anti-Cheat erkannt.",
    )
    await adb.shell(
        f"input swipe {x1} {y1} {x2} {y2} {duration_ms}",
        root=False, timeout=max(5, duration_ms // 1000 + 3),
    )
    return {
        "status": "warning",
        "method": "adb_input_UNSAFE",
        "warning": f"Installiere {HYDRA_INPUT_PATH} für Kernel-Level Input.",
    }


# =============================================================================
# Hilfsfunktionen
# =============================================================================

def _safe_dict(obj: Any) -> dict:
    """Konvertiert ein dataclass-Objekt in ein JSON-serialisierbares dict."""
    try:
        d = asdict(obj)
        # Entferne nicht-serialisierbare Audit-Objekte (AuditCheck hat CheckStatus Enum)
        return _make_serializable(d)
    except Exception:
        return {"raw": str(obj)}


def _make_serializable(obj: Any) -> Any:
    """Rekursive Konvertierung zu JSON-serialisierbaren Typen."""
    if isinstance(obj, dict):
        return {k: _make_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_make_serializable(i) for i in obj]
    elif hasattr(obj, "value"):  # Enum
        return obj.value
    elif isinstance(obj, (str, int, float, bool, type(None))):
        return obj
    else:
        return str(obj)
