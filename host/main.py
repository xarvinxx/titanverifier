"""
Host-Side FastAPI Entrypoint
=============================

Startet den Host-Side Orchestrator mit:
  - SQLite DB Initialisierung
  - API-Router (Control, Dashboard)
  - WebSocket (Live-Logs)
  - Jinja2 Templates (Dashboard UI)

Start:
    uvicorn host.main:app --reload --host 0.0.0.0 --port 8000

Oder:
    python -m host.main
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import AsyncGenerator

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from host.config import API_HOST, API_PORT, API_TITLE, API_VERSION, DATABASE_PATH, LOCAL_TZ
from host.database import db
from host.engine.hookguard import HookGuard

# =============================================================================
# Logging Setup — MUSS vor allen anderen Modul-Imports passieren
# Explizit Europe/Berlin für korrekte deutsche Uhrzeiten in Logs
# =============================================================================


class _BerlinFormatter(logging.Formatter):
    """Log-Formatter mit expliziter Europe/Berlin Zeitzone (CET/CEST)."""

    def formatTime(self, record: logging.LogRecord, datefmt: str | None = None) -> str:
        ct = datetime.fromtimestamp(record.created, tz=LOCAL_TZ)
        if datefmt:
            return ct.strftime(datefmt)
        return ct.strftime("%Y-%m-%d %H:%M:%S")


_console_handler = logging.StreamHandler()
_console_handler.setFormatter(
    _BerlinFormatter(
        fmt="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )
)
logging.root.addHandler(_console_handler)
logging.root.setLevel(logging.INFO)

# =============================================================================
# FIX-25: Persistenter File-Logger mit Rotation
# =============================================================================
# Logs werden zusätzlich in host.log geschrieben (max ~40MB Disk):
#   - 10 MB pro Datei, 3 alte Dateien behalten
#   - DEBUG-Level (mehr Details als Console/WebSocket)
#   - Post-Mortem bei Crashes möglich
# =============================================================================

from logging.handlers import RotatingFileHandler  # noqa: E402

_log_dir = Path(__file__).resolve().parent.parent  # Projekt-Root
_log_file = _log_dir / "host.log"

_file_handler = RotatingFileHandler(
    str(_log_file),
    maxBytes=10_000_000,   # 10 MB pro Datei
    backupCount=3,          # 3 alte Dateien behalten (host.log.1, .2, .3)
    encoding="utf-8",
)
_file_handler.setFormatter(
    _BerlinFormatter(
        fmt="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
)
_file_handler.setLevel(logging.DEBUG)  # Alles loggen, auch DEBUG
logging.root.addHandler(_file_handler)

logger = logging.getLogger("host.main")

# =============================================================================
# WebSocket Log-Handler registrieren
# Fängt alle "host.*" Logs ab und streamt sie an WS-Clients
# =============================================================================

from host.api.dashboard import ws_log_handler, websocket_logs  # noqa: E402

_host_root_logger = logging.getLogger("host")
_host_root_logger.addHandler(ws_log_handler)


# =============================================================================
# Templates & Static Files
# =============================================================================

_FRONTEND_DIR = Path(__file__).resolve().parent / "frontend"
_TEMPLATES_DIR = _FRONTEND_DIR / "templates"

templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))


# =============================================================================
# Lifespan (Startup / Shutdown)
# =============================================================================

_hookguard = None  # HookGuard instance, set in lifespan


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Application Lifespan:
      - Startup:  DB initialisieren, Backup-Ordner erstellen
      - Shutdown: DB sauber schliessen
    """
    # --- Startup ---
    logger.info("=" * 60)
    logger.info("  Device Manager v%s", API_VERSION)
    logger.info("  Database: %s", DATABASE_PATH)
    logger.info("  Dashboard: http://%s:%d", API_HOST, API_PORT)
    logger.info("=" * 60)

    await db.initialize()

    # Backup-Verzeichnis erstellen
    from host.config import BACKUP_DIR
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)

    # HookGuard init + auto-start
    from host.adb.client import ADBClient
    adb = ADBClient()
    global _hookguard
    try:
        _hookguard = HookGuard(adb)
        await _hookguard.start()
        logger.info("HookGuard automatisch gestartet")
    except Exception as e:
        logger.warning("HookGuard init/start failed: %s", e)
        if _hookguard is None:
            pass

    # Backup-Status aus Dateisystem in DB synchronisieren
    try:
        from host.engine.db_ops import sync_backup_status_from_disk
        synced = await sync_backup_status_from_disk()
        if synced:
            logger.info("Backup-Sync: %d Profile aktualisiert", synced)
    except Exception as e:
        logger.warning("Backup-Sync fehlgeschlagen: %s", e)

    logger.info("Command Center bereit.")

    yield

    # --- Shutdown ---
    if _hookguard and _hookguard.is_running:
        await _hookguard.stop()
    logger.info("Shutdown: Schliesse Datenbank...")
    await db.close()
    logger.info("Command Center gestoppt.")


# =============================================================================
# FastAPI App
# =============================================================================

app = FastAPI(
    title=API_TITLE,
    version=API_VERSION,
    description=(
        "Host-Side Identity Orchestration Platform. "
        "Verwaltet 1000+ O2-DE Hardware-Identitäten auf Pixel 6 via ADB Root."
    ),
    lifespan=lifespan,
)


# =============================================================================
# Router registrieren
# =============================================================================

from host.api.control import router as control_router  # noqa: E402
from host.api.dashboard import router as dashboard_router  # noqa: E402
from host.api.vault import router as vault_router  # noqa: E402

app.include_router(control_router)
app.include_router(dashboard_router)
app.include_router(vault_router)


# =============================================================================
# WebSocket Endpoint (direkt auf App, nicht über Router)
# =============================================================================

@app.websocket("/ws/logs")
async def ws_logs_endpoint(ws: WebSocket):
    """Echtzeit Log-Stream via WebSocket."""
    await websocket_logs(ws)


@app.websocket("/ws/hookguard")
async def ws_hookguard_endpoint(ws: WebSocket):
    await ws.accept()
    guard = _hookguard
    if guard:
        guard.register_ws(ws)
    try:
        while True:
            await ws.receive_text()  # keep alive
    except WebSocketDisconnect:
        pass
    finally:
        if guard:
            guard.unregister_ws(ws)


# =============================================================================
# Dashboard UI (Jinja2 Template)
# =============================================================================

@app.get("/", response_class=HTMLResponse, tags=["UI"])
async def dashboard(request: Request):
    """Haupt-Dashboard — Device Manager."""
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "version": API_VERSION},
    )


@app.get("/vault", response_class=HTMLResponse, tags=["UI"])
async def vault_page(request: Request):
    """Profile Vault — Account Management."""
    return templates.TemplateResponse(
        "vault.html",
        {"request": request, "version": API_VERSION},
    )


# =============================================================================
# Health Check
# =============================================================================

@app.get("/api/health", tags=["System"])
async def health_check():
    """Health Check: Prüft DB-Verbindung."""
    try:
        async with db.connection() as conn:
            cursor = await conn.execute("SELECT COUNT(*) FROM identities")
            identity_count = (await cursor.fetchone())[0]
            cursor = await conn.execute("SELECT COUNT(*) FROM profiles")
            profile_count = (await cursor.fetchone())[0]

        return {
            "status": "healthy",
            "database": "connected",
            "identities": identity_count,
            "profiles": profile_count,
        }
    except Exception as e:
        return JSONResponse(
            status_code=503,
            content={"status": "unhealthy", "error": str(e)},
        )


# =============================================================================
# Globaler Exception Handler
# =============================================================================

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Fängt unbehandelte Exceptions und gibt ein sauberes JSON zurück."""
    logger.error("Unhandled exception on %s: %s", request.url, exc, exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "internal_server_error",
            "detail": str(exc),
        },
    )


# =============================================================================
# Direct Execution
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "host.main:app",
        host=API_HOST,
        port=API_PORT,
        reload=True,
        log_level="info",
    )
