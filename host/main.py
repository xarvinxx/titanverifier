"""
Project Titan — FastAPI Entrypoint
====================================

Startet den Host-Side Orchestrator mit:
  - SQLite DB Initialisierung (titan.db)
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
from pathlib import Path
from typing import AsyncGenerator

from fastapi import FastAPI, Request, WebSocket
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from host.config import API_HOST, API_PORT, API_TITLE, API_VERSION, DATABASE_PATH
from host.database import db

# =============================================================================
# Logging Setup — MUSS vor allen anderen Modul-Imports passieren
# =============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("titan.main")

# =============================================================================
# WebSocket Log-Handler registrieren
# Fängt alle "titan.*" Logs ab und streamt sie an WS-Clients
# =============================================================================

from host.api.dashboard import ws_log_handler, websocket_logs  # noqa: E402

_titan_root_logger = logging.getLogger("titan")
_titan_root_logger.addHandler(ws_log_handler)


# =============================================================================
# Templates & Static Files
# =============================================================================

_FRONTEND_DIR = Path(__file__).resolve().parent / "frontend"
_TEMPLATES_DIR = _FRONTEND_DIR / "templates"

templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))


# =============================================================================
# Lifespan (Startup / Shutdown)
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Application Lifespan:
      - Startup:  DB initialisieren, Backup-Ordner erstellen
      - Shutdown: DB sauber schliessen
    """
    # --- Startup ---
    logger.info("=" * 60)
    logger.info("  Project Titan — Command Center v%s", API_VERSION)
    logger.info("  Database: %s", DATABASE_PATH)
    logger.info("  Dashboard: http://%s:%d", API_HOST, API_PORT)
    logger.info("=" * 60)

    await db.initialize()

    # Backup-Verzeichnis erstellen
    from host.config import BACKUP_DIR
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)

    logger.info("Titan Command Center bereit.")

    yield

    # --- Shutdown ---
    logger.info("Shutdown: Schliesse Datenbank...")
    await db.close()
    logger.info("Titan Command Center gestoppt.")


# =============================================================================
# FastAPI App
# =============================================================================

app = FastAPI(
    title=API_TITLE,
    version=API_VERSION,
    description=(
        "Project Titan — Host-Side Identity Orchestration Platform. "
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


# =============================================================================
# Dashboard UI (Jinja2 Template)
# =============================================================================

@app.get("/", response_class=HTMLResponse, tags=["UI"])
async def dashboard(request: Request):
    """Haupt-Dashboard — Titan Command Center."""
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
