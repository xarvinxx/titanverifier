"""
Project Titan — Switch Flow (Warm Switch / Existing Profile) v2.0
===================================================================

TITAN_CONTEXT.md §3C — FLOW 2: SWITCH (Erweitert mit Full-State Restore)

Wechselt zu einem existierenden Profil, ohne das Gerät
vollständig neu zu starten. Schneller als Genesis.

Zwingender Ablauf (6 Schritte):
  1. SAFETY KILL    — force-stop GMS + GSF + TikTok (alles tot)
  2. INJECT         — Ziel-Identität in Bridge-Datei schreiben
  3. RESTORE STATE  — Full-State Restore: GMS + Account-DBs + TikTok
  4. RESTORE TIKTOK — TikTok App-Daten (Legacy-Fallback wenn kein Full-State)
  5. SOFT RESET     — killall zygote (Framework Restart)
  6. QUICK AUDIT    — Bridge-Serial prüfen

DB-Tracking (v2.0):
  - Flow-History: Eintrag bei Start, Updates bei jedem Schritt, Finalize
  - Profile: switch_count++, last_switch_at, last_active_at
  - Identity: usage_count++, last_used_at
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from host.adb.client import ADBClient, ADBError
from host.config import GMS_BACKUP_PACKAGES, LOCAL_TZ, TIMING
from host.database import db
from host.engine.auditor import TitanAuditor
from host.engine.db_ops import (
    create_flow_history,
    find_profile_by_identity,
    increment_identity_usage,
    update_flow_history,
    update_profile_activity,
)
from host.engine.injector import TitanInjector
from host.engine.shifter import TitanShifter
from host.flows.genesis import FlowStep, FlowStepStatus
from host.models.identity import IdentityRead, IdentityStatus

logger = logging.getLogger("titan.flows.switch")


# =============================================================================
# Flow-Ergebnis
# =============================================================================

@dataclass
class SwitchResult:
    """Ergebnis des Switch-Flows."""
    success: bool = False
    profile_id: Optional[int] = None
    identity_id: Optional[int] = None
    identity_name: str = ""
    serial: str = ""
    steps: list[FlowStep] = field(default_factory=list)
    audit_passed: Optional[bool] = None
    error: Optional[str] = None
    started_at: str = field(
        default_factory=lambda: datetime.now(LOCAL_TZ).isoformat()
    )
    finished_at: Optional[str] = None
    duration_ms: int = 0
    flow_history_id: Optional[int] = None

    @property
    def step_summary(self) -> str:
        parts = []
        for s in self.steps:
            icon = {"success": "+", "failed": "!", "skipped": "-"}.get(s.status.value, "?")
            parts.append(f"[{icon}] {s.name}")
        return " | ".join(parts)


# =============================================================================
# Switch Flow
# =============================================================================

class SwitchFlow:
    """
    Warm-Switch Flow: Wechselt zu einem existierenden Profil.

    Unterstützt zwei Modi:
      A) Full-State Restore (profile_name angegeben):
         → Restored GMS + Account-DBs + TikTok aus dem Profil-Verzeichnis
         → Google-Login bleibt erhalten!
      B) Legacy-Modus (nur backup_path angegeben):
         → Restored nur TikTok App-Daten (wie bisher)
         → Google-Logout wahrscheinlich

    Usage:
        adb = ADBClient()
        flow = SwitchFlow(adb)

        # Full-State (empfohlen):
        result = await flow.execute(
            identity_id=42,
            profile_name="DE_Berlin_001",
        )

        # Legacy (nur TikTok):
        result = await flow.execute(
            identity_id=42,
            backup_path="/backups/profile_42_20240101.tar",
        )
    """

    STEP_NAMES = [
        "Safety Kill",
        "Inject",
        "Restore State",
        "Restore TikTok",
        "Soft Reset",
        "Quick Audit",
    ]

    def __init__(self, adb: ADBClient):
        self._adb = adb
        self._injector = TitanInjector(adb)
        self._shifter = TitanShifter(adb)
        self._auditor = TitanAuditor(adb)

    async def execute(
        self,
        identity_id: int,
        profile_name: Optional[str] = None,
        backup_path: Optional[str | Path] = None,
        profile_id: Optional[int] = None,
    ) -> SwitchResult:
        """
        Führt den Switch-Flow aus.

        Args:
            identity_id:   DB-ID der Ziel-Identität
            profile_name:  Name des Profils für Full-State Restore (bevorzugt)
            backup_path:   Pfad zum TikTok tar-Backup (Legacy-Fallback)
            profile_id:    Zugehörige Profil-ID (für DB-Updates)

        Returns:
            SwitchResult mit Schritt-Details
        """
        result = SwitchResult(
            identity_id=identity_id,
            profile_id=profile_id,
        )
        result.steps = [FlowStep(name=n) for n in self.STEP_NAMES]
        flow_start = _now_ms()

        flow_history_id: Optional[int] = None

        # Identität aus DB laden
        identity = await self._load_identity(identity_id)
        if not identity:
            result.error = f"Identität {identity_id} nicht in DB gefunden"
            for s in result.steps:
                s.status = FlowStepStatus.SKIPPED
            return result

        result.identity_name = identity.name
        result.serial = identity.serial

        # Profil-ID auflösen falls nicht angegeben
        if not profile_id:
            try:
                profile_id = await find_profile_by_identity(identity_id)
                result.profile_id = profile_id
            except Exception:
                pass

        # Bestimme Restore-Modus
        use_full_state = profile_name is not None

        logger.info("=" * 60)
        logger.info(
            "  SWITCH FLOW: %s (id=%d) [%s]",
            identity.name, identity_id,
            "Full-State" if use_full_state else "Legacy",
        )
        logger.info("=" * 60)

        # ------------------------------------------------------------------
        # Flow-History: Eintrag erstellen
        # ------------------------------------------------------------------
        try:
            flow_history_id = await create_flow_history(
                flow_type="switch",
                identity_id=identity_id,
                profile_id=profile_id,
            )
            result.flow_history_id = flow_history_id
        except Exception as e:
            logger.warning("Flow-History Eintrag konnte nicht erstellt werden: %s", e)

        try:
            # =================================================================
            # Schritt 1: SAFETY KILL (GMS + TikTok + Vending)
            # =================================================================
            step = result.steps[0]
            step.status = FlowStepStatus.RUNNING
            step_start = _now_ms()

            logger.info("[1/6] Safety Kill: Alle Apps stoppen...")
            killed = []
            for pkg in [*GMS_BACKUP_PACKAGES, "com.zhiliaoapp.musically"]:
                try:
                    await self._adb.shell(
                        f"am force-stop {pkg}", root=True,
                    )
                    killed.append(pkg.split(".")[-1])
                except ADBError:
                    pass

            step.status = FlowStepStatus.SUCCESS
            step.detail = f"Gestoppt: {', '.join(killed)}"
            step.duration_ms = _now_ms() - step_start
            logger.info("[1/6] Safety Kill: OK (%s)", step.detail)

            # =================================================================
            # Schritt 2: INJECT
            # =================================================================
            step = result.steps[1]
            step.status = FlowStepStatus.RUNNING
            step_start = _now_ms()

            logger.info("[2/6] Inject: Bridge-Datei aktualisieren...")
            await self._injector.inject(
                identity, label=identity.name, distribute=True,
            )

            # Aktive Identität in DB umschalten + usage_count++
            await self._activate_identity(identity_id)
            try:
                await increment_identity_usage(identity_id)
            except Exception as e:
                logger.warning("Usage-Counter Update fehlgeschlagen: %s", e)

            step.status = FlowStepStatus.SUCCESS
            step.detail = f"serial={identity.serial}"
            step.duration_ms = _now_ms() - step_start
            logger.info("[2/6] Inject: OK")

            # =================================================================
            # Schritt 3: RESTORE STATE (GMS + Account-DBs)
            # =================================================================
            step = result.steps[2]
            step.status = FlowStepStatus.RUNNING
            step_start = _now_ms()

            if use_full_state:
                logger.info("[3/6] Restore State: GMS + Account-DBs...")
                try:
                    state_results = await self._shifter.restore_full_state(
                        profile_name,
                    )
                    gms_ok = state_results.get("gms", False)
                    accounts_ok = state_results.get("accounts", False)
                    tiktok_from_state = state_results.get("tiktok", False)

                    if gms_ok and accounts_ok:
                        step.status = FlowStepStatus.SUCCESS
                        step.detail = (
                            f"GMS: {'OK' if gms_ok else 'FAIL'}, "
                            f"Accounts: {'OK' if accounts_ok else 'FAIL'}, "
                            f"TikTok: {'OK' if tiktok_from_state else 'FAIL'}"
                        )
                    elif gms_ok or accounts_ok:
                        step.status = FlowStepStatus.SUCCESS  # Teilweise OK
                        step.detail = (
                            f"Teilweise: GMS={'OK' if gms_ok else 'SKIP'}, "
                            f"Accounts={'OK' if accounts_ok else 'SKIP'}, "
                            f"TikTok={'OK' if tiktok_from_state else 'SKIP'}"
                        )
                        logger.warning(
                            "[3/6] Partial Restore — Google Logout möglich"
                        )
                    else:
                        step.status = FlowStepStatus.SUCCESS  # Non-critical
                        step.detail = "Keine GMS/Account Backups vorhanden"
                        logger.warning("[3/6] Kein GMS-State vorhanden")

                except Exception as e:
                    step.status = FlowStepStatus.SUCCESS  # Non-critical
                    step.detail = f"State Restore Fehler: {e}"
                    logger.warning("[3/6] State Restore Fehler: %s", e)

            else:
                step.status = FlowStepStatus.SKIPPED
                step.detail = "Legacy-Modus — kein Full-State Restore"
                logger.info("[3/6] Restore State: Übersprungen (Legacy)")

            step.duration_ms = _now_ms() - step_start

            # =================================================================
            # Schritt 4: RESTORE TIKTOK (Legacy-Fallback)
            # =================================================================
            step = result.steps[3]
            step.status = FlowStepStatus.RUNNING
            step_start = _now_ms()

            if use_full_state:
                # TikTok wurde bereits in Schritt 3 restored
                step.status = FlowStepStatus.SKIPPED
                step.detail = "Bereits in Schritt 3 (Full-State) enthalten"
                logger.info("[4/6] TikTok: In Full-State enthalten")

            elif backup_path:
                # Legacy-Modus: Nur TikTok restoren
                logger.info("[4/6] Restore TikTok: Legacy-Modus...")
                try:
                    await self._shifter.restore(backup_path)
                    step.status = FlowStepStatus.SUCCESS
                    step.detail = f"Restored from {Path(backup_path).name}"
                except FileNotFoundError as e:
                    step.status = FlowStepStatus.FAILED
                    step.detail = f"Backup nicht gefunden: {e}"
                    raise ADBError(f"Backup nicht gefunden: {e}")
                except ADBError as e:
                    step.status = FlowStepStatus.FAILED
                    step.detail = f"Restore fehlgeschlagen: {e}"
                    if profile_id:
                        await self._mark_profile_corrupted(profile_id)
                    raise
            else:
                step.status = FlowStepStatus.SKIPPED
                step.detail = "Kein Backup angegeben"
                logger.info("[4/6] TikTok: Übersprungen (kein Backup)")

            step.duration_ms = _now_ms() - step_start

            # =================================================================
            # Schritt 5: SOFT RESET (killall zygote)
            # =================================================================
            step = result.steps[4]
            step.status = FlowStepStatus.RUNNING
            step_start = _now_ms()

            logger.info("[5/6] Soft Reset: killall zygote...")
            try:
                await self._adb.shell("killall zygote", root=True)
            except ADBError:
                # killall zygote kann Verbindung kurz unterbrechen
                pass

            # Warte unbegrenzt bis Gerät wieder erreichbar
            logger.info("[5/6] Warte auf Framework-Restart (unbegrenzt)...")
            booted = await self._adb.wait_for_device(timeout=0, poll_interval=2)

            if booted:
                # Post-Boot Settle + Unlock
                logger.info(
                    "[5/6] Framework bereit — warte %ds + Unlock...",
                    TIMING.POST_BOOT_SETTLE_SECONDS,
                )
                await asyncio.sleep(TIMING.POST_BOOT_SETTLE_SECONDS)
                await self._adb.unlock_device()

                step.status = FlowStepStatus.SUCCESS
                step.detail = (
                    f"Framework Restart + Unlock in "
                    f"{(_now_ms() - step_start) / 1000:.1f}s"
                )
            else:
                step.status = FlowStepStatus.FAILED
                step.detail = "Gerät nach Zygote-Kill nicht erreichbar"
                logger.warning("[5/6] Gerät nach Soft Reset nicht erreichbar")

            step.duration_ms = _now_ms() - step_start
            logger.info("[5/6] Soft Reset: %s", step.status.value)

            # =================================================================
            # Schritt 6: QUICK AUDIT
            # =================================================================
            step = result.steps[5]
            step.status = FlowStepStatus.RUNNING
            step_start = _now_ms()

            logger.info("[6/6] Quick Audit: Bridge-Serial prüfen...")
            audit_ok = await self._auditor.quick_audit(identity.serial)
            result.audit_passed = audit_ok

            if audit_ok:
                step.status = FlowStepStatus.SUCCESS
                step.detail = f"Bridge serial={identity.serial} bestätigt"
            else:
                step.status = FlowStepStatus.FAILED
                step.detail = "Bridge-Serial stimmt nicht überein!"
                logger.warning("[6/6] Quick Audit FAIL — Serial mismatch!")

            step.duration_ms = _now_ms() - step_start

            # Update Profile switch_count + last_switch_at
            if profile_id:
                try:
                    await update_profile_activity(profile_id)
                except Exception as e:
                    logger.warning("Profile Activity Update fehlgeschlagen: %s", e)

            # =================================================================
            # Ergebnis
            # =================================================================
            critical_failed = any(
                s.status == FlowStepStatus.FAILED
                for s in result.steps
                if s.name in ("Inject", "Restore TikTok")
            )
            result.success = not critical_failed

        except ADBError as e:
            for step in result.steps:
                if step.status == FlowStepStatus.RUNNING:
                    step.status = FlowStepStatus.FAILED
                    step.detail = str(e)
                    break

            for step in result.steps:
                if step.status == FlowStepStatus.PENDING:
                    step.status = FlowStepStatus.SKIPPED

            result.error = str(e)
            logger.error("Switch Flow ADB-Fehler: %s", e)

        except Exception as e:
            result.error = f"Unerwarteter Fehler: {e}"
            logger.error("Switch Flow Fehler: %s", e, exc_info=True)

            for step in result.steps:
                if step.status == FlowStepStatus.RUNNING:
                    step.status = FlowStepStatus.FAILED
                    step.detail = str(e)
                elif step.status == FlowStepStatus.PENDING:
                    step.status = FlowStepStatus.SKIPPED

        finally:
            result.finished_at = datetime.now(LOCAL_TZ).isoformat()
            result.duration_ms = _now_ms() - flow_start

            # Flow-History: Finalize
            if flow_history_id:
                try:
                    steps_json = json.dumps(
                        [{"name": s.name, "status": s.status.value,
                          "detail": s.detail, "duration_ms": s.duration_ms}
                         for s in result.steps],
                        ensure_ascii=False,
                    )
                    await update_flow_history(
                        flow_history_id,
                        status="success" if result.success else "failed",
                        duration_ms=result.duration_ms,
                        steps_json=steps_json,
                        error=result.error,
                    )
                except Exception as e:
                    logger.warning("Flow-History Finalize fehlgeschlagen: %s", e)

            logger.info("=" * 60)
            logger.info(
                "  SWITCH %s: %s (%d ms)",
                "ERFOLG" if result.success else "FEHLGESCHLAGEN",
                identity.name if identity else "?",
                result.duration_ms,
            )
            logger.info("  %s", result.step_summary)
            logger.info("=" * 60)

        return result

    # =========================================================================
    # DB-Operationen
    # =========================================================================

    async def _load_identity(self, identity_id: int) -> Optional[IdentityRead]:
        """Lädt eine Identität aus der Datenbank."""
        async with db.connection() as conn:
            cursor = await conn.execute(
                "SELECT * FROM identities WHERE id = ?", (identity_id,),
            )
            row = await cursor.fetchone()
            if not row:
                return None
            return IdentityRead(**dict(row))

    async def _activate_identity(self, identity_id: int) -> None:
        """
        Setzt die Ziel-Identität auf 'active' und alle anderen auf 'ready'.
        """
        now = datetime.now(LOCAL_TZ).isoformat()
        async with db.transaction() as conn:
            # Alle anderen deaktivieren
            await conn.execute(
                "UPDATE identities SET status = 'ready', updated_at = ? "
                "WHERE status = 'active' AND id != ?",
                (now, identity_id),
            )
            # Ziel aktivieren
            await conn.execute(
                "UPDATE identities SET status = 'active', "
                "updated_at = ?, last_used_at = ? WHERE id = ?",
                (now, now, identity_id),
            )

    async def _mark_profile_corrupted(self, profile_id: int) -> None:
        """Markiert ein Profil-Backup als corrupted."""
        now = datetime.now(LOCAL_TZ).isoformat()
        async with db.transaction() as conn:
            await conn.execute(
                "UPDATE profiles SET backup_status = 'corrupted', updated_at = ? "
                "WHERE id = ?",
                (now, profile_id),
            )
        logger.warning("Profil %d Backup als corrupted markiert", profile_id)


# =============================================================================
# Hilfsfunktionen
# =============================================================================

def _now_ms() -> int:
    """Aktuelle Zeit in Millisekunden."""
    return int(datetime.now(LOCAL_TZ).timestamp() * 1000)
