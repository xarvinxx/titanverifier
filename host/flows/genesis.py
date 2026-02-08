"""
Project Titan — Genesis Flow (Cold Start / New Account)
=========================================================

TITAN_CONTEXT.md §3C — FLOW 1: GENESIS

Erzeugt eine komplett neue Identität von Grund auf.
Dieser Flow ist stateless und atomar: Entweder alles klappt,
oder die Identität wird als 'corrupted' markiert.

Zwingender Ablauf (7 Schritte):
  1. STERILIZE — Deep Clean (pm clear TikTok + GMS)
  2. GENERATE  — Neue O2-DE Identität generieren
  3. PERSIST   — In DB speichern (Status: 'active')
  4. INJECT    — Bridge-Datei auf Gerät schreiben
  5. HARD RESET — adb reboot + warten auf sys.boot_completed
  6. NETWORK   — Flugmodus AN → 12s Lease-Wait → Flugmodus AUS
  7. AUDIT     — Device-Audit. Bei Score < 100% → Status 'corrupted'

Fehlerbehandlung:
  - Bei ADB-Fehler in Schritt 1-4: Rollback (Identity löschen)
  - Bei Fehler in Schritt 5-7: Identity bleibt, wird als corrupted markiert
  - Der Flow loggt jeden Schritt detailliert
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from host.adb.client import ADBClient, ADBError
from host.config import TIMING
from host.database import db
from host.engine.auditor import AuditResult, TitanAuditor
from host.engine.identity_engine import IdentityGenerator
from host.engine.injector import TitanInjector
from host.engine.network import NetworkChecker
from host.engine.shifter import TitanShifter
from host.models.identity import IdentityRead, IdentityStatus

logger = logging.getLogger("titan.flows.genesis")


# =============================================================================
# Flow-Ergebnis
# =============================================================================

class FlowStepStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class FlowStep:
    """Ein einzelner Schritt im Flow."""
    name: str
    status: FlowStepStatus = FlowStepStatus.PENDING
    detail: str = ""
    duration_ms: int = 0


@dataclass
class GenesisResult:
    """Ergebnis des Genesis-Flows."""
    success: bool = False
    identity_id: Optional[int] = None
    identity_name: str = ""
    serial: str = ""
    steps: list[FlowStep] = field(default_factory=list)
    audit: Optional[AuditResult] = None
    error: Optional[str] = None
    started_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    finished_at: Optional[str] = None
    duration_ms: int = 0

    @property
    def step_summary(self) -> str:
        parts = []
        for s in self.steps:
            icon = {"success": "+", "failed": "!", "skipped": "-"}.get(s.status.value, "?")
            parts.append(f"[{icon}] {s.name}")
        return " | ".join(parts)


# =============================================================================
# Genesis Flow
# =============================================================================

class GenesisFlow:
    """
    Cold-Start Flow: Erzeugt eine komplett neue Identität.

    Usage:
        adb = ADBClient()
        flow = GenesisFlow(adb)
        result = await flow.execute("DE_Berlin_001", notes="Test")
        print(result.step_summary)
    """

    STEP_NAMES = [
        "Sterilize",
        "Generate",
        "Persist",
        "Inject",
        "Hard Reset",
        "Network Init",
        "Audit",
    ]

    def __init__(self, adb: ADBClient):
        self._adb = adb
        self._generator = IdentityGenerator()
        self._injector = TitanInjector(adb)
        self._shifter = TitanShifter(adb)
        self._auditor = TitanAuditor(adb)
        self._network = NetworkChecker(adb)

    async def execute(
        self,
        name: str,
        notes: Optional[str] = None,
    ) -> GenesisResult:
        """
        Führt den vollständigen Genesis-Flow aus.

        Args:
            name:  Anzeigename für die neue Identität
            notes: Optionale Notizen

        Returns:
            GenesisResult mit Schritt-Details und Audit-Ergebnis
        """
        result = GenesisResult(identity_name=name)
        result.steps = [FlowStep(name=n) for n in self.STEP_NAMES]
        flow_start = _now_ms()

        identity: Optional[IdentityRead] = None
        db_identity_id: Optional[int] = None

        logger.info("=" * 60)
        logger.info("  GENESIS FLOW: %s", name)
        logger.info("=" * 60)

        try:
            # =================================================================
            # Schritt 1: STERILIZE
            # =================================================================
            step = result.steps[0]
            step.status = FlowStepStatus.RUNNING
            step_start = _now_ms()

            logger.info("[1/7] Sterilize: Deep Clean...")
            clean_results = await self._shifter.deep_clean()
            success_count = sum(1 for v in clean_results.values() if v)

            step.status = FlowStepStatus.SUCCESS
            step.detail = f"{success_count}/{len(clean_results)} Operationen"
            step.duration_ms = _now_ms() - step_start
            logger.info("[1/7] Sterilize: OK (%s)", step.detail)

            # =================================================================
            # Schritt 2: GENERATE
            # =================================================================
            step = result.steps[1]
            step.status = FlowStepStatus.RUNNING
            step_start = _now_ms()

            logger.info("[2/7] Generate: Neue O2-DE Identität...")
            identity = self._generator.generate_new(name, notes=notes)
            result.serial = identity.serial

            step.status = FlowStepStatus.SUCCESS
            step.detail = f"serial={identity.serial} imei1={identity.imei1[:8]}..."
            step.duration_ms = _now_ms() - step_start
            logger.info("[2/7] Generate: OK (serial=%s)", identity.serial)

            # =================================================================
            # Schritt 3: PERSIST
            # =================================================================
            step = result.steps[2]
            step.status = FlowStepStatus.RUNNING
            step_start = _now_ms()

            logger.info("[3/7] Persist: In DB speichern (Status: active)...")
            db_identity_id = await self._persist_identity(identity)
            result.identity_id = db_identity_id

            step.status = FlowStepStatus.SUCCESS
            step.detail = f"id={db_identity_id}"
            step.duration_ms = _now_ms() - step_start
            logger.info("[3/7] Persist: OK (id=%d)", db_identity_id)

            # =================================================================
            # Schritt 4: INJECT
            # =================================================================
            step = result.steps[3]
            step.status = FlowStepStatus.RUNNING
            step_start = _now_ms()

            logger.info("[4/7] Inject: Bridge-Datei schreiben...")
            await self._injector.inject(identity, label=name, distribute=True)
            await self._injector.remove_kill_switch()

            step.status = FlowStepStatus.SUCCESS
            step.detail = "Bridge + Distribution + Kill-Switch entfernt"
            step.duration_ms = _now_ms() - step_start
            logger.info("[4/7] Inject: OK")

            # =================================================================
            # Schritt 5: HARD RESET
            # =================================================================
            step = result.steps[4]
            step.status = FlowStepStatus.RUNNING
            step_start = _now_ms()

            logger.info("[5/7] Hard Reset: adb reboot...")
            await self._adb.reboot()

            logger.info("[5/7] Warte auf Boot (unbegrenzt, pollt alle %ds)...", TIMING.BOOT_POLL_INTERVAL)
            booted = await self._adb.wait_for_device(
                timeout=TIMING.BOOT_WAIT_SECONDS,
                poll_interval=TIMING.BOOT_POLL_INTERVAL,
            )

            if not booted:
                step.status = FlowStepStatus.FAILED
                step.detail = "Boot-Timeout"
                step.duration_ms = _now_ms() - step_start
                raise ADBError("Gerät nicht gebootet (Timeout)")

            # Post-Boot Settle: Warten bis alle Services initialisiert sind
            logger.info(
                "[5/7] Boot erkannt — warte %ds bevor Unlock...",
                TIMING.POST_BOOT_SETTLE_SECONDS,
            )
            await asyncio.sleep(TIMING.POST_BOOT_SETTLE_SECONDS)

            # Gerät entsperren
            await self._adb.unlock_device()

            boot_secs = (_now_ms() - step_start) / 1000
            step.status = FlowStepStatus.SUCCESS
            step.detail = f"Boot + Unlock in {boot_secs:.1f}s"
            step.duration_ms = _now_ms() - step_start
            logger.info("[5/7] Hard Reset: OK (%s)", step.detail)

            # =================================================================
            # Schritt 6: NETWORK INIT
            # =================================================================
            step = result.steps[5]
            step.status = FlowStepStatus.RUNNING
            step_start = _now_ms()

            logger.info("[6/7] Network Init: Flugmodus-Cycle + IP-Audit...")
            await self._airplane_mode_cycle()

            # Warte auf O2-Mobilfunk-Stabilisierung
            logger.info(
                "[6/7] Warte %ds auf Mobilfunk-Stabilisierung...",
                TIMING.IP_AUDIT_WAIT_SECONDS,
            )
            await asyncio.sleep(TIMING.IP_AUDIT_WAIT_SECONDS)

            # IP-Check via ares_curl (DNS-Bypass)
            ip_result = await self._network.get_public_ip()
            if ip_result.success:
                step.status = FlowStepStatus.SUCCESS
                step.detail = (
                    f"Flugmodus-Cycle OK | "
                    f"Öffentliche IP: {ip_result.ip} (via {ip_result.service})"
                )
                logger.info("[6/7] Network Init: IP = %s (via %s)", ip_result.ip, ip_result.service)
            else:
                step.status = FlowStepStatus.SUCCESS  # Nicht-kritisch
                step.detail = (
                    f"Flugmodus-Cycle OK | "
                    f"IP-Check fehlgeschlagen: {ip_result.error}"
                )
                logger.warning("[6/7] IP-Check fehlgeschlagen: %s", ip_result.error)

            step.duration_ms = _now_ms() - step_start

            # =================================================================
            # Schritt 7: AUDIT
            # =================================================================
            step = result.steps[6]
            step.status = FlowStepStatus.RUNNING
            step_start = _now_ms()

            logger.info("[7/7] Audit: Device prüfen...")
            audit = await self._auditor.audit_device(identity)
            result.audit = audit

            if audit.passed:
                step.status = FlowStepStatus.SUCCESS
                step.detail = f"Score: {audit.score_percent}% — PERFEKT"
                logger.info("[7/7] Audit: PASS (%d%%)", audit.score_percent)
            else:
                step.status = FlowStepStatus.FAILED
                step.detail = (
                    f"Score: {audit.score_percent}% — "
                    f"{audit.failed_checks} Check(s) fehlgeschlagen"
                )
                logger.warning(
                    "[7/7] Audit: FAIL (%d%%) — markiere als corrupted",
                    audit.score_percent,
                )
                # Identität als corrupted markieren
                if db_identity_id:
                    await self._update_identity_status(
                        db_identity_id, IdentityStatus.CORRUPTED,
                    )

            step.duration_ms = _now_ms() - step_start

            # =================================================================
            # Ergebnis
            # =================================================================
            all_critical_passed = all(
                s.status == FlowStepStatus.SUCCESS
                for s in result.steps
            )
            result.success = all_critical_passed

        except ADBError as e:
            # ADB-Fehler: Aktuellen Step als FAILED markieren
            for step in result.steps:
                if step.status == FlowStepStatus.RUNNING:
                    step.status = FlowStepStatus.FAILED
                    step.detail = str(e)
                    break

            # Restliche Steps als SKIPPED markieren
            for step in result.steps:
                if step.status == FlowStepStatus.PENDING:
                    step.status = FlowStepStatus.SKIPPED

            result.error = str(e)
            logger.error("Genesis Flow ADB-Fehler: %s", e)

            # Rollback: Wenn Identity in DB gespeichert aber Injection fehlgeschlagen
            if db_identity_id and not any(
                s.name == "Inject" and s.status == FlowStepStatus.SUCCESS
                for s in result.steps
            ):
                await self._update_identity_status(
                    db_identity_id, IdentityStatus.CORRUPTED,
                )
                logger.warning("Identity %d als corrupted markiert (Rollback)", db_identity_id)

        except Exception as e:
            result.error = f"Unerwarteter Fehler: {e}"
            logger.error("Genesis Flow Fehler: %s", e, exc_info=True)

            for step in result.steps:
                if step.status == FlowStepStatus.RUNNING:
                    step.status = FlowStepStatus.FAILED
                    step.detail = str(e)
                elif step.status == FlowStepStatus.PENDING:
                    step.status = FlowStepStatus.SKIPPED

        finally:
            result.finished_at = datetime.now(timezone.utc).isoformat()
            result.duration_ms = _now_ms() - flow_start

            logger.info("=" * 60)
            logger.info(
                "  GENESIS %s: %s (%d ms)",
                "ERFOLG" if result.success else "FEHLGESCHLAGEN",
                name,
                result.duration_ms,
            )
            logger.info("  %s", result.step_summary)
            logger.info("=" * 60)

        return result

    # =========================================================================
    # Interne Methoden
    # =========================================================================

    async def _persist_identity(self, identity: IdentityRead) -> int:
        """
        Speichert die Identität in der Datenbank mit Status 'active'.

        Setzt alle anderen aktiven Identitäten auf 'ready' zurück
        (nur eine kann gleichzeitig aktiv sein).

        Returns:
            Die neue DB-ID der Identität
        """
        async with db.transaction() as conn:
            # Alle bisherigen 'active' Identitäten deaktivieren
            await conn.execute(
                "UPDATE identities SET status = 'ready', updated_at = ? "
                "WHERE status = 'active'",
                (datetime.now(timezone.utc).isoformat(),),
            )

            # Neue Identität einfügen
            cursor = await conn.execute(
                """INSERT INTO identities (
                    name, status, notes,
                    serial, boot_serial, imei1, imei2,
                    gsf_id, android_id, wifi_mac, widevine_id,
                    imsi, sim_serial, operator_name, phone_number,
                    sim_operator, sim_operator_name, voicemail_number,
                    build_id, build_fingerprint, security_patch,
                    created_at, last_used_at
                ) VALUES (
                    ?, 'active', ?,
                    ?, ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?,
                    ?, ?, ?,
                    ?, ?
                )""",
                (
                    identity.name, identity.notes,
                    identity.serial, identity.boot_serial,
                    identity.imei1, identity.imei2,
                    identity.gsf_id, identity.android_id,
                    identity.wifi_mac, identity.widevine_id,
                    identity.imsi, identity.sim_serial,
                    identity.operator_name, identity.phone_number,
                    identity.sim_operator, identity.sim_operator_name,
                    identity.voicemail_number,
                    identity.build_id, identity.build_fingerprint,
                    identity.security_patch,
                    datetime.now(timezone.utc).isoformat(),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )

            return cursor.lastrowid

    async def _update_identity_status(
        self, identity_id: int, status: IdentityStatus,
    ) -> None:
        """Aktualisiert den Status einer Identität in der DB."""
        async with db.transaction() as conn:
            await conn.execute(
                "UPDATE identities SET status = ?, updated_at = ? WHERE id = ?",
                (status.value, datetime.now(timezone.utc).isoformat(), identity_id),
            )

    async def _airplane_mode_cycle(self) -> None:
        """
        Flugmodus-Cycle für O2-Lease-Reset.

        TITAN_CONTEXT.md §3C FLOW 1, Schritt 4:
          Airplane Mode ON → 12 Sekunden warten → Airplane Mode OFF

        Dies zwingt das Modem, eine neue IP-Lease vom O2-Netz anzufordern,
        wodurch die alte Tracking-Session getrennt wird.
        """
        # Flugmodus AN
        await self._adb.shell(
            "settings put global airplane_mode_on 1", root=True,
        )
        await self._adb.shell(
            "am broadcast -a android.intent.action.AIRPLANE_MODE --ez state true",
            root=True,
        )
        logger.info("Flugmodus: AN")

        # Lease-Wait (12 Sekunden — aus TITAN_CONTEXT.md)
        await asyncio.sleep(TIMING.AIRPLANE_MODE_LEASE_SECONDS)

        # Flugmodus AUS
        await self._adb.shell(
            "settings put global airplane_mode_on 0", root=True,
        )
        await self._adb.shell(
            "am broadcast -a android.intent.action.AIRPLANE_MODE --ez state false",
            root=True,
        )
        logger.info("Flugmodus: AUS (nach %ds Lease-Wait)", TIMING.AIRPLANE_MODE_LEASE_SECONDS)

        # Kurz warten bis Netzwerk wieder steht
        await asyncio.sleep(3)


# =============================================================================
# Hilfsfunktionen
# =============================================================================

def _now_ms() -> int:
    """Aktuelle Zeit in Millisekunden (für Duration-Tracking)."""
    return int(datetime.now(timezone.utc).timestamp() * 1000)
