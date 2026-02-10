"""
Project Titan — Genesis Flow (Cold Start / New Account) v3.0
==============================================================

TITAN_CONTEXT.md §3C — FLOW 1: GENESIS

Erzeugt eine komplett neue Identität von Grund auf.
Dieser Flow ist stateless und atomar: Entweder alles klappt,
oder die Identität wird als 'corrupted' markiert.

Zwingender Ablauf (9 Schritte):
  1. STERILIZE      — Deep Clean (pm clear TikTok + GMS + Account-DBs + chmod 777)
  2. GENERATE       — Neue O2-DE Identität (GSF-ID = Platzhalter!)
  3. PERSIST        — In DB speichern (Status: 'active') + Auto-Profil
  4. INJECT         — Bridge + PIF + Namespace-Nuke + Kill-Switch (2080-konform)
  5. HARD RESET     — Robust Reboot (ADBError tolerant) + 15s Pre-Wait + Boot-Poll
  6. NETWORK        — Flugmodus AN → 12s Lease-Wait → Flugmodus AUS + IP-Check
  7. GMS READY      — Finsky Kill + MinuteMaid + Kickstart + GSF-ID Wait → Sync
  8. CAPTURE STATE  — Baseline-Trigger: Quick-Audit → 60s Retry → Golden Baseline
  9. AUDIT          — Full Device-Audit. Bei Score < 100% → Status 'corrupted'

v3.0 — "Golden Baseline" (State-Layering):
  Nach pm clear GMS braucht GMS 10-30 Min für Re-Checkin.
  Sobald die GSF-ID da ist:
    1. Echte GSF-ID in titan.db + Bridge-Datei zurückschreiben (Hardware=Software)
    2. GMS-State als "Golden Baseline" sichern (capture_gms_state)
  Beim Switch: Kein pm clear GMS mehr nötig → sofort Play Integrity bereit.

  pm clear GMS wird NUR im Genesis ausgeführt (Initial Seed), NICHT im Switch.

DB-Tracking (v2.0):
  - Flow-History: Eintrag bei Start, Updates bei jedem Schritt
  - IP-History: Erkannte IP in ip_history + identities.last_public_ip
  - Audit-History: Audit-Ergebnis in audit_history + identities.last_audit_*
  - Auto-Profil: Nach Persist automatisch Profil in profiles erstellen
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional

from host.adb.client import ADBClient, ADBError
from host.adb.device import DeviceHelper
from host.config import LOCAL_TZ, TIMING
from host.database import db
from host.engine.auditor import AuditResult, TitanAuditor
from host.engine.db_ops import (
    create_flow_history,
    create_profile_auto,
    record_audit,
    record_ip,
    update_flow_history,
    update_identity_audit,
    update_identity_network,
)
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
    profile_id: Optional[int] = None
    identity_name: str = ""
    serial: str = ""
    steps: list[FlowStep] = field(default_factory=list)
    audit: Optional[AuditResult] = None
    public_ip: Optional[str] = None
    ip_service: Optional[str] = None
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
        "GMS Ready",
        "Capture State",        # *** NEU v3.0 *** Golden Baseline
        "Audit",
    ]

    def __init__(self, adb: ADBClient):
        self._adb = adb
        self._generator = IdentityGenerator()
        self._injector = TitanInjector(adb)
        self._shifter = TitanShifter(adb)
        self._auditor = TitanAuditor(adb)
        self._network = NetworkChecker(adb)
        self._device = DeviceHelper(adb)

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
        flow_history_id: Optional[int] = None

        logger.info("=" * 60)
        logger.info("  GENESIS FLOW: %s", name)
        logger.info("=" * 60)

        # ------------------------------------------------------------------
        # Flow-History: Eintrag erstellen
        # ------------------------------------------------------------------
        try:
            flow_history_id = await create_flow_history(
                flow_type="genesis",
            )
            result.flow_history_id = flow_history_id
        except Exception as e:
            logger.warning("Flow-History Eintrag konnte nicht erstellt werden: %s", e)

        try:
            # =================================================================
            # Schritt 1: STERILIZE (pm clear GMS nur bei Genesis!)
            # =================================================================
            step = result.steps[0]
            step.status = FlowStepStatus.RUNNING
            step_start = _now_ms()

            logger.info("[1/9] Sterilize: Deep Clean (inkl. GMS — Initial Seed)...")
            # v3.0: include_gms=True weil Genesis = Erstinitialisierung
            # Beim Switch wird include_gms=False verwendet (Golden Baseline schützen)
            clean_results = await self._shifter.deep_clean(include_gms=True)
            success_count = sum(1 for v in clean_results.values() if v)

            step.status = FlowStepStatus.SUCCESS
            step.detail = f"{success_count}/{len(clean_results)} Operationen (inkl. GMS)"
            step.duration_ms = _now_ms() - step_start
            logger.info("[1/9] Sterilize: OK (%s)", step.detail)

            # =================================================================
            # Schritt 2: GENERATE
            # =================================================================
            step = result.steps[1]
            step.status = FlowStepStatus.RUNNING
            step_start = _now_ms()

            logger.info("[2/9] Generate: Neue O2-DE Identität...")
            identity = self._generator.generate_new(name, notes=notes)
            result.serial = identity.serial

            # PASSIVE SEEDING: Die generierte GSF-ID ist ein Platzhalter.
            # In Schritt 7 (GMS Ready) wartet das Gerät auf eine echte GSF-ID
            # vom Google-Checkin. Erst dann wird die Bridge-Datei gepatcht,
            # damit Hardware (GMS-DB) und Software (Bridge) identisch sind.
            logger.info(
                "[2/9] Generate: GSF-ID Platzhalter: %s...%s (wird in Schritt 7 durch echte ID ersetzt)",
                identity.gsf_id[:4], identity.gsf_id[-4:],
            )

            step.status = FlowStepStatus.SUCCESS
            step.detail = f"serial={identity.serial} imei1={identity.imei1[:8]}... (gsf_id=PLACEHOLDER)"
            step.duration_ms = _now_ms() - step_start
            logger.info("[2/9] Generate: OK (serial=%s)", identity.serial)

            # Flow-History: Serial + IMEI speichern
            if flow_history_id:
                await update_flow_history(
                    flow_history_id,
                    generated_serial=identity.serial,
                    generated_imei=identity.imei1,
                )

            # =================================================================
            # Schritt 3: PERSIST + AUTO-PROFIL
            # =================================================================
            step = result.steps[2]
            step.status = FlowStepStatus.RUNNING
            step_start = _now_ms()

            logger.info("[3/9] Persist: In DB speichern (Status: active)...")
            db_identity_id = await self._persist_identity(identity)
            result.identity_id = db_identity_id

            # Flow-History: Identity-ID setzen
            if flow_history_id:
                async with db.transaction() as conn:
                    await conn.execute(
                        "UPDATE flow_history SET identity_id = ? WHERE id = ?",
                        (db_identity_id, flow_history_id),
                    )

            # Auto-Profil erstellen
            try:
                profile_id = await create_profile_auto(
                    identity_id=db_identity_id,
                    name=name,
                )
                result.profile_id = profile_id
                logger.info("[3/9] Auto-Profil erstellt: id=%d", profile_id)

                # Flow-History: Profile-ID setzen
                if flow_history_id:
                    async with db.transaction() as conn:
                        await conn.execute(
                            "UPDATE flow_history SET profile_id = ? WHERE id = ?",
                            (profile_id, flow_history_id),
                        )
            except Exception as e:
                logger.warning("[3/9] Auto-Profil Fehler (nicht-kritisch): %s", e)

            step.status = FlowStepStatus.SUCCESS
            step.detail = f"identity_id={db_identity_id}, profile_id={result.profile_id}"
            step.duration_ms = _now_ms() - step_start
            logger.info("[3/9] Persist: OK (%s)", step.detail)

            # =================================================================
            # Schritt 4: INJECT (2080-konform: Bridge → PIF → Nuke → Fix)
            # =================================================================
            # v3.2 Reihenfolge:
            #   4a. Hardware-IDs via TitanBridge setzen
            #   4b. pif.json (Software-Fingerprint) injizieren
            #   4c. Namespace-Nuke: alte Auth-Token vernichten
            #   4d. Kill-Switch entfernen
            #
            # PIF MUSS vor dem Reboot gesetzt sein, damit beim Boot
            # der Fingerprint sofort greift. Der Nuke räumt veraltete
            # GMS-States auf, damit der frische Checkin sauber läuft.
            # =================================================================
            step = result.steps[3]
            step.status = FlowStepStatus.RUNNING
            step_start = _now_ms()

            # 4a. Hardware-IDs: Bridge-Datei schreiben + verteilen
            logger.info("[4/9] Inject: Bridge-Datei schreiben...")
            await self._injector.inject(identity, label=name, distribute=True)

            # 4b. PIF Fingerprint: /data/adb/pif.json pushen
            # Wähle den Build-Index passend zum gewählten Build-Fingerprint
            logger.info("[4/9] PIF: Software-Fingerprint injizieren...")
            pif_ok = await self._injector.inject_pif_fingerprint()
            if pif_ok:
                logger.info("[4/9] PIF: OK → MEETS_BASIC_INTEGRITY vorbereitet")
            else:
                logger.warning("[4/9] PIF: WARN — pif.json konnte nicht geschrieben werden")

            # 4c. Namespace-Nuke: Alte Auth-Token + DroidGuard-Cache vernichten
            # Verwendet su -M -c (KernelSU Mount-Master) für SELinux-Bypass
            logger.info("[4/9] Namespace-Nuke: GMS Auth-Reset...")
            nuke_results = await self._injector.namespace_nuke()
            nuke_success = sum(1 for v in nuke_results.values() if v)
            logger.info("[4/9] Namespace-Nuke: %d/%d OK", nuke_success, len(nuke_results))

            # 4d. Kill-Switch entfernen (aktiviert Hooks)
            await self._injector.remove_kill_switch()

            step.status = FlowStepStatus.SUCCESS
            step.detail = (
                f"Bridge + PIF({'OK' if pif_ok else 'WARN'}) + "
                f"Nuke({nuke_success}/{len(nuke_results)}) + Kill-Switch entfernt"
            )
            step.duration_ms = _now_ms() - step_start
            logger.info("[4/9] Inject: OK (%s)", step.detail)

            # =================================================================
            # Schritt 5: HARD RESET
            # =================================================================
            step = result.steps[4]
            step.status = FlowStepStatus.RUNNING
            step_start = _now_ms()

            logger.info("[5/9] Hard Reset: adb reboot...")

            # Robust Reboot: ADB-Verbindung trennt sich beim Reboot sofort —
            # das ist erwartetes Verhalten, kein Fehler. Timeout auf 30s setzen
            # und ADBError lautlos abfangen.
            try:
                await self._adb.reboot()
            except ADBError as e:
                # Erwarteter Verbindungsabbruch beim Reboot — kein Fehler
                logger.info("[5/9] Reboot gesendet (ADB-Trennung erwartet: %s)", e)

            # Pre-Wait: 15s warten bevor wir anfangen zu pollen.
            # Das Gerät braucht Zeit um den Bootloader zu passieren und
            # den ADB-Daemon neu zu starten. Ohne diese Pause pollt
            # wait_for_device sinnlos gegen ein offline Gerät.
            logger.info("[5/9] Pre-Wait: 15s bevor Boot-Polling startet...")
            await asyncio.sleep(15)

            logger.info("[5/9] Warte auf Boot (unbegrenzt, pollt alle %ds)...", TIMING.BOOT_POLL_INTERVAL)
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
                "[5/9] Boot erkannt — warte %ds bevor Popup-Hammer...",
                TIMING.POST_BOOT_SETTLE_SECONDS,
            )
            await asyncio.sleep(TIMING.POST_BOOT_SETTLE_SECONDS)

            # =============================================================
            # POPUP HAMMER — VOR dem Unlock!
            # =============================================================
            # Das "Internal Problem with your device" Popup (Vendor
            # Mismatch) blockiert den Touchscreen komplett. Der Unlock-
            # Swipe funktioniert nicht, solange das Popup drauf ist.
            # Deshalb: Erst Popup weg, DANN unlock.
            # =============================================================
            logger.info("[5/9] Popup Hammer: Fehler-Dialoge unterdrücken...")

            # 1. Settings-basierte Suppression (Versuch 1 — sofort)
            try:
                await self._adb.shell(
                    "settings put global hide_error_dialogs 1", root=True, timeout=5,
                )
            except (ADBError, Exception):
                pass

            # 2. UI-Blind-Klicker (Versuch 2 — The Hammer)
            # 3 Runden: TAB → ENTER → BACK
            # TAB: Fokus auf "OK" Button verschieben
            # ENTER: Button bestätigen
            # BACK: Falls noch ein Dialog übrig ist
            for round_nr in range(3):
                try:
                    await self._adb.shell("input keyevent 61", timeout=3)   # TAB
                    await asyncio.sleep(0.5)
                    await self._adb.shell("input keyevent 66", timeout=3)   # ENTER
                    await asyncio.sleep(0.5)
                    await self._adb.shell("input keyevent 4", timeout=3)    # BACK
                    await asyncio.sleep(1)
                except (ADBError, Exception):
                    pass  # Nicht-kritisch, weiter versuchen

            logger.info("[5/9] Popup Hammer abgeschlossen — Unlock starten...")

            # Gerät entsperren (Swipe — jetzt ohne Popup-Blocker)
            await self._adb.unlock_device()

            # Nochmal suppress_system_dialogs als Sicherheitsnetz
            # (setzt auch device_provisioned + user_setup_complete)
            await self._device.suppress_system_dialogs()

            boot_secs = (_now_ms() - step_start) / 1000
            step.status = FlowStepStatus.SUCCESS
            step.detail = f"Boot + Popup-Hammer + Unlock in {boot_secs:.1f}s"
            step.duration_ms = _now_ms() - step_start
            logger.info("[5/9] Hard Reset: OK (%s)", step.detail)

            # =================================================================
            # Schritt 6: NETWORK INIT + IP-TRACKING
            # =================================================================
            step = result.steps[5]
            step.status = FlowStepStatus.RUNNING
            step_start = _now_ms()

            logger.info("[6/9] Network Init: Flugmodus-Cycle + IP-Audit...")
            await self._airplane_mode_cycle()

            # Warte auf O2-Mobilfunk-Stabilisierung
            logger.info(
                "[6/9] Warte %ds auf Mobilfunk-Stabilisierung...",
                TIMING.IP_AUDIT_WAIT_SECONDS,
            )
            await asyncio.sleep(TIMING.IP_AUDIT_WAIT_SECONDS)

            # IP-Check via ares_curl (DNS-Bypass)
            ip_result = await self._network.get_public_ip()
            if ip_result.success:
                result.public_ip = ip_result.ip
                result.ip_service = ip_result.service

                step.status = FlowStepStatus.SUCCESS
                step.detail = (
                    f"Flugmodus-Cycle OK | "
                    f"Öffentliche IP: {ip_result.ip} (via {ip_result.service})"
                )
                logger.info("[6/9] Network Init: IP = %s (via %s)", ip_result.ip, ip_result.service)

                # DB: IP in identities + ip_history speichern
                try:
                    if db_identity_id:
                        await update_identity_network(
                            db_identity_id, ip_result.ip, ip_result.service,
                        )
                        await record_ip(
                            public_ip=ip_result.ip,
                            identity_id=db_identity_id,
                            profile_id=result.profile_id,
                            ip_service=ip_result.service,
                            connection_type="mobile_o2",
                            flow_type="genesis",
                        )
                    # Flow-History: IP
                    if flow_history_id:
                        await update_flow_history(
                            flow_history_id,
                            public_ip=ip_result.ip,
                            ip_service=ip_result.service,
                        )
                except Exception as e:
                    logger.warning("IP-DB-Update fehlgeschlagen: %s", e)
            else:
                step.status = FlowStepStatus.SUCCESS  # Nicht-kritisch
                step.detail = (
                    f"Flugmodus-Cycle OK | "
                    f"IP-Check fehlgeschlagen: {ip_result.error}"
                )
                logger.warning("[6/9] IP-Check fehlgeschlagen: %s", ip_result.error)

            step.duration_ms = _now_ms() - step_start

            # =================================================================
            # Schritt 7: GMS READY (Network-First + Kickstart + Smart Wait)
            # =================================================================
            # v3.0 NETWORK-FIRST: GMS-Kickstart darf ERST starten, wenn
            # eine aktive Internetverbindung bestätigt ist. Ohne Netz kann
            # GMS keinen Checkin durchführen → GSF-ID wird nie generiert.
            #
            # ANTI-RATE-LIMIT: Nach pm clear GMS fehlen DroidGuard-Module,
            # GSF-ID und Integrity-Token-Keys. Anstatt blind die Play
            # Integrity API zu pingen (→ Bot-Detection Risiko), warten
            # wir lokal bis die GSF-ID regeneriert wurde.
            # =================================================================
            step = result.steps[6]
            step.status = FlowStepStatus.RUNNING
            step_start = _now_ms()

            logger.info("[7/9] GMS Ready: Network-First Gate + Kickstart + Smart Wait...")

            # =========================================================
            # v3.0 NETWORK-FIRST GATE
            # =========================================================
            # Prüfe Konnektivität BEVOR wir GMS kickstarten.
            # Wenn kein Netz: warten + erneut prüfen, max 2 Versuche.
            # =========================================================
            connectivity_ok = False
            if result.public_ip:
                # IP wurde in Schritt 6 bestätigt → Netz steht sicher
                connectivity_ok = True
                logger.info("[7/9] Network-First: IP bereits bestätigt (%s)", result.public_ip)
            else:
                # IP-Check in Schritt 6 fehlgeschlagen → explizite Prüfung
                logger.info("[7/9] Network-First: Keine IP — prüfe Konnektivität...")
                for attempt in range(3):
                    connectivity_ok = await self._device.check_connectivity()
                    if connectivity_ok:
                        logger.info("[7/9] Network-First: Konnektivität bestätigt (Versuch %d)", attempt + 1)
                        break
                    logger.warning(
                        "[7/9] Network-First: Kein Netz (Versuch %d/3) — warte %ds...",
                        attempt + 1, TIMING.NETWORK_CONNECTIVITY_WAIT,
                    )
                    await asyncio.sleep(TIMING.NETWORK_CONNECTIVITY_WAIT)

                if not connectivity_ok:
                    logger.error("[7/9] Network-First: Kein Netzwerk nach 3 Versuchen — Kickstart trotzdem versuchen")

            # =========================================================
            # GMS RECOVERY LAYER v3.1
            # Reihenfolge: Finsky Kill → MinuteMaid Repair → Kickstart
            #
            # 1. kill_finsky():          Hängende TLS-Handshakes beenden
            # 2. reset_gms_internal():   Auth-Lockdown aufheben (MinuteMaid)
            # 3. kickstart_gms():        8-Stufen-Checkin-Trigger
            # =========================================================

            # A) Finsky Kill: Play Store hart beenden (am kill + killall -9)
            # Verhindert, dass alte Zertifikats-Abfragen den GSF-Wait blockieren
            logger.info("[7/9] Finsky Kill: Play Store hart beenden...")
            await self._device.kill_finsky()

            # B) GMS Core Repair: MinuteMaid Auth-Reparatur starten
            # Hebt den GMS-Lockdown auf, der Play-Store-Login unmöglich macht
            logger.info("[7/9] GMS Core Repair: MinuteMaid starten...")
            repair_ok = await self._device.reset_gms_internal()
            if repair_ok:
                # MinuteMaid 3s arbeiten lassen bevor Kickstart
                await asyncio.sleep(3)
            else:
                logger.info("[7/9] MinuteMaid nicht verfügbar — Kickstart trotzdem fortsetzen")

            # C) Kickstart: 8-Stufen GMS-Checkin anstoßen (mit reparierter Auth-Kette)
            kickstart_ok = await self._device.kickstart_gms()

            # Kurz warten nach Kickstart damit GMS den Intent verarbeitet
            await asyncio.sleep(TIMING.GMS_KICKSTART_SETTLE_SECONDS)

            # D) Passive Sensor: Warte auf lokale GSF-ID (KEIN Netzwerk!)
            gsf_result = await self._device.wait_for_gsf_id()

            # Variable für die echte GSF-ID als Dezimal (wird in Schritt 8 gebraucht)
            # Die DB und Bridge speichern die GSF-ID als 17-Dezimalziffern
            real_gsf_id: str | None = None

            if gsf_result.success:
                real_gsf_id = gsf_result.gsf_id_decimal or gsf_result.gsf_id
                step.status = FlowStepStatus.SUCCESS
                step.detail = (
                    f"GSF-ID bereit nach {gsf_result.elapsed_seconds:.0f}s "
                    f"({gsf_result.polls} Polls) | "
                    f"Kickstart: {'OK' if kickstart_ok else 'WARN'}"
                )
                logger.info(
                    "[7/9] GMS Ready: GSF-ID nach %.0fs — Capture + Audit folgen",
                    gsf_result.elapsed_seconds,
                )

                # =========================================================
                # *** NEU v3.0 *** GSF-ID SYNC (Hardware = Software)
                # =========================================================
                # Die echte GSF-ID vom GMS-Checkin zurückschreiben in:
                #   1. titan.db (identities.gsf_id)
                #   2. Bridge-Datei auf dem Gerät
                # Damit Zygisk exakt die ID spoofed, die GMS kennt.
                # =========================================================
                if real_gsf_id and db_identity_id:
                    try:
                        # 1. DB-Update: Echte GSF-ID in identities-Tabelle
                        async with db.transaction() as conn:
                            await conn.execute(
                                "UPDATE identities SET gsf_id = ?, updated_at = ? "
                                "WHERE id = ?",
                                (
                                    real_gsf_id,
                                    datetime.now(LOCAL_TZ).isoformat(),
                                    db_identity_id,
                                ),
                            )
                        logger.info(
                            "[7/9] GSF-ID Sync DB: %s...%s → identity_id=%d",
                            real_gsf_id[:4], real_gsf_id[-4:], db_identity_id,
                        )

                        # 2. Bridge-Update: Auf dem Gerät patchen
                        await self._injector.update_bridge_gsf_id(real_gsf_id)
                        logger.info("[7/9] GSF-ID Sync Bridge: OK")

                    except Exception as e:
                        logger.warning("[7/9] GSF-ID Sync fehlgeschlagen: %s", e)

            else:
                # GSF-ID Timeout — Audit trotzdem versuchen, aber warnen
                step.status = FlowStepStatus.SUCCESS  # Nicht-kritisch (Audit entscheidet)
                step.detail = (
                    f"GSF-ID Timeout nach {gsf_result.elapsed_seconds:.0f}s — "
                    f"Audit wird trotzdem versucht | "
                    f"Kickstart: {'OK' if kickstart_ok else 'WARN'}"
                )
                logger.warning(
                    "[7/9] GMS Ready: GSF-ID Timeout nach %.0fs — "
                    "Capture State wird übersprungen, Audit trotzdem versucht",
                    gsf_result.elapsed_seconds,
                )

            step.duration_ms = _now_ms() - step_start

            # =================================================================
            # Schritt 8: CAPTURE STATE (Golden Baseline) *** NEU v3.0 ***
            # =================================================================
            # Sichert den aktuellen GMS-State als "Golden Baseline".
            # Dieser Snapshot ist die Basis für alle Switch-Operationen.
            #
            # BASELINE-TRIGGER: Die Golden Baseline darf erst erstellt
            # werden, wenn Basic Integrity (Bridge-Audit) bestätigt ist.
            # Wenn der Quick-Audit fehlschlägt, warten wir 60s damit GMS
            # seine Initialisierung abschließen kann, und prüfen erneut.
            # =================================================================
            step = result.steps[7]
            step.status = FlowStepStatus.RUNNING
            step_start = _now_ms()

            if real_gsf_id:
                # =========================================================
                # BASELINE-TRIGGER: Quick-Audit vor Capture
                # =========================================================
                logger.info("[8/9] Baseline-Trigger: Prüfe Bridge-Integrität vor Capture...")
                integrity_ok = False
                for integrity_attempt in range(2):
                    try:
                        pre_audit = await self._auditor.audit_device(identity)
                        if pre_audit.passed:
                            integrity_ok = True
                            logger.info(
                                "[8/9] Baseline-Trigger: Integrität bestätigt (%d%%)",
                                pre_audit.score_percent,
                            )
                            break
                        else:
                            if integrity_attempt == 0:
                                logger.warning(
                                    "[8/9] Baseline-Trigger: Integrität NICHT bestätigt "
                                    "(%d%%) — warte 60s für GMS-Stabilisierung...",
                                    pre_audit.score_percent,
                                )
                                await asyncio.sleep(60)
                            else:
                                logger.warning(
                                    "[8/9] Baseline-Trigger: Integrität weiterhin %d%% "
                                    "— Capture trotzdem fortsetzen",
                                    pre_audit.score_percent,
                                )
                    except Exception as e:
                        logger.warning("[8/9] Baseline-Trigger Audit fehlgeschlagen: %s", e)
                        if integrity_attempt == 0:
                            await asyncio.sleep(60)

                # Golden Baseline capturen (auch bei imperfekter Integrität)
                logger.info("[8/9] Capture State: Golden Baseline sichern...")
                try:
                    capture_result = await self._shifter.capture_gms_state(
                        profile_name=name,
                        gsf_id=real_gsf_id,
                    )
                    gms_ok = capture_result.get("gms") is not None
                    accounts_ok = capture_result.get("accounts") is not None

                    if gms_ok and accounts_ok:
                        step.status = FlowStepStatus.SUCCESS
                        step.detail = (
                            f"Golden Baseline: GMS + Accounts gesichert"
                            f" | Integrität: {'OK' if integrity_ok else 'DEGRADED'}"
                        )
                        logger.info("[8/9] Capture State: Golden Baseline komplett")
                    elif gms_ok or accounts_ok:
                        step.status = FlowStepStatus.SUCCESS
                        step.detail = (
                            f"Golden Baseline teilweise: "
                            f"GMS={'OK' if gms_ok else 'FAIL'}, "
                            f"Accounts={'OK' if accounts_ok else 'FAIL'}"
                        )
                        logger.warning("[8/9] Capture State: Teilweise (%s)", step.detail)
                    else:
                        step.status = FlowStepStatus.FAILED
                        step.detail = "Golden Baseline: Beide Snapshots fehlgeschlagen"
                        logger.error("[8/9] Capture State: FEHLGESCHLAGEN")

                except Exception as e:
                    step.status = FlowStepStatus.FAILED
                    step.detail = f"Capture Fehler: {e}"
                    logger.error("[8/9] Capture State Fehler: %s", e)
            else:
                # Kein GSF-ID → kein Golden Baseline möglich
                step.status = FlowStepStatus.SKIPPED
                step.detail = "Übersprungen: Keine GSF-ID verfügbar"
                logger.warning("[8/9] Capture State: Übersprungen (keine GSF-ID)")

            step.duration_ms = _now_ms() - step_start

            # =================================================================
            # Schritt 9: AUDIT + AUDIT-TRACKING
            # =================================================================
            step = result.steps[8]
            step.status = FlowStepStatus.RUNNING
            step_start = _now_ms()

            logger.info("[9/9] Audit: Device prüfen...")
            audit = await self._auditor.audit_device(identity)
            result.audit = audit

            # DB: Audit in audit_history + identities speichern
            audit_detail_json = json.dumps(
                [{"name": c.name, "status": c.status.value, "expected": c.expected,
                  "actual": c.actual, "detail": c.detail}
                 for c in audit.checks],
                ensure_ascii=False,
            )

            try:
                if db_identity_id:
                    await update_identity_audit(
                        db_identity_id,
                        score=audit.score_percent,
                        detail=audit_detail_json,
                    )
                    await record_audit(
                        identity_id=db_identity_id,
                        flow_id=flow_history_id,
                        score_percent=audit.score_percent,
                        total_checks=audit.total_checks,
                        passed_checks=audit.passed_checks,
                        failed_checks=audit.failed_checks,
                        checks_json=audit_detail_json,
                    )
                # Flow-History: Audit
                if flow_history_id:
                    await update_flow_history(
                        flow_history_id,
                        audit_score=audit.score_percent,
                        audit_detail=audit_detail_json,
                    )
            except Exception as e:
                logger.warning("Audit-DB-Update fehlgeschlagen: %s", e)

            if audit.passed:
                step.status = FlowStepStatus.SUCCESS
                step.detail = f"Score: {audit.score_percent}% — PERFEKT"
                logger.info("[9/9] Audit: PASS (%d%%)", audit.score_percent)
            else:
                step.status = FlowStepStatus.FAILED
                step.detail = (
                    f"Score: {audit.score_percent}% — "
                    f"{audit.failed_checks} Check(s) fehlgeschlagen"
                )
                logger.warning(
                    "[9/9] Audit: FAIL (%d%%) — markiere als corrupted",
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
                (datetime.now(LOCAL_TZ).isoformat(),),
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
                    created_at, last_used_at, usage_count
                ) VALUES (
                    ?, 'active', ?,
                    ?, ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?,
                    ?, ?, ?,
                    ?, ?, 1
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
                    datetime.now(LOCAL_TZ).isoformat(),
                    datetime.now(LOCAL_TZ).isoformat(),
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
                (status.value, datetime.now(LOCAL_TZ).isoformat(), identity_id),
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
    return int(datetime.now(LOCAL_TZ).timestamp() * 1000)
