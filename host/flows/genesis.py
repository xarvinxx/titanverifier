"""
Project Titan — Genesis Flow (Cold Start / New Account) v3.0
==============================================================

TITAN_CONTEXT.md §3C — FLOW 1: GENESIS

Erzeugt eine komplett neue Identität von Grund auf.
Dieser Flow ist stateless und atomar: Entweder alles klappt,
oder die Identität wird als 'corrupted' markiert.

Zwingender Ablauf (11 Schritte — v5.1):
   1. AIRPLANE MODE  — Flugmodus AN (Netz sofort trennen, ganz am Anfang!)
   2. AUTO-BACKUP    — Optionales Dual-Path Backup des aktiven Profils
   3. STERILIZE      — Deep Clean (pm clear NUR Target-Apps, GMS UNANGETASTET!)
   4. GENERATE       — Neue O2-DE Identität (GSF-ID = final, kein Platzhalter!)
   5. PERSIST        — In DB speichern (Status: 'active') + Auto-Profil
   6. INJECT         — Bridge + Kill-Switch (Flugmodus bereits AN seit Schritt 1)
   7. HARD RESET     — Robust Reboot + 15s Pre-Wait + Boot-Poll + Bridge-Verifikation
   8. NETWORK INIT   — 20s Post-Boot → Flugmodus AUS → Neue IP
   9. GMS READY      — Finsky Kill + MinuteMaid + Kickstart
  10. CAPTURE STATE  — Baseline-Trigger: Quick-Audit → 60s Retry → Golden Baseline
  11. AUDIT          — Full Device-Audit. Bei Score < 100% → Status 'corrupted'

v4.0 — "GMS-Schutz" Architektur:
  GMS/GSF/Vending werden NIEMALS angerührt (kein pm clear, kein namespace_nuke).
  Grund: Das Löschen von GMS-Daten zerstört die Google Trust-Chain:
    - Play Integrity verliert BASIC (nur noch DEVICE)
    - Google-Login bricht ab
    - DroidGuard muss komplett neu attestieren (30-50 Min)
  
  Stattdessen:
    - Hooks spoofen Device-IDs NUR für Target-Apps (TikTok, Instagram, etc.)
    - GMS sieht immer die echten Werte → Trust-Chain bleibt intakt
    - Play Integrity bleibt BASIC + DEVICE durchgehend stabil
    - Google-Account bleibt eingeloggt

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
        "Airplane Mode",        # v5.1: Flugmodus AN (separat, ganz am Anfang)
        "Auto-Backup",          # v5.1: Optionales Backup des aktiven Profils
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
        backup_before: bool = False,
    ) -> GenesisResult:
        """
        Führt den vollständigen Genesis-Flow aus.

        Args:
            name:           Anzeigename für die neue Identität
            notes:          Optionale Notizen
            backup_before:  Wenn True, wird das aktive Profil vor dem
                            Genesis-Flow gesichert (Dual-Path Backup)

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
            # Schritt 1: AIRPLANE MODE ON (v5.1 — ganz am Anfang!)
            # =================================================================
            # Flugmodus SOFORT an — vor Backup, vor Deep Clean, vor allem.
            # Das verhindert jede Netzwerkkommunikation der alten Identität
            # während wir backuppen und sterilisieren.
            # =================================================================
            step = result.steps[0]
            step.status = FlowStepStatus.RUNNING
            step_start = _now_ms()

            logger.info("[1/11] Flugmodus AN (Netz sofort trennen)...")
            await self._adb.shell(
                "settings put global airplane_mode_on 1", root=True,
            )
            await self._adb.shell(
                "am broadcast -a android.intent.action.AIRPLANE_MODE --ez state true",
                root=True,
            )

            step.status = FlowStepStatus.SUCCESS
            step.detail = "Flugmodus AN — Modem getrennt"
            step.duration_ms = _now_ms() - step_start
            logger.info("[1/11] Flugmodus: AN")

            # =================================================================
            # Schritt 2: AUTO-BACKUP (optional — nur wenn backup_before=True)
            # =================================================================
            # v5.1: Sichert das aktive Profil BEVOR wir sterilisieren.
            # Wird nur ausgeführt wenn der User die Checkbox gesetzt hat.
            # Flugmodus ist bereits AN → keine Netzwerk-Leaks während Backup.
            # =================================================================
            step = result.steps[1]
            step.status = FlowStepStatus.RUNNING
            step_start = _now_ms()

            if backup_before:
                logger.info("[2/11] Auto-Backup: Aktives Profil sichern...")
                try:
                    active_profile = await self._find_active_profile()
                    if active_profile:
                        active_name = active_profile["name"]
                        logger.info(
                            "[2/11] Auto-Backup: Profil '%s' (ID %d) wird gesichert...",
                            active_name, active_profile["id"],
                        )
                        backup_result = await self._shifter.backup_tiktok_dual(
                            active_name, timeout=300,
                        )
                        saved = sum(1 for v in backup_result.values() if v is not None)
                        step.status = FlowStepStatus.SUCCESS
                        step.detail = f"Profil '{active_name}': {saved}/2 Komponenten gesichert"
                        logger.info("[2/11] Auto-Backup: %s", step.detail)
                    else:
                        step.status = FlowStepStatus.SKIPPED
                        step.detail = "Kein aktives Profil gefunden (erster Lauf?)"
                        logger.info("[2/11] Auto-Backup: %s", step.detail)
                except Exception as e:
                    # Backup-Fehler ist NICHT kritisch — Genesis fortsetzen!
                    step.status = FlowStepStatus.SUCCESS
                    step.detail = f"Backup-Warnung: {e} (Genesis wird fortgesetzt)"
                    logger.warning("[2/11] Auto-Backup fehlgeschlagen (nicht kritisch): %s", e)
            else:
                step.status = FlowStepStatus.SKIPPED
                step.detail = "Backup-Option nicht aktiviert"
                logger.info("[2/11] Auto-Backup: Übersprungen (nicht aktiviert)")

            step.duration_ms = _now_ms() - step_start

            # =================================================================
            # Schritt 3: STERILIZE (pm clear NUR Target-Apps!)
            # =================================================================
            step = result.steps[2]
            step.status = FlowStepStatus.RUNNING
            step_start = _now_ms()

            logger.info("[3/11] Sterilize: Deep Clean (NUR Target-Apps, GMS bleibt!)...")
            # v4.0: include_gms=False — GMS/GSF/Vending NIEMALS anrühren!
            clean_results = await self._shifter.deep_clean(include_gms=False)
            success_count = sum(1 for v in clean_results.values() if v)

            step.status = FlowStepStatus.SUCCESS
            step.detail = f"{success_count}/{len(clean_results)} Operationen (GMS geschützt)"
            step.duration_ms = _now_ms() - step_start
            logger.info("[3/11] Sterilize: OK (%s)", step.detail)

            # =================================================================
            # Schritt 4: GENERATE
            # =================================================================
            step = result.steps[3]
            step.status = FlowStepStatus.RUNNING
            step_start = _now_ms()

            logger.info("[4/11] Generate: Neue O2-DE Identität...")
            identity = self._generator.generate_new(name, notes=notes)
            result.serial = identity.serial

            # v5.0: Die generierte GSF-ID ist FINAL — kein Platzhalter mehr!
            # Da wir GMS nicht clearen (GMS-Schutz), bleibt die echte GMS
            # GSF-ID immer gleich. Die Hooks spoofen die generierte GSF-ID
            # NUR für Target-Apps → jede Identity hat eine einzigartige GSF-ID.
            logger.info(
                "[4/11] Generate: GSF-ID generiert: %s...%s (v5.0 — FINAL, kein Platzhalter)",
                identity.gsf_id[:4], identity.gsf_id[-4:],
            )

            step.status = FlowStepStatus.SUCCESS
            step.detail = f"serial={identity.serial} imei1={identity.imei1[:8]}... gsf_id={identity.gsf_id[:6]}..."
            step.duration_ms = _now_ms() - step_start
            logger.info("[4/11] Generate: OK (serial=%s)", identity.serial)

            # Flow-History: Serial + IMEI speichern
            if flow_history_id:
                await update_flow_history(
                    flow_history_id,
                    generated_serial=identity.serial,
                    generated_imei=identity.imei1,
                )

            # =================================================================
            # Schritt 5: PERSIST + AUTO-PROFIL
            # =================================================================
            step = result.steps[4]
            step.status = FlowStepStatus.RUNNING
            step_start = _now_ms()

            logger.info("[5/11] Persist: In DB speichern (Status: active)...")
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
                logger.info("[5/11] Auto-Profil erstellt: id=%d", profile_id)

                # Flow-History: Profile-ID setzen
                if flow_history_id:
                    async with db.transaction() as conn:
                        await conn.execute(
                            "UPDATE flow_history SET profile_id = ? WHERE id = ?",
                            (profile_id, flow_history_id),
                        )
            except Exception as e:
                logger.warning("[5/11] Auto-Profil Fehler (nicht-kritisch): %s", e)

            step.status = FlowStepStatus.SUCCESS
            step.detail = f"identity_id={db_identity_id}, profile_id={result.profile_id}"
            step.duration_ms = _now_ms() - step_start
            logger.info("[5/11] Persist: OK (%s)", step.detail)

            # =================================================================
            # Schritt 6: INJECT (v5.1: Flugmodus bereits AN seit Schritt 1)
            # =================================================================
            # v5.1: Flugmodus ist seit Schritt 1 aktiv. Hier nur Bridge
            # schreiben + Kill-Switch entfernen.
            # =================================================================
            step = result.steps[5]
            step.status = FlowStepStatus.RUNNING
            step_start = _now_ms()

            # Flugmodus ist seit Schritt 1 AN — kein erneutes Setzen nötig

            # 6a. Hardware-IDs: Bridge-Datei schreiben + verteilen
            logger.info("[6/11] Inject: Bridge-Datei schreiben...")
            await self._injector.inject(identity, label=name, distribute=True)

            # 6b. PIF: von KSU-Modul verwaltet
            logger.info("[6/11] PIF: Übersprungen (v4.1 — von KSU PlayIntegrityFix verwaltet)")

            # 6c. Namespace-Nuke: DEAKTIVIERT (v4.0 — GMS-Schutz)
            logger.info("[6/11] Namespace-Nuke: Übersprungen (v4.0 — GMS-Schutz)")

            # 6d. Kill-Switch entfernen (aktiviert Hooks)
            await self._injector.remove_kill_switch()

            step.status = FlowStepStatus.SUCCESS
            step.detail = "Bridge + Kill-Switch entfernt (PIF=KSU, Nuke=SKIP)"
            step.duration_ms = _now_ms() - step_start
            logger.info("[6/11] Inject: OK (%s)", step.detail)

            # =================================================================
            # Schritt 7: HARD RESET
            # =================================================================
            step = result.steps[6]
            step.status = FlowStepStatus.RUNNING
            step_start = _now_ms()

            logger.info("[7/11] Hard Reset: adb reboot...")

            # Robust Reboot: ADB-Verbindung trennt sich beim Reboot sofort —
            # das ist erwartetes Verhalten, kein Fehler.
            try:
                await self._adb.reboot()
            except ADBError as e:
                # Erwarteter Verbindungsabbruch beim Reboot — kein Fehler
                logger.info("[7/11] Reboot gesendet (ADB-Trennung erwartet: %s)", e)

            # Pre-Wait: 15s warten bevor wir anfangen zu pollen.
            # Das Gerät braucht Zeit um den Bootloader zu passieren und
            # den ADB-Daemon neu zu starten.
            logger.info("[7/11] Pre-Wait: 15s bevor ADB-Reconnect...")
            await asyncio.sleep(15)

            # =============================================================
            # v4.0 ADB AUTO-RECONNECT
            # =============================================================
            # Nach dem Reboot muss ADB sich neu verbinden. Statt blind zu
            # pollen, verwenden wir ensure_connection() das den ADB-Daemon
            # neu startet und `adb wait-for-device` ausführt.
            # Das überbrückt USB-Reconnects und Auth-Dialoge zuverlässig.
            # =============================================================
            logger.info("[7/11] ADB Reconnect: Warte auf Gerät (max 120s)...")
            reconnected = await self._adb.ensure_connection(timeout=120)
            if not reconnected:
                logger.warning(
                    "[7/11] ADB Reconnect fehlgeschlagen — "
                    "versuche trotzdem wait_for_device..."
                )

            logger.info("[7/11] Warte auf Boot (unbegrenzt, pollt alle %ds)...", TIMING.BOOT_POLL_INTERVAL)
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
                "[7/11] Boot erkannt — warte %ds bevor Popup-Hammer...",
                TIMING.POST_BOOT_SETTLE_SECONDS,
            )
            await asyncio.sleep(TIMING.POST_BOOT_SETTLE_SECONDS)

            # v4.0: Nochmal sicherstellen dass ADB stabil verbunden ist
            # (verhindert Race-Conditions wo ADB kurz da war aber wieder weggeht)
            if not await self._adb.is_connected():
                logger.warning("[7/11] ADB nach Boot-Settle weg — Reconnect...")
                await self._adb.ensure_connection(timeout=60)

            # =============================================================
            # POPUP HAMMER — VOR dem Unlock!
            # =============================================================
            # Das "Internal Problem with your device" Popup (Vendor
            # Mismatch) blockiert den Touchscreen komplett. Der Unlock-
            # Swipe funktioniert nicht, solange das Popup drauf ist.
            # Deshalb: Erst Popup weg, DANN unlock.
            # =============================================================
            logger.info("[7/11] Popup Hammer: Fehler-Dialoge unterdrücken...")

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

            logger.info("[7/11] Popup Hammer abgeschlossen — Unlock starten...")

            # Gerät entsperren (Swipe — jetzt ohne Popup-Blocker)
            await self._adb.unlock_device()

            # Nochmal suppress_system_dialogs als Sicherheitsnetz
            # (setzt auch device_provisioned + user_setup_complete)
            await self._device.suppress_system_dialogs()

            # =============================================================
            # POST-REBOOT BRIDGE VERIFICATION
            # =============================================================
            # Nach dem Reboot muss die Bridge-Datei noch vorhanden sein.
            # Bei manchen Geräten wird /data/local/tmp/ beim Boot geleert,
            # aber /data/adb/modules/ und /data/data/ überleben den Reboot.
            # Hier prüfen wir, ob der Serial in der Bridge noch korrekt ist.
            # =============================================================
            logger.info("[7/11] Post-Reboot Bridge-Verifikation...")
            try:
                from host.config import BRIDGE_FILE_PATH as _BFP
                verify_result = await self._adb.shell(
                    f"grep '^serial=' {_BFP}", root=True, timeout=5,
                )
                if verify_result.success and verify_result.output.strip():
                    on_device_serial = verify_result.output.strip().split("=", 1)[-1]
                    if on_device_serial == identity.serial:
                        logger.info(
                            "[7/11] Bridge-Verifikation: OK (serial=%s nach Reboot korrekt)",
                            on_device_serial,
                        )
                    else:
                        logger.error(
                            "[7/11] BRIDGE MISMATCH NACH REBOOT! "
                            "Auf Gerät: serial=%s, Erwartet: serial=%s — "
                            "Die Bridge-Datei wurde beim Reboot überschrieben/gelöscht!",
                            on_device_serial, identity.serial,
                        )
                else:
                    logger.warning(
                        "[7/11] Bridge-Datei nach Reboot nicht lesbar! "
                        "Pfad %s existiert möglicherweise nicht mehr.", _BFP,
                    )
            except Exception as e:
                logger.warning("[7/11] Bridge-Verifikation fehlgeschlagen: %s", e)

            boot_secs = (_now_ms() - step_start) / 1000
            step.status = FlowStepStatus.SUCCESS
            step.detail = f"Boot + Popup-Hammer + Unlock in {boot_secs:.1f}s"
            step.duration_ms = _now_ms() - step_start
            logger.info("[7/11] Hard Reset: OK (%s)", step.detail)

            # =================================================================
            # Schritt 8: NETWORK INIT (Flugmodus AUS + neue IP)
            # =================================================================
            # Flugmodus war seit Schritt 1 AN. Das Gerät hat mit
            # Flugmodus gerebootet → Modem war die ganze Zeit offline.
            # Jetzt: 20s warten → Flugmodus AUS → neue IP.
            # =================================================================
            step = result.steps[7]
            step.status = FlowStepStatus.RUNNING
            step_start = _now_ms()

            logger.info(
                "[8/11] Network Init: Warte 20s post-boot, dann Flugmodus AUS..."
            )

            # 20 Sekunden warten nach Boot (Modem + RIL brauchen Zeit)
            await asyncio.sleep(20)

            # Flugmodus AUS → Modem verbindet sich FRISCH
            await self._adb.shell(
                "settings put global airplane_mode_on 0", root=True,
            )
            await self._adb.shell(
                "am broadcast -a android.intent.action.AIRPLANE_MODE --ez state false",
                root=True,
            )
            logger.info("[8/11] Flugmodus: AUS — Modem verbindet sich neu")

            # IP-Cache invalidieren (neue IP erwartet)
            NetworkChecker.invalidate_ip_cache()

            # Warte auf O2-Mobilfunk-Stabilisierung
            logger.info(
                "[8/11] Warte %ds auf neue Mobilfunk-Verbindung...",
                TIMING.IP_AUDIT_WAIT_SECONDS,
            )
            await asyncio.sleep(TIMING.IP_AUDIT_WAIT_SECONDS)

            # IP-Check (EINMALIG — die einzige Stelle wo die IP ermittelt wird)
            ip_result = await self._network.get_public_ip(skip_cache=True)
            if ip_result.success:
                result.public_ip = ip_result.ip
                result.ip_service = ip_result.service

                step.status = FlowStepStatus.SUCCESS
                step.detail = (
                    f"Neue IP: {ip_result.ip} (via {ip_result.service})"
                )
                logger.info(
                    "[8/11] Network Init: Neue IP = %s (via %s)",
                    ip_result.ip, ip_result.service,
                )

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
                step.detail = f"IP-Check fehlgeschlagen: {ip_result.error}"
                logger.warning("[8/11] IP-Check fehlgeschlagen: %s", ip_result.error)

            step.duration_ms = _now_ms() - step_start

            # =================================================================
            # Schritt 9: GMS READY
            # =================================================================
            step = result.steps[8]
            step.status = FlowStepStatus.RUNNING
            step_start = _now_ms()

            # =================================================================
            # v5.0 GMS-Schutz Architektur — GSF-ID NICHT mehr synchronisieren
            # =================================================================
            #
            # WARUM DIE ALTE LOGIK FALSCH WAR:
            #   Alte Versionen (<v5.0) warteten auf die echte GSF-ID vom
            #   GMS-Checkin und schrieben sie in Bridge + DB zurück.
            #   Problem: Da wir GMS NICHT clearen (GMS-Schutz), hat das
            #   Gerät IMMER dieselbe echte GSF-ID. Alle Identitäten bekamen
            #   dadurch dieselbe GSF-ID → keine echte Identity-Trennung!
            #
            # v5.0 KORREKTE LOGIK:
            #   - Die Bridge enthält bereits eine zufällig generierte GSF-ID
            #     (aus Schritt 2: GENERATE, via secrets CSPRNG)
            #   - Die Hooks spoofen diese GSF-ID NUR für Target-Apps
            #     (TikTok, Instagram, etc.)
            #   - GMS sieht immer die ECHTE GSF-ID → Trust-Chain bleibt intakt
            #   - Jede Identity hat ihre EIGENE einzigartige GSF-ID
            #
            # → KEIN GSF-ID Wait, KEIN GSF-ID Sync, KEIN Bridge-Patch!
            #
            # Was wir noch tun:
            #   1. Konnektivität prüfen (für Play Integrity)
            #   2. GMS Kickstart (Checkin triggern für DroidGuard)
            #   3. Finsky Kill (hängende Prozesse beenden)
            # =================================================================

            logger.info("[9/11] GMS Ready: Konnektivität + Kickstart (v5.0 — GSF-ID bleibt generiert)...")

            # --- Konnektivitäts-Check ---
            connectivity_ok = False
            if result.public_ip:
                connectivity_ok = True
                logger.info("[9/11] Network: IP bereits bestätigt (%s)", result.public_ip)
            else:
                logger.info("[9/11] Network: Keine IP — prüfe Konnektivität...")
                for attempt in range(3):
                    connectivity_ok = await self._device.check_connectivity()
                    if connectivity_ok:
                        logger.info("[9/11] Network: Konnektivität bestätigt (Versuch %d)", attempt + 1)
                        break
                    logger.warning(
                        "[9/11] Network: Kein Netz (Versuch %d/3) — warte %ds...",
                        attempt + 1, TIMING.NETWORK_CONNECTIVITY_WAIT,
                    )
                    await asyncio.sleep(TIMING.NETWORK_CONNECTIVITY_WAIT)

                if not connectivity_ok:
                    logger.error("[9/11] Network: Kein Netzwerk nach 3 Versuchen")

            # --- GMS Kickstart (für DroidGuard + Play Integrity) ---
            logger.info("[9/11] Finsky Kill: Play Store hart beenden...")
            await self._device.kill_finsky()

            logger.info("[9/11] GMS Core Repair: MinuteMaid starten...")
            repair_ok = await self._device.reset_gms_internal()
            if repair_ok:
                await asyncio.sleep(3)
            else:
                logger.info("[9/11] MinuteMaid nicht verfügbar")

            kickstart_ok = await self._device.kickstart_gms()
            await asyncio.sleep(TIMING.GMS_KICKSTART_SETTLE_SECONDS)

            # --- GSF-ID: Bridge-Wert beibehalten (v5.0) ---
            # Die generierte GSF-ID aus Schritt 2 bleibt UNVERÄNDERT in
            # Bridge und DB. KEINE Synchronisierung mit der echten GMS GSF-ID!
            logger.info(
                "[9/11] GSF-ID: Generierte ID beibehalten (v5.0 — KEIN Sync mit GMS). "
                "Bridge-GSF-ID: %s...%s",
                identity.gsf_id[:4], identity.gsf_id[-4:],
            )

            # real_gsf_id = die generierte (nicht die echte GMS-ID!)
            real_gsf_id = identity.gsf_id

            step.status = FlowStepStatus.SUCCESS
            step.detail = (
                f"GMS Kickstart {'OK' if kickstart_ok else 'WARN'} | "
                f"GSF-ID: generiert beibehalten (v5.0) | "
                f"Netz: {'OK' if connectivity_ok else 'WARN'}"
            )
            step.duration_ms = _now_ms() - step_start
            logger.info("[9/11] GMS Ready: OK (%s)", step.detail)

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
            step = result.steps[9]
            step.status = FlowStepStatus.RUNNING
            step_start = _now_ms()

            if real_gsf_id:
                # =========================================================
                # BASELINE-TRIGGER: Quick-Audit vor Capture
                # =========================================================
                logger.info("[10/11] Baseline-Trigger: Prüfe Bridge-Integrität vor Capture...")
                integrity_ok = False
                for integrity_attempt in range(2):
                    try:
                        pre_audit = await self._auditor.audit_device(identity)
                        if pre_audit.passed:
                            integrity_ok = True
                            logger.info(
                                "[10/11] Baseline-Trigger: Integrität bestätigt (%d%%)",
                                pre_audit.score_percent,
                            )
                            break
                        else:
                            if integrity_attempt == 0:
                                logger.warning(
                                    "[10/11] Baseline-Trigger: Integrität NICHT bestätigt "
                                    "(%d%%) — warte 60s für GMS-Stabilisierung...",
                                    pre_audit.score_percent,
                                )
                                await asyncio.sleep(60)
                            else:
                                logger.warning(
                                    "[10/11] Baseline-Trigger: Integrität weiterhin %d%% "
                                    "— Capture trotzdem fortsetzen",
                                    pre_audit.score_percent,
                                )
                    except Exception as e:
                        logger.warning("[10/11] Baseline-Trigger Audit fehlgeschlagen: %s", e)
                        if integrity_attempt == 0:
                            await asyncio.sleep(60)

                # Golden Baseline capturen (auch bei imperfekter Integrität)
                logger.info("[10/11] Capture State: Golden Baseline sichern...")
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
                        logger.info("[10/11] Capture State: Golden Baseline komplett")
                    elif gms_ok or accounts_ok:
                        step.status = FlowStepStatus.SUCCESS
                        step.detail = (
                            f"Golden Baseline teilweise: "
                            f"GMS={'OK' if gms_ok else 'FAIL'}, "
                            f"Accounts={'OK' if accounts_ok else 'FAIL'}"
                        )
                        logger.warning("[10/11] Capture State: Teilweise (%s)", step.detail)
                    else:
                        step.status = FlowStepStatus.FAILED
                        step.detail = "Golden Baseline: Beide Snapshots fehlgeschlagen"
                        logger.error("[10/11] Capture State: FEHLGESCHLAGEN")

                except Exception as e:
                    step.status = FlowStepStatus.FAILED
                    step.detail = f"Capture Fehler: {e}"
                    logger.error("[10/11] Capture State Fehler: %s", e)
            else:
                # Kein GSF-ID → kein Golden Baseline möglich
                step.status = FlowStepStatus.SKIPPED
                step.detail = "Übersprungen: Keine GSF-ID verfügbar"
                logger.warning("[10/11] Capture State: Übersprungen (keine GSF-ID)")

            step.duration_ms = _now_ms() - step_start

            # =================================================================
            # Schritt 11: AUDIT + AUDIT-TRACKING
            # =================================================================
            step = result.steps[10]
            step.status = FlowStepStatus.RUNNING
            step_start = _now_ms()

            logger.info("[11/11] Audit: Device prüfen...")
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
                logger.info("[11/11] Audit: PASS (%d%%)", audit.score_percent)
            else:
                step.status = FlowStepStatus.FAILED
                step.detail = (
                    f"Score: {audit.score_percent}% — "
                    f"{audit.failed_checks} Check(s) fehlgeschlagen"
                )
                logger.warning(
                    "[11/11] Audit: FAIL (%d%%) — markiere als corrupted",
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
                s.status in (FlowStepStatus.SUCCESS, FlowStepStatus.SKIPPED)
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

    async def _find_active_profile(self) -> Optional[dict]:
        """
        Findet das aktuell aktive Profil (für Auto-Backup vor Genesis).

        Returns:
            Dict mit {"id": int, "name": str, "identity_id": int} oder None
        """
        async with db.connection() as conn:
            cursor = await conn.execute(
                "SELECT p.id, p.name, p.identity_id "
                "FROM profiles p WHERE p.status = 'active' LIMIT 1"
            )
            row = await cursor.fetchone()
            if row:
                return dict(row)
            return None

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
