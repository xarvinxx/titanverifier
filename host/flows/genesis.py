"""
Genesis Flow (Cold Start / New Account) v6.0
============================================

FLOW 1: GENESIS — Erzeugt eine komplett neue Identität von Grund auf.
Dieser Flow ist stateless und atomar: Entweder alles klappt,
oder die Identität wird als 'corrupted' markiert.

Zwingender Ablauf (11 Schritte — v6.0 Zygote-First):
   1. AIRPLANE MODE  — Flugmodus AN (Netz sofort trennen)
   2. AUTO-BACKUP    — Optionales Dual-Path Backup des aktiven Profils
   3. STERILIZE      — Deep Clean (pm clear NUR Target-Apps, GMS UNANGETASTET!)
   4. GENERATE       — Neue O2-DE Identität (GSF-ID = final)
   5. PERSIST        — In DB speichern (Status: 'active') + Auto-Profil
   6. INJECT         — Bridge + Kill-Switch
   7. HARD RESET     — Reboot + Boot-Poll + Bridge-Verifikation
   8. NETWORK INIT   — Flugmodus AUS → Neue IP
   9. GMS READY      — Dynamisches GMS-Readiness-Polling (statt statische Waits)
  10. CAPTURE STATE  — Golden Baseline (GMS + Accounts sichern)
  11. AUDIT          — Full Device-Audit + Account-Check

v6.1 — "Zygote-First" + "GMS-Schutz" + "PIF-Inject" Architektur:
  Inject (Bridge + PIF) → Reboot → DG-Sanitize → GMS-Readiness → Capture.
  Das System bootet unter der neuen Identität bevor GMS-State gecaptured wird.
  
  GMS/GSF/Vending werden NIEMALS gelöscht (Trust-Chain intakt).
  DroidGuard-Cache (dg.db) wird nach JEDEM Reboot gelöscht (Neu-Attestierung).
  PIF custom.pif.prop wird bei jedem Flow frisch generiert (BASIC_INTEGRITY).
  TikTok Instance-IDs werden bei Restores automatisch entfernt.

DB-Tracking:
  - Flow-History, IP-History, Audit-History, Auto-Profil
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional

from host.adb.client import ADBClient, ADBError, ADBTimeoutError

from host.config import (
    BACKUP_ACCOUNTS_SUBDIR,
    BACKUP_DIR,
    BACKUP_GMS_SUBDIR,
    LOCAL_TZ,
    TIMING,
)
from host.database import db
from host.engine.auditor import AuditResult, DeviceAuditor
from host.engine.db_ops import (
    capture_profile_log,
    check_genesis_frequency,
    check_ip_collision,
    check_subnet_saturation,
    create_flow_history,
    create_profile_auto,
    record_audit,
    record_ip,
    update_flow_history,
    update_identity_audit,
    update_profile_accounts_backup,
    update_profile_gms_backup,
    update_profile_tiktok_backup,
    update_identity_network,
)
from host.engine.identity_engine import IdentityGenerator
from host.engine.injector import BridgeInjector
from host.engine.network import NetworkChecker
from host.engine.shifter import AppShifter
from host.models.identity import IdentityRead, IdentityStatus

logger = logging.getLogger("host.flows.genesis")


async def _auto_start_hookguard(restart: bool = False) -> None:
    """Start or restart HookGuard after a Genesis flow.

    Args:
        restart: If True, stop+start even if already running (needed after
                 Genesis because bridge file + identity changed).
    """
    try:
        import host.main as _main
        guard = getattr(_main, "_hookguard", None)
        if guard is None:
            logger.warning("HookGuard Instanz nicht gefunden in host.main")
            return

        if guard.is_running and restart:
            await guard.stop()
            await guard.start()
            logger.info("HookGuard neu gestartet (Bridge-Hash refreshed)")
        elif guard.is_running:
            await guard.refresh_bridge_hash()
            logger.info("HookGuard laeuft — Bridge-Hash refreshed")
        else:
            await guard.start()
            logger.info("HookGuard automatisch gestartet")
    except Exception as e:
        logger.warning("HookGuard Auto-Start fehlgeschlagen: %s", e)


async def _capture_profile_snapshot(
    adb: ADBClient,
    profile_id: int,
    identity_id: Optional[int],
    trigger: str,
) -> None:
    """
    Liest Live Monitor + HookGuard Daten vom Gerät und speichert
    einen Snapshot in der DB.
    """
    import dataclasses
    import json as _json

    live_summary = None
    hookguard_dict = None
    kill_events = None

    # 1. Live Monitor Summary lesen
    try:
        for pkg in ("com.zhiliaoapp.musically", "com.ss.android.ugc.trill"):
            result = await adb.shell(
                f"cat /data/data/{pkg}/files/.titan_access_summary.json 2>/dev/null",
                root=True, timeout=5,
            )
            if result.success and result.output.strip().startswith("{"):
                live_summary = _json.loads(result.output.strip())
                break
    except Exception as e:
        logger.debug("Live Monitor read failed: %s", e)

    # 2. HookGuard State lesen
    try:
        import host.main as _main
        guard = getattr(_main, "_hookguard", None)
        if guard and guard.is_running:
            hookguard_dict = dataclasses.asdict(guard.state)
            hookguard_dict["status"] = guard.state.status.value
            kill_events = hookguard_dict.pop("device_kill_events", [])
    except Exception as e:
        logger.debug("HookGuard state read failed: %s", e)

    # 3. Device Kill Events aus logcat (Fallback falls HookGuard nicht läuft)
    if not kill_events:
        try:
            result = await adb.shell(
                "logcat -d -s TitanKillSwitch:* -v time 2>/dev/null | tail -20",
                root=True, timeout=5,
            )
            if result.success and result.output:
                kill_events = []
                for line in result.output.strip().split("\n"):
                    if "TitanKillSwitch" in line:
                        kill_events.append({"raw": line.strip()})
        except Exception:
            pass

    # 4. In DB speichern
    try:
        log_id = await capture_profile_log(
            profile_id=profile_id,
            identity_id=identity_id,
            trigger=trigger,
            live_summary=live_summary,
            hookguard_state=hookguard_dict,
            kill_events=kill_events,
        )
        logger.info("Profile snapshot captured: log_id=%d trigger=%s", log_id, trigger)
    except Exception as e:
        logger.warning("Profile snapshot capture failed: %s", e)


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
        self._injector = BridgeInjector(adb)
        self._shifter = AppShifter(adb)
        self._auditor = DeviceAuditor(adb)
        self._network = NetworkChecker(adb)


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
        # PRE-CHECK: Genesis Frequency Guard
        # TikTok rate-limitet auf Carrier/ASN-Ebene. Zu viele Flows in
        # kurzer Zeit lösen "Zu viele Versuche" aus.
        # ------------------------------------------------------------------
        try:
            freq = await check_genesis_frequency()
            stats = freq["stats"]
            logger.info(
                "Genesis Frequency: %d/2h, %d/24h, %d total "
                "(Limits: %d/2h, %d/24h, Cooldown %dmin)",
                stats["last_2h"], stats["last_24h"], stats["total"],
                stats["limits"]["max_2h"], stats["limits"]["max_24h"],
                stats["limits"]["cooldown_min"],
            )
            if not freq["allowed"]:
                logger.warning("GENESIS BLOCKED: %s", freq["reason"])
                result.success = False
                result.error = freq["reason"]
                result.duration_ms = _now_ms() - flow_start
                return result
        except Exception as e:
            logger.warning("Frequency-Check fehlgeschlagen (Flow wird fortgesetzt): %s", e)

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
            await _airplane_on_safe(self._adb)

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

            # =================================================================
            # FIX-11: Intelligente Backup-Logik
            #   - Aktives Profil MIT tiktok_username → IMMER Backup
            #   - Aktives Profil OHNE tiktok_username + Checkbox → Backup
            #   - Kein aktives Profil + Checkbox → Versuche Backup
            #   - Sonst → KEIN Backup
            # =================================================================
            logger.info("[2/11] Auto-Backup: Prüfe aktives Profil...")
            try:
                active_profile = await self._find_active_profile()

                should_backup = False
                backup_reason = ""

                if active_profile:
                    tiktok_user = active_profile.get("tiktok_username")
                    if tiktok_user and tiktok_user.strip():
                        # TikTok-Account eingerichtet → IMMER Backup
                        should_backup = True
                        backup_reason = f"TikTok @{tiktok_user} aktiv"
                    elif backup_before:
                        # Kein TikTok-User aber Checkbox gesetzt → Backup (User Override)
                        should_backup = True
                        backup_reason = "Checkbox aktiviert (kein TikTok-Account)"
                elif backup_before:
                    # Kein aktives Profil aber Checkbox → skip
                    should_backup = False
                    backup_reason = "Kein aktives Profil"

                if should_backup and active_profile:
                    active_name = active_profile["name"]
                    logger.info(
                        "[2/11] Auto-Backup: Profil '%s' — Full-State "
                        "(TikTok + GMS + Accounts) (%s)...",
                        active_name, backup_reason,
                    )

                    # A) TikTok Dual-Path Backup
                    backup_result = await self._shifter.backup_tiktok_dual(
                        active_name, timeout=300,
                    )
                    tt_saved = sum(1 for v in backup_result.values() if v is not None)

                    # B) GMS + Accounts Backup
                    gms_saved = 0
                    active_pid = active_profile["id"]
                    profile_dir = BACKUP_DIR / active_name
                    try:
                        gms_dir = profile_dir / BACKUP_GMS_SUBDIR
                        gms_dir.mkdir(parents=True, exist_ok=True)
                        gms_path = await self._shifter._backup_gms_packages(
                            gms_dir, timeout=120,
                        )
                        gms_saved += 1
                        await update_profile_gms_backup(
                            active_pid, str(gms_path), gms_path.stat().st_size,
                        )
                    except Exception as gms_err:
                        logger.warning("[2/11] GMS-Backup fehlgeschlagen: %s", gms_err)

                    try:
                        acc_dir = profile_dir / BACKUP_ACCOUNTS_SUBDIR
                        acc_dir.mkdir(parents=True, exist_ok=True)
                        acc_path = await self._shifter._backup_account_dbs(acc_dir)
                        gms_saved += 1
                        await update_profile_accounts_backup(
                            active_pid, str(acc_path),
                        )
                    except Exception as acc_err:
                        logger.warning("[2/11] Accounts-Backup fehlgeschlagen: %s", acc_err)

                    # C) DB-Update: TikTok Backup-Status
                    tt_path = backup_result.get("app_data")
                    if tt_path and tt_path.exists():
                        try:
                            await update_profile_tiktok_backup(
                                active_pid,
                                str(tt_path),
                                tt_path.stat().st_size,
                            )
                        except Exception as db_err:
                            logger.warning(
                                "[2/11] Backup DB-Update fehlgeschlagen: %s", db_err,
                            )

                    total_saved = tt_saved + gms_saved
                    step.status = FlowStepStatus.SUCCESS
                    step.detail = (
                        f"Profil '{active_name}': "
                        f"TikTok={tt_saved}/2, GMS+Acc={gms_saved}/2 "
                        f"(Total: {total_saved}/4) ({backup_reason})"
                    )
                    logger.info("[2/11] Auto-Backup: %s", step.detail)
                else:
                    step.status = FlowStepStatus.SKIPPED
                    if not active_profile:
                        step.detail = "Kein aktives Profil gefunden (erster Lauf?)"
                    elif not backup_before:
                        step.detail = f"Profil '{active_profile['name']}' hat keinen TikTok-Account — Checkbox nicht gesetzt"
                    else:
                        step.detail = backup_reason
                    logger.info("[2/11] Auto-Backup: %s", step.detail)
            except Exception as e:
                # Backup-Fehler ist NICHT kritisch — Genesis fortsetzen!
                step.status = FlowStepStatus.SUCCESS
                step.detail = f"Backup-Warnung: {e} (Genesis wird fortgesetzt)"
                logger.warning("[2/11] Auto-Backup fehlgeschlagen (nicht kritisch): %s", e)

            step.duration_ms = _now_ms() - step_start

            # =================================================================
            # Schritt 3: STERILIZE (pm clear NUR Target-Apps!)
            # =================================================================
            step = result.steps[2]
            step.status = FlowStepStatus.RUNNING
            step_start = _now_ms()

            logger.info("[3/11] Sterilize: Deep Clean (NUR Target-Apps, GMS bleibt!)...")
            clean_results = await self._shifter.deep_clean(include_gms=False)
            success_count = sum(1 for v in clean_results.values() if v)
            failed_ops = [k for k, v in clean_results.items() if not v]

            critical_failures = [
                op for op in failed_ops
                if op.startswith("pm_clear_")
            ]

            if critical_failures:
                step.status = FlowStepStatus.ERROR
                step.detail = (
                    f"{success_count}/{len(clean_results)} OK — "
                    f"KRITISCH FEHLGESCHLAGEN: {', '.join(critical_failures)}"
                )
                step.duration_ms = _now_ms() - step_start
                logger.error(
                    "[3/11] Sterilize: FEHLER — pm clear fehlgeschlagen: %s",
                    critical_failures,
                )
                raise ADBError(
                    f"Sterilize fehlgeschlagen: pm clear gescheitert für "
                    f"{', '.join(critical_failures)}",
                )
            else:
                step.status = FlowStepStatus.SUCCESS
                detail_parts = [f"{success_count}/{len(clean_results)} Operationen (GMS geschützt)"]
                if failed_ops:
                    detail_parts.append(f"nicht-kritisch fehlgeschlagen: {', '.join(failed_ops)}")
                step.detail = " | ".join(detail_parts)
                step.duration_ms = _now_ms() - step_start
                logger.info("[3/11] Sterilize: OK (%s)", step.detail)

            # Clipboard wipe before app start
            await self._shifter._clear_clipboard()

            # Disable Google backup to prevent cloud restore
            await self._shifter._disable_google_backup()

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

            # 6b. PIF: custom.pif.prop generieren + pushen
            # KRITISCH für MEETS_BASIC_INTEGRITY!
            # TrickyStore liefert DEVICE_INTEGRITY (Hardware-Keybox),
            # aber BASIC_INTEGRITY braucht einen gültigen Software-Fingerprint.
            # Ohne custom.pif.prop → nur DEVICE, kein BASIC!
            logger.info("[6/11] PIF v5.0: autopif4-First Strategie (BASIC_INTEGRITY)...")
            pif_ok = False
            try:
                pif_ok = await self._injector.inject_pif_fingerprint()
                if pif_ok:
                    logger.info("[6/11] PIF: custom.pif.prop erfolgreich gepusht")
                else:
                    logger.warning("[6/11] PIF: Injection fehlgeschlagen — BASIC_INTEGRITY gefährdet!")
            except Exception as e:
                logger.warning("[6/11] PIF Fehler (nicht-kritisch): %s", e)

            # 6c. Namespace-Nuke: DEAKTIVIERT (v4.0 — GMS-Schutz)
            logger.info("[6/11] Namespace-Nuke: Übersprungen (v4.0 — GMS-Schutz)")

            # =============================================================
            # 6d. GHOST PROTOCOL: Kernel-Level Identity Deployment
            # =============================================================
            logger.info("[6/11] Ghost Protocol: Kernel-Level Deployment...")

            # 6d-i. SUSFS Fake-Dateien (ARP, MAC, Input Devices)
            await self._injector.write_susfs_fakes(identity)

            # 6d-ii. Boot-Scripts (post-fs-data.sh + service.sh)
            await self._injector.deploy_boot_scripts()

            # 6d-iii. SSAID per-App patchen
            await self._injector.patch_ssaid(identity.android_id)

            # 6d-iv. GAID zuruecksetzen (neue Werbe-ID bei naechstem GMS-Start)
            await self._injector.reset_gaid()

            # 6d-v. Bluetooth Pairing-Daten loeschen (IRK-Reset)
            await self._injector.cleanup_bluetooth()

            logger.info("[6/11] Ghost Protocol: Deployment abgeschlossen")

            # 6e. Kill-Switch entfernen (aktiviert Hooks)
            await self._injector.remove_kill_switch()

            step.status = FlowStepStatus.SUCCESS
            step.detail = f"Bridge + Ghost Protocol + Kill-Switch entfernt | PIF={'OK' if pif_ok else 'FAIL'}"
            step.duration_ms = _now_ms() - step_start
            logger.info("[6/11] Inject: OK (%s)", step.detail)

            # =================================================================
            # Schritt 7: HARD RESET
            # =================================================================
            step = result.steps[6]
            step.status = FlowStepStatus.RUNNING
            step_start = _now_ms()

            logger.info("[7/11] Hard Reset: adb reboot...")

            # CRITICAL: Filesystem sync BEVOR wir rebooten!
            # f2fs Page-Cache muss auf Flash geschrieben werden, sonst
            # gehen Bridge-Daten verloren (Inode-Size korrekt, Data = 0x00).
            try:
                await self._adb.shell("sync", root=True, timeout=15)
                logger.info("[7/11] Filesystem sync: OK")
            except (ADBError, ADBTimeoutError):
                logger.warning("[7/11] Filesystem sync fehlgeschlagen — Reboot trotzdem")

            # LSPosed DB sichern VOR dem Reboot (Schutz gegen Korruption)
            try:
                await self._adb.shell(
                    "cp /data/adb/lspd/config/modules_config.db "
                    "/data/adb/lspd/config/modules_config.db.pre_reboot 2>/dev/null",
                    root=True, timeout=5,
                )
            except (ADBError, ADBTimeoutError):
                pass

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
                "[7/11] Boot erkannt — warte %ds post-boot...",
                TIMING.POST_BOOT_SETTLE_SECONDS,
            )
            await asyncio.sleep(TIMING.POST_BOOT_SETTLE_SECONDS)

            # v4.0: Nochmal sicherstellen dass ADB stabil verbunden ist
            # (verhindert Race-Conditions wo ADB kurz da war aber wieder weggeht)
            if not await self._adb.is_connected():
                logger.warning("[7/11] ADB nach Boot-Settle weg — Reconnect...")
                await self._adb.ensure_connection(timeout=60)

            # LSPosed DB Integritätsprüfung nach Reboot
            try:
                db_check = await self._adb.shell(
                    "su -c '"
                    "if [ -f /data/adb/lspd/config/modules_config.db ]; then "
                    "  head -c 16 /data/adb/lspd/config/modules_config.db "
                    "  | grep -q SQLite && echo OK || echo CORRUPT; "
                    "else echo MISSING; fi'",
                    root=False, timeout=5,
                )
                db_state = db_check.stdout.strip()
                if db_state != "OK":
                    logger.warning(
                        "[7/11] LSPosed DB %s nach Reboot! "
                        "Stelle aus Backup wieder her...", db_state,
                    )
                    await self._adb.shell(
                        "cp /data/adb/lspd/config/modules_config.db.pre_reboot "
                        "/data/adb/lspd/config/modules_config.db && "
                        "chmod 600 /data/adb/lspd/config/modules_config.db",
                        root=True, timeout=5,
                    )
                    logger.info("[7/11] LSPosed DB wiederhergestellt")
            except (ADBError, ADBTimeoutError):
                pass

            # Gerät entsperren
            await self._adb.unlock_device()

            # =============================================================
            # POST-REBOOT BRIDGE VERIFICATION
            # =============================================================
            # Nach dem Reboot muss die Bridge-Datei noch vorhanden sein.
            # Bei manchen Geräten wird /data/local/tmp/ beim Boot geleert,
            # aber /data/adb/modules/ und /data/data/ überleben den Reboot.
            # Hier prüfen wir, ob der Serial in der Bridge noch korrekt ist.
            # =============================================================
            # =============================================================
            # FIX-9: Bridge-Verifikation auf ALLE Pfade ausweiten
            # =============================================================
            # Prüfe alle 3 Hauptpfade nach dem Reboot:
            #   1. Primär: /data/adb/modules/... (Zygisk liest hier)
            #   2. SDCard: /sdcard/.hw_config (LSPosed Fallback)
            #   3. App:    /data/data/.../files/.hw_config (Audit)
            # Primärpfad-Mismatch = FAIL. Andere = nur WARNING.
            # =============================================================
            logger.info("[7/11] Post-Reboot Bridge-Verifikation (alle Pfade)...")
            from host.config import (
                BRIDGE_APP_TEMPLATE as _BAT,
                BRIDGE_FILE_PATH as _BFP,
                BRIDGE_SDCARD_PATH as _BSP,
            )

            bridge_paths = {
                "primär": _BFP,
                "sdcard": _BSP,
                "app": _BAT.format(package="com.oem.hardware.service"),
            }
            primary_ok = False
            for path_label, bridge_path in bridge_paths.items():
                try:
                    verify_result = await self._adb.shell(
                        f"grep '^serial=' {bridge_path}", root=True, timeout=5,
                    )
                    if verify_result.success and verify_result.output.strip():
                        on_device_serial = verify_result.output.strip().split("=", 1)[-1]
                        if on_device_serial == identity.serial:
                            logger.info(
                                "[7/11] Bridge [%s]: OK (serial=%s)",
                                path_label, on_device_serial,
                            )
                            if path_label == "primär":
                                primary_ok = True
                        else:
                            if path_label == "primär":
                                logger.error(
                                    "[7/11] BRIDGE MISMATCH [%s]! "
                                    "Auf Gerät: %s, Erwartet: %s",
                                    path_label, on_device_serial, identity.serial,
                                )
                            else:
                                logger.warning(
                                    "[7/11] Bridge [%s]: Mismatch (serial=%s, erwartet=%s)",
                                    path_label, on_device_serial, identity.serial,
                                )
                    else:
                        if path_label == "primär":
                            logger.warning(
                                "[7/11] Bridge [%s]: Nicht lesbar! Pfad: %s",
                                path_label, bridge_path,
                            )
                        else:
                            logger.debug(
                                "[7/11] Bridge [%s]: Nicht vorhanden (optional)",
                                path_label,
                            )
                except Exception as e:
                    logger.debug("[7/11] Bridge [%s] Check fehlgeschlagen: %s", path_label, e)

            if primary_ok:
                logger.info("[7/11] Bridge-Verifikation: Primärpfad OK")
            else:
                logger.warning("[7/11] Bridge-Verifikation: Primärpfad NICHT bestätigt!")

            boot_secs = (_now_ms() - step_start) / 1000
            step.status = FlowStepStatus.SUCCESS
            step.detail = f"Boot + Unlock in {boot_secs:.1f}s"
            step.duration_ms = _now_ms() - step_start
            logger.info("[7/11] Hard Reset: OK (%s)", step.detail)

            # =================================================================
            # Schritt 7b: DROIDGUARD SANITIZE + GMS FORCE-RESTART
            # =================================================================
            # KRITISCH: Nach dem Reboot mit neuer Identity enthält die
            # DroidGuard-DB (dg.db) noch gecachte Attestierungs-Tokens
            # der ALTEN Identity. Google erkennt den Hardware-Mismatch
            # und degradiert Play Integrity (nur DEVICE, kein BASIC).
            #
            # Lösung: dg.db + app_dg_cache löschen → GMS force-stop →
            # GMS startet neu und attestiert FRISCH gegen die neue Identity.
            # =================================================================
            logger.info("[7b/11] DroidGuard Sanitize: Stale Attestierungs-Tokens löschen...")
            try:
                dg_cleaned = await self._shifter._sanitize_droidguard()
                if dg_cleaned:
                    logger.info("[7b/11] DroidGuard-Cache gelöscht — erzwinge GMS-Neustart...")
                    # v7.1: gms.unstable ZUERST beenden (Zombie-Prävention)
                    await self._shifter._reap_gms_zombies()
                    await self._adb.shell(
                        "am force-stop com.google.android.gms", root=True, timeout=10,
                    )
                    # Nochmal prüfen ob force-stop einen neuen Zombie erzeugt hat
                    await self._shifter._reap_gms_zombies()
                    await asyncio.sleep(5)
                    logger.info("[7b/11] GMS neu gestartet — frische Attestierung eingeleitet")
                else:
                    logger.debug("[7b/11] Kein DroidGuard-Cache vorhanden (sauberer Zustand)")
            except Exception as e:
                logger.warning("[7b/11] DroidGuard Sanitize fehlgeschlagen (nicht-kritisch): %s", e)

            # =================================================================
            # Schritt 7c: "BEWOHNTES HAUS" — Dummy App Presence Check
            # =================================================================
            # Anti-Fraud-Systeme (TikTok, Meta) flaggen Geräte auf denen
            # NUR eine einzelne Social-Media-App installiert ist. Ein echtes
            # Gerät hat WhatsApp, YouTube, Gmail, Maps, eine Banking-App, etc.
            #
            # Prüfung:
            #   1. Liste der erwarteten "normalen" Apps checken
            #   2. Fehlende Apps per pm install-existing reaktivieren
            #      (funktioniert für System-Apps die deaktiviert wurden)
            #   3. Nicht-reaktivierbare Apps → Warnung loggen
            #
            # pm install-existing: Reaktiviert eine deaktivierte System-App
            # ohne APK zu benötigen. Funktioniert nur für Apps die auf der
            # System-Partition vorhanden sind (z.B. YouTube, Gmail, Maps).
            # =================================================================
            logger.info("[7c/11] Bewohntes Haus: Prüfe Dummy-App-Präsenz...")
            try:
                # Apps die auf einem normalen Pixel 6 installiert sein sollten
                # (sortiert nach Erkennungs-Relevanz)
                EXPECTED_APPS = [
                    # Tier 1: Kritisch (deren Fehlen ist sofort verdächtig)
                    ("com.google.android.youtube", "YouTube"),
                    ("com.google.android.apps.maps", "Google Maps"),
                    ("com.google.android.gm", "Gmail"),
                    ("com.google.android.apps.photos", "Google Photos"),
                    ("com.google.android.apps.messaging", "Messages"),
                    # Tier 2: Wichtig (stark verdächtig wenn fehlend)
                    ("com.google.android.dialer", "Phone"),
                    ("com.google.android.contacts", "Contacts"),
                    ("com.google.android.calendar", "Google Calendar"),
                    ("com.google.android.deskclock", "Clock"),
                    ("com.google.android.apps.docs", "Google Drive"),
                    # Tier 3: Nice-to-have (weniger verdächtig)
                    ("com.google.android.keep", "Google Keep"),
                    ("com.google.android.apps.translate", "Google Translate"),
                ]

                # Installierte Pakete abfragen (schneller als pro-App pm path)
                installed_result = await self._adb.shell(
                    "pm list packages 2>/dev/null", root=False, timeout=15,
                )
                installed_packages = set()
                if installed_result.success:
                    for line in installed_result.output.strip().split("\n"):
                        line = line.strip()
                        if line.startswith("package:"):
                            installed_packages.add(line[8:])

                missing_apps = []
                present_apps = []
                for pkg, label in EXPECTED_APPS:
                    if pkg in installed_packages:
                        present_apps.append(label)
                    else:
                        missing_apps.append((pkg, label))

                # Fehlende Apps per pm install-existing reaktivieren
                reactivated = []
                still_missing = []
                for pkg, label in missing_apps:
                    try:
                        reactivate = await self._adb.shell(
                            f"pm install-existing {pkg} 2>&1",
                            root=True, timeout=10,
                        )
                        if reactivate.success and "installed" in reactivate.output.lower():
                            reactivated.append(label)
                            logger.info(
                                "[7c/11] App reaktiviert: %s (%s)", label, pkg,
                            )
                        else:
                            still_missing.append((pkg, label))
                    except Exception:
                        still_missing.append((pkg, label))

                # Ergebnis loggen
                total_expected = len(EXPECTED_APPS)
                total_present = len(present_apps) + len(reactivated)
                coverage = (total_present / total_expected * 100) if total_expected > 0 else 0

                if still_missing:
                    missing_names = ", ".join(l for _, l in still_missing)
                    logger.warning(
                        "[7c/11] BEWOHNTES HAUS: %d/%d Apps vorhanden (%.0f%%). "
                        "Fehlend: %s — Gerät könnte als 'frisch' erkannt werden!",
                        total_present, total_expected, coverage, missing_names,
                    )
                else:
                    logger.info(
                        "[7c/11] BEWOHNTES HAUS: %d/%d Apps vorhanden (%.0f%%) — OK",
                        total_present, total_expected, coverage,
                    )
                if reactivated:
                    logger.info(
                        "[7c/11] Reaktiviert: %s", ", ".join(reactivated),
                    )

            except Exception as e:
                logger.warning("[7c/11] Bewohntes Haus Check fehlgeschlagen: %s", e)

            # =================================================================
            # PRE-NETWORK: Post-Reboot Sterilisierung
            # =================================================================
            # Nach dem Reboot könnten Google Auto-Restore oder System-Services
            # TikTok-Daten wiederhergestellt haben. Außerdem muss External
            # Storage leer sein und die GMS Analytics bereinigt werden,
            # BEVOR das Netz eingeschaltet wird.
            # =================================================================
            logger.info("[7d/11] Post-Reboot Sterilisierung...")
            try:
                _post_reboot_cleaned = 0

                for _ext_path in [
                    "/sdcard/Android/data/com.zhiliaoapp.musically",
                    "/sdcard/Android/data/com.ss.android.ugc.trill",
                ]:
                    _check = await self._adb.shell(
                        f"test -d {_ext_path}", root=True, timeout=5,
                    )
                    if _check.success:
                        await self._adb.shell(
                            f"rm -rf {_ext_path}", root=True, timeout=10,
                        )
                        _post_reboot_cleaned += 1
                        logger.warning(
                            "[7d/11] External Storage existierte nach Reboot! "
                            "Gelöscht: %s (Auto-Restore?)", _ext_path,
                        )

                for _pkg in ["com.zhiliaoapp.musically", "com.ss.android.ugc.trill"]:
                    _app_check = await self._adb.shell(
                        f"test -d /data/data/{_pkg}/databases", root=True, timeout=5,
                    )
                    if _app_check.success:
                        await self._adb.shell(
                            f"pm clear {_pkg}", root=True, timeout=15,
                        )
                        _post_reboot_cleaned += 1
                        logger.warning(
                            "[7d/11] TikTok hatte Daten nach Reboot! "
                            "Re-cleared: %s (Auto-Restore?)", _pkg,
                        )

                await self._shifter._disable_google_backup()

                if _post_reboot_cleaned > 0:
                    logger.info(
                        "[7d/11] Post-Reboot Cleanup: %d Artefakte entfernt",
                        _post_reboot_cleaned,
                    )
                else:
                    logger.info("[7d/11] Post-Reboot: Sauber — keine Artefakte gefunden")

            except Exception as e:
                logger.warning("[7d/11] Post-Reboot Sterilisierung Fehler: %s", e)

            # =================================================================
            # PRE-NETWORK: HookGuard starten BEVOR das Netz eingeschaltet wird
            # =================================================================
            logger.info("[7e/11] HookGuard Pre-Network Start...")
            await _auto_start_hookguard(restart=True)

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
            await _airplane_off(self._adb)
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

                    # FIX-18: IP-Collision-Check
                    collision = await check_ip_collision(
                        ip_result.ip, current_profile_id=result.profile_id,
                    )
                    if collision["collision"]:
                        step.detail += f" | ⚠ IP-Collision: {collision['message']}"
                        logger.warning("[8/11] %s", collision["message"])

                    # Subnet/ASN Saturation Check
                    subnet = await check_subnet_saturation(ip_result.ip)
                    if subnet["warning"]:
                        step.detail += f" | ⚠ {subnet['message']}"
                        logger.warning("[8/11] %s", subnet["message"])

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
            # =============================================================
            # v6.0: Dynamisches GMS-Readiness-Polling
            # =============================================================
            # Statt statischer Wartezeiten nutzen wir aktives Polling:
            #   1. sys.boot_completed == 1
            #   2. GmsCore Service aktiv (dumpsys activity services)
            # GSF-ID wird NICHT synchronisiert (Bridge-Wert beibehalten).
            # =============================================================
            logger.info("[9/11] GMS Ready: Dynamisches Readiness-Polling (v6.0)...")

            readiness = await self._shifter.verify_system_readiness(
                timeout=180, poll_interval=5,
            )

            connectivity_ok = readiness.get("gms_ready", False)
            if not connectivity_ok and result.public_ip:
                connectivity_ok = True
                logger.info("[9/11] GMS nicht via Service bestätigt, aber IP vorhanden")

            real_gsf_id = identity.gsf_id
            logger.info(
                "[9/11] GSF-ID: Generierte ID beibehalten. Bridge-GSF: %s...%s",
                identity.gsf_id[:4], identity.gsf_id[-4:],
            )

            if readiness["gms_ready"]:
                step.status = FlowStepStatus.SUCCESS
                step.detail = (
                    f"GMS Verbindung steht ({readiness['elapsed_s']:.0f}s) | "
                    f"GSF-ID: generiert beibehalten"
                )
                logger.info(
                    "[9/11] GMS Verbindung steht - Bereit zum Loslegen! (%s)",
                    readiness["detail"],
                )
            else:
                step.status = FlowStepStatus.SUCCESS  # Nicht blockierend
                step.detail = f"GMS-Timeout ({readiness['detail']}) | GSF-ID beibehalten"
                logger.warning("[9/11] GMS nicht bereit nach %ds", readiness["elapsed_s"])

            step.duration_ms = _now_ms() - step_start
            logger.info("[9/11] GMS Ready: %s", step.detail)

            # =================================================================
            # Schritt 10: CAPTURE STATE (Golden Baseline) v6.0
            # =================================================================
            # Sichert den aktuellen GMS-State als "Golden Baseline".
            # v6.0: Nutzt dynamisches GMS-Readiness-Polling statt
            # statischer 60s-Wartezeiten für den Baseline-Trigger.
            # =================================================================
            step = result.steps[9]
            step.status = FlowStepStatus.RUNNING
            step_start = _now_ms()

            if real_gsf_id:
                # =========================================================
                # BASELINE-TRIGGER v6.0: Quick-Audit mit dynamischem Retry
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
                                    "(%d%%) — dynamisches GMS-Polling...",
                                    pre_audit.score_percent,
                                )
                                # v6.0: Dynamisches Polling statt statischer 60s
                                retry_readiness = await self._shifter.verify_system_readiness(
                                    timeout=90, poll_interval=5,
                                )
                                if retry_readiness["gms_ready"]:
                                    logger.info(
                                        "[10/11] GMS bereit nach %ds — Retry Audit",
                                        retry_readiness["elapsed_s"],
                                    )
                                else:
                                    logger.warning(
                                        "[10/11] GMS-Timeout nach %ds — Retry Audit trotzdem",
                                        retry_readiness["elapsed_s"],
                                    )
                            else:
                                logger.warning(
                                    "[10/11] Baseline-Trigger: Integrität weiterhin %d%% "
                                    "— Capture trotzdem fortsetzen",
                                    pre_audit.score_percent,
                                )
                    except Exception as e:
                        logger.warning("[10/11] Baseline-Trigger Audit fehlgeschlagen: %s", e)
                        if integrity_attempt == 0:
                            # v6.0: Dynamisches Polling statt statischer 60s
                            await self._shifter.verify_system_readiness(
                                timeout=60, poll_interval=5,
                            )

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
                step.status = FlowStepStatus.SKIPPED
                step.detail = "Übersprungen: Keine GSF-ID verfügbar"
                logger.warning("[10/11] Capture State: Übersprungen (keine GSF-ID)")

            step.duration_ms = _now_ms() - step_start

            # =================================================================
            # Schritt 11: AUDIT + ACCOUNT-CHECK + ID-VALIDATION (v6.1)
            # =================================================================
            step = result.steps[10]
            step.status = FlowStepStatus.RUNNING
            step_start = _now_ms()

            logger.info("[11/11] Audit + Account-Check + TikTok ID-Validation (v6.1)...")
            audit = await self._auditor.audit_device(identity)
            result.audit = audit

            # v6.0: Google Account Verifikation
            account_info = await self._shifter.verify_google_account()
            account_detail = account_info["detail"]
            logger.info("[11/11] %s", account_detail)

            # v6.2: Silent TikTok Launch + install_id DB-Persistierung
            # Startet TikTok kurz → extrahiert install_id → Collision-Check
            # gegen dediziertes DB-Feld → Speichern in profiles.tiktok_install_id
            install_id_detail = ""
            try:
                logger.info(
                    "[11/11] TikTok Silent Launch: ID-Generierung starten..."
                )
                tiktok_install_id = await self._shifter.launch_and_extract_install_id(
                    wait_seconds=15,
                )
                if tiktok_install_id:
                    # v6.2: Collision-Check gegen dediziertes DB-Feld
                    from host.engine.db_ops import (
                        check_install_id_collision,
                        save_tiktok_install_id,
                    )
                    collision = await check_install_id_collision(
                        tiktok_install_id,
                        exclude_profile_id=result.profile_id,
                    )
                    if collision["collision"]:
                        install_id_detail = (
                            f"WARNUNG: install_id {tiktok_install_id[:8]}… "
                            f"bereits vergeben an Profil "
                            f"'{collision['existing_profile_name']}' "
                            f"(#{collision['existing_profile_id']}) — "
                            f"Deep-Clean war nicht gründlich genug!"
                        )
                        logger.error("[11/11] ID-COLLISION: %s", install_id_detail)
                    else:
                        # Unique → in DB speichern
                        if result.profile_id:
                            await save_tiktok_install_id(
                                result.profile_id, tiktok_install_id,
                            )
                        install_id_detail = (
                            f"install_id={tiktok_install_id[:8]}…"
                            f"{tiktok_install_id[-4:]} (UNIQUE, gespeichert)"
                        )
                        logger.info("[11/11] TikTok install_id: %s", install_id_detail)
                else:
                    install_id_detail = "install_id nicht extrahierbar (TikTok nicht installiert?)"
                    logger.warning("[11/11] %s", install_id_detail)
            except Exception as e:
                install_id_detail = f"ID-Check fehlgeschlagen: {e}"
                logger.warning("[11/11] TikTok ID-Check: %s", e)

            # DB: Audit in audit_history + identities speichern
            audit_detail_json = json.dumps(
                [{"name": c.name, "status": c.status.value, "expected": c.expected,
                  "actual": c.actual, "detail": c.detail, "critical": c.critical}
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
                base = f"Score: {audit.score_percent}% | {account_detail}"
                suffix = f" | {install_id_detail}" if install_id_detail else ""
                step.detail = base + suffix
                logger.info("[11/11] Audit: PASS (%d%%) | %s", audit.score_percent, account_detail)
            else:
                step.status = FlowStepStatus.FAILED
                step.detail = (
                    f"Score: {audit.score_percent}% — "
                    f"{audit.failed_checks} Check(s) fehlgeschlagen | {account_detail}"
                )
                logger.warning(
                    "[11/11] Audit: FAIL (%d%%) — markiere als corrupted | %s",
                    audit.score_percent, account_detail,
                )
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

            # =================================================================
            # FIX-22: Rollback bei JEDEM Fehler (nicht nur Inject-Fehler)
            # =================================================================
            # Alte Logik: Nur corrupted wenn Inject NICHT erfolgreich war.
            # Neue Logik: IMMER corrupted wenn Identity in DB existiert und
            # der Flow fehlgeschlagen ist. Das Gerät ist in einem unbekannten
            # Zustand — die Identity darf nicht als 'active' bleiben.
            # =================================================================
            if db_identity_id:
                inject_succeeded = any(
                    s.name == "Inject" and s.status == FlowStepStatus.SUCCESS
                    for s in result.steps
                )
                await self._update_identity_status(
                    db_identity_id, IdentityStatus.CORRUPTED,
                )
                if inject_succeeded:
                    result.error = (
                        f"{result.error} | ⚠ Identity '{name}' als corrupted markiert — "
                        f"Genesis Flow NACH Inject abgebrochen. "
                        f"Bitte neuen Genesis-Flow starten."
                    )
                    logger.warning(
                        "FIX-22: Identity %d als corrupted markiert "
                        "(Flow NACH Inject fehlgeschlagen: %s)",
                        db_identity_id, e,
                    )
                else:
                    logger.warning(
                        "Identity %d als corrupted markiert (Inject nicht erreicht)",
                        db_identity_id,
                    )

        except Exception as e:
            result.error = f"Unerwarteter Fehler: {e}"
            logger.error("Genesis Flow Fehler: %s", e, exc_info=True)

            for step in result.steps:
                if step.status == FlowStepStatus.RUNNING:
                    step.status = FlowStepStatus.FAILED
                    step.detail = str(e)
                elif step.status == FlowStepStatus.PENDING:
                    step.status = FlowStepStatus.SKIPPED

            # FIX-22: Auch bei unerwarteten Fehlern: Identity als corrupted
            if db_identity_id:
                try:
                    await self._update_identity_status(
                        db_identity_id, IdentityStatus.CORRUPTED,
                    )
                    result.error = (
                        f"{result.error} | ⚠ Identity '{name}' als corrupted markiert — "
                        f"Unerwarteter Fehler. Bitte neuen Genesis-Flow starten."
                    )
                    logger.warning(
                        "FIX-22: Identity %d als corrupted markiert "
                        "(Unerwarteter Fehler: %s)",
                        db_identity_id, e,
                    )
                except Exception as rollback_err:
                    logger.error(
                        "FIX-22: Rollback fehlgeschlagen für Identity %d: %s",
                        db_identity_id, rollback_err,
                    )

        finally:
            result.finished_at = datetime.now(LOCAL_TZ).isoformat()
            result.duration_ms = _now_ms() - flow_start

            # ─── CLEANUP: Auto-Restore re-enable + Error Recovery ─────────
            try:
                await self._shifter._reenable_auto_restore()
            except Exception:
                pass

            if not result.success:
                logger.warning("ERROR RECOVERY: Flow fehlgeschlagen — räume auf...")
                try:
                    await _airplane_off(self._adb)
                    logger.info("ERROR RECOVERY: Flugmodus AUS")
                except Exception as recovery_err:
                    logger.error(
                        "ERROR RECOVERY: Flugmodus konnte nicht deaktiviert werden: %s",
                        recovery_err,
                    )
                try:
                    await self._adb.shell("bmgr enable true", root=True, timeout=5)
                    logger.info("ERROR RECOVERY: Backup-Manager reaktiviert")
                except Exception:
                    pass

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

            if result.success:
                await _auto_start_hookguard(restart=True)

                # Profile Log Snapshot: TikTok starten und auf Hooks warten,
                # damit der Snapshot aussagekräftige Daten enthält.
                if result.profile_id:
                    try:
                        logger.info("Genesis Snapshot: Starte TikTok für Hook-Verifikation...")
                        await self._adb.shell(
                            "am start -n com.zhiliaoapp.musically/com.ss.android.ugc.aweme.splash.SplashActivity",
                            root=False, timeout=10,
                        )
                        import host.main as _main
                        guard = getattr(_main, "_hookguard", None)
                        _snapshot_ok = False
                        for _wait_round in range(8):
                            await asyncio.sleep(3)
                            if guard and guard.is_running:
                                await guard._poll_once()
                                st = guard.state
                                if st.guard_loaded and (st.native_hooks > 0 or st.art_hooks > 0):
                                    logger.info(
                                        "Genesis Snapshot: Hooks aktiv (native=%d, art=%d) nach %ds",
                                        st.native_hooks, st.art_hooks, (_wait_round + 1) * 3,
                                    )
                                    _snapshot_ok = True
                                    break
                        if not _snapshot_ok:
                            logger.warning(
                                "Genesis Snapshot: Hooks nicht innerhalb von 24s aktiv — "
                                "Snapshot wird trotzdem aufgenommen"
                            )
                    except Exception as snap_err:
                        logger.warning("Genesis Snapshot: TikTok-Start fehlgeschlagen: %s", snap_err)
                    await _capture_profile_snapshot(
                        self._adb, result.profile_id,
                        db_identity_id, "genesis_end",
                    )

        return result

    # =========================================================================
    # Interne Methoden
    # =========================================================================

    async def _find_active_profile(self) -> Optional[dict]:
        """
        Findet das aktuell aktive Profil (für Auto-Backup vor Genesis).

        FIX-11: Gibt jetzt auch tiktok_username zurück für die
        intelligente Backup-Entscheidung.

        Returns:
            Dict mit {"id", "name", "identity_id", "tiktok_username"} oder None
        """
        async with db.connection() as conn:
            cursor = await conn.execute(
                "SELECT p.id, p.name, p.identity_id, p.tiktok_username "
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
                    advertising_id, bluetooth_mac,
                    imsi, sim_serial, operator_name, phone_number,
                    sim_operator, sim_operator_name, voicemail_number,
                    build_id, build_fingerprint, security_patch,
                    build_incremental, build_description,
                    created_at, last_used_at, usage_count
                ) VALUES (
                    ?, 'active', ?,
                    ?, ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?,
                    ?, ?, ?,
                    ?, ?,
                    ?, ?, 1
                )""",
                (
                    identity.name, identity.notes,
                    identity.serial, identity.boot_serial,
                    identity.imei1, identity.imei2,
                    identity.gsf_id, identity.android_id,
                    identity.wifi_mac, identity.widevine_id,
                    getattr(identity, 'advertising_id', None),
                    getattr(identity, 'bluetooth_mac', None),
                    identity.imsi, identity.sim_serial,
                    identity.operator_name, identity.phone_number,
                    identity.sim_operator, identity.sim_operator_name,
                    identity.voicemail_number,
                    identity.build_id, identity.build_fingerprint,
                    identity.security_patch,
                    identity.build_incremental, identity.build_description,
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
        """Flugmodus-Cycle für O2-Lease-Reset (Wireless-ADB-safe)."""
        await _airplane_on_safe(self._adb)
        logger.info("Flugmodus: AN")

        await asyncio.sleep(TIMING.AIRPLANE_MODE_LEASE_SECONDS)

        await _airplane_off(self._adb)
        logger.info("Flugmodus: AUS (nach %ds Lease-Wait)", TIMING.AIRPLANE_MODE_LEASE_SECONDS)

        await asyncio.sleep(3)


# =============================================================================
# Hilfsfunktionen
# =============================================================================

def _now_ms() -> int:
    """Aktuelle Zeit in Millisekunden (für Duration-Tracking)."""
    return int(datetime.now(LOCAL_TZ).timestamp() * 1000)


async def _airplane_on_safe(adb: ADBClient) -> None:
    """Flugmodus AN."""
    await adb.shell(
        "settings put global airplane_mode_on 1", root=True,
    )
    await adb.shell(
        "am broadcast -a android.intent.action.AIRPLANE_MODE "
        "--ez state true",
        root=True,
    )


async def _airplane_off(adb: ADBClient) -> None:
    """Flugmodus AUS."""
    await adb.shell(
        "settings put global airplane_mode_on 0", root=True,
    )
    await adb.shell(
        "am broadcast -a android.intent.action.AIRPLANE_MODE "
        "--ez state false",
        root=True,
    )
