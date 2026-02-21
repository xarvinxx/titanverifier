"""
Switch Flow (Warm Switch / Existing Profile) v6.0
=================================================

FLOW 2: SWITCH (Zygote-First Architecture).

Wechselt zu einem existierenden Profil mit sicherem
Identity-Timing: Neue DNA wird injected und das Framework
restarted BEVOR App-Daten restored werden.

Zwingender Ablauf (10 Schritte — v6.0 Zygote-First):
  1.  AIRPLANE MODE  — Flugmodus AN (Netz sofort trennen)
  2.  AUTO-BACKUP    — Aktives Profil automatisch sichern (Dual-Path)
  3.  SAFETY KILL    — force-stop GMS + GSF + TikTok (alles tot)
  4.  INJECT         — Bridge-Datei aktualisieren (neue DNA)
  5.  SOFT RESET     — killall zygote (Framework bootet mit NEUER Identität)
  6.  GMS READY      — Warte auf Boot + GMS-Readiness (dynamisches Polling)
  7.  RESTORE STATE  — Full-State Restore: GMS + Account-DBs
  8.  RESTORE TIKTOK — TikTok Dual-Path Restore (+ Instance-ID Sanitizing)
  9.  NETWORK INIT   — Flugmodus AUS + neue IP
  10. QUICK AUDIT    — Bridge-Serial prüfen + Account-Check + Audit-Score

v6.0 — "Zygote-First" Architektur:
  KRITISCHE ÄNDERUNG: Das System muss unter der neuen Identität
  'booten' (Zygote-Kill), BEVOR App-Daten geschrieben werden.
  Sonst triggern File-Watcher im system_server/GMS sofort mit der
  alten ID auf die neuen Daten → Shadowban.

  Zusätzlich:
  - PIF custom.pif.prop wird bei jedem Switch frisch generiert (BASIC_INTEGRITY)
  - DroidGuard-Cache (dg.db) wird nach GMS-Restore gelöscht (Neu-Attestierung)
  - TikTok Instance-IDs (install_id, client_udid) werden sanitized
  - Dynamisches GMS-Readiness-Polling statt statischer Wartezeiten
  - Google-Account Verifikation nach Restore

DB-Tracking:
  - Flow-History: Eintrag bei Start, Updates bei jedem Schritt, Finalize + Audit-Score
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

from host.adb.client import ADBClient, ADBError, ADBTimeoutError
from host.config import (
    BACKUP_ACCOUNTS_SUBDIR,
    BACKUP_DIR,
    BACKUP_GMS_SUBDIR,
    GMS_BACKUP_PACKAGES,
    LOCAL_TZ,
    TIKTOK_PACKAGES,
    TIMING,
)
from host.database import db
from host.engine.auditor import DeviceAuditor
from host.engine.db_ops import (
    capture_profile_log,
    check_ip_collision,
    create_flow_history,
    find_profile_by_identity,
    increment_identity_usage,
    record_ip,
    update_flow_history,
    update_identity_audit,
    update_identity_network,
    update_profile_activity,
    update_profile_accounts_backup,
    update_profile_gms_backup,
    update_profile_tiktok_backup,
)
from host.engine.injector import BridgeInjector
from host.engine.shifter import AppShifter
from host.flows.genesis import (
    FlowStep,
    FlowStepStatus,
    _airplane_off,
    _airplane_on_safe,
    _auto_start_hookguard,
    _capture_profile_snapshot,
)
from host.models.identity import IdentityRead, IdentityStatus

logger = logging.getLogger("host.flows.switch")


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
        "Airplane Mode",        # 1: Flugmodus AN
        "Auto-Backup",          # 2: Aktives Profil sichern
        "Safety Kill",          # 3: Alle Apps stoppen
        "Inject",               # 4: Bridge schreiben (neue DNA)
        "Soft Reset",           # 5: killall zygote (Zygote-First!)
        "GMS Ready",            # 6: Boot + GMS-Readiness Polling
        "Restore State",        # 7: GMS + Account-DBs (NACH Zygote!)
        "Restore TikTok",       # 8: TikTok Dual-Path + Sanitize
        "Network Init",         # 9: Flugmodus AUS + neue IP
        "Quick Audit",          # 10: Audit + Account-Check
    ]

    def __init__(self, adb: ADBClient):
        self._adb = adb
        self._injector = BridgeInjector(adb)
        self._shifter = AppShifter(adb)
        self._auditor = DeviceAuditor(adb)

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
            # Schritt 1: AIRPLANE MODE ON (v5.1 — ganz am Anfang!)
            # =================================================================
            step = result.steps[0]
            step.status = FlowStepStatus.RUNNING
            step_start = _now_ms()

            logger.info("[1/10] Flugmodus AN (Netz sofort trennen)...")
            await _airplane_on_safe(self._adb)

            step.status = FlowStepStatus.SUCCESS
            step.detail = "Flugmodus AN — Modem getrennt"
            step.duration_ms = _now_ms() - step_start
            logger.info("[1/10] Flugmodus: AN")

            # =================================================================
            # Schritt 2: AUTO-BACKUP (aktives Profil sichern vor Switch)
            # =================================================================
            step = result.steps[1]
            step.status = FlowStepStatus.RUNNING
            step_start = _now_ms()

            # =============================================================
            # FIX-11: Intelligente Backup-Logik
            #   - Aktives Profil MIT tiktok_username → IMMER Backup
            #   - Aktives Profil OHNE tiktok_username → KEIN Backup
            #   - Kein aktives Profil → KEIN Backup
            # =============================================================
            logger.info("[2/10] Auto-Backup: Aktives Profil prüfen...")
            try:
                active_profile = await self._find_active_profile()
                if active_profile and active_profile["id"] != profile_id:
                    active_name = active_profile["name"]
                    tiktok_user = active_profile.get("tiktok_username")

                    if tiktok_user and tiktok_user.strip():
                        # TikTok-Account eingerichtet → Full-State Backup
                        logger.info(
                            "[2/10] Auto-Backup: Profil '%s' (TikTok: @%s) — "
                            "Full-State (TikTok + GMS + Accounts)...",
                            active_name, tiktok_user,
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
                            logger.warning("[2/10] GMS-Backup fehlgeschlagen: %s", gms_err)

                        try:
                            acc_dir = profile_dir / BACKUP_ACCOUNTS_SUBDIR
                            acc_dir.mkdir(parents=True, exist_ok=True)
                            acc_path = await self._shifter._backup_account_dbs(acc_dir)
                            gms_saved += 1
                            await update_profile_accounts_backup(
                                active_pid, str(acc_path),
                            )
                        except Exception as acc_err:
                            logger.warning("[2/10] Accounts-Backup fehlgeschlagen: %s", acc_err)

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
                                    "[2/10] Backup DB-Update fehlgeschlagen: %s", db_err,
                                )

                        total_saved = tt_saved + gms_saved
                        step.status = FlowStepStatus.SUCCESS
                        step.detail = (
                            f"Profil '{active_name}' (@{tiktok_user}): "
                            f"TikTok={tt_saved}/2, GMS+Acc={gms_saved}/2 "
                            f"(Total: {total_saved}/4)"
                        )
                        logger.info("[2/10] Auto-Backup: %s", step.detail)
                    else:
                        # Kein TikTok-Username → kein Account → nichts zu sichern
                        step.status = FlowStepStatus.SKIPPED
                        step.detail = f"Profil '{active_name}' hat keinen TikTok-Account — kein Backup nötig"
                        logger.info("[2/10] Auto-Backup: %s", step.detail)
                else:
                    step.status = FlowStepStatus.SKIPPED
                    if active_profile:
                        step.detail = "Ziel-Profil ist bereits aktiv"
                    else:
                        step.detail = "Kein aktives Profil gefunden"
                    logger.info("[2/10] Auto-Backup: %s", step.detail)
            except Exception as e:
                # Auto-Backup ist nicht kritisch — Switch fortsetzen
                step.status = FlowStepStatus.SUCCESS
                step.detail = f"Backup-Warnung: {e} (Switch wird fortgesetzt)"
                logger.warning("[2/10] Auto-Backup fehlgeschlagen (nicht kritisch): %s", e)

            step.duration_ms = _now_ms() - step_start

            # switch_out: Snapshot des bisherigen Profils (vor dem Wechsel)
            if active_profile and active_profile["id"] != profile_id:
                try:
                    await _capture_profile_snapshot(
                        self._adb, active_profile["id"],
                        active_profile.get("identity_id"), "switch_out",
                    )
                except Exception:
                    pass

            # =================================================================
            # Schritt 3: SAFETY KILL (GMS + TikTok + Vending)
            # =================================================================
            step = result.steps[2]
            step.status = FlowStepStatus.RUNNING
            step_start = _now_ms()

            logger.info("[3/10] Safety Kill: Alle Apps stoppen...")
            # v7.1: gms.unstable ZUERST beenden (Zombie-Prävention)
            await self._shifter._reap_gms_zombies()
            killed = []
            for pkg in [*GMS_BACKUP_PACKAGES, "com.zhiliaoapp.musically"]:
                try:
                    await self._adb.shell(
                        f"am force-stop {pkg}", root=True,
                    )
                    killed.append(pkg.split(".")[-1])
                except ADBError:
                    pass
            # Nochmal prüfen ob force-stop einen neuen Zombie erzeugt hat
            await self._shifter._reap_gms_zombies()

            step.status = FlowStepStatus.SUCCESS
            step.detail = f"Gestoppt: {', '.join(killed)}"
            step.duration_ms = _now_ms() - step_start
            logger.info("[3/10] Safety Kill: OK (%s)", step.detail)

            # =================================================================
            # FIX-29: Gründlicher State-Wipe (ersetzt FIX-16 Mini-Clean)
            # =================================================================
            # Löscht ALLE TikTok-Daten (App-Daten inkl. Hidden Files,
            # Sandbox, Tracking-Dateien, ART Profiles, Compiler Cache,
            # Settings-ContentProvider). Der Restore in Step 5/6 schreibt
            # dann in eine garantiert saubere Umgebung.
            #
            # Unterschied zu FIX-16 Mini-Clean:
            #   - Löscht /data/data/<pkg>/ komplett (nicht nur /sdcard/)
            #   - Bereinigt ART Profiles + Compiler Cache
            #   - Bereinigt Settings-ContentProvider (FIX-14)
            #   - Verhindert Identity-Leakage durch Hidden Files
            # =================================================================
            try:
                logger.info("[3→4] FIX-29: Gründlicher State-Wipe vor Restore...")
                clean_results = await self._shifter.prepare_switch_clean()
                clean_ok = sum(1 for v in clean_results.values() if v)
                clean_failed = [k for k, v in clean_results.items() if not v]
                if clean_failed:
                    logger.warning(
                        "[3→4] FIX-29: State-Wipe %d/%d OK — FEHLGESCHLAGEN: %s",
                        clean_ok, len(clean_results), ", ".join(clean_failed),
                    )
                else:
                    logger.info(
                        "[3→4] FIX-29: State-Wipe %d/%d Operationen ALLE OK",
                        clean_ok, len(clean_results),
                    )
            except Exception as e:
                logger.warning("[3→4] FIX-29: State-Wipe fehlgeschlagen (nicht kritisch): %s", e)

            # =================================================================
            # Schritt 4: INJECT (Bridge schreiben — neue DNA)
            # =================================================================
            step = result.steps[3]
            step.status = FlowStepStatus.RUNNING
            step_start = _now_ms()

            logger.info("[4/10] Inject: Bridge-Datei aktualisieren...")
            await self._injector.inject(
                identity, label=identity.name, distribute=True,
            )

            # PIF v5.0: autopif4-First Strategie (BASIC_INTEGRITY)
            pif_ok = False
            try:
                pif_ok = await self._injector.inject_pif_fingerprint()
                if pif_ok:
                    logger.info("[4/10] PIF v5.0: custom.pif.prop OK (autopif4-First)")
                else:
                    logger.warning("[4/10] PIF: Injection fehlgeschlagen — BASIC_INTEGRITY gefährdet!")
            except Exception as e:
                logger.warning("[4/10] PIF Fehler (nicht-kritisch): %s", e)

            await self._activate_identity(identity_id)
            try:
                await increment_identity_usage(identity_id)
            except Exception as e:
                logger.warning("Usage-Counter Update fehlgeschlagen: %s", e)

            step.status = FlowStepStatus.SUCCESS
            step.detail = f"serial={identity.serial} | PIF={'OK' if pif_ok else 'FAIL'}"
            step.duration_ms = _now_ms() - step_start
            logger.info("[4/10] Inject: OK (%s)", step.detail)

            # =================================================================
            # Schritt 5: SAFE ZYGOTE RESTART (Anti-Bootloop v2.0)
            # =================================================================
            # KRITISCH: Zygote-Kill MUSS vor dem Restore kommen!
            # Das Framework muss unter der NEUEN Identität booten,
            # BEVOR App-Daten geschrieben werden. Sonst sehen
            # File-Watcher im system_server die neuen Daten mit
            # der alten Hardware-ID → sofortiges Flagging.
            #
            # BOOTLOOP-PRÄVENTION (6 Schutzschichten):
            #   1. LSPosed DB Backup
            #   2. SQLite WAL Checkpoint auf system_server DBs
            #   3. Accounts-DB löschen (wird in Step 7 restored)
            #   4. Filesystem sync + Verifikation
            #   5. Graceful Kill: SIGTERM → wait → SIGKILL
            #   6. Post-Kill: LSPosed DB Integritäts-Check
            # =================================================================
            step = result.steps[4]
            step.status = FlowStepStatus.RUNNING
            step_start = _now_ms()

            # --- Schicht 1: LSPosed DB sichern ---
            try:
                await self._adb.shell(
                    "cp /data/adb/lspd/config/modules_config.db "
                    "/data/adb/lspd/config/modules_config.db.pre_zygote 2>/dev/null",
                    root=True, timeout=5,
                )
                logger.debug("[5/10] LSPosed DB gesichert (pre-zygote backup)")
            except (ADBError, ADBTimeoutError):
                logger.debug("[5/10] LSPosed DB Backup übersprungen")

            # --- Schicht 2: SQLite WAL Checkpoint ---
            # Zwingt alle pending WAL-Writes in die Haupt-DB.
            # Ohne Checkpoint korruptiert SIGKILL die WAL → Bootloop.
            _wal_dbs = [
                "/data/system_ce/0/accounts_ce.db",
                "/data/system_de/0/accounts_de.db",
                "/data/system/sync/stats.bin",
            ]
            for db_path in _wal_dbs:
                try:
                    await self._adb.shell(
                        f'sqlite3 {db_path} "PRAGMA wal_checkpoint(TRUNCATE);" 2>/dev/null',
                        root=True, timeout=5,
                    )
                except (ADBError, ADBTimeoutError):
                    pass
            logger.info("[5/10] SQLite WAL Checkpoint: erledigt")

            # --- Schicht 3: Accounts-DB — NUR löschen wenn Backup existiert ---
            # Ohne Accounts-Backup → DB behalten! Sonst verliert das Gerät
            # den Google-Account und GMS/Play Store trennen sich.
            # WAL-Checkpoint (Schicht 2) schützt bereits vor Korruption.
            _has_accounts_backup = False
            if use_full_state and profile_name:
                _acc_dir = BACKUP_DIR / profile_name / BACKUP_ACCOUNTS_SUBDIR
                _has_accounts_backup = (
                    _acc_dir.exists()
                    and any(_acc_dir.glob("*.tar"))
                )

            if _has_accounts_backup:
                try:
                    await self._adb.shell(
                        "rm -f "
                        "/data/system_ce/0/accounts_ce.db "
                        "/data/system_ce/0/accounts_ce.db-journal "
                        "/data/system_ce/0/accounts_ce.db-wal "
                        "/data/system_ce/0/accounts_ce.db-shm "
                        "/data/system_de/0/accounts_de.db "
                        "/data/system_de/0/accounts_de.db-journal "
                        "/data/system_de/0/accounts_de.db-wal "
                        "/data/system_de/0/accounts_de.db-shm",
                        root=True, timeout=5,
                    )
                    logger.info("[5/10] Accounts-DB entfernt (Backup vorhanden → wird in Step 7 restored)")
                except (ADBError, ADBTimeoutError):
                    logger.warning("[5/10] Accounts-DB entfernen fehlgeschlagen")
            else:
                logger.info(
                    "[5/10] Accounts-DB BEHALTEN — kein Backup vorhanden. "
                    "WAL-Checkpoint schützt vor Korruption."
                )

            # --- Schicht 4: Filesystem sync + Verifikation ---
            try:
                await self._adb.shell("sync", root=True, timeout=15)
                if _has_accounts_backup:
                    verify = await self._adb.shell(
                        "test -f /data/system_ce/0/accounts_ce.db "
                        "&& echo EXISTS || echo GONE",
                        root=True, timeout=5,
                    )
                    if verify.success and "GONE" in (verify.output or ""):
                        logger.info("[5/10] Sync + Verify: accounts_ce.db GELÖSCHT bestätigt")
                    else:
                        logger.warning(
                            "[5/10] WARNUNG: accounts_ce.db noch vorhanden nach rm+sync! "
                            "Versuche erneut..."
                        )
                        await self._adb.shell(
                            "rm -f /data/system_ce/0/accounts_ce.db* && sync",
                            root=True, timeout=10,
                        )
                else:
                    logger.info("[5/10] Sync: OK (Accounts-DB bewahrt)")
            except (ADBError, ADBTimeoutError):
                logger.warning("[5/10] Sync/Verify fehlgeschlagen")

            # --- Schicht 5: Graceful Zygote Kill ---
            # SIGTERM (15) zuerst → gibt system_server 2s um offene
            # SQLite-Transaktionen zu committen und File-Handles zu
            # schließen. Dann SIGKILL als Fallback.
            logger.info("[5/10] Soft Reset: Graceful Zygote Kill...")
            try:
                await self._adb.shell(
                    "kill -SIGTERM $(pidof zygote64) $(pidof zygote) 2>/dev/null",
                    root=True, timeout=5,
                )
                logger.debug("[5/10] SIGTERM gesendet — warte 2s auf Cleanup...")
            except (ADBError, ADBTimeoutError):
                pass
            await asyncio.sleep(2)
            try:
                await self._adb.shell("killall -9 zygote 2>/dev/null", root=True)
            except ADBError:
                pass

            logger.info(
                "[5/10] Warte %ds auf Zygote-Restart...",
                TIMING.ZYGOTE_RESTART_WAIT,
            )
            await asyncio.sleep(TIMING.ZYGOTE_RESTART_WAIT)
            if not await self._adb.is_connected():
                logger.info("[5/10] ADB nach Zygote-Kill weg — Reconnect...")
                await self._adb.ensure_connection(timeout=60)

            # --- Schicht 6: LSPosed DB Integritäts-Check ---
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
                        "[5/10] LSPosed DB %s nach Zygote-Kill! "
                        "Stelle aus pre-zygote Backup wieder her...",
                        db_state,
                    )
                    await self._adb.shell(
                        "cp /data/adb/lspd/config/modules_config.db.pre_zygote "
                        "/data/adb/lspd/config/modules_config.db && "
                        "chmod 600 /data/adb/lspd/config/modules_config.db",
                        root=True, timeout=5,
                    )
                    logger.info("[5/10] LSPosed DB aus Backup wiederhergestellt")
                else:
                    logger.debug("[5/10] LSPosed DB intakt nach Zygote-Kill")
            except (ADBError, ADBTimeoutError):
                logger.debug("[5/10] LSPosed DB-Check übersprungen")

            step.status = FlowStepStatus.SUCCESS
            step.detail = f"Graceful Zygote-Kill (SIGTERM→SIGKILL) + {TIMING.ZYGOTE_RESTART_WAIT}s Wait"
            step.duration_ms = _now_ms() - step_start

            # =================================================================
            # Schritt 6: GMS READY (Dynamisches Readiness-Polling)
            # =================================================================
            # Wartet auf:
            #   1. sys.boot_completed == 1
            #   2. GmsCore Service aktiv (dumpsys activity services)
            # Ersetzt das alte statische sleep(5) + boot_completed polling.
            # =================================================================
            step = result.steps[5]
            step.status = FlowStepStatus.RUNNING
            step_start = _now_ms()

            logger.info("[6/10] GMS Ready: Warte auf Boot + GMS-Readiness...")
            readiness = await self._shifter.verify_system_readiness(
                timeout=180, poll_interval=5,
            )

            if readiness["boot_ready"]:
                await self._adb.unlock_device()

            if readiness["boot_ready"] and readiness["gms_ready"]:
                step.status = FlowStepStatus.SUCCESS
                step.detail = (
                    f"System bereit in {readiness['elapsed_s']:.0f}s "
                    f"({readiness['detail']}) — GMS Verbindung steht"
                )
                logger.info(
                    "[6/10] GMS Verbindung steht - Bereit zum Loslegen! (%s)",
                    readiness["detail"],
                )
            elif readiness["boot_ready"]:
                # v6.5 FIX: GMS-Timeout ist gefährlich — prüfe Uptime
                # Wenn Uptime < 30s trotz 180s Timeout → Gerät war im Bootloop
                try:
                    uptime_r = await self._adb.shell("cat /proc/uptime", root=False, timeout=5)
                    uptime_secs = float(uptime_r.output.strip().split()[0]) if uptime_r.success else 999
                except Exception:
                    uptime_secs = 999

                if uptime_secs < 60:
                    # Gerät hat sich während des Wartens neugestartet → Bootloop!
                    # AUTO-RECOVERY: Accounts-DB löschen + sync + Reboot via Fastboot
                    logger.error(
                        "[6/10] BOOTLOOP ERKANNT (uptime=%.0fs) — "
                        "starte Auto-Recovery...",
                        uptime_secs,
                    )
                    try:
                        await self._adb.shell(
                            "rm -f "
                            "/data/system_ce/0/accounts_ce.db* "
                            "/data/system_de/0/accounts_de.db* "
                            "&& sync",
                            root=True, timeout=10,
                        )
                        logger.info("[6/10] Auto-Recovery: Accounts-DB gelöscht + sync")
                        await self._adb.shell("reboot bootloader", root=True)
                        logger.info("[6/10] Auto-Recovery: Gerät in Fastboot gesendet")
                        await asyncio.sleep(10)
                    except (ADBError, ADBTimeoutError) as recovery_err:
                        logger.error("[6/10] Auto-Recovery fehlgeschlagen: %s", recovery_err)

                    step.status = FlowStepStatus.FAILED
                    step.detail = (
                        f"ABORT: Bootloop erkannt (uptime={uptime_secs:.0f}s). "
                        f"Auto-Recovery: Accounts-DB gelöscht → Gerät in Fastboot. "
                        f"Bitte manuell 'fastboot reboot' ausführen."
                    )
                    raise ADBError(
                        f"Bootloop erkannt (uptime={uptime_secs:.0f}s) — "
                        f"Auto-Recovery ausgeführt, Gerät in Fastboot"
                    )
                else:
                    step.status = FlowStepStatus.SUCCESS
                    step.detail = f"Boot OK, GMS-Timeout ({readiness['detail']})"
                    logger.warning("[6/10] GMS nicht bereit — Restore fortsetzen (uptime=%.0fs OK)", uptime_secs)
            else:
                step.status = FlowStepStatus.FAILED
                step.detail = f"Boot-Timeout: {readiness['detail']}"
                logger.error("[6/10] Gerät nach Soft Reset nicht erreichbar")
                raise ADBError("Gerät nach Soft Reset nicht erreichbar — Switch abgebrochen")

            step.duration_ms = _now_ms() - step_start

            # =================================================================
            # Schritt 7: RESTORE STATE (GMS + Account-DBs — NACH Zygote!)
            # =================================================================
            # Das System läuft jetzt unter der NEUEN Identität.
            # Erst JETZT werden App-Daten geschrieben.
            # =================================================================
            step = result.steps[6]
            step.status = FlowStepStatus.RUNNING
            step_start = _now_ms()

            if use_full_state:
                logger.info("[7/10] Restore State: GMS + Account-DBs (nach Zygote-First)...")
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
                            f"TikTok: {'OK' if tiktok_from_state else 'FAIL'} "
                            f"(DroidGuard sanitized)"
                        )
                    elif gms_ok or accounts_ok:
                        step.status = FlowStepStatus.SUCCESS
                        step.detail = (
                            f"Teilweise: GMS={'OK' if gms_ok else 'SKIP'}, "
                            f"Accounts={'OK' if accounts_ok else 'SKIP'}"
                        )
                        logger.warning("[7/10] Partial Restore — Google Logout möglich")
                    else:
                        # v6.5 FIX: FAILED statt SUCCESS wenn NICHTS restored wurde
                        step.status = FlowStepStatus.FAILED
                        step.detail = "KRITISCH: 0/2 Komponenten restored (GMS+Accounts fehlen)"
                        logger.error("[7/10] KRITISCH: Kein GMS-State restored — Bootloop-Gefahr!")

                except Exception as e:
                    # v6.5 FIX: Exception = FAILED, nicht SUCCESS
                    step.status = FlowStepStatus.FAILED
                    step.detail = f"State Restore Fehler: {e}"
                    logger.error("[7/10] State Restore FEHLER: %s", e)
            else:
                # Legacy-Modus: Kein GMS-Restore, aber DroidGuard trotzdem
                # bereinigen! Die alten Attestierungs-Tokens passen nicht
                # zur neuen Identity → BASIC_INTEGRITY degradiert.
                logger.info("[7/10] Legacy-Modus — DroidGuard Sanitize als Safety-Net...")
                try:
                    await self._shifter._sanitize_droidguard()
                    # v7.1: gms.unstable ZUERST beenden (Zombie-Prävention)
                    await self._shifter._reap_gms_zombies()
                    await self._adb.shell(
                        "am force-stop com.google.android.gms", root=True, timeout=10,
                    )
                    await self._shifter._reap_gms_zombies()
                    logger.info("[7/10] DroidGuard gelöscht + GMS neu gestartet")
                except Exception as e:
                    logger.warning("[7/10] DroidGuard Sanitize fehlgeschlagen: %s", e)

                step.status = FlowStepStatus.SKIPPED
                step.detail = "Legacy-Modus — kein Full-State Restore (DG sanitized)"

            step.duration_ms = _now_ms() - step_start

            # =================================================================
            # Schritt 8: RESTORE TIKTOK (Dual-Path + Instance-ID Sanitizing)
            # =================================================================
            step = result.steps[7]
            step.status = FlowStepStatus.RUNNING
            step_start = _now_ms()

            if use_full_state or profile_name:
                logger.info("[8/10] TikTok Restore + Sanitize...")
                try:
                    dual_result = await self._shifter.restore_tiktok_dual(
                        profile_name,
                    )
                    sandbox_ok = dual_result.get("sandbox", False)
                    app_ok = dual_result.get("app_data", False)

                    if sandbox_ok or app_ok:
                        step.status = FlowStepStatus.SUCCESS
                        step.detail = (
                            f"App: {'OK' if app_ok else 'SKIP'}, "
                            f"Sandbox: {'OK' if sandbox_ok else 'SKIP'} "
                            f"(Instance-IDs sanitized)"
                        )
                    else:
                        step.status = FlowStepStatus.SKIPPED
                        step.detail = "Keine TikTok Backups vorhanden"
                except Exception as e:
                    # v6.5 FIX: Exception = FAILED, nicht SUCCESS
                    step.status = FlowStepStatus.FAILED
                    step.detail = f"TikTok-Restore FEHLER: {e}"
                    logger.error("[8/10] TikTok-Restore FEHLER: %s", e)

            elif backup_path:
                logger.info("[8/10] Restore TikTok: Legacy-Modus...")
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

            step.duration_ms = _now_ms() - step_start

            # Post-Restore Verifikation (v6.5: KEIN pm clear mehr!)
            # Das alte "Zombie-Schutz" pm clear hat die gerade restored Daten
            # KOMPLETT gelöscht → Login-Session verloren → nutzloser Switch.
            if use_full_state or profile_name:
                try:
                    verify = await self._shifter.verify_app_data_restored()
                    if not verify["ok"]:
                        logger.warning(
                            "[8/10] Post-Restore Verifikation WARNUNG: %s",
                            verify["detail"],
                        )
                        # v6.5 FIX: NUR warnen, NICHT pm clear!
                        # pm clear zerstört die restored Login-Session.
                        tiktok_step = result.steps[7]
                        if tiktok_step.status == FlowStepStatus.SUCCESS:
                            tiktok_step.status = FlowStepStatus.FAILED
                            tiktok_step.detail = f"Verifikation FEHL: {verify['detail']}"
                    else:
                        logger.info("[8/10] Post-Restore Verifikation OK")
                except Exception as e:
                    logger.warning("[8/10] Verifikation fehlgeschlagen: %s", e)

            # Randomize timestamps to hide restore signature
            for pkg in TIKTOK_PACKAGES:
                await self._shifter._randomize_timestamps(pkg)

            # Clipboard wipe
            await self._shifter._clear_clipboard()

            # Disable Google backup
            await self._shifter._disable_google_backup()

            # =================================================================
            # PRE-NETWORK: HookGuard starten BEVOR das Netz eingeschaltet wird
            # =================================================================
            logger.info("[8b/10] HookGuard Pre-Network Start...")
            await _auto_start_hookguard(restart=True)

            # =================================================================
            # Schritt 9: NETWORK INIT (Flugmodus AUS + neue IP)
            # =================================================================
            step = result.steps[8]
            step.status = FlowStepStatus.RUNNING
            step_start = _now_ms()

            logger.info("[9/10] Network Init: Flugmodus AUS...")
            await asyncio.sleep(10)

            await _airplane_off(self._adb)
            logger.info("[9/10] Flugmodus: AUS — Modem verbindet sich neu")

            from host.engine.network import NetworkChecker
            NetworkChecker.invalidate_ip_cache()

            await asyncio.sleep(TIMING.IP_AUDIT_WAIT_SECONDS)

            try:
                network = NetworkChecker(self._adb)
                ip_result = await network.get_public_ip(skip_cache=True)
                if ip_result.success:
                    step.detail = f"Neue IP: {ip_result.ip} (via {ip_result.service})"
                    logger.info("[9/10] Network Init: IP = %s", ip_result.ip)

                    try:
                        if identity_id:
                            await update_identity_network(
                                identity_id, ip_result.ip, ip_result.service,
                            )
                            await record_ip(
                                public_ip=ip_result.ip,
                                identity_id=identity_id,
                                profile_id=profile_id,
                                ip_service=ip_result.service,
                                connection_type="mobile_o2",
                                flow_type="switch",
                            )
                        collision = await check_ip_collision(
                            ip_result.ip, current_profile_id=profile_id,
                        )
                        if collision["collision"]:
                            step.detail += f" | IP-Collision: {collision['message']}"
                            logger.warning("[9/10] %s", collision["message"])
                    except Exception as db_e:
                        logger.warning("[9/10] IP-DB fehlgeschlagen: %s", db_e)

                    step.status = FlowStepStatus.SUCCESS
                else:
                    step.status = FlowStepStatus.SUCCESS
                    step.detail = f"Flugmodus AUS, IP-Check fehlgeschlagen: {ip_result.error}"
            except Exception as e:
                step.status = FlowStepStatus.SUCCESS
                step.detail = f"Flugmodus AUS, IP-Fehler: {e}"

            step.duration_ms = _now_ms() - step_start

            # =================================================================
            # Schritt 10: QUICK AUDIT + ACCOUNT-CHECK + TRACKING
            # =================================================================
            step = result.steps[9]
            step.status = FlowStepStatus.RUNNING
            step_start = _now_ms()

            logger.info("[10/10] Quick Audit + Account-Check...")
            audit_ok = await self._auditor.quick_audit(identity.serial, expected_identity=identity)
            result.audit_passed = audit_ok

            # Account-Verifikation nach Restore
            account_info = await self._shifter.verify_google_account()
            account_detail = account_info["detail"]

            audit_score = 100 if audit_ok else 0
            try:
                if identity_id:
                    await update_identity_audit(
                        identity_id,
                        score=audit_score,
                        detail=json.dumps(
                            [{"name": "bridge_serial", "status": "pass" if audit_ok else "fail",
                              "expected": identity.serial,
                              "actual": identity.serial if audit_ok else "MISMATCH",
                              "detail": f"Switch v6.0 | {account_detail}"}],
                            ensure_ascii=False,
                        ),
                    )
                if flow_history_id:
                    await update_flow_history(
                        flow_history_id,
                        audit_score=audit_score,
                    )
            except Exception as e:
                logger.warning("Audit-Score DB-Update fehlgeschlagen: %s", e)

            if audit_ok:
                step.status = FlowStepStatus.SUCCESS
                step.detail = (
                    f"Bridge serial={identity.serial} (Score: {audit_score}%) "
                    f"| {account_detail}"
                )
            else:
                step.status = FlowStepStatus.FAILED
                step.detail = f"Bridge-Serial MISMATCH! | {account_detail}"
                logger.warning("[10/10] Quick Audit FAIL!")

            step.duration_ms = _now_ms() - step_start

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

            # ─── CLEANUP: Auto-Restore re-enable ───
            try:
                await self._shifter._reenable_auto_restore()
            except Exception:
                pass

            # ─── ERROR RECOVERY: Flugmodus + Backup-Manager reparieren ───
            if not result.success:
                logger.warning("ERROR RECOVERY: Switch fehlgeschlagen — räume auf...")
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
                "  SWITCH %s: %s (%d ms)",
                "ERFOLG" if result.success else "FEHLGESCHLAGEN",
                identity.name if identity else "?",
                result.duration_ms,
            )
            logger.info("  %s", result.step_summary)
            logger.info("=" * 60)

            if result.success:
                await _auto_start_hookguard(restart=True)

                # switch_in: Snapshot erst NACH TikTok-Start aufnehmen.
                # Ohne laufendes TikTok schreibt das Zygisk-Modul keine
                # Guard-Datei → Snapshot würde 0 Hooks / 0 Heartbeat zeigen
                # und irreführende "Leak"-Warnungen produzieren.
                if profile_id:
                    try:
                        logger.info("Switch-In Snapshot: Starte TikTok für Hook-Verifikation...")
                        await self._adb.shell(
                            "am start -n com.zhiliaoapp.musically/com.ss.android.ugc.aweme.splash.SplashActivity",
                            root=False, timeout=10,
                        )
                        # Warte bis Zygisk-Modul Guard-Datei schreibt + erste Hooks aktiv
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
                                        "Switch-In Snapshot: Hooks aktiv (native=%d, art=%d) nach %ds",
                                        st.native_hooks, st.art_hooks, (_wait_round + 1) * 3,
                                    )
                                    _snapshot_ok = True
                                    break
                        if not _snapshot_ok:
                            logger.warning(
                                "Switch-In Snapshot: Hooks nicht innerhalb von 24s aktiv — "
                                "Snapshot wird trotzdem aufgenommen"
                            )
                        await _capture_profile_snapshot(
                            self._adb, profile_id, identity_id, "switch_in",
                        )
                    except Exception as snap_err:
                        logger.warning("Switch-In Snapshot fehlgeschlagen: %s", snap_err)

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

    async def _find_active_profile(self) -> Optional[dict]:
        """
        Findet das aktuell aktive Profil (für Auto-Backup vor Switch).

        FIX-11: Gibt jetzt auch tiktok_username zurück für die
        intelligente Backup-Entscheidung (Backup wenn Username gesetzt).

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
