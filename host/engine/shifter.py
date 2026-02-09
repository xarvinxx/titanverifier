"""
Project Titan — TitanShifter v3.0 ("Golden Baseline")
=======================================================

Verwaltet App-Daten (TikTok + GMS) für Profile-Switching.

Architektur v3.0 — State-Layering:
  GMS wird NICHT mehr bei jedem Switch gelöscht. Stattdessen:
  1. Genesis: pm clear GMS (einmalig) → warten auf GSF-ID → Golden Baseline sichern
  2. Switch:  Golden Baseline restoren → sofort Play Integrity bereit

Operationen:
  - backup / restore:        TikTok App-Daten
  - deep_clean:              Vollsterilisierung (pm clear GMS nur bei include_gms=True)
  - capture_gms_state:       *** NEU v3.0 *** Golden Baseline Snapshot
  - kill_all_targets:        *** NEU v3.0 *** Robuster Process Kill + sync
  - backup_full_state:       Kompletter Session-State (TikTok + GMS + Accounts)
  - restore_full_state:      Kompletter Session-Restore mit SQLite Safety

KRITISCH — Magic Permission Fix (aus TITAN_CONTEXT.md §3B):
  Nach jedem Restore MUSS die UID der App ermittelt und
  chown -R UID:UID auf den gesamten Datenordner ausgeführt werden.
  Ohne diesen Fix verliert die App den Zugriff auf ihre Daten
  und der Login geht verloren.

  KEIN restorecon auf App-Daten verwenden — verursacht Bootloops auf Android 14!
  (restorecon ist NUR für accounts_ce.db erlaubt)
"""

from __future__ import annotations

import logging
import os
from datetime import datetime

from host.config import LOCAL_TZ
from pathlib import Path
from typing import Optional

from host.adb.client import ADBClient, ADBError, ADBTimeoutError
from host.config import (
    ACCOUNTS_DB_MODE,
    ACCOUNTS_DB_OWNER,
    ACCOUNTS_DB_GROUP,
    ACCOUNTS_DB_SELINUX,
    BACKUP_ACCOUNTS_SUBDIR,
    BACKUP_DIR,
    BACKUP_GMS_SUBDIR,
    BACKUP_TIKTOK_SUBDIR,
    GMS_BACKUP_PACKAGES,
    GMS_PACKAGES,
    SYSTEM_ACCOUNT_DBS,
    TIKTOK_PACKAGES,
)

logger = logging.getLogger("titan.engine.shifter")

# =============================================================================
# Konstanten
# =============================================================================

# Primäres TikTok-Paket (International)
TIKTOK_PRIMARY = "com.zhiliaoapp.musically"

# TikTok-Datenverzeichnisse die bereinigt werden müssen
TIKTOK_SDCARD_DIRS = [
    "/sdcard/Android/data/com.zhiliaoapp.musically",
    "/sdcard/Android/obb/com.zhiliaoapp.musically",
    "/sdcard/Android/data/com.ss.android.ugc.trill",
    "/sdcard/Android/obb/com.ss.android.ugc.trill",
]

# TikTok Tracking-Dateien auf der SD-Karte
TIKTOK_TRACKING_GLOBS = [
    "/sdcard/.tt*",           # TikTok Tracking Cookies
    "/sdcard/.tg*",           # TikTok Tracking (variant)
    "/sdcard/.tobid*",        # TikTok TOBID tracking
]


class TitanShifter:
    """
    App-Data Manager für Profile-Switching.

    Sichert und stellt TikTok App-Daten her, inklusive dem
    kritischen Magic Permission Fix nach dem Restore.

    Usage:
        adb = ADBClient()
        shifter = TitanShifter(adb)

        # Backup
        path, size = await shifter.backup("profile_001")

        # Restore
        await shifter.restore("profile_001")

        # Deep Clean
        await shifter.deep_clean()
    """

    def __init__(
        self,
        adb: ADBClient,
        backup_dir: Optional[Path] = None,
        package: str = TIKTOK_PRIMARY,
    ):
        self._adb = adb
        self._backup_dir = backup_dir or BACKUP_DIR
        self._package = package
        self._data_path = f"/data/data/{package}"

        # Backup-Verzeichnis sicherstellen
        self._backup_dir.mkdir(parents=True, exist_ok=True)

    # =========================================================================
    # *** NEU v3.0 *** Kill-All-Targets: Robuster Process Kill
    # =========================================================================

    async def kill_all_targets(self) -> list[str]:
        """
        Robuster Kill-Flow: Stoppt ALLE relevanten Prozesse VOR einem State-Swap.

        Verhindert File-Corruption wenn tar-Restore während offener
        DB-Handles / Socket-Connections läuft.

        Ablauf:
          1. am force-stop für alle GMS + TikTok Pakete
          2. killall -9 für hartnäckige GMS-Prozesse + android.process.acore
          3. sync — Filesystem-Buffer flushen

        Returns:
            Liste der gestoppten Paket-Kurznamen
        """
        logger.info("Kill-All-Targets: Stoppe alle relevanten Prozesse...")
        killed: list[str] = []

        # Phase 1: Sauberer force-stop (ActivityManager)
        kill_targets = [
            *GMS_BACKUP_PACKAGES,           # gms, gsf, vending
            *TIKTOK_PACKAGES,               # musically, trill
            "com.google.android.googlequicksearchbox",  # Google App
        ]
        for pkg in kill_targets:
            try:
                await self._adb.shell(f"am force-stop {pkg}", root=True, timeout=5)
                killed.append(pkg.split(".")[-1])
            except (ADBError, ADBTimeoutError):
                pass

        # Phase 2: Hard kill für hartnäckige Prozesse (SIGKILL)
        hard_kill_procs = [
            "com.google.android.gms",
            "com.google.android.gms.persistent",
            "com.google.process.gapps",
            "android.process.acore",          # Contacts/Accounts Provider
        ]
        for proc in hard_kill_procs:
            try:
                await self._adb.shell(
                    f"killall -9 {proc} 2>/dev/null", root=True, timeout=5,
                )
            except (ADBError, ADBTimeoutError):
                pass  # Prozess existiert möglicherweise nicht

        # Phase 3: Filesystem sync — pending writes flushen
        try:
            await self._adb.shell("sync", root=True, timeout=10)
        except (ADBError, ADBTimeoutError):
            logger.warning("sync fehlgeschlagen (nicht kritisch)")

        logger.info("Kill-All-Targets: %d Apps gestoppt + sync", len(killed))
        return killed

    # =========================================================================
    # *** NEU v3.0 *** Capture GMS State: Golden Baseline Snapshot
    # =========================================================================

    async def capture_gms_state(
        self,
        profile_name: str,
        gsf_id: str | None = None,
    ) -> dict[str, Path | None]:
        """
        Sichert den aktuellen GMS-State als "Golden Baseline".

        Wird im GenesisFlow aufgerufen sobald wait_for_gsf_id() erfolgreich ist.
        Der gesicherte State enthält:
          1. GMS App-Daten (com.google.android.gms, gsf, vending)
          2. System Account-DBs (accounts_ce.db + Journal/WAL/SHM)

        Dieser Snapshot ist die kryptografische Basis für alle späteren
        Switches mit dieser Identität. KEIN pm clear nötig beim Switch!

        Args:
            profile_name: Profil-Name für den Backup-Ordner
            gsf_id:       Optional — die gerade generierte GSF-ID (für Logging)

        Returns:
            Dict mit Pfaden: {"gms": Path|None, "accounts": Path|None}
        """
        logger.info("=" * 60)
        logger.info("  GOLDEN BASELINE CAPTURE: %s", profile_name)
        if gsf_id:
            logger.info("  GSF-ID: %s...%s", gsf_id[:4], gsf_id[-4:])
        logger.info("=" * 60)

        results: dict[str, Path | None] = {"gms": None, "accounts": None}

        profile_dir = self._backup_dir / profile_name
        profile_dir.mkdir(parents=True, exist_ok=True)

        # Stoppe alle Prozesse für konsistenten Snapshot
        await self.kill_all_targets()

        # --- 1. GMS Snapshot ---
        try:
            gms_dir = profile_dir / BACKUP_GMS_SUBDIR
            gms_dir.mkdir(parents=True, exist_ok=True)
            gms_path = await self._backup_gms_packages(gms_dir)
            results["gms"] = gms_path
            logger.info("Golden Baseline GMS: OK (%s)", gms_path.name)
        except (ADBError, Exception) as e:
            logger.error("Golden Baseline GMS fehlgeschlagen: %s", e)

        # --- 2. Account-DBs Snapshot ---
        try:
            accounts_dir = profile_dir / BACKUP_ACCOUNTS_SUBDIR
            accounts_dir.mkdir(parents=True, exist_ok=True)
            accounts_path = await self._backup_account_dbs(accounts_dir)
            results["accounts"] = accounts_path
            logger.info("Golden Baseline Accounts: OK (%s)", accounts_path.name)
        except (ADBError, Exception) as e:
            logger.error("Golden Baseline Accounts fehlgeschlagen: %s", e)

        success = sum(1 for v in results.values() if v is not None)
        logger.info(
            "Golden Baseline: %d/2 Komponenten gesichert",
            success,
        )
        return results

    # =========================================================================
    # Backup: App-Daten → tar → Host
    # =========================================================================

    async def backup(
        self,
        profile_name: str,
        timeout: int = 300,
    ) -> tuple[Path, int]:
        """
        Sichert die TikTok App-Daten als tar-Archiv auf den Host.

        Methode: `adb exec-out` mit `tar -cf -` für direktes Binary-Streaming.
        Kein Zwischenspeicher auf dem Gerät nötig.

        Args:
            profile_name: Name des Profils (wird als Dateiname verwendet)
            timeout:      Timeout in Sekunden (Default: 5 Min)

        Returns:
            Tuple(lokaler Pfad zum tar, Dateigröße in Bytes)

        Raises:
            ADBError:      bei ADB-Fehlern
            ADBTimeoutError: wenn Streaming zu lange dauert
        """
        # Prüfe ob App-Datenordner existiert
        check = await self._adb.shell(
            f"test -d {self._data_path}", root=True,
        )
        if not check.success:
            raise ADBError(
                f"App-Datenordner nicht gefunden: {self._data_path}. "
                f"Ist {self._package} installiert?"
            )

        # Ziel-Pfad auf dem Host
        timestamp = datetime.now(LOCAL_TZ).strftime("%Y%m%d_%H%M%S")
        tar_filename = f"{profile_name}_{timestamp}.tar"
        tar_path = self._backup_dir / tar_filename

        logger.info(
            "Backup starten: %s → %s",
            self._data_path, tar_path,
        )

        # Stoppe App vor Backup (konsistenter State)
        await self._force_stop()

        # Streame tar direkt vom Gerät
        # su -c nötig weil /data/data/ nur als root lesbar
        tar_cmd = f"su -c 'tar -cf - -C / data/data/{self._package}'"
        bytes_written = await self._adb.exec_out_to_file(
            tar_cmd,
            str(tar_path),
            timeout=timeout,
        )

        # Validierung: tar muss > 0 Bytes sein
        if bytes_written == 0:
            tar_path.unlink(missing_ok=True)
            raise ADBError(
                f"Backup leer (0 Bytes). "
                f"App-Daten existieren möglicherweise nicht: {self._data_path}"
            )

        # Minimale tar-Header Validierung (tar magic: "ustar" bei Byte 257)
        try:
            with open(tar_path, "rb") as f:
                f.seek(257)
                magic = f.read(5)
                if magic != b"ustar":
                    logger.warning(
                        "tar magic mismatch: erwartet b'ustar', bekam %r "
                        "(Datei könnte trotzdem valide sein — GNU tar Format)",
                        magic,
                    )
        except (OSError, ValueError):
            pass

        size_mb = bytes_written / (1024 * 1024)
        logger.info(
            "Backup fertig: %s (%.1f MB, %d Bytes)",
            tar_filename, size_mb, bytes_written,
        )

        return tar_path, bytes_written

    # =========================================================================
    # Restore: Host → tar → Gerät + Magic Permission Fix
    # =========================================================================

    async def restore(
        self,
        profile_name_or_path: str | Path,
        timeout: int = 300,
    ) -> None:
        """
        Stellt TikTok App-Daten aus einem tar-Archiv wieder her.

        KRITISCHER ABLAUF:
          1. Force-stop der App
          2. Bestehende Daten löschen
          3. tar-Stream auf das Gerät entpacken
          4. **Magic Permission Fix**: UID ermitteln + chown -R
          5. App-Daten Verzeichnis Permissions fixen

        KEIN restorecon! (Bootloop-Gefahr auf Android 14)

        Args:
            profile_name_or_path: Profil-Name oder direkter Pfad zum tar
            timeout:              Timeout in Sekunden

        Raises:
            FileNotFoundError: tar-Archiv nicht gefunden
            ADBError:          bei ADB-Fehlern
        """
        tar_path = self._resolve_tar_path(profile_name_or_path)

        if not tar_path.exists():
            raise FileNotFoundError(f"Backup nicht gefunden: {tar_path}")

        tar_size = tar_path.stat().st_size
        size_mb = tar_size / (1024 * 1024)
        logger.info(
            "Restore starten: %s (%.1f MB) → %s",
            tar_path.name, size_mb, self._data_path,
        )

        # 1. Force-stop App
        await self._force_stop()

        # 2. Bestehende Daten löschen (aber Ordner behalten für UID)
        # Erst UID ermitteln BEVOR wir löschen (falls App installiert)
        uid = await self._get_app_uid()

        await self._adb.shell(
            f"rm -rf {self._data_path}/*", root=True,
        )
        logger.debug("Alte Daten gelöscht: %s/*", self._data_path)

        # 3. tar-Stream auf das Gerät
        # tar wurde relativ zu / erstellt (data/data/pkg/...)
        restore_result = await self._adb.exec_in_from_file(
            f"tar -xf - -C /",
            str(tar_path),
            timeout=timeout,
        )

        if not restore_result.success:
            logger.error(
                "tar-Restore fehlgeschlagen (exit %d): %s",
                restore_result.returncode,
                restore_result.stderr[:300],
            )
            raise ADBError(
                f"Restore fehlgeschlagen: exit {restore_result.returncode}",
                returncode=restore_result.returncode,
                stderr=restore_result.stderr,
            )

        # 4. MAGIC PERMISSION FIX (KRITISCH!)
        # UID nochmal ermitteln (falls sie sich geändert hat)
        uid = await self._get_app_uid()
        await self._apply_magic_permissions(uid)

        logger.info(
            "Restore komplett: %s → %s (UID %s)",
            tar_path.name, self._package, uid,
        )

    # =========================================================================
    # Magic Permission Fix
    # =========================================================================

    async def _get_app_uid(self) -> str:
        """
        Ermittelt die UID der Ziel-App.

        Methode: stat -c '%u' auf den App-Datenordner.
        Fallback: Parst `pm list packages -U`.

        Returns:
            UID als String (z.B. "10245")

        Raises:
            ADBError: wenn UID nicht ermittelbar
        """
        # Methode 1: stat auf Datenordner
        result = await self._adb.shell(
            f"stat -c '%u' {self._data_path} 2>/dev/null", root=True,
        )
        uid = result.output.strip("'").strip()
        if uid.isdigit() and int(uid) >= 10000:
            return uid

        # Methode 2: pm list packages -U
        result = await self._adb.shell(
            f"pm list packages -U {self._package}", root=True,
        )
        if "uid:" in result.stdout:
            uid = result.stdout.split("uid:")[-1].strip()
            if uid.isdigit():
                return uid

        raise ADBError(
            f"UID für {self._package} nicht ermittelbar. "
            f"Ist die App installiert?"
        )

    async def _apply_magic_permissions(self, uid: str) -> None:
        """
        Wendet den Magic Permission Fix an.

        TITAN_CONTEXT.md §3B — CRITICAL FIX:
          Nach Restore MUSS chown -R UID:UID auf dem Datenordner
          ausgeführt werden, damit die App ihre Daten lesen kann
          und der Login erhalten bleibt.

          KEIN restorecon (Bootloop-Gefahr auf Android 14).

        Args:
            uid: App-UID (z.B. "10245")
        """
        logger.info(
            "Magic Permission Fix: chown -R %s:%s %s",
            uid, uid, self._data_path,
        )

        # Rekursiver chown auf den gesamten Datenordner
        await self._adb.shell(
            f"chown -R {uid}:{uid} {self._data_path}",
            root=True,
            check=True,
        )

        # Ordner-Permissions fixieren (Standard für App-Daten)
        await self._adb.shell(
            f"chmod 700 {self._data_path}",
            root=True,
        )

        # Cache und Files Unterordner
        for subdir in ["cache", "code_cache", "files", "shared_prefs", "databases"]:
            await self._adb.shell(
                f"chmod 700 {self._data_path}/{subdir} 2>/dev/null",
                root=True,
            )

        logger.info("Magic Permission Fix angewendet (UID %s)", uid)

    # =========================================================================
    # Deep Clean: Vollständige Sterilisierung
    # =========================================================================

    async def deep_clean(self, include_gms: bool = True) -> dict[str, bool]:
        """
        Führt eine vollständige Sterilisierung durch.

        TITAN_CONTEXT.md §3C — FLOW 1 (GENESIS), Schritt 1:
          1. pm clear TikTok (beide Pakete)
          2. pm clear GMS — NUR wenn include_gms=True (Standard)
          3. Lösche /sdcard/Android/data/<tiktok>/
          4. Lösche /sdcard/.tt* Tracking-Dateien

        v3.0: `include_gms` Parameter erlaubt es, GMS beim Switch
        zu schonen (Golden Baseline bleibt erhalten).

        Args:
            include_gms: True = pm clear GMS (Genesis/Erstinitialisierung)
                         False = GMS State schonen (Switch mit Golden Baseline)

        Returns:
            Dict mit Ergebnis pro Operation
        """
        mode = "VOLLSTERILISIERUNG (inkl. GMS)" if include_gms else "LEICHTE STERILISIERUNG (ohne GMS)"
        logger.info("Deep Clean starten — %s", mode)
        results: dict[str, bool] = {}

        # 1. pm clear TikTok (alle Pakete)
        for pkg in TIKTOK_PACKAGES:
            try:
                result = await self._adb.shell(f"pm clear {pkg}", root=True)
                success = "Success" in result.stdout
                results[f"pm_clear_{pkg}"] = success
                if success:
                    logger.info("pm clear %s: OK", pkg)
                else:
                    logger.debug("pm clear %s: %s (evtl. nicht installiert)", pkg, result.output)
            except ADBError as e:
                results[f"pm_clear_{pkg}"] = False
                logger.warning("pm clear %s fehlgeschlagen: %s", pkg, e)

        # 2. pm clear GMS — NUR bei include_gms=True (Genesis / Initial Seed)
        if include_gms:
            for pkg in GMS_PACKAGES:
                try:
                    result = await self._adb.shell(f"pm clear {pkg}", root=True)
                    success = "Success" in result.stdout
                    results[f"pm_clear_{pkg}"] = success
                    if success:
                        logger.info("pm clear %s: OK", pkg)
                except ADBError as e:
                    results[f"pm_clear_{pkg}"] = False
                    logger.warning("pm clear %s fehlgeschlagen: %s", pkg, e)
        else:
            logger.info("GMS-Clear übersprungen (include_gms=False → Golden Baseline schützen)")

        # 3. Lösche TikTok SD-Karten-Daten
        for sd_dir in TIKTOK_SDCARD_DIRS:
            try:
                result = await self._adb.shell(f"rm -rf {sd_dir}", root=True)
                results[f"rm_{sd_dir}"] = result.success
                logger.debug("Gelöscht: %s", sd_dir)
            except ADBError:
                results[f"rm_{sd_dir}"] = False

        # 4. Lösche TikTok Tracking-Dateien auf SD-Karte
        for glob_pattern in TIKTOK_TRACKING_GLOBS:
            try:
                result = await self._adb.shell(f"rm -f {glob_pattern}", root=True)
                results[f"rm_{glob_pattern}"] = result.success
            except ADBError:
                results[f"rm_{glob_pattern}"] = False

        # Zusammenfassung
        success_count = sum(1 for v in results.values() if v)
        total_count = len(results)
        logger.info(
            "Deep Clean abgeschlossen: %d/%d Operationen erfolgreich",
            success_count, total_count,
        )

        return results

    # =========================================================================
    # Full-State Backup: TikTok + GMS + Account-DBs
    # =========================================================================

    async def backup_full_state(
        self,
        profile_name: str,
        timeout: int = 600,
    ) -> dict[str, Optional[Path]]:
        """
        Sichert den kompletten Session-State eines Profils:
          1. TikTok App-Daten (wie bisher)
          2. GMS App-Daten (com.google.android.gms, gsf, vending)
          3. System Account-Datenbanken (accounts_ce.db + Journal)

        Alle Backups landen in profil-spezifischen Unterordnern.

        Args:
            profile_name: Name des Profils (z.B. "DE_Berlin_001")
            timeout:      Timeout pro Einzeloperation in Sekunden

        Returns:
            Dict mit Pfaden: {"tiktok": Path, "gms": Path, "accounts": Path}
            Werte sind None wenn das Backup für diese Komponente fehlgeschlagen ist.
        """
        logger.info("=" * 60)
        logger.info("  FULL-STATE BACKUP: %s", profile_name)
        logger.info("=" * 60)

        results: dict[str, Optional[Path]] = {
            "tiktok": None,
            "gms": None,
            "accounts": None,
        }

        # Profil-Backup-Verzeichnis erstellen
        profile_dir = self._backup_dir / profile_name
        profile_dir.mkdir(parents=True, exist_ok=True)

        # --- 1. TikTok Backup ---
        try:
            tiktok_dir = profile_dir / BACKUP_TIKTOK_SUBDIR
            tiktok_dir.mkdir(parents=True, exist_ok=True)

            tiktok_path = await self._backup_package(
                self._package, tiktok_dir, timeout=timeout,
            )
            results["tiktok"] = tiktok_path
            logger.info("TikTok Backup: OK (%s)", tiktok_path.name)
        except (ADBError, Exception) as e:
            logger.warning("TikTok Backup fehlgeschlagen: %s", e)

        # --- 2. GMS Backup (alle 3 Pakete in einem tar) ---
        try:
            gms_dir = profile_dir / BACKUP_GMS_SUBDIR
            gms_dir.mkdir(parents=True, exist_ok=True)

            gms_path = await self._backup_gms_packages(gms_dir, timeout=timeout)
            results["gms"] = gms_path
            logger.info("GMS Backup: OK (%s)", gms_path.name)
        except (ADBError, Exception) as e:
            logger.warning("GMS Backup fehlgeschlagen: %s", e)

        # --- 3. System Account-DBs ---
        try:
            accounts_dir = profile_dir / BACKUP_ACCOUNTS_SUBDIR
            accounts_dir.mkdir(parents=True, exist_ok=True)

            accounts_path = await self._backup_account_dbs(accounts_dir)
            results["accounts"] = accounts_path
            logger.info("Account-DBs Backup: OK (%s)", accounts_path.name)
        except (ADBError, Exception) as e:
            logger.warning("Account-DBs Backup fehlgeschlagen: %s", e)

        # Zusammenfassung
        success_count = sum(1 for v in results.values() if v is not None)
        logger.info(
            "Full-State Backup abgeschlossen: %d/3 Komponenten gesichert",
            success_count,
        )
        return results

    # =========================================================================
    # Full-State Restore: GMS + Account-DBs + TikTok
    # =========================================================================

    async def restore_full_state(
        self,
        profile_name: str,
        timeout: int = 600,
    ) -> dict[str, bool]:
        """
        Stellt den kompletten Session-State eines Profils wieder her.

        REIHENFOLGE KRITISCH:
          1. Alle relevanten Apps stoppen
          2. GMS App-Daten restoren (Auth-Tokens, Sessions)
          3. System Account-DBs restoren (Konto-Registry)
          4. TikTok App-Daten restoren (Login-Session)

        GMS MUSS vor TikTok kommen, weil TikTok beim Start
        GMS-Tokens prüft.

        Args:
            profile_name: Name des Profils
            timeout:      Timeout pro Einzeloperation

        Returns:
            Dict mit Ergebnissen: {"gms": bool, "accounts": bool, "tiktok": bool}
        """
        logger.info("=" * 60)
        logger.info("  FULL-STATE RESTORE: %s", profile_name)
        logger.info("=" * 60)

        results: dict[str, bool] = {
            "gms": False,
            "accounts": False,
            "tiktok": False,
        }

        profile_dir = self._backup_dir / profile_name

        if not profile_dir.exists():
            logger.error("Profil-Backup-Verzeichnis nicht gefunden: %s", profile_dir)
            return results

        # --- 0. Kill-All-Targets (v3.0: Robuster Kill + sync) ---
        logger.info("Kill-All-Targets: Alle Prozesse stoppen vor Restore...")
        await self.kill_all_targets()

        # --- 1. GMS App-Daten restoren ---
        gms_dir = profile_dir / BACKUP_GMS_SUBDIR
        if gms_dir.exists():
            try:
                gms_tar = self._find_latest_tar(gms_dir)
                if gms_tar:
                    await self._restore_gms_packages(gms_tar, timeout=timeout)
                    results["gms"] = True
                    logger.info("GMS Restore: OK")
                else:
                    logger.warning("Kein GMS-Backup gefunden in %s", gms_dir)
            except (ADBError, Exception) as e:
                logger.error("GMS Restore fehlgeschlagen: %s", e)
        else:
            logger.info("Kein GMS-Backup vorhanden — überspringe")

        # --- 2. Account-DBs restoren ---
        accounts_dir = profile_dir / BACKUP_ACCOUNTS_SUBDIR
        if accounts_dir.exists():
            try:
                accounts_tar = self._find_latest_tar(accounts_dir)
                if accounts_tar:
                    await self._restore_account_dbs(accounts_tar)
                    results["accounts"] = True
                    logger.info("Account-DBs Restore: OK")
                else:
                    logger.warning("Kein Account-DB-Backup in %s", accounts_dir)
            except (ADBError, Exception) as e:
                logger.error("Account-DBs Restore fehlgeschlagen: %s", e)
        else:
            logger.info("Kein Account-DB-Backup vorhanden — überspringe")

        # --- 3. TikTok App-Daten restoren ---
        tiktok_dir = profile_dir / BACKUP_TIKTOK_SUBDIR
        if tiktok_dir.exists():
            try:
                tiktok_tar = self._find_latest_tar(tiktok_dir)
                if tiktok_tar:
                    await self.restore(tiktok_tar, timeout=timeout)
                    results["tiktok"] = True
                    logger.info("TikTok Restore: OK")
                else:
                    logger.warning("Kein TikTok-Backup in %s", tiktok_dir)
            except (ADBError, FileNotFoundError, Exception) as e:
                logger.error("TikTok Restore fehlgeschlagen: %s", e)
        else:
            logger.info("Kein TikTok-Backup vorhanden — überspringe")

        # Zusammenfassung
        success_count = sum(1 for v in results.values() if v)
        logger.info(
            "Full-State Restore abgeschlossen: %d/3 Komponenten wiederhergestellt",
            success_count,
        )
        return results

    # =========================================================================
    # GMS-Pakete Backup (3 Pakete in einem tar)
    # =========================================================================

    async def _backup_gms_packages(
        self,
        target_dir: Path,
        timeout: int = 300,
    ) -> Path:
        """
        Sichert alle GMS App-Daten-Ordner in ein einzelnes tar.

        Pakete: com.google.android.gms, com.google.android.gsf, com.android.vending
        """
        # Prüfe welche Pakete installiert sind
        existing_paths = []
        for pkg in GMS_BACKUP_PACKAGES:
            check = await self._adb.shell(
                f"test -d /data/data/{pkg}", root=True,
            )
            if check.success:
                existing_paths.append(f"data/data/{pkg}")
            else:
                logger.debug("GMS-Paket nicht gefunden: %s", pkg)

        if not existing_paths:
            raise ADBError("Keine GMS-Pakete gefunden!")

        # Alle Apps stoppen für konsistenten State
        for pkg in GMS_BACKUP_PACKAGES:
            try:
                await self._adb.shell(f"am force-stop {pkg}", root=True)
            except ADBError:
                pass

        # Multi-Verzeichnis tar
        timestamp = datetime.now(LOCAL_TZ).strftime("%Y%m%d_%H%M%S")
        tar_filename = f"gms_{timestamp}.tar"
        tar_path = target_dir / tar_filename

        paths_str = " ".join(existing_paths)
        tar_cmd = f"su -c 'tar -cf - -C / {paths_str}'"

        bytes_written = await self._adb.exec_out_to_file(
            tar_cmd, str(tar_path), timeout=timeout,
        )

        if bytes_written == 0:
            tar_path.unlink(missing_ok=True)
            raise ADBError("GMS-Backup leer (0 Bytes)")

        size_mb = bytes_written / (1024 * 1024)
        logger.info(
            "GMS tar: %s (%.1f MB) — %d Pakete",
            tar_filename, size_mb, len(existing_paths),
        )
        return tar_path

    # =========================================================================
    # GMS-Pakete Restore + Magic Permission Fix pro Paket
    # =========================================================================

    async def _restore_gms_packages(
        self,
        tar_path: Path,
        timeout: int = 300,
    ) -> None:
        """
        Stellt GMS App-Daten aus einem tar wieder her.

        KRITISCH: Magic Permission Fix muss für JEDES Paket einzeln
        ausgeführt werden, da jedes seine eigene UID hat.
        """
        logger.info("GMS Restore: %s (%.1f MB)",
                     tar_path.name, tar_path.stat().st_size / (1024 * 1024))

        # Alle GMS-Apps stoppen
        for pkg in GMS_BACKUP_PACKAGES:
            try:
                await self._adb.shell(f"am force-stop {pkg}", root=True)
            except ADBError:
                pass

        # Bestehende GMS-Daten löschen
        for pkg in GMS_BACKUP_PACKAGES:
            await self._adb.shell(
                f"rm -rf /data/data/{pkg}/*", root=True,
            )

        # *** SQLite Safety v3.0 ***
        # Lösche WAL/SHM Dateien in GMS-Verzeichnissen VOR dem Restore
        # um Datenbank-Korruption durch inkonsistente Journal-States zu vermeiden
        for pkg in GMS_BACKUP_PACKAGES:
            for suffix in ["-wal", "-shm"]:
                try:
                    await self._adb.shell(
                        f"find /data/data/{pkg} -name '*{suffix}' -delete 2>/dev/null",
                        root=True, timeout=10,
                    )
                except (ADBError, ADBTimeoutError):
                    pass
        logger.debug("SQLite Safety: WAL/SHM Dateien in GMS-Verzeichnissen gelöscht")

        # tar-Restore (alle Pakete auf einmal — tar enthält data/data/pkg/...)
        restore_result = await self._adb.exec_in_from_file(
            "tar -xf - -C /",
            str(tar_path),
            timeout=timeout,
        )

        if not restore_result.success:
            raise ADBError(
                f"GMS tar-Restore fehlgeschlagen: exit {restore_result.returncode}"
            )

        # Magic Permission Fix für JEDES GMS-Paket
        for pkg in GMS_BACKUP_PACKAGES:
            data_path = f"/data/data/{pkg}"
            try:
                check = await self._adb.shell(f"test -d {data_path}", root=True)
                if not check.success:
                    continue

                # UID ermitteln
                result = await self._adb.shell(
                    f"stat -c '%u' {data_path} 2>/dev/null", root=True,
                )
                uid = result.output.strip("'").strip()

                if not uid.isdigit() or int(uid) < 1000:
                    # Fallback: UID aus pm
                    result = await self._adb.shell(
                        f"pm list packages -U {pkg}", root=True,
                    )
                    if "uid:" in result.stdout:
                        uid = result.stdout.split("uid:")[-1].strip()

                if uid.isdigit():
                    await self._adb.shell(
                        f"chown -R {uid}:{uid} {data_path}", root=True,
                    )
                    await self._adb.shell(f"chmod 700 {data_path}", root=True)
                    logger.info("Magic Fix [%s]: UID %s", pkg, uid)
                else:
                    logger.warning("UID nicht ermittelbar für %s", pkg)

            except ADBError as e:
                logger.warning("Magic Fix für %s fehlgeschlagen: %s", pkg, e)

        logger.info("GMS Restore komplett: %d Pakete", len(GMS_BACKUP_PACKAGES))

    # =========================================================================
    # System Account-DBs Backup
    # =========================================================================

    async def _backup_account_dbs(self, target_dir: Path) -> Path:
        """
        Sichert die System Account-Datenbanken.

        Dateien:
          /data/system_ce/0/accounts_ce.db
          /data/system_ce/0/accounts_ce.db-journal
          /data/system_ce/0/accounts_ce.db-wal   (falls vorhanden)
          /data/system_ce/0/accounts_ce.db-shm   (falls vorhanden)

        Alle werden in ein tar gepackt.
        """
        # Prüfe welche DB-Dateien existieren
        existing_paths = []
        for db_path in SYSTEM_ACCOUNT_DBS:
            check = await self._adb.shell(
                f"test -f {db_path}", root=True,
            )
            if check.success:
                # Relativer Pfad für tar (ohne führenden /)
                existing_paths.append(db_path.lstrip("/"))

        if not existing_paths:
            raise ADBError("Keine Account-Datenbanken gefunden!")

        # tar erstellen
        timestamp = datetime.now(LOCAL_TZ).strftime("%Y%m%d_%H%M%S")
        tar_filename = f"accounts_{timestamp}.tar"
        tar_path = target_dir / tar_filename

        paths_str = " ".join(existing_paths)
        tar_cmd = f"su -c 'tar -cf - -C / {paths_str}'"

        bytes_written = await self._adb.exec_out_to_file(
            tar_cmd, str(tar_path), timeout=30,
        )

        if bytes_written == 0:
            tar_path.unlink(missing_ok=True)
            raise ADBError("Account-DB Backup leer (0 Bytes)")

        logger.info(
            "Account-DBs tar: %s (%d Bytes, %d Dateien)",
            tar_filename, bytes_written, len(existing_paths),
        )
        return tar_path

    # =========================================================================
    # System Account-DBs Restore (mit korrekten Permissions!)
    # =========================================================================

    async def _restore_account_dbs(self, tar_path: Path) -> None:
        """
        Stellt die System Account-Datenbanken wieder her.

        KRITISCH — Reihenfolge:
          1. tar entpacken (als root)
          2. Owner: system:system (UID 1000:1000)
          3. Mode: 660 (rw-rw----)
          4. SELinux: u:object_r:accounts_data_file:s0

        WARNUNG: Falsche Permissions = Bootloop-Gefahr!
        """
        logger.info(
            "Account-DBs Restore: %s (%d Bytes)",
            tar_path.name, tar_path.stat().st_size,
        )

        # *** SQLite Safety v3.0 ***
        # Lösche bestehende WAL/SHM Dateien VOR dem Entpacken
        # um Datenbank-Korruption durch alte Journal-States zu vermeiden
        for suffix in ["-wal", "-shm", "-journal"]:
            try:
                await self._adb.shell(
                    f"rm -f /data/system_ce/0/accounts_ce.db{suffix}",
                    root=True, timeout=5,
                )
            except (ADBError, ADBTimeoutError):
                pass
        logger.debug("SQLite Safety: Alte WAL/SHM/Journal für accounts_ce.db gelöscht")

        # tar entpacken
        restore_result = await self._adb.exec_in_from_file(
            "tar -xf - -C /",
            str(tar_path),
            timeout=30,
        )

        if not restore_result.success:
            raise ADBError(
                f"Account-DB tar-Restore fehlgeschlagen: "
                f"exit {restore_result.returncode}"
            )

        # Permissions fixen für alle DB-Dateien (einzeln)
        for db_path in SYSTEM_ACCOUNT_DBS:
            try:
                check = await self._adb.shell(
                    f"test -f {db_path}", root=True,
                )
                if not check.success:
                    continue

                # Owner: system:system
                await self._adb.shell(
                    f"chown {ACCOUNTS_DB_OWNER}:{ACCOUNTS_DB_GROUP} {db_path}",
                    root=True,
                )
                # Mode: rw-rw----
                await self._adb.shell(
                    f"chmod {ACCOUNTS_DB_MODE} {db_path}",
                    root=True,
                )
                # SELinux Context (einzeln pro Datei)
                await self._adb.shell(
                    f"chcon {ACCOUNTS_DB_SELINUX} {db_path}",
                    root=True,
                )
                logger.debug("Account-DB fixed: %s", db_path)

            except ADBError as e:
                logger.warning("Account-DB Permission Fix für %s: %s", db_path, e)

        # ---------------------------------------------------------------
        # CRITICAL FIX: Force SELinux Context via Glob + restorecon
        # ---------------------------------------------------------------
        # Diagnose: accounts_ce.db hatte u:object_r:system_data_file:s0
        # statt dem korrekten u:object_r:accounts_data_file:s0.
        # SELinux blockiert den Zugriff beim Booten → Accounts weg.
        # Glob-chcon fängt alle Varianten (.db, .db-journal, .db-wal, .db-shm)
        # auch wenn SYSTEM_ACCOUNT_DBS nicht komplett ist.
        # ---------------------------------------------------------------
        try:
            result = await self._adb.shell(
                f"chcon {ACCOUNTS_DB_SELINUX} /data/system_ce/0/accounts_ce.db*",
                root=True,
            )
            if result.success:
                logger.info("SELinux Glob-Fix: accounts_ce.db* → %s", ACCOUNTS_DB_SELINUX)
            else:
                logger.warning("SELinux Glob-Fix exit=%d", result.returncode)
        except ADBError as e:
            logger.warning("SELinux Glob-Fix fehlgeschlagen: %s", e)

        # Fallback: restorecon (liest die SELinux file_contexts Policy)
        try:
            result = await self._adb.shell(
                "restorecon -Rv /data/system_ce/0/accounts_ce.db",
                root=True,
            )
            if result.success:
                logger.info("restorecon Fallback: OK (%s)", result.output.strip()[:100])
            else:
                logger.debug("restorecon Fallback: exit=%d (nicht kritisch)", result.returncode)
        except ADBError as e:
            logger.debug("restorecon nicht verfügbar: %s", e)

        # Verifizierung: Prüfe den tatsächlichen SELinux Context
        try:
            result = await self._adb.shell(
                "ls -Z /data/system_ce/0/accounts_ce.db",
                root=True,
            )
            if result.success:
                logger.info("SELinux Verify: %s", result.output.strip())
                if "accounts_data_file" not in result.output:
                    logger.error(
                        "WARNUNG: SELinux Context ist NICHT accounts_data_file! "
                        "Accounts werden beim nächsten Boot möglicherweise gelöscht!"
                    )
        except ADBError:
            pass

        # Auch den übergeordneten Ordner prüfen
        await self._adb.shell(
            f"chown {ACCOUNTS_DB_OWNER}:{ACCOUNTS_DB_GROUP} "
            f"/data/system_ce/0/",
            root=True,
        )

        logger.info("Account-DBs Restore komplett (Permissions + SELinux gesetzt)")

    # =========================================================================
    # Einzelnes Paket Backup (generisch)
    # =========================================================================

    async def _backup_package(
        self,
        package: str,
        target_dir: Path,
        timeout: int = 300,
    ) -> Path:
        """
        Sichert ein einzelnes App-Paket als tar.

        Generische Version von backup() — für beliebige Pakete nutzbar.
        """
        data_path = f"/data/data/{package}"

        check = await self._adb.shell(f"test -d {data_path}", root=True)
        if not check.success:
            raise ADBError(f"App nicht gefunden: {data_path}")

        # App stoppen
        try:
            await self._adb.shell(f"am force-stop {package}", root=True)
        except ADBError:
            pass

        timestamp = datetime.now(LOCAL_TZ).strftime("%Y%m%d_%H%M%S")
        tar_filename = f"{package.split('.')[-1]}_{timestamp}.tar"
        tar_path = target_dir / tar_filename

        tar_cmd = f"su -c 'tar -cf - -C / data/data/{package}'"
        bytes_written = await self._adb.exec_out_to_file(
            tar_cmd, str(tar_path), timeout=timeout,
        )

        if bytes_written == 0:
            tar_path.unlink(missing_ok=True)
            raise ADBError(f"Backup leer: {package}")

        return tar_path

    # =========================================================================
    # Hilfsmethoden
    # =========================================================================

    def _find_latest_tar(self, directory: Path) -> Optional[Path]:
        """Findet das neueste tar-Archiv in einem Verzeichnis."""
        tars = sorted(
            directory.glob("*.tar"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        return tars[0] if tars else None

    async def _force_stop(self) -> None:
        """Stoppt die Ziel-App forciert."""
        await self._adb.shell(f"am force-stop {self._package}", root=True)
        logger.debug("Force-stop: %s", self._package)

    def _resolve_tar_path(self, name_or_path: str | Path) -> Path:
        """
        Löst einen Profil-Namen oder direkten Pfad zu einer tar-Datei auf.

        Sucht im Backup-Verzeichnis nach dem neuesten Archiv für ein Profil.

        Args:
            name_or_path: Profil-Name (z.B. "profile_001") oder voller Pfad

        Returns:
            Path zum tar-Archiv
        """
        path = Path(name_or_path)

        # Direkter Pfad?
        if path.suffix == ".tar" and path.exists():
            return path

        # Suche im Backup-Verzeichnis nach dem neuesten Match
        pattern = f"{name_or_path}_*.tar"
        matches = sorted(
            self._backup_dir.glob(pattern),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )

        if matches:
            return matches[0]

        # Exakter Dateiname im Backup-Verzeichnis?
        exact = self._backup_dir / f"{name_or_path}.tar"
        return exact  # Existenz wird im Caller geprüft

    def get_backup_path(self, profile_name: str) -> Optional[Path]:
        """
        Gibt den Pfad zum neuesten Backup eines Profils zurück.

        Returns:
            Path oder None wenn kein Backup existiert
        """
        pattern = f"{profile_name}_*.tar"
        matches = sorted(
            self._backup_dir.glob(pattern),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        return matches[0] if matches else None

    def list_backups(self, profile_name: Optional[str] = None) -> list[dict]:
        """
        Listet alle Backups auf.

        Args:
            profile_name: Filter nach Profilname (Optional)

        Returns:
            Liste von Dicts mit path, size, modified
        """
        pattern = f"{profile_name}_*.tar" if profile_name else "*.tar"
        backups = []

        for tar_path in sorted(self._backup_dir.glob(pattern), reverse=True):
            stat = tar_path.stat()
            backups.append({
                "path": str(tar_path),
                "filename": tar_path.name,
                "size_bytes": stat.st_size,
                "size_mb": round(stat.st_size / (1024 * 1024), 1),
                "modified": datetime.fromtimestamp(stat.st_mtime, tz=LOCAL_TZ).isoformat(),
            })

        return backups
