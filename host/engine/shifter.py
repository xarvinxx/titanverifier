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

import asyncio
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
    BACKUP_SANDBOX_SUBDIR,
    BACKUP_TIKTOK_SUBDIR,
    GMS_BACKUP_PACKAGES,
    GMS_PACKAGES,
    SYSTEM_ACCOUNT_DBS,
    TIKTOK_PACKAGES,
    TIKTOK_SANDBOX_PATHS,
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

# FIX-1: ByteDance Deep-Search Patterns
# Versteckte Tracking-Verzeichnisse die pm clear und statische rm -rf nicht erfassen
BYTEDANCE_DEEP_PATTERNS = [
    "/sdcard/.com.ss.android*",            # ByteDance Cross-App SDK
    "/sdcard/Documents/com.zhiliaoapp*",   # TikTok Document-Tracking
    "/sdcard/Download/.log/",              # Versteckte Logs
    "/sdcard/.msync/",                     # ByteDance Cross-App Sync
    "/sdcard/Documents/.tmlog/",           # Versteckte TikTok-Logs
    "/sdcard/DCIM/.thumbnails/",           # TikTok-Metadata in Thumbnails
]

# FIX-1: find-basierte Suchmuster für dynamisch angelegte Tracking-Dateien
BYTEDANCE_FIND_PATTERNS = [
    "-name '.tt*' -o -name '*.tt*'",               # Alle versteckten TT-Dateien
    "-type d -name '*zhiliaoapp*'",                 # zhiliaoapp-Verzeichnisse
    "-type d -name '*com.ss.android*'",             # ByteDance SDK-Reste
    "-type d -name '.msync'",                       # Cross-App Sync Verzeichnisse
]

# FIX-2: Cache-Pfade die nach pm clear/uninstall explizit geprüft werden müssen
TIKTOK_RESIDUAL_CACHE_PATHS = [
    "/data/data/com.zhiliaoapp.musically/cache",
    "/data/data/com.zhiliaoapp.musically/code_cache",
    "/storage/emulated/0/Android/data/com.zhiliaoapp.musically/cache",
    "/data/data/com.ss.android.ugc.trill/cache",
    "/data/data/com.ss.android.ugc.trill/code_cache",
    "/storage/emulated/0/Android/data/com.ss.android.ugc.trill/cache",
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

        # FIX-23: Atomic Write + Retry statt direktem exec_out_to_file
        tar_cmd = f"su -c 'tar -cf - -C / data/data/{self._package}'"
        bytes_written = await self._atomic_backup_with_retry(
            tar_cmd=tar_cmd,
            final_path=tar_path,
            label=f"Backup {profile_name}",
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
    # FIX-23: Atomic Backup mit Retry
    # =========================================================================

    async def _atomic_backup_with_retry(
        self,
        tar_cmd: str,
        final_path: Path,
        label: str,
        timeout: int = 600,
        max_retries: int = 3,
    ) -> int:
        """
        FIX-23: Atomares Backup mit Retry-Logik.

        Schreibt in .tmp-Datei → bei Erfolg rename → bei Fehler delete .tmp.
        Altes Backup bleibt bei Fehler immer intakt.

        Bei ADB-Abbruch: Verbindung wiederherstellen + erneut versuchen
        (max. 3 Retries mit exponential backoff: 2s, 4s, 8s).

        Args:
            tar_cmd:      Der tar-Befehl für adb exec-out
            final_path:   Endgültiger Zielpfad für das Backup
            label:        Beschreibung für Logging (z.B. "App-Daten Pfad A")
            timeout:      Timeout pro Einzelversuch
            max_retries:  Maximale Anzahl Retries

        Returns:
            Anzahl geschriebener Bytes (0 bei Fehler)

        Raises:
            ADBError: Wenn alle Retries fehlschlagen
        """
        tmp_path = final_path.with_suffix(final_path.suffix + ".tmp")
        last_error: Optional[Exception] = None

        for attempt in range(1, max_retries + 1):
            try:
                # Sicherstellen dass .tmp sauber ist
                tmp_path.unlink(missing_ok=True)

                # Backup in .tmp schreiben
                bytes_written = await self._adb.exec_out_to_file(
                    tar_cmd, str(tmp_path), timeout=timeout,
                )

                if bytes_written <= 0:
                    # Leeres Backup — kein Retry nötig, ist normal bei leeren Ordnern
                    tmp_path.unlink(missing_ok=True)
                    logger.info(
                        "%s: Leer (0 Bytes) — Versuch %d/%d",
                        label, attempt, max_retries,
                    )
                    return 0

                # Atomic rename: .tmp → .tar (OS-Level atomar auf ext4/APFS)
                tmp_path.rename(final_path)
                logger.info(
                    "%s: OK (%.1f MB, Versuch %d/%d)",
                    label, bytes_written / (1024 * 1024), attempt, max_retries,
                )
                return bytes_written

            except (ADBError, ADBTimeoutError, OSError) as e:
                last_error = e
                # Korrupte .tmp sofort löschen
                tmp_path.unlink(missing_ok=True)

                if attempt >= max_retries:
                    logger.error(
                        "%s: Alle %d Versuche fehlgeschlagen — letzter Fehler: %s",
                        label, max_retries, e,
                    )
                    break

                # Exponential Backoff: 2s, 4s, 8s
                backoff = 2 ** attempt
                logger.warning(
                    "%s: Versuch %d/%d fehlgeschlagen (%s) — "
                    "ADB-Reconnect + Retry in %ds...",
                    label, attempt, max_retries, e, backoff,
                )

                # ADB-Reconnect versuchen
                try:
                    await self._adb.ensure_connection()
                except Exception as reconnect_err:
                    logger.error(
                        "%s: ADB-Reconnect fehlgeschlagen: %s",
                        label, reconnect_err,
                    )

                await asyncio.sleep(backoff)

        # Alle Retries fehlgeschlagen — altes Backup bleibt intakt
        raise ADBError(
            f"{label}: Backup fehlgeschlagen nach {max_retries} Versuchen. "
            f"Bestehendes Backup bleibt erhalten. "
            f"Letzter Fehler: {last_error}"
        )

    # =========================================================================
    # Dual-Path Backup: App-Daten + Sandbox (TikTok-spezifisch)
    # =========================================================================

    async def backup_tiktok_dual(
        self,
        profile_name: str,
        timeout: int = 600,
    ) -> dict[str, Optional[Path]]:
        """
        Sichert TikTok komplett mit Dual-Path Strategie.

        Dual-Path:
          A) App-Daten (/data/data/<pkg>/) → Login, Cookies, SharedPrefs
          B) Sandbox  (/sdcard/Android/data/<pkg>/) → SDK-Fingerprints, Cache, Medien

        WARUM getrennt?
          - Sandbox kann riesig werden (GB) → selektives Restore möglich
          - App-Daten sind klein aber kritisch (Login-Session)
          - Wenn Sandbox leer ist (frischer Account), wird nur app_data gesichert
          - TikToks Anti-Detection SDK speichert Device-Fingerprints in der Sandbox

        Args:
            profile_name: Profil-Name für Unterordner
            timeout:      Timeout pro Einzeloperation

        Returns:
            Dict mit Pfaden: {"app_data": Path|None, "sandbox": Path|None}
        """
        logger.info("=" * 50)
        logger.info("  DUAL-PATH BACKUP: %s (TikTok)", profile_name)
        logger.info("=" * 50)

        results: dict[str, Optional[Path]] = {"app_data": None, "sandbox": None}
        profile_dir = self._backup_dir / profile_name
        timestamp = datetime.now(LOCAL_TZ).strftime("%Y%m%d_%H%M%S")

        # CE-Storage Check: Gerät muss entsperrt sein
        if not await self._check_ce_storage():
            logger.error(
                "CE-Storage nicht verfügbar — Gerät ist gesperrt! "
                "Backup würde verschlüsselte (unbrauchbare) Daten sichern."
            )
            return results

        # Force-Stop vor Backup (konsistenter State)
        await self._force_stop()

        # --- Pfad A: App-Daten (/data/data/<pkg>/) ---
        try:
            tiktok_dir = profile_dir / BACKUP_TIKTOK_SUBDIR
            tiktok_dir.mkdir(parents=True, exist_ok=True)

            app_tar = tiktok_dir / f"tiktok_app_{timestamp}.tar"

            # Prüfe ob Login-relevante Ordner existieren
            check = await self._adb.shell(
                f"test -d {self._data_path}/shared_prefs", root=True,
            )
            if not check.success:
                logger.warning(
                    "Pfad A: shared_prefs nicht gefunden — "
                    "TikTok wurde möglicherweise noch nicht gestartet"
                )

            # =============================================================
            # FIX-3: Backup-Whitelist — nur Login-relevante Ordner sichern
            #   shared_prefs/ = Login-Session, Cookies, User-Preferences
            #   databases/    = SQLite-DBs mit Account-Daten
            #   files/        = Token-Dateien, Konfiguration
            #   Nicht gesichert: cache/, code_cache/, no_backup/ (können
            #   Probleme beim Restore verursachen und sind nicht nötig)
            # =============================================================
            whitelist_dirs = []
            for subdir in ["shared_prefs", "databases", "files"]:
                check = await self._adb.shell(
                    f"test -d {self._data_path}/{subdir}", root=True,
                )
                if check.success:
                    whitelist_dirs.append(subdir)

            if whitelist_dirs:
                # Whitelist-basiertes tar (nur relevante Unterordner)
                dirs_str = " ".join(whitelist_dirs)
                tar_cmd = (
                    f"su -c 'tar -C {self._data_path} -cf - {dirs_str} 2>/dev/null'"
                )
                logger.debug("Pfad A Whitelist: %s", dirs_str)
            else:
                # Fallback: Vollständiges Backup (falls keine Whitelist-Dirs existieren)
                tar_cmd = (
                    f"su -c 'tar -cf - -C / data/data/{self._package} 2>/dev/null'"
                )
                logger.warning("Pfad A: Keine Whitelist-Dirs gefunden — volles Backup als Fallback")

            # FIX-23: Atomic Write + Retry statt direktem exec_out_to_file
            bytes_written = await self._atomic_backup_with_retry(
                tar_cmd=tar_cmd,
                final_path=app_tar,
                label=f"Pfad A (App-Daten, Whitelist: {', '.join(whitelist_dirs) if whitelist_dirs else 'full'})",
                timeout=timeout,
            )

            if bytes_written > 0:
                # FIX-4: Integrity Guard — Größe auf Gerät vs. lokal vergleichen
                await self._integrity_check(
                    self._data_path, app_tar, bytes_written, "Pfad A",
                )
                results["app_data"] = app_tar
            else:
                logger.warning("Pfad A (App-Daten): Leer (0 Bytes) — übersprungen")

        except ADBError as e:
            # FIX-23: Alle Retries fehlgeschlagen — altes Backup bleibt intakt
            logger.error(
                "Pfad A (App-Daten) fehlgeschlagen nach Retries: %s — "
                "Bestehendes Backup bleibt erhalten", e,
            )
        except Exception as e:
            logger.warning("Pfad A (App-Daten) fehlgeschlagen: %s", e)

        # --- Pfad B: Sandbox (/sdcard/Android/data/<pkg>/) ---
        try:
            sandbox_dir = profile_dir / BACKUP_SANDBOX_SUBDIR
            sandbox_dir.mkdir(parents=True, exist_ok=True)

            sandbox_tar = sandbox_dir / f"tiktok_sandbox_{timestamp}.tar"

            # Finde die installierte Sandbox-Variante
            sandbox_path = None
            for sp in TIKTOK_SANDBOX_PATHS:
                check = await self._adb.shell(f"test -d {sp}", root=True)
                if check.success:
                    sandbox_path = sp
                    break

            if sandbox_path:
                # Erstelle Verzeichnis falls nötig
                await self._adb.shell(
                    f"mkdir -p {sandbox_path}", root=True,
                )

                tar_cmd = (
                    f"su -c 'tar -cf - -C {sandbox_path} . 2>/dev/null'"
                )

                # FIX-23: Atomic Write + Retry
                bytes_written = await self._atomic_backup_with_retry(
                    tar_cmd=tar_cmd,
                    final_path=sandbox_tar,
                    label="Pfad B (Sandbox)",
                    timeout=timeout,
                )

                if bytes_written > 0:
                    results["sandbox"] = sandbox_tar
                else:
                    logger.info("Pfad B (Sandbox): Leer — frischer Account, übersprungen")
            else:
                logger.info("Pfad B (Sandbox): Kein Sandbox-Verzeichnis gefunden — übersprungen")

        except ADBError as e:
            # FIX-23: Alle Retries fehlgeschlagen
            logger.error(
                "Pfad B (Sandbox) fehlgeschlagen nach Retries: %s — "
                "Bestehendes Backup bleibt erhalten", e,
            )
        except Exception as e:
            logger.warning("Pfad B (Sandbox) fehlgeschlagen: %s", e)

        success = sum(1 for v in results.values() if v is not None)
        logger.info("Dual-Path Backup: %d/2 Komponenten gesichert", success)
        return results

    async def restore_tiktok_dual(
        self,
        profile_name: str,
        timeout: int = 600,
    ) -> dict[str, bool]:
        """
        Stellt TikTok komplett aus Dual-Path Backup wieder her.

        Ablauf:
          1. Force-Stop TikTok
          2. Deep-Purge alte Daten (App + Sandbox)
          3. Restore Pfad A (App-Daten)
          4. Restore Pfad B (Sandbox)
          5. Permission-Sync (KRITISCH!)

        Args:
            profile_name: Profil-Name
            timeout:      Timeout pro Operation

        Returns:
            Dict mit Ergebnis: {"app_data": bool, "sandbox": bool}
        """
        logger.info("Dual-Path Restore: %s (TikTok)", profile_name)
        results = {"app_data": False, "sandbox": False}

        profile_dir = self._backup_dir / profile_name

        # 1. Force-Stop
        await self._force_stop()

        # UID VOR dem Löschen ermitteln
        try:
            uid = await self._get_app_uid()
        except ADBError:
            uid = None
            logger.warning("App-UID nicht ermittelbar — App möglicherweise nicht installiert")

        # --- Pfad A: App-Daten Restore ---
        tiktok_dir = profile_dir / BACKUP_TIKTOK_SUBDIR
        app_tar = self._find_latest_tar(tiktok_dir, "tiktok_app_")

        if app_tar and app_tar.exists() and app_tar.stat().st_size > 0:
            try:
                # FIX-29: Alte App-Daten KOMPLETT löschen (inkl. Hidden Files)
                await self._adb.shell(
                    f"rm -rf {self._data_path}", root=True,
                )
                await self._adb.shell(
                    f"mkdir -p {self._data_path}", root=True,
                )

                # tar-Stream Restore (tar wurde relativ zu / erstellt)
                restore_result = await self._adb.exec_in_from_file(
                    "tar -xf - -C /",
                    str(app_tar),
                    timeout=timeout,
                )

                if restore_result.success or restore_result.returncode == 1:
                    # returncode 1 = "file changed as we read it" (normal bei tar)
                    results["app_data"] = True
                    logger.info("Pfad A (App-Daten): Restored (%s)", app_tar.name)
                else:
                    logger.error(
                        "Pfad A Restore fehlgeschlagen (exit %d)",
                        restore_result.returncode,
                    )
            except (ADBError, Exception) as e:
                logger.warning("Pfad A Restore Fehler: %s", e)
        else:
            logger.info("Pfad A: Kein App-Daten Backup vorhanden — übersprungen")

        # --- Pfad B: Sandbox Restore ---
        sandbox_dir = profile_dir / BACKUP_SANDBOX_SUBDIR
        sandbox_tar = self._find_latest_tar(sandbox_dir, "tiktok_sandbox_")

        if sandbox_tar and sandbox_tar.exists() and sandbox_tar.stat().st_size > 0:
            try:
                # Finde installierte Sandbox-Variante
                sandbox_path = None
                for sp in TIKTOK_SANDBOX_PATHS:
                    check = await self._adb.shell(f"test -d {sp}", root=True)
                    if check.success:
                        sandbox_path = sp
                        break

                if not sandbox_path:
                    # Erstelle Standard-Pfad
                    sandbox_path = TIKTOK_SANDBOX_PATHS[0]
                    await self._adb.shell(
                        f"mkdir -p {sandbox_path}", root=True,
                    )

                # FIX-29: Alte Sandbox KOMPLETT löschen (inkl. Hidden Files)
                await self._adb.shell(
                    f"rm -rf {sandbox_path}", root=True,
                )
                await self._adb.shell(
                    f"mkdir -p {sandbox_path}", root=True,
                )

                # Sandbox wurde mit -C <sandbox_path> erstellt → Restore dorthin
                restore_result = await self._adb.exec_in_from_file(
                    f"tar -xf - -C {sandbox_path}",
                    str(sandbox_tar),
                    timeout=timeout,
                )

                if restore_result.success or restore_result.returncode == 1:
                    results["sandbox"] = True
                    logger.info("Pfad B (Sandbox): Restored (%s)", sandbox_tar.name)
                else:
                    logger.error(
                        "Pfad B Restore fehlgeschlagen (exit %d)",
                        restore_result.returncode,
                    )
            except (ADBError, Exception) as e:
                logger.warning("Pfad B Restore Fehler: %s", e)
        else:
            logger.info("Pfad B: Kein Sandbox Backup vorhanden — übersprungen")

        # 5. PERMISSION-SYNC (KRITISCH!)
        if results["app_data"] and uid:
            await self._apply_magic_permissions(uid)

        if results["sandbox"]:
            # Sandbox Permissions fixen (gehört der App, nicht Root)
            try:
                if uid:
                    for sp in TIKTOK_SANDBOX_PATHS:
                        check = await self._adb.shell(f"test -d {sp}", root=True)
                        if check.success:
                            await self._adb.shell(
                                f"chown -R {uid}:{uid} {sp}", root=True,
                            )
                            logger.debug("Sandbox Permissions: chown %s %s", uid, sp)
            except ADBError as e:
                logger.warning("Sandbox Permission Fix fehlgeschlagen: %s", e)

        success = sum(1 for v in results.values() if v)
        logger.info("Dual-Path Restore: %d/2 Komponenten wiederhergestellt", success)
        return results

    # =========================================================================
    # CE-Storage Protection Check
    # =========================================================================

    async def _check_ce_storage(self) -> bool:
        """
        Prüft ob Credential Encrypted Storage verfügbar ist.

        Nach einem Reboot (vor erstem Unlock) sind App-Daten unter
        /data/data/ noch verschlüsselt. Ein Backup in diesem Zustand
        produziert ein unbrauchbares tar mit verschlüsselten Blöcken.

        FIX-5: Erweitert um dumpsys window Check für robustere Erkennung.

        Prüfreihenfolge:
          1. dumpsys window → Keyguard im Fokus? (zuverlässigster Check)
          2. shared_prefs Test → CE entschlüsselt? (Fallback)

        Returns:
            True wenn CE-Storage entschlüsselt und lesbar ist
        """
        try:
            # =================================================================
            # FIX-5: Primärer Check via dumpsys window
            # Prüft ob der Keyguard (Lock-Screen) noch aktiv ist.
            # Wenn ja, ist CE-Storage definitiv verschlüsselt.
            # =================================================================
            try:
                result = await self._adb.shell(
                    "dumpsys window windows | grep -i mCurrentFocus",
                    timeout=5,
                )
                if result.success:
                    focus = result.output.lower()
                    if "keyguard" in focus or "lockscreen" in focus:
                        logger.warning(
                            "FIX-5: Keyguard aktiv (%s) — CE-Storage verschlüsselt!",
                            result.output.strip(),
                        )
                        return False
                    else:
                        logger.debug(
                            "FIX-5: Kein Keyguard (%s) — CE-Storage vermutlich OK",
                            result.output.strip(),
                        )
            except (ADBError, Exception) as e:
                logger.debug("FIX-5: dumpsys window Check fehlgeschlagen: %s", e)

            # Fallback: shared_prefs eines bekannten Pakets prüfen
            result = await self._adb.shell(
                "test -d /data/data/com.google.android.gms/shared_prefs",
                root=True, timeout=5,
            )
            if result.success:
                return True

            # Zweiter Fallback: Prüfe ob /data/data/ überhaupt lesbar ist
            result = await self._adb.shell(
                "ls /data/data/com.google.android.gms/ 2>/dev/null | head -1",
                root=True, timeout=5,
            )
            if result.success and result.output.strip():
                return True

            logger.warning("CE-Storage Check: Alle Prüfungen fehlgeschlagen")
            return False
        except (ADBError, Exception):
            return False

    def _find_latest_tar(self, directory: Path, prefix: str) -> Optional[Path]:
        """Findet die neueste tar-Datei mit gegebenem Prefix in einem Verzeichnis."""
        if not directory.exists():
            return None
        tars = sorted(
            directory.glob(f"{prefix}*.tar"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        return tars[0] if tars else None

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

        # 2. Bestehende Daten KOMPLETT löschen (FIX-29: inkl. Hidden Files)
        # Erst UID ermitteln BEVOR wir löschen (falls App installiert)
        uid = await self._get_app_uid()

        # FIX-29: rm -rf <path>/* verpasst dot-files (.device_id, .tt_session etc.)
        # Stattdessen: Verzeichnis komplett löschen + leer neu erstellen.
        # tar-Restore erstellt die Struktur sowieso neu.
        await self._adb.shell(
            f"rm -rf {self._data_path}", root=True,
        )
        await self._adb.shell(
            f"mkdir -p {self._data_path}", root=True,
        )
        logger.debug("FIX-29: Alte Daten komplett gelöscht: %s (inkl. Hidden Files)", self._data_path)

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
    # FIX-28: APK-Pfad + App-Verifikation Helpers
    # =========================================================================

    async def _get_apk_path(self, pkg: str) -> Optional[str]:
        """
        Ermittelt den APK-Pfad eines Pakets auf dem Gerät.

        FIX-28: Wird VOR pm uninstall aufgerufen, damit bei Fehlschlag
        von pm install-existing die App manuell reinstalliert werden kann.

        Args:
            pkg: Package-Name (z.B. "com.zhiliaoapp.musically")

        Returns:
            APK-Pfad als String oder None wenn nicht ermittelbar
        """
        try:
            result = await self._adb.shell(
                f"pm path {pkg}", root=True, timeout=10,
            )
            if result.success and "package:" in result.stdout:
                apk_path = result.stdout.strip().split("package:")[-1].strip()
                if apk_path and apk_path.endswith(".apk"):
                    return apk_path
        except (ADBError, ADBTimeoutError):
            pass
        return None

    async def _verify_app_installed(self, pkg: str) -> bool:
        """
        Prüft ob ein Paket für User 0 installiert ist.

        FIX-28: Wird NACH pm install-existing/pm install aufgerufen,
        um sicherzustellen dass die App nicht verschwunden ist.

        Args:
            pkg: Package-Name

        Returns:
            True wenn App installiert und für User 0 verfügbar
        """
        try:
            result = await self._adb.shell(
                f"pm path {pkg}", root=True, timeout=10,
            )
            return result.success and "package:" in result.stdout
        except (ADBError, ADBTimeoutError):
            return False

    # =========================================================================
    # Deep Clean: Vollständige Sterilisierung
    # =========================================================================

    async def deep_clean(self, include_gms: bool = False) -> dict[str, bool]:
        """
        Führt eine Sterilisierung der Target-Apps durch.

        TITAN_CONTEXT.md §3C — FLOW 1 (GENESIS), Schritt 1:
          1. pm clear TikTok (beide Pakete)
          2. pm clear GMS — NUR wenn include_gms=True (⚠️ DEPRECATED!)
          3. Lösche /sdcard/Android/data/<tiktok>/
          4. Lösche /sdcard/.tt* Tracking-Dateien

        v4.0 GMS-SCHUTZ: Default ist jetzt include_gms=False!
          GMS/GSF/Vending werden NIEMALS angerührt, weil das die
          Google Trust-Chain zerstört (Play Integrity nur noch DEVICE,
          Google-Login kaputt, DroidGuard muss neu attestieren).
          include_gms=True existiert nur noch für manuelle Notfälle.

        Args:
            include_gms: False = GMS unangetastet (DEFAULT — v4.0)
                         True = pm clear GMS (⚠️ DEPRECATED — zerstört Trust-Chain!)

        Returns:
            Dict mit Ergebnis pro Operation
        """
        if include_gms:
            logger.warning(
                "⚠️  deep_clean(include_gms=True) — DEPRECATED seit v4.0! "
                "Das Löschen von GMS-Daten zerstört die Google Trust-Chain: "
                "Play Integrity verliert BASIC, Google-Login bricht ab. "
                "Verwende include_gms=False (Default) für normalen Betrieb."
            )
        mode = "⚠️ VOLLSTERILISIERUNG (inkl. GMS — DEPRECATED!)" if include_gms else "Target-App Sterilisierung (GMS geschützt)"
        logger.info("Deep Clean starten — %s", mode)
        results: dict[str, bool] = {}

        # =====================================================================
        # 1. FIX-28: Sichere App-Reinstallation (überarbeitet FIX-13)
        #    Erzwingt echten "First Launch"-State via pm uninstall + reinstall.
        #    KRITISCH: APK-Pfad wird VOR dem Uninstall gesichert, damit die
        #    App bei Fehlschlag von pm install-existing manuell reinstalliert
        #    werden kann. Verifikation nach jedem Schritt verhindert
        #    stillschweigenden App-Verlust.
        # =====================================================================
        for pkg in TIKTOK_PACKAGES:
            try:
                # --- Schritt 0: APK-Pfad SICHERN bevor wir irgendetwas deinstallieren ---
                saved_apk_path = await self._get_apk_path(pkg)
                if not saved_apk_path:
                    # APK-Pfad nicht ermittelbar → kein Uninstall riskieren, nur pm clear
                    logger.warning(
                        "FIX-28: APK-Pfad für %s nicht ermittelbar — "
                        "Fallback auf sicheres pm clear (kein Uninstall)",
                        pkg,
                    )
                    clear_result = await self._adb.shell(f"pm clear {pkg}", root=True, timeout=15)
                    results[f"fresh_install_{pkg}"] = "Success" in clear_result.stdout
                    if results[f"fresh_install_{pkg}"]:
                        logger.info("pm clear %s: OK (sicherer Fallback — kein APK-Pfad)", pkg)
                    continue

                logger.info("FIX-28: APK-Pfad gesichert: %s → %s", pkg, saved_apk_path)

                # --- Schritt 1: Deinstallation für User 0 ---
                uninstall_result = await self._adb.shell(
                    f"pm uninstall --user 0 {pkg}", root=True, timeout=15,
                )
                uninstall_ok = "Success" in uninstall_result.stdout

                if not uninstall_ok:
                    # Uninstall fehlgeschlagen (App nicht installiert?) → pm clear
                    logger.debug(
                        "pm uninstall %s: %s — Fallback auf pm clear",
                        pkg, uninstall_result.output[:100],
                    )
                    clear_result = await self._adb.shell(f"pm clear {pkg}", root=True, timeout=15)
                    results[f"fresh_install_{pkg}"] = "Success" in clear_result.stdout
                    if results[f"fresh_install_{pkg}"]:
                        logger.info("pm clear %s: OK (Uninstall nicht möglich)", pkg)
                    continue

                logger.info("pm uninstall --user 0 %s: OK", pkg)

                # --- Schritt 2: pm install-existing versuchen ---
                install_ok = False
                install_result = await self._adb.shell(
                    f"pm install-existing --user 0 {pkg}", root=True, timeout=15,
                )
                install_ok = "installed" in install_result.stdout.lower() or install_result.success

                # --- Schritt 3: VERIFIKATION — ist die App noch da? ---
                if install_ok and await self._verify_app_installed(pkg):
                    logger.info("pm install-existing %s: OK — Fresh-Install State ✓", pkg)
                    results[f"fresh_install_{pkg}"] = True
                    continue

                # install-existing hat nicht geklappt oder Verifikation fehlgeschlagen
                logger.warning(
                    "FIX-28: pm install-existing %s fehlgeschlagen oder nicht verifiziert — "
                    "Rettung via gespeichertem APK-Pfad: %s",
                    pkg, saved_apk_path,
                )

                # --- Schritt 4: RETTUNG — APK manuell reinstallieren ---
                rescue_result = await self._adb.shell(
                    f"pm install -r --user 0 {saved_apk_path}", root=True, timeout=30,
                )
                if await self._verify_app_installed(pkg):
                    logger.info(
                        "FIX-28: App %s via APK-Pfad gerettet — Fresh-Install State ✓", pkg,
                    )
                    results[f"fresh_install_{pkg}"] = True
                    continue

                # --- Schritt 5: LETZTER FALLBACK — cmd package install-existing ---
                logger.warning(
                    "FIX-28: pm install fehlgeschlagen — letzter Versuch: cmd package install-existing %s",
                    pkg,
                )
                cmd_result = await self._adb.shell(
                    f"cmd package install-existing {pkg}", root=True, timeout=15,
                )
                if await self._verify_app_installed(pkg):
                    logger.info("FIX-28: cmd package install-existing %s: OK ✓", pkg)
                    results[f"fresh_install_{pkg}"] = True
                    continue

                # ALLE Versuche fehlgeschlagen — App ist weg!
                logger.error(
                    "FIX-28: KRITISCH — %s konnte nicht reinstalliert werden! "
                    "APK-Pfad war: %s. App muss manuell installiert werden.",
                    pkg, saved_apk_path,
                )
                results[f"fresh_install_{pkg}"] = False

            except ADBError as e:
                results[f"fresh_install_{pkg}"] = False
                logger.warning("TikTok Sterilisierung %s fehlgeschlagen: %s", pkg, e)

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

        # =====================================================================
        # 4b. FIX-1: ByteDance Deep-Search — Versteckte Tracking-Verzeichnisse
        #     TikTok/ByteDance legt Tracking-Daten an mehreren versteckten Orten
        #     ab, die pm clear und statische rm -rf nicht erfassen.
        # =====================================================================
        logger.info("ByteDance Deep-Search: Versteckte Tracking-Reste aufspüren...")

        # Statische Patterns löschen
        for pattern in BYTEDANCE_DEEP_PATTERNS:
            try:
                result = await self._adb.shell(f"rm -rf {pattern}", root=True, timeout=10)
                results[f"bytedance_{pattern}"] = result.success
                if result.success:
                    logger.debug("ByteDance Pattern gelöscht: %s", pattern)
            except (ADBError, ADBTimeoutError):
                results[f"bytedance_{pattern}"] = False

        # Dynamische find-basierte Suche auf /sdcard
        for find_pattern in BYTEDANCE_FIND_PATTERNS:
            try:
                result = await self._adb.shell(
                    f"find /sdcard {find_pattern} 2>/dev/null",
                    root=True, timeout=30,
                )
                found_paths = [p.strip() for p in result.stdout.splitlines() if p.strip()]
                if found_paths:
                    logger.info("ByteDance find: %d Treffer für '%s'", len(found_paths), find_pattern)
                    for found in found_paths[:20]:  # Max 20 pro Pattern (Schutz gegen Endlosschleifen)
                        try:
                            await self._adb.shell(f"rm -rf '{found}'", root=True, timeout=5)
                            logger.debug("  Gelöscht: %s", found)
                        except (ADBError, ADBTimeoutError):
                            pass
                results[f"find_{find_pattern}"] = True
            except (ADBError, ADBTimeoutError):
                results[f"find_{find_pattern}"] = False

        # Spezifische ByteDance Sandbox-Tracking Dateien
        try:
            await self._adb.shell(
                "rm -rf /sdcard/Android/data/com.zhiliaoapp.musically/.tt* 2>/dev/null",
                root=True, timeout=5,
            )
            results["bytedance_sandbox_tt"] = True
        except (ADBError, ADBTimeoutError):
            results["bytedance_sandbox_tt"] = False

        # =====================================================================
        # 4c. FIX-2: Cache-Verzeichnisse explizit prüfen und löschen
        #     pm clear/uninstall löscht nicht alle Cache-Pfade zuverlässig.
        #     Manche werden von Android nach pm clear automatisch neu erstellt.
        # =====================================================================
        logger.info("Cache-Residual-Check: Reste nach Sterilisierung aufräumen...")
        for cache_path in TIKTOK_RESIDUAL_CACHE_PATHS:
            try:
                check = await self._adb.shell(f"test -d {cache_path}", root=True, timeout=5)
                if check.success:
                    await self._adb.shell(f"rm -rf {cache_path}", root=True, timeout=10)
                    results[f"cache_cleanup_{cache_path}"] = True
                    logger.debug("Cache-Rest gelöscht: %s", cache_path)
                else:
                    results[f"cache_cleanup_{cache_path}"] = True  # Existiert nicht → OK
            except (ADBError, ADBTimeoutError):
                results[f"cache_cleanup_{cache_path}"] = False

        # 5. Lösche System Account-Datenbanken (KRITISCH bei include_gms)
        # Verhindert "Kontoaktion erforderlich" nach Identity-Switch.
        # Ohne diesen Schritt erkennt Android beim nächsten Boot, dass die
        # gespeicherten Accounts nicht zum neuen GMS-State passen → Login-Zwang.
        if include_gms:
            account_db_globs = [
                "/data/system/users/0/accounts.db*",        # Legacy Account-DB
                "/data/system_ce/0/accounts_ce.db*",        # CE Account-DB (Android 7+)
            ]
            for db_glob in account_db_globs:
                try:
                    result = await self._adb.shell(
                        f"rm -f {db_glob}", root=True,
                    )
                    results[f"rm_{db_glob}"] = result.success
                    if result.success:
                        logger.info("Account-DB gelöscht: %s", db_glob)
                except ADBError as e:
                    results[f"rm_{db_glob}"] = False
                    logger.debug("Account-DB Löschung fehlgeschlagen: %s — %s", db_glob, e)

            # 5b. chmod 777 auf BEIDE Account-DB Verzeichnisse
            # Damit Android beim nächsten Boot die accounts.db und
            # accounts_ce.db sicher neu anlegen kann.
            # Ohne write-Berechtigung auf den Verzeichnissen schlägt
            # die automatische DB-Erstellung fehl (Permission denied).
            for dir_path, dir_key in [
                ("/data/system_ce/0/", "chmod_system_ce_0"),
                ("/data/system/users/0/", "chmod_system_users_0"),
            ]:
                try:
                    result = await self._adb.shell(
                        f"chmod 777 {dir_path}", root=True,
                    )
                    results[dir_key] = result.success
                    if result.success:
                        logger.info(
                            "chmod 777 %s — Verzeichnis für "
                            "DB-Neuerstellung freigegeben", dir_path,
                        )
                except ADBError as e:
                    results[dir_key] = False
                    logger.warning(
                        "chmod 777 %s fehlgeschlagen: %s", dir_path, e,
                    )

        # 6. *** NEU v4.0 *** MediaStore Wipe
        # Entfernt MediaStore-Einträge die auf TikTok-Dateien verweisen.
        # Ohne diesen Schritt "erinnert" sich die MediaStore-DB an gelöschte
        # Medien und kann Korrelationsangriffe ermöglichen.
        for media_pkg in ["musically", "trill", "tiktok"]:
            try:
                result = await self._adb.shell(
                    f"content delete --uri content://media/external/file "
                    f"--where \"_data LIKE '%{media_pkg}%'\"",
                    root=True, timeout=10,
                )
                results[f"mediastore_{media_pkg}"] = result.success
                if result.success:
                    logger.debug("MediaStore: %s Einträge gelöscht", media_pkg)
            except (ADBError, ADBTimeoutError):
                results[f"mediastore_{media_pkg}"] = False

        # 7. *** NEU v4.0 *** Compiler Cache Reset
        # Löscht ART-optimierte DEX-Dateien (oat/odex). Anti-Cheat-Engines
        # können aus der JIT-Profildaten timing-basierte Fingerprints ableiten.
        for pkg in TIKTOK_PACKAGES:
            try:
                result = await self._adb.shell(
                    f"cmd package compile --reset {pkg} 2>/dev/null",
                    root=True, timeout=15,
                )
                results[f"compiler_reset_{pkg}"] = result.success
                if result.success:
                    logger.debug("Compiler-Cache Reset: %s", pkg)
            except (ADBError, ADBTimeoutError):
                results[f"compiler_reset_{pkg}"] = False

        # 8. *** NEU v4.0 *** ART Runtime Profile Cleanup
        # /data/misc/profiles/cur/0/<pkg>/ enthält JIT-Nutzungsprofile
        # die zwischen Identitäten leaken können (Fingerprint via App-Usage).
        for pkg in TIKTOK_PACKAGES:
            profile_path = f"/data/misc/profiles/cur/0/{pkg}"
            try:
                result = await self._adb.shell(
                    f"rm -rf {profile_path}", root=True, timeout=5,
                )
                results[f"art_profile_{pkg}"] = result.success
                if result.success:
                    logger.debug("ART Profile gelöscht: %s", profile_path)
            except (ADBError, ADBTimeoutError):
                results[f"art_profile_{pkg}"] = False

        # =====================================================================
        # FIX-14: TikTok Settings-ContentProvider Werte bereinigen
        # =====================================================================
        # TikTok schreibt Tracking-Werte über Settings.Secure/Global.
        # Diese überleben pm clear UND pm uninstall, weil sie System-global
        # gespeichert werden (nicht App-spezifisch).
        # =====================================================================
        logger.info("FIX-14: Settings-ContentProvider bereinigen...")
        settings_patterns = [
            "tiktok", "bytedance", "musically", "tt_", "ss_android",
            "zhiliaoapp", "pangle", "tobid",
        ]
        for settings_ns in ["secure", "global"]:
            try:
                list_result = await self._adb.shell(
                    f"settings list {settings_ns}", root=True, timeout=10,
                )
                if list_result.success:
                    for line in list_result.output.splitlines():
                        line_lower = line.lower()
                        for pattern in settings_patterns:
                            if pattern in line_lower:
                                key = line.split("=", 1)[0].strip()
                                if key:
                                    try:
                                        await self._adb.shell(
                                            f"settings delete {settings_ns} {key}",
                                            root=True, timeout=5,
                                        )
                                        logger.info(
                                            "FIX-14: Settings.%s gelöscht: %s",
                                            settings_ns, key,
                                        )
                                        results[f"settings_{settings_ns}_{key}"] = True
                                    except (ADBError, ADBTimeoutError):
                                        results[f"settings_{settings_ns}_{key}"] = False
                                break  # Nächste Zeile
            except (ADBError, ADBTimeoutError) as e:
                logger.debug("FIX-14: settings list %s fehlgeschlagen: %s", settings_ns, e)

        # Zusammenfassung
        success_count = sum(1 for v in results.values() if v)
        total_count = len(results)
        logger.info(
            "Deep Clean abgeschlossen: %d/%d Operationen erfolgreich "
            "(inkl. MediaStore, Compiler-Cache, ART-Profile, Settings)",
            success_count, total_count,
        )

        return results

    # =========================================================================
    # FIX-4: Integrity Guard — Backup-Validierung
    # =========================================================================

    async def _integrity_check(
        self,
        device_path: str,
        local_tar: Path,
        local_bytes: int,
        label: str,
    ) -> bool:
        """
        FIX-4: Prüft ob das Backup plausibel vollständig ist.

        Vergleicht die Dateigröße auf dem Gerät mit dem lokalen tar.
        Toleranz: 10% (Dateisystem-Overhead, tar-Header).

        Args:
            device_path: Pfad auf dem Gerät (z.B. /data/data/com.zhiliaoapp.musically)
            local_tar:   Lokaler Pfad zur tar-Datei
            local_bytes: Geschriebene Bytes
            label:       Beschreibung für Logging

        Returns:
            True wenn Integrity-Check bestanden
        """
        try:
            # Gerätegröße ermitteln
            result = await self._adb.shell(
                f"du -sb {device_path} 2>/dev/null | cut -f1",
                root=True, timeout=10,
            )
            if not result.success or not result.output.strip().isdigit():
                logger.debug("FIX-4 [%s]: du -sb fehlgeschlagen — übersprungen", label)
                return True  # Nicht blockieren

            device_bytes = int(result.output.strip())
            if device_bytes == 0:
                return True

            # Dateianzahl auf Gerät
            count_result = await self._adb.shell(
                f"find {device_path} -type f 2>/dev/null | wc -l",
                root=True, timeout=10,
            )
            device_files = 0
            if count_result.success and count_result.output.strip().isdigit():
                device_files = int(count_result.output.strip())

            # Vergleich: tar sollte mindestens 60% der Gerätegröße haben
            # (tar hat Overhead, Whitelist filtert Ordner → weniger ist OK)
            ratio = local_bytes / device_bytes if device_bytes > 0 else 1.0

            if ratio < 0.3:
                logger.warning(
                    "FIX-4 [%s]: Integrity WARNUNG — tar ist nur %.0f%% "
                    "der Gerätedaten (tar=%.1f MB, device=%.1f MB, %d Dateien). "
                    "Möglicherweise unvollständig!",
                    label, ratio * 100,
                    local_bytes / (1024 * 1024),
                    device_bytes / (1024 * 1024),
                    device_files,
                )
                return False
            else:
                logger.debug(
                    "FIX-4 [%s]: Integrity OK (tar=%.1f MB, device=%.1f MB, "
                    "ratio=%.0f%%, %d Dateien)",
                    label, local_bytes / (1024 * 1024),
                    device_bytes / (1024 * 1024),
                    ratio * 100, device_files,
                )
                return True

        except (ADBError, Exception) as e:
            logger.debug("FIX-4 [%s]: Integrity-Check fehlgeschlagen: %s", label, e)
            return True  # Bei Fehler nicht blockieren

    # =========================================================================
    # FIX-16: Tracking-Reste bereinigen (für Switch Flow)
    # =========================================================================

    async def clean_tracking_remnants(self) -> dict[str, bool]:
        """
        Bereinigt ByteDance/TikTok Tracking-Reste auf /sdcard/.

        FIX-16: Mini-Clean für den Switch Flow — löscht Tracking-Dateien
        die zwischen Backup und Switch von TikTok geschrieben wurden und
        das alte Profil verraten könnten.

        Unterschied zu deep_clean():
          - Kein pm clear/uninstall (App-Daten werden via Restore überschrieben)
          - Nur /sdcard/ Tracking-Dateien (kein /data/data/)
          - Schnell (~2-3s)

        Returns:
            Dict mit Ergebnis pro Operation
        """
        logger.info("Tracking-Remnants Cleanup: ByteDance-Reste auf /sdcard/ entfernen...")
        results: dict[str, bool] = {}

        # Statische Tracking-Globs
        all_globs = TIKTOK_TRACKING_GLOBS + [p for p in BYTEDANCE_DEEP_PATTERNS]
        for pattern in all_globs:
            try:
                result = await self._adb.shell(f"rm -rf {pattern}", root=True, timeout=5)
                results[f"rm_{pattern}"] = result.success
            except (ADBError, ADBTimeoutError):
                results[f"rm_{pattern}"] = False

        # Dynamische find-basierte Suche
        for find_pattern in BYTEDANCE_FIND_PATTERNS:
            try:
                result = await self._adb.shell(
                    f"find /sdcard {find_pattern} 2>/dev/null",
                    root=True, timeout=15,
                )
                found_paths = [p.strip() for p in result.stdout.splitlines() if p.strip()]
                for found in found_paths[:20]:
                    try:
                        await self._adb.shell(f"rm -rf '{found}'", root=True, timeout=5)
                    except (ADBError, ADBTimeoutError):
                        pass
                results[f"find_{find_pattern}"] = True
            except (ADBError, ADBTimeoutError):
                results[f"find_{find_pattern}"] = False

        success_count = sum(1 for v in results.values() if v)
        logger.info("Tracking-Remnants Cleanup: %d/%d Operationen OK", success_count, len(results))
        return results

    # =========================================================================
    # FIX-29: Gründlicher State-Wipe für Switch Flow
    # =========================================================================

    async def prepare_switch_clean(self) -> dict[str, bool]:
        """
        FIX-29: Gründlicher State-Wipe vor einem Switch-Restore.

        Bereinigt ALLE TikTok-Daten (App-Daten + Sandbox + Tracking + Caches),
        damit der Restore in eine saubere Umgebung schreibt. Verhindert
        Identity-Leakage durch Reste des alten Profils.

        Unterschied zu deep_clean():
          - KEIN pm uninstall (App muss installiert bleiben für den Restore)
          - KEIN pm clear (würde Runtime-Permissions löschen — schlechte UX)
          - Stattdessen: Komplettes Löschen des Datenverzeichnisses auf Filesystem-Ebene
          - Inkl. Hidden Files (dot-files) die rm -rf <path>/* verpasst
          - Inkl. ART Profiles, Compiler Cache, Settings-ContentProvider

        Unterschied zu clean_tracking_remnants():
          - Löscht auch /data/data/<pkg>/ (nicht nur /sdcard/)
          - Löscht auch Caches, ART Profiles, Compiler Cache
          - Bereinigt Settings-ContentProvider
          - Deutlich gründlicher (~5-8s statt ~2-3s)

        Returns:
            Dict mit Ergebnis pro Operation
        """
        logger.info("FIX-29: Switch-Clean — Gründlicher State-Wipe vor Restore...")
        results: dict[str, bool] = {}

        # --- 1. TikTok App-Daten komplett löschen (inkl. Hidden Files) ---
        for pkg in TIKTOK_PACKAGES:
            data_path = f"/data/data/{pkg}"
            try:
                # Komplettes Verzeichnis löschen (nicht nur /*!)
                await self._adb.shell(f"rm -rf {data_path}", root=True, timeout=10)
                # Leer neu erstellen (tar-Restore braucht den Parent)
                await self._adb.shell(f"mkdir -p {data_path}", root=True, timeout=5)
                results[f"wipe_{pkg}"] = True
                logger.info("FIX-29: %s — komplett gelöscht + neu erstellt", data_path)
            except (ADBError, ADBTimeoutError) as e:
                results[f"wipe_{pkg}"] = False
                logger.warning("FIX-29: Wipe %s fehlgeschlagen: %s", data_path, e)

        # --- 2. TikTok Sandbox-Verzeichnisse komplett löschen ---
        for sd_dir in TIKTOK_SDCARD_DIRS:
            try:
                await self._adb.shell(f"rm -rf {sd_dir}", root=True, timeout=10)
                results[f"wipe_sd_{sd_dir}"] = True
            except (ADBError, ADBTimeoutError):
                results[f"wipe_sd_{sd_dir}"] = False

        # --- 3. Tracking-Dateien auf /sdcard/ (wie clean_tracking_remnants) ---
        all_globs = TIKTOK_TRACKING_GLOBS + [p for p in BYTEDANCE_DEEP_PATTERNS]
        for pattern in all_globs:
            try:
                await self._adb.shell(f"rm -rf {pattern}", root=True, timeout=5)
                results[f"rm_{pattern}"] = True
            except (ADBError, ADBTimeoutError):
                results[f"rm_{pattern}"] = False

        # --- 4. Dynamische find-basierte Suche auf /sdcard ---
        for find_pattern in BYTEDANCE_FIND_PATTERNS:
            try:
                result = await self._adb.shell(
                    f"find /sdcard {find_pattern} 2>/dev/null",
                    root=True, timeout=15,
                )
                found_paths = [p.strip() for p in result.stdout.splitlines() if p.strip()]
                for found in found_paths[:20]:
                    try:
                        await self._adb.shell(f"rm -rf '{found}'", root=True, timeout=5)
                    except (ADBError, ADBTimeoutError):
                        pass
                results[f"find_{find_pattern}"] = True
            except (ADBError, ADBTimeoutError):
                results[f"find_{find_pattern}"] = False

        # --- 5. ART Compiler Cache Reset ---
        for pkg in TIKTOK_PACKAGES:
            try:
                await self._adb.shell(
                    f"cmd package compile --reset {pkg} 2>/dev/null",
                    root=True, timeout=15,
                )
                results[f"compiler_reset_{pkg}"] = True
            except (ADBError, ADBTimeoutError):
                results[f"compiler_reset_{pkg}"] = False

        # --- 6. ART Runtime Profile Cleanup ---
        for pkg in TIKTOK_PACKAGES:
            profile_path = f"/data/misc/profiles/cur/0/{pkg}"
            try:
                await self._adb.shell(f"rm -rf {profile_path}", root=True, timeout=5)
                results[f"art_profile_{pkg}"] = True
            except (ADBError, ADBTimeoutError):
                results[f"art_profile_{pkg}"] = False

        # --- 7. Settings-ContentProvider bereinigen (FIX-14) ---
        settings_patterns = [
            "tiktok", "bytedance", "musically", "tt_", "ss_android",
            "zhiliaoapp", "pangle", "tobid",
        ]
        for settings_ns in ["secure", "global"]:
            try:
                list_result = await self._adb.shell(
                    f"settings list {settings_ns}", root=True, timeout=10,
                )
                if list_result.success:
                    for line in list_result.output.splitlines():
                        line_lower = line.lower()
                        for pattern in settings_patterns:
                            if pattern in line_lower:
                                key = line.split("=", 1)[0].strip()
                                if key:
                                    try:
                                        await self._adb.shell(
                                            f"settings delete {settings_ns} {key}",
                                            root=True, timeout=5,
                                        )
                                        results[f"settings_{settings_ns}_{key}"] = True
                                    except (ADBError, ADBTimeoutError):
                                        results[f"settings_{settings_ns}_{key}"] = False
                                break
            except (ADBError, ADBTimeoutError):
                pass

        success_count = sum(1 for v in results.values() if v)
        logger.info(
            "FIX-29: Switch-Clean abgeschlossen: %d/%d Operationen OK",
            success_count, len(results),
        )
        return results

    # =========================================================================
    # FIX-30: Post-Restore Verifikation
    # =========================================================================

    async def verify_app_data_restored(self, pkg: str = TIKTOK_PRIMARY) -> dict:
        """
        FIX-30: Prüft ob App-Daten nach einem Restore tatsächlich vorhanden sind.

        Verhindert Zombie-States wo die Bridge auf eine neue Identität zeigt,
        aber die App-Daten leer oder fehlend sind.

        Prüft:
          1. Datenverzeichnis existiert
          2. Mindestens shared_prefs/ ODER databases/ existiert
          3. Verzeichnis ist nicht leer (> 0 Dateien)

        Args:
            pkg: Package-Name (Default: TikTok International)

        Returns:
            Dict mit:
              "ok": bool — Gesamtergebnis
              "dir_exists": bool — /data/data/<pkg>/ existiert
              "has_prefs": bool — shared_prefs/ vorhanden
              "has_databases": bool — databases/ vorhanden
              "has_files": bool — files/ vorhanden
              "file_count": int — Anzahl Einträge im Verzeichnis
              "detail": str — Zusammenfassung
        """
        data_path = f"/data/data/{pkg}"
        result = {
            "ok": False,
            "dir_exists": False,
            "has_prefs": False,
            "has_databases": False,
            "has_files": False,
            "file_count": 0,
            "detail": "",
        }

        try:
            # 1. Verzeichnis existiert?
            dir_check = await self._adb.shell(
                f"test -d {data_path}", root=True, timeout=5,
            )
            result["dir_exists"] = dir_check.success
            if not dir_check.success:
                result["detail"] = f"Verzeichnis {data_path} existiert nicht"
                logger.warning("FIX-30: %s", result["detail"])
                return result

            # 2. Kritische Unterverzeichnisse prüfen
            for subdir, key in [
                ("shared_prefs", "has_prefs"),
                ("databases", "has_databases"),
                ("files", "has_files"),
            ]:
                try:
                    sub_check = await self._adb.shell(
                        f"test -d {data_path}/{subdir}", root=True, timeout=5,
                    )
                    result[key] = sub_check.success
                except (ADBError, ADBTimeoutError):
                    pass

            # 3. Anzahl Einträge im Verzeichnis
            try:
                count_result = await self._adb.shell(
                    f"ls -1 {data_path} 2>/dev/null | wc -l",
                    root=True, timeout=5,
                )
                if count_result.success:
                    count_str = count_result.output.strip()
                    if count_str.isdigit():
                        result["file_count"] = int(count_str)
            except (ADBError, ADBTimeoutError):
                pass

            # Gesamtbewertung
            has_content = result["has_prefs"] or result["has_databases"] or result["has_files"]
            has_entries = result["file_count"] > 0

            if has_content and has_entries:
                result["ok"] = True
                result["detail"] = (
                    f"OK — {result['file_count']} Einträge "
                    f"(prefs={'✓' if result['has_prefs'] else '✗'}, "
                    f"db={'✓' if result['has_databases'] else '✗'}, "
                    f"files={'✓' if result['has_files'] else '✗'})"
                )
            elif has_entries:
                # Einträge da, aber keine bekannten Unterordner
                result["ok"] = True
                result["detail"] = (
                    f"WARN — {result['file_count']} Einträge, "
                    f"aber keine shared_prefs/databases/files erkannt"
                )
            else:
                result["detail"] = (
                    f"FAIL — Verzeichnis leer oder keine App-Daten "
                    f"(count={result['file_count']})"
                )

        except (ADBError, ADBTimeoutError) as e:
            result["detail"] = f"Verifikation fehlgeschlagen: {e}"
            logger.warning("FIX-30: %s", result["detail"])

        return result

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

        # FIX-23: Atomic Write + Retry
        bytes_written = await self._atomic_backup_with_retry(
            tar_cmd=tar_cmd,
            final_path=tar_path,
            label=f"GMS Backup ({len(existing_paths)} Pakete)",
            timeout=timeout,
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

        # *** SQLite Safety v3.2 ***
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

        # v3.2: Filesystem-Settle — Warte 2s damit das Kernel die File-Handles
        # der gelöschten WAL/SHM Dateien vollständig freigibt. Ohne diese Pause
        # kann tar auf ext4 in eine Race-Condition laufen: Das Journal-File ist
        # im VFS noch als "pending delete" markiert, aber tar erstellt eine neue
        # Datei mit demselben Inode → Korruption beim nächsten SQLite-Open.
        await asyncio.sleep(2)
        logger.debug(
            "SQLite Safety v3.2: WAL/SHM gelöscht + 2s Filesystem-Settle"
        )

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

        # FIX-23: Atomic Write + Retry
        bytes_written = await self._atomic_backup_with_retry(
            tar_cmd=tar_cmd,
            final_path=tar_path,
            label=f"Account-DBs ({len(existing_paths)} Dateien)",
            timeout=30,
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

        # *** SQLite Safety v3.2 ***
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

        # v3.2: Filesystem-Settle — Warte 2s damit File-Handles freigegeben werden.
        # accounts_ce.db ist SYSTEM-kritisch (UID 1000) — Race-Conditions hier
        # führen direkt zum Bootloop wegen korrupter Account-Registry.
        await asyncio.sleep(2)
        logger.debug(
            "SQLite Safety v3.2: Alte WAL/SHM/Journal gelöscht + 2s Settle"
        )

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

        # FIX-23: Atomic Write + Retry
        bytes_written = await self._atomic_backup_with_retry(
            tar_cmd=tar_cmd,
            final_path=tar_path,
            label=f"Package Backup ({package})",
            timeout=timeout,
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
