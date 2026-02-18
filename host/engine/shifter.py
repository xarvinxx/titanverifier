"""
App Shifter v3.0 ("Golden Baseline")
====================================

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

KRITISCH — Magic Permission Fix:
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
    BRIDGE_FILE_PATH,
    GMS_BACKUP_PACKAGES,
    GMS_PACKAGES,
    SYSTEM_ACCOUNT_DBS,
    TIKTOK_PACKAGES,
    TIKTOK_SANDBOX_PATHS,
)

logger = logging.getLogger("host.shifter")

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


class AppShifter:
    """
    App-Data Manager für Profile-Switching.

    Sichert und stellt TikTok App-Daten her, inklusive dem
    kritischen Magic Permission Fix nach dem Restore.

    Usage:
        adb = ADBClient()
        shifter = AppShifter(adb)

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
                # v6.3: Smart Clean — lib-Symlink bewahren!
                # rm -rf /data/data/<pkg> zerstört den lib-Symlink
                # (→ /data/app/<hash>/lib/arm64/), was zu sofortigem Crash führt.
                # find ... ! -name 'lib' löscht alles andere sicher.
                await self._adb.shell(
                    f"find {self._data_path} -mindepth 1 -maxdepth 1 "
                    f"! -name 'lib' -exec rm -rf {{}} +",
                    root=True, timeout=15,
                )

                # v6.6 FIX: Push-then-Extract statt Pipe.
                # Stdin-Pipe kann Binärdaten korrumpieren. Toybox tar kennt
                # kein --keep-old-files. lib-Schutz via Smart Clean oben.
                device_tar = "/data/local/tmp/_titan_dual_restore.tar"
                await self._adb.push(
                    str(app_tar), device_tar, timeout=timeout,
                )
                restore_result = await self._adb.shell(
                    f"tar -xf {device_tar} -C /",
                    root=True, timeout=timeout,
                )
                # Cleanup temp tar
                try:
                    await self._adb.shell(
                        f"rm -f {device_tar}", root=True, timeout=10,
                    )
                except (ADBError, ADBTimeoutError):
                    pass

                if restore_result.success or restore_result.returncode in (0, 1):
                    results["app_data"] = True
                    logger.info("Pfad A (App-Daten): Restored (%s)", app_tar.name)

                    # lib-Symlink Verifikation
                    lib_check = await self._adb.shell(
                        f"test -L {self._data_path}/lib && echo SYMLINK || echo MISSING",
                        root=True, timeout=5,
                    )
                    if "MISSING" in (lib_check.output or ""):
                        logger.warning(
                            "[Restore] lib-Symlink FEHLT — Repair via install-existing"
                        )
                        await self._adb.shell(
                            f"cmd package install-existing --user 0 {self._package}",
                            root=False, timeout=30,
                        )
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

                # v6.6: Push-then-Extract (Sandbox)
                device_sandbox_tar = "/data/local/tmp/_titan_sandbox_restore.tar"
                await self._adb.push(
                    str(sandbox_tar), device_sandbox_tar, timeout=timeout,
                )
                restore_result = await self._adb.shell(
                    f"tar -xf {device_sandbox_tar} -C {sandbox_path}",
                    root=True, timeout=timeout,
                )
                try:
                    await self._adb.shell(
                        f"rm -f {device_sandbox_tar}", root=True, timeout=10,
                    )
                except (ADBError, ADBTimeoutError):
                    pass

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

        # 4b. TikTok Instance-ID Sanitizing (VOR Permission-Fix!)
        # Entfernt install_id, client_udid, device_id etc. aus shared_prefs.
        # Ohne dies erkennt TikTok: 'Neue Hardware, gleiche Install-ID'
        if results["app_data"]:
            try:
                sanitized = await self._sanitize_shared_prefs(self._package)
                if sanitized > 0:
                    logger.info("TikTok Sanitize: %d Instance-IDs entfernt", sanitized)
            except Exception as e:
                logger.warning("TikTok Sanitize fehlgeschlagen (nicht kritisch): %s", e)

        # v6.4: Deep-Clean hier ENTFERNT!
        # FIX-30 _deep_clean_tiktok_storage() löschte databases/, files/mmkv/,
        # app_webview/ — also genau die Daten, die gerade aus dem Backup
        # wiederhergestellt wurden. Die Login-Session (in databases/ und
        # files/mmkv/) wurde dadurch zerstört.
        #
        # Deep-Clean gehört NUR in den Genesis Flow (deep_clean() Methode),
        # wo wir einen sauberen First-Launch-State wollen.
        # Im Switch Flow (restore_tiktok_dual) wollen wir die Session ERHALTEN.
        #
        # shared_prefs Sanitizing (Step 4b oben) reicht: Es entfernt nur
        # Tracking-IDs (install_id, device_id), nicht die Login-Tokens.

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

    async def _clear_clipboard(self) -> None:
        """Clear system clipboard to prevent identity leaks via clipboard data."""
        logger.info("Clearing system clipboard...")
        cmds = [
            "service call clipboard 2 i32 1 2>/dev/null",
            "am broadcast -a clipclear 2>/dev/null",
        ]
        for cmd in cmds:
            try:
                await self._adb.shell(cmd, root=True, timeout=5)
            except Exception:
                pass
        logger.info("Clipboard cleared")

    async def _disable_google_backup(self) -> None:
        """Disable Google auto-backup to prevent TikTok data restoration from cloud."""
        logger.info("Disabling Google auto-backup for TikTok packages...")
        try:
            await self._adb.shell("bmgr enable false", root=True, timeout=5)
        except Exception as e:
            logger.warning("bmgr disable failed: %s", e)

        for pkg in TIKTOK_PACKAGES:
            try:
                await self._adb.shell(
                    f"bmgr backupnow --cancel {pkg}", root=True, timeout=5,
                )
            except Exception:
                pass
            try:
                await self._adb.shell(
                    f"bmgr wipe com.google.android.gms/.backup.BackupTransportService {pkg}",
                    root=True, timeout=10,
                )
            except Exception:
                pass
        logger.info("Google backup disabled for TikTok packages")

    async def _randomize_timestamps(self, package: str) -> None:
        """Randomize file modification times to prevent restore-detection via uniform timestamps."""
        logger.info("Randomizing file timestamps for %s...", package)
        script = (
            f'for f in $(find /data/data/{package} -type f -not -path "*/lib/*" 2>/dev/null | head -200); do '
            f'  h=$((RANDOM % 336 + 1)); '
            f'  touch -d "@$(($(date +%s) - h * 3600))" "$f" 2>/dev/null; '
            f'done'
        )
        try:
            await self._adb.shell(script, root=True, timeout=30)
            logger.info("Timestamps randomized for %s", package)
        except Exception as e:
            logger.warning("Timestamp randomization failed for %s: %s", package, e)

    def _find_latest_tar(self, directory: Path, prefix: str = "") -> Optional[Path]:
        """Findet die neueste tar-Datei mit optionalem Prefix in einem Verzeichnis."""
        if not directory.exists():
            return None
        pattern = f"{prefix}*.tar" if prefix else "*.tar"
        tars = sorted(
            directory.glob(pattern),
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
        Stellt TikTok App-Daten aus einem tar-Archiv wieder her (v6.2).

        KRITISCHER ABLAUF (lib-safe + SELinux-safe):
          1. Force-stop der App
          2. UID ermitteln (via dumpsys package — zuverlässigste Methode)
          3. Smart Clean: Alles löschen AUSSER /lib (Symlink zum APK!)
          4. tar-Stream auf das Gerät entpacken
          5. Permission Fix: chown -R + chmod + restorecon -R

        WICHTIG — lib Symlink:
          /data/data/<pkg>/lib ist ein Symlink auf /data/app/<hash>/lib/
          Wird er gelöscht, findet die App ihre nativen Libraries nicht mehr
          → sofortiger Crash (SIGABRT). `rm -rf /data/data/<pkg>` zerstört
          diesen Symlink. Die Smart-Clean-Methode bewahrt ihn.

        WICHTIG — restorecon:
          restorecon -R auf /data/data/<pkg> ist SICHER (setzt app_data_file).
          Gefährlich ist restorecon auf /data/system/ oder Account-DBs
          (dort braucht man accounts_data_file statt system_data_file).

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
            "[Restore v6.2] Starten: %s (%.1f MB) → %s",
            tar_path.name, size_mb, self._data_path,
        )

        # ─── Phase 1: Force-Stop ─────────────────────────────────────
        logger.info("[Restore] Phase 1: Force-stop %s", self._package)
        await self._force_stop()

        # ─── Phase 2: UID ermitteln ──────────────────────────────────
        logger.info("[Restore] Phase 2: UID ermitteln via dumpsys...")
        uid = await self._get_app_uid()
        logger.info("[Restore] App-UID: %s (für %s)", uid, self._package)

        # ─── Phase 3: Smart Clean (lib bewahren!) ────────────────────
        # find -mindepth 1 -maxdepth 1: Nur direkte Kinder von /data/data/<pkg>
        # ! -name 'lib': Alles AUSSER lib löschen
        # Der lib-Ordner ist ein Symlink auf /data/app/<hash>/lib/arm64
        # Ohne ihn crasht die App sofort (kann native .so nicht laden)
        logger.info(
            "[Restore] Phase 3: Smart Clean — lösche alles ausser lib-Symlink..."
        )

        # Prüfe ob lib existiert und was es ist (Symlink oder Ordner)
        lib_check = await self._adb.shell(
            f"ls -la {self._data_path}/lib 2>/dev/null || echo MISSING",
            root=True, timeout=5,
        )
        lib_status = "MISSING"
        if "MISSING" not in lib_check.output:
            if "->" in lib_check.output:
                lib_status = "SYMLINK"
            else:
                lib_status = "DIR"
        logger.debug("[Restore] lib Status: %s (%s)", lib_status, lib_check.output.strip()[:120])

        # Smart-Delete: Alles ausser lib
        clean_result = await self._adb.shell(
            f"find {self._data_path} -mindepth 1 -maxdepth 1 "
            f"! -name 'lib' -exec rm -rf {{}} +",
            root=True, timeout=30,
        )
        if clean_result.success:
            logger.info(
                "[Restore] Smart Clean OK — lib-Symlink bewahrt (%s)", lib_status,
            )
        else:
            logger.warning(
                "[Restore] Smart Clean Warnung: exit=%d — %s",
                clean_result.returncode, clean_result.output[:200],
            )

        # ─── Phase 4: tar entpacken (Push-then-Extract) ────────────
        # v6.6 FIX: Stdin-Pipe (exec_in_from_file) korrumpiert Binärdaten
        # bei manchen adb-Versionen. Sicherer Weg: Push → Extract → Cleanup.
        logger.info("[Restore] Phase 4: tar aufs Gerät pushen + entpacken (%s)...", tar_path.name)

        device_tar = "/data/local/tmp/_titan_restore.tar"
        try:
            push_result = await self._adb.push(
                str(tar_path), device_tar, timeout=timeout,
            )
            logger.debug("[Restore] Push OK: %s → %s", tar_path.name, device_tar)
        except (ADBError, ADBTimeoutError) as e:
            logger.error("[Restore] Push fehlgeschlagen: %s", e)
            raise

        extract_result = await self._adb.shell(
            f"tar -xf {device_tar} -C /",
            root=True, timeout=timeout,
        )

        # Verifiziere dass Daten tatsächlich extrahiert wurden
        verify = await self._adb.shell(
            f"test -d {self._data_path}/shared_prefs && echo OK || echo FAIL",
            root=True, timeout=5,
        )
        if "OK" in verify.output:
            logger.info("[Restore] tar-Entpacken OK (Daten verifiziert)")
        elif extract_result.success:
            logger.info("[Restore] tar-Entpacken OK (exit 0)")
        else:
            logger.error(
                "[Restore] tar-Entpacken FEHLGESCHLAGEN: exit=%d — %s",
                extract_result.returncode, extract_result.output[:200],
            )

        # Temp-Tar aufräumen
        try:
            await self._adb.shell(
                f"rm -f {device_tar}", root=True, timeout=10,
            )
        except (ADBError, ADBTimeoutError):
            pass

        # ─── Phase 5: Permission Fix (KRITISCH!) ─────────────────────
        logger.info("[Restore] Phase 5: Permission Fix (UID=%s)...", uid)
        await self._apply_magic_permissions(uid)

        # Verifiziere lib-Symlink nach Restore
        lib_post = await self._adb.shell(
            f"ls -la {self._data_path}/lib 2>/dev/null || echo MISSING",
            root=True, timeout=5,
        )
        if "MISSING" in lib_post.output:
            logger.error(
                "[Restore] KRITISCH: lib-Symlink FEHLT nach Restore! "
                "App wird abstürzen. Versuche pm install-existing Repair..."
            )
            # Notfall-Repair: Package Manager repariert den lib-Symlink
            await self._adb.shell(
                f"pm install-existing {self._package} 2>/dev/null",
                root=True, timeout=30,
            )
        elif "->" in lib_post.output:
            logger.info("[Restore] lib-Symlink intakt nach Restore")
        else:
            logger.debug("[Restore] lib ist ein Verzeichnis (kein Symlink)")

        logger.info(
            "[Restore v6.2] Komplett: %s → %s (UID %s, lib=%s)",
            tar_path.name, self._package, uid,
            "OK" if "MISSING" not in lib_post.output else "REPARIERT",
        )

    # =========================================================================
    # Magic Permission Fix
    # =========================================================================

    async def _get_app_uid(self) -> str:
        """
        Ermittelt die UID der Ziel-App (v6.2 — 3-Methoden-Kaskade).

        Reihenfolge (zuverlässigste zuerst):
          1. dumpsys package — parst "userId=XXXXX" (funktioniert immer
             wenn die App installiert ist, auch wenn /data/data nicht existiert)
          2. stat -c '%u' auf den Datenordner (schnell, braucht existierenden Ordner)
          3. pm list packages -U (Fallback)

        Returns:
            UID als String (z.B. "10245")

        Raises:
            ADBError: wenn UID nicht ermittelbar (App nicht installiert?)
        """
        import re

        # Methode 1: dumpsys package (zuverlässigste Methode)
        try:
            result = await self._adb.shell(
                f"dumpsys package {self._package} 2>/dev/null | grep 'userId='",
                root=True, timeout=10,
            )
            if result.success and result.output.strip():
                # Format: "    userId=10245" oder "    userId=10245 gids=[...]"
                match = re.search(r'userId=(\d+)', result.output)
                if match:
                    uid = match.group(1)
                    if int(uid) >= 10000:
                        logger.debug(
                            "[UID] %s → %s (via dumpsys package)", self._package, uid,
                        )
                        return uid
        except Exception as e:
            logger.debug("[UID] dumpsys fehlgeschlagen: %s", e)

        # Methode 2: stat auf Datenordner
        try:
            result = await self._adb.shell(
                f"stat -c '%u' {self._data_path} 2>/dev/null", root=True,
            )
            uid = result.output.strip("'\" \n\r")
            if uid.isdigit() and int(uid) >= 10000:
                logger.debug("[UID] %s → %s (via stat)", self._package, uid)
                return uid
        except Exception as e:
            logger.debug("[UID] stat fehlgeschlagen: %s", e)

        # Methode 3: pm list packages -U (Fallback)
        try:
            result = await self._adb.shell(
                f"pm list packages -U {self._package}", root=True,
            )
            output = result.output if hasattr(result, 'output') else result.stdout
            if "uid:" in output:
                uid = output.split("uid:")[-1].strip().split()[0]
                if uid.isdigit() and int(uid) >= 10000:
                    logger.debug("[UID] %s → %s (via pm list)", self._package, uid)
                    return uid
        except Exception as e:
            logger.debug("[UID] pm list fehlgeschlagen: %s", e)

        raise ADBError(
            f"UID für {self._package} nicht ermittelbar (3 Methoden fehlgeschlagen). "
            f"Ist die App installiert?"
        )

    async def _apply_magic_permissions(self, uid: str) -> None:
        """
        Wendet den Magic Permission Fix an (v6.2 — chown + chmod + restorecon).

        Nach einem tar-Restore gehören alle Dateien root:root und haben
        oft falsche SELinux-Labels. Ohne Fix:
          - App kann eigene Dateien nicht lesen → "Permission Denied" Logs
          - SELinux blockiert Dateizugriffe → App crasht oder verliert Login
          - shared_prefs mit 000 Permissions → Einstellungen weg

        Ablauf:
          1. chown -R uid:uid  — Ownership auf App-User setzen
          2. chmod 771 Basis   — Basis-Verzeichnis (Android Standard)
          3. chmod -R 770 Dirs — Alle Unterordner lesbar für App + Cache-GID
          4. chmod -R 660 Files — Alle Dateien lesen/schreiben für Owner
          5. restorecon -R      — SELinux-Labels reparieren (app_data_file)

        SICHERHEITSHINWEIS:
          restorecon -R auf /data/data/<pkg> ist SICHER (setzt app_data_file).
          Wir verwenden es NICHT auf /data/system/ oder Account-DBs!

        Args:
            uid: App-UID (z.B. "10245")
        """
        logger.info(
            "[PermFix] Start: chown + chmod + restorecon für %s (UID %s)",
            self._data_path, uid,
        )

        # ─── Step 1: Ownership (KRITISCHSTER Schritt) ────────────────
        chown_result = await self._adb.shell(
            f"chown -R {uid}:{uid} {self._data_path}",
            root=True, timeout=30,
        )
        if chown_result.success:
            logger.info("[PermFix] chown -R %s:%s — OK", uid, uid)
        else:
            logger.error(
                "[PermFix] chown FEHLGESCHLAGEN: %s — App wird nicht funktionieren!",
                chown_result.output[:200],
            )

        # ─── Step 2: Basis-Verzeichnis (771 = Android Standard) ──────
        await self._adb.shell(
            f"chmod 771 {self._data_path}", root=True,
        )

        # ─── Step 3: Rekursive Verzeichnis-Permissions ────────────────
        # Alle Unterordner: 770 (rwxrwx--- für uid:uid)
        # Includes: shared_prefs, databases, files, cache, code_cache,
        #           no_backup, app_webview, etc.
        await self._adb.shell(
            f"find {self._data_path} -type d -exec chmod 770 {{}} + 2>/dev/null",
            root=True, timeout=30,
        )
        logger.debug("[PermFix] Verzeichnisse → 770")

        # ─── Step 4: Rekursive Datei-Permissions ──────────────────────
        # Alle Dateien: 660 (rw-rw---- für uid:uid)
        await self._adb.shell(
            f"find {self._data_path} -type f -exec chmod 660 {{}} + 2>/dev/null",
            root=True, timeout=30,
        )
        logger.debug("[PermFix] Dateien → 660")

        # ─── Step 5: SELinux Context reparieren ───────────────────────
        # restorecon setzt den Kontext auf "u:object_r:app_data_file:s0:..."
        # basierend auf dem Pfad. Das ist der korrekte Kontext für App-Daten.
        restorecon_result = await self._adb.shell(
            f"restorecon -RF {self._data_path} 2>&1",
            root=True, timeout=30,
        )
        if restorecon_result.success:
            logger.info("[PermFix] restorecon -RF — OK (SELinux-Labels repariert)")
        else:
            logger.warning(
                "[PermFix] restorecon Warnung: %s (App könnte trotzdem funktionieren)",
                restorecon_result.output[:200],
            )

        # ─── Verifikation ─────────────────────────────────────────────
        verify_result = await self._adb.shell(
            f"ls -la {self._data_path}/ 2>/dev/null | head -5",
            root=True, timeout=5,
        )
        logger.info(
            "[PermFix] Komplett (UID %s). Verzeichnis:\n%s",
            uid, verify_result.output[:300] if verify_result.success else "nicht lesbar",
        )

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
    # v6.3: Robuste App-Reinstallation mit APK-Backup + Session-Install
    # =========================================================================
    # PROBLEM: Auf Single-User-Geräten (nur User 0) löscht
    #   "pm uninstall --user 0" die APKs KOMPLETT aus /data/app/.
    #   Danach ist "install-existing" unmöglich.
    #
    # LÖSUNG: APKs VOR dem Uninstall nach /data/local/tmp/ kopieren,
    #   dann per Session-Install (pm install-create/write/commit)
    #   reinstallieren. Das funktioniert auch mit Split-APKs.
    # =========================================================================

    _APK_BACKUP_DIR = "/data/local/tmp/_titan_apk_backup"

    async def _reinstall_app(self, pkg: str) -> bool:
        """
        Hard-Reset einer App: APK sichern → Uninstall → Session-Install.

        v6.4 — Fixes:
          - Timeouts massiv erhöht (TikTok kann 30+ Split-APKs / 200+ MB haben)
          - Fehler VOR dem Uninstall führen zu pm clear Fallback (nicht false-positive)
          - Tracking ob Uninstall stattfand → Fallback weiß ob App noch Daten hat

        Ablauf:
          1. Existenz-Check + alle APK-Pfade ermitteln (base + splits)
          2. APKs in sicheres Temp-Verzeichnis kopieren
          3. pm uninstall --user 0 (löscht App-Daten + APKs)
          4. Session-Install: pm install-create → write für jede APK → commit
          5. Finale Verifikation + Temp-Cleanup

        Args:
            pkg: Package-Name (z.B. "com.zhiliaoapp.musically")

        Returns:
            True wenn App erfolgreich reinstalliert, False bei Fehler
        """
        logger.info("[Reinstall v6.5] Hard-Reset starten: %s", pkg)
        backup_dir = f"{self._APK_BACKUP_DIR}/{pkg}"
        uninstall_done = False

        try:
            # ─── Step 0: LSPosed Scope sichern ────────────────────────────
            # Uninstall entfernt die App aus ALLEN LSPosed-Modul-Scopes.
            # Wir sichern die Einträge und stellen sie nach Reinstall wieder her.
            lsposed_scope_backup = await self._backup_lsposed_scope(pkg)
            if lsposed_scope_backup:
                logger.info(
                    "[Reinstall] LSPosed Scope gesichert: %d Modul(e) betroffen",
                    len(lsposed_scope_backup),
                )

            # ─── Step 1: Existenz-Check + APK-Pfade sammeln ─────────────
            check = await self._adb.shell(
                f"pm path {pkg}", root=True, timeout=15,
            )
            if not check.success or "package:" not in check.output:
                logger.error(
                    "[Reinstall] KRITISCH: %s ist nicht installiert! Abbruch.",
                    pkg,
                )
                return False

            apk_paths = [
                line.strip().replace("package:", "", 1)
                for line in check.output.strip().splitlines()
                if line.strip().startswith("package:")
            ]

            if not apk_paths:
                logger.error("[Reinstall] Keine APK-Pfade für %s gefunden!", pkg)
                return False

            logger.info(
                "[Reinstall] %s: %d APK(s) gefunden — %s",
                pkg, len(apk_paths),
                ", ".join(p.rsplit("/", 1)[-1] for p in apk_paths[:10]),
            )

            # ─── Step 2: APKs in Backup-Verzeichnis kopieren ────────────
            # Timeout großzügig: TikTok kann 30+ APKs haben, altes Backup
            # kann hunderte MB groß sein → rm -rf braucht Zeit
            await self._adb.shell(
                f"rm -rf {backup_dir} && mkdir -p {backup_dir}",
                root=True, timeout=60,
            )

            for apk in apk_paths:
                filename = apk.rsplit("/", 1)[-1]
                cp_res = await self._adb.shell(
                    f"cp \"{apk}\" \"{backup_dir}/{filename}\"",
                    root=True, timeout=120,
                )
                if not cp_res.success:
                    logger.error(
                        "[Reinstall] APK-Backup fehlgeschlagen: %s → %s",
                        apk, cp_res.output.strip()[:100],
                    )
                    # Backup fehlgeschlagen VOR Uninstall → pm clear als Fallback
                    return await self._pm_clear_fallback(pkg)

            # APKs für shell-User lesbar machen (Session-Install läuft als shell)
            await self._adb.shell(
                f"chmod 755 {backup_dir} && chmod 644 {backup_dir}/*.apk",
                root=True, timeout=30,
            )

            # Verifikation: Anzahl APKs im Backup prüfen
            ls_res = await self._adb.shell(
                f"ls {backup_dir}/*.apk | wc -l", root=True, timeout=10,
            )
            backup_count = 0
            if ls_res.success:
                try:
                    backup_count = int(ls_res.output.strip())
                except ValueError:
                    pass

            if backup_count < len(apk_paths):
                logger.error(
                    "[Reinstall] APK-Backup unvollständig: %d/%d — Abbruch!",
                    backup_count, len(apk_paths),
                )
                return await self._pm_clear_fallback(pkg)

            logger.info(
                "[Reinstall] APK-Backup komplett: %d/%d APKs gesichert",
                backup_count, len(apk_paths),
            )

            # ─── Step 3: Deinstallation ─────────────────────────────────
            uninstall_res = await self._adb.shell(
                f"pm uninstall --user 0 {pkg}",
                root=True, timeout=30,
            )
            uninstall_done = True
            logger.info(
                "[Reinstall] pm uninstall --user 0 %s: %s",
                pkg, uninstall_res.output.strip()[:80],
            )

            await asyncio.sleep(1)

            # ─── Step 4: Session-Install (Split-APK-kompatibel) ─────────
            # WICHTIG: Session-Install MUSS als shell-User laufen (root=False)!
            # Grund: pm install-create bindet die Session an die Caller-UID.
            # su = UID 0, adb shell = UID 2000. Session ist UID-gebunden.

            # Berechne Gesamtgröße aller APKs
            size_res = await self._adb.shell(
                f"du -cb {backup_dir}/*.apk | tail -1",
                root=True, timeout=15,
            )
            total_size = "0"
            if size_res.success:
                parts = size_res.output.strip().split()
                if parts and parts[0].isdigit():
                    total_size = parts[0]

            logger.info("[Reinstall] Gesamtgröße: %s Bytes", total_size)

            # 4a. Session erstellen (als shell-User!)
            create_res = await self._adb.shell(
                f"pm install-create -S {total_size}",
                root=False, timeout=15,
            )

            # Session-ID extrahieren: "Success: created install session [1234567]"
            session_id = None
            if create_res.success and "[" in create_res.output:
                try:
                    session_id = create_res.output.split("[")[1].split("]")[0].strip()
                except (IndexError, ValueError):
                    pass

            if not session_id or not session_id.isdigit():
                logger.error(
                    "[Reinstall] Session-Erstellung fehlgeschlagen: %s",
                    create_res.output.strip()[:200],
                )
                return await self._reinstall_simple_fallback(pkg, backup_dir, apk_paths)

            logger.info("[Reinstall] Install-Session erstellt: ID=%s", session_id)

            # 4b. Jede APK in die Session schreiben (als shell-User!)
            for idx, apk in enumerate(apk_paths):
                filename = apk.rsplit("/", 1)[-1]
                local_path = f"{backup_dir}/{filename}"

                # Dateigröße ermitteln
                fsize_res = await self._adb.shell(
                    f"stat -c %s \"{local_path}\"",
                    root=True, timeout=10,
                )
                file_size = fsize_res.output.strip() if fsize_res.success else "0"

                # APK in Session schreiben via cat-pipe (als shell-User!)
                # Timeout 120s pro APK — base.apk kann 130+ MB sein
                write_res = await self._adb.shell(
                    f"cat \"{local_path}\" | pm install-write -S {file_size} {session_id} {idx} -",
                    root=False, timeout=120,
                )

                if not write_res.success or "success" not in write_res.output.lower():
                    logger.error(
                        "[Reinstall] install-write fehlgeschlagen für %s: %s",
                        filename, write_res.output.strip()[:150],
                    )
                    await self._adb.shell(
                        f"pm install-abandon {session_id}",
                        root=False, timeout=10,
                    )
                    return await self._reinstall_simple_fallback(pkg, backup_dir, apk_paths)

                logger.debug(
                    "[Reinstall] install-write %d/%d: %s OK",
                    idx + 1, len(apk_paths), filename,
                )

            # 4c. Session committen (als shell-User!)
            commit_res = await self._adb.shell(
                f"pm install-commit {session_id}",
                root=False, timeout=60,
            )

            if commit_res.success and "success" in commit_res.output.lower():
                logger.info(
                    "[Reinstall] Session-Install ERFOLG: %s → %s",
                    pkg, commit_res.output.strip()[:120],
                )
            else:
                logger.warning(
                    "[Reinstall] install-commit Ergebnis: %s",
                    commit_res.output.strip()[:200],
                )

            # ─── Step 5: Finale Verifikation + LSPosed Scope Restore ─────
            await asyncio.sleep(1)

            if await self._verify_app_installed(pkg):
                logger.info("[Reinstall] VERIFIZIERT: %s ist installiert", pkg)
                # LSPosed Scope wiederherstellen (NACH Install!)
                if lsposed_scope_backup:
                    await self._restore_lsposed_scope(pkg, lsposed_scope_backup)
                return True

            logger.warning(
                "[Reinstall] Session-Install hat nicht verifiziert — "
                "versuche Simple-Fallback..."
            )
            fallback_ok = await self._reinstall_simple_fallback(pkg, backup_dir, apk_paths)
            if fallback_ok and lsposed_scope_backup:
                await self._restore_lsposed_scope(pkg, lsposed_scope_backup)
            return fallback_ok

        except Exception as e:
            logger.error("[Reinstall] Fehler für %s: %s", pkg, e)

            if not uninstall_done:
                # Fehler VOR dem Uninstall → App hat noch alte Daten!
                # pm clear als sicherer Fallback (löscht Daten, behält App)
                logger.warning(
                    "[Reinstall] Fehler VOR Uninstall — App hat noch alte Daten! "
                    "Fallback: pm clear"
                )
                return await self._pm_clear_fallback(pkg)
            else:
                # Fehler NACH dem Uninstall → App muss reinstalliert werden
                try:
                    return await self._reinstall_simple_fallback(pkg, backup_dir, apk_paths)
                except Exception:
                    logger.error(
                        "[Reinstall] FATAL: %s wurde deinstalliert und konnte nicht "
                        "wiederhergestellt werden!",
                        pkg,
                    )
                    return False
        finally:
            # Cleanup: Backup-Verzeichnis entfernen
            try:
                await self._adb.shell(
                    f"rm -rf {backup_dir}",
                    root=True, timeout=60,
                )
                logger.debug("[Reinstall] Backup-Cleanup: %s entfernt", backup_dir)
            except (ADBError, ADBTimeoutError):
                pass

    # =========================================================================
    # LSPosed Scope Backup / Restore (v6.5)
    # =========================================================================

    _LSPOSED_DB = "/data/adb/lspd/config/modules_config.db"

    async def _backup_lsposed_scope(self, pkg: str) -> list[dict]:
        """
        Sichert alle LSPosed-Scope-Einträge für ein Paket.

        LSPosed speichert Scopes in einer SQLite-DB:
          /data/adb/lspd/config/modules_config.db
          Tabelle: scope (mid INTEGER, app_pkg_name TEXT, user_id INTEGER)

        Bei Uninstall entfernt LSPosed den Scope-Eintrag automatisch.
        Wir sichern ihn VOR dem Uninstall und stellen ihn danach wieder her.

        Returns:
            Liste von {mid, user_id} Dicts (leere Liste wenn LSPosed nicht installiert)
        """
        try:
            # Prüfe ob LSPosed DB existiert
            check = await self._adb.shell(
                f"test -f {self._LSPOSED_DB} && echo EXISTS",
                root=True, timeout=5,
            )
            if "EXISTS" not in (check.output or ""):
                logger.debug("[LSPosed] DB nicht gefunden — überspringe Scope-Backup")
                return []

            # Scope-Einträge für das Paket abfragen
            # Da kein sqlite3 auf dem Gerät ist, nutzen wir cat + lokal parsen
            # Alternative: Wir lesen die DB binär und parsen lokal
            # Einfachere Lösung: Nutze den dd/strings-Trick oder kopiere die DB

            # DB nach /data/local/tmp kopieren (lesbar für adb pull)
            tmp_db = "/data/local/tmp/_lsposed_scope_backup.db"
            await self._adb.shell(
                f"cp {self._LSPOSED_DB} {tmp_db}",
                root=True, timeout=10,
            )

            # DB auf Host ziehen und lokal mit sqlite3 parsen
            import subprocess
            import tempfile

            with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
                local_db = tf.name

            pull_result = subprocess.run(
                ["adb", "shell", "su", "-c", f"cat {tmp_db}"],
                capture_output=True, timeout=10,
            )
            if pull_result.returncode != 0:
                logger.debug("[LSPosed] DB konnte nicht gelesen werden")
                return []

            import os
            with open(local_db, "wb") as f:
                f.write(pull_result.stdout)

            # Lokal mit sqlite3 parsen
            query = (
                f"SELECT mid, user_id FROM scope "
                f"WHERE app_pkg_name = '{pkg}';"
            )
            sql_result = subprocess.run(
                ["sqlite3", local_db, query],
                capture_output=True, text=True, timeout=5,
            )

            entries = []
            if sql_result.returncode == 0 and sql_result.stdout.strip():
                for line in sql_result.stdout.strip().splitlines():
                    parts = line.split("|")
                    if len(parts) == 2:
                        entries.append({
                            "mid": int(parts[0]),
                            "user_id": int(parts[1]),
                        })

            # Aufräumen
            os.unlink(local_db)
            await self._adb.shell(f"rm -f {tmp_db}", root=True, timeout=5)

            if entries:
                logger.info(
                    "[LSPosed] Scope-Backup für %s: %d Einträge (module IDs: %s)",
                    pkg, len(entries),
                    ", ".join(str(e["mid"]) for e in entries),
                )
            else:
                logger.debug("[LSPosed] Keine Scope-Einträge für %s gefunden", pkg)

            return entries

        except Exception as e:
            logger.debug("[LSPosed] Scope-Backup fehlgeschlagen (nicht kritisch): %s", e)
            return []

    async def _restore_lsposed_scope(
        self, pkg: str, scope_entries: list[dict],
    ) -> bool:
        """
        Stellt LSPosed-Scope-Einträge nach einem Reinstall wieder her.

        Schreibt die gesicherten (mid, app_pkg_name, user_id) Tupel
        zurück in die LSPosed-DB.

        Args:
            pkg:           Package-Name (z.B. "com.zhiliaoapp.musically")
            scope_entries: Liste von {mid, user_id} Dicts aus _backup_lsposed_scope

        Returns:
            True wenn Restore erfolgreich
        """
        if not scope_entries:
            return True

        try:
            import subprocess
            import tempfile
            import os

            # DB vom Gerät holen
            tmp_db = "/data/local/tmp/_lsposed_scope_restore.db"
            await self._adb.shell(
                f"cp {self._LSPOSED_DB} {tmp_db}",
                root=True, timeout=10,
            )

            with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
                local_db = tf.name

            pull_result = subprocess.run(
                ["adb", "shell", "su", "-c", f"cat {tmp_db}"],
                capture_output=True, timeout=10,
            )
            if pull_result.returncode != 0:
                logger.warning("[LSPosed] DB konnte nicht für Restore gelesen werden")
                return False

            with open(local_db, "wb") as f:
                f.write(pull_result.stdout)

            # Scope-Einträge einfügen (INSERT OR IGNORE für Idempotenz)
            insert_cmds = []
            for entry in scope_entries:
                insert_cmds.append(
                    f"INSERT OR IGNORE INTO scope (mid, app_pkg_name, user_id) "
                    f"VALUES ({entry['mid']}, '{pkg}', {entry['user_id']});"
                )

            sql_cmd = " ".join(insert_cmds)
            sql_result = subprocess.run(
                ["sqlite3", local_db, sql_cmd],
                capture_output=True, text=True, timeout=5,
            )

            if sql_result.returncode != 0:
                logger.error(
                    "[LSPosed] Scope-Insert fehlgeschlagen: %s",
                    sql_result.stderr.strip()[:200],
                )
                os.unlink(local_db)
                return False

            # Modifizierte DB zurück aufs Gerät pushen
            push_result = subprocess.run(
                ["adb", "push", local_db, "/data/local/tmp/_lsposed_fixed.db"],
                capture_output=True, text=True, timeout=10,
            )

            if push_result.returncode != 0:
                logger.error("[LSPosed] DB-Push fehlgeschlagen")
                os.unlink(local_db)
                return False

            # Atomic swap: Backup → Replace → Fix Permissions
            await self._adb.shell(
                f"cp {self._LSPOSED_DB} {self._LSPOSED_DB}.bak",
                root=True, timeout=10,
            )
            await self._adb.shell(
                f"cp /data/local/tmp/_lsposed_fixed.db {self._LSPOSED_DB}",
                root=True, timeout=10,
            )
            # Permissions wie Original setzen (root:root, 600)
            await self._adb.shell(
                f"chown root:root {self._LSPOSED_DB} && chmod 600 {self._LSPOSED_DB}",
                root=True, timeout=5,
            )
            # WAL-Modus Artefakte bereinigen (sonst liest LSPosed alte Daten)
            await self._adb.shell(
                f"rm -f {self._LSPOSED_DB}-wal {self._LSPOSED_DB}-shm",
                root=True, timeout=5,
            )

            # Cleanup
            os.unlink(local_db)
            await self._adb.shell(
                "rm -f /data/local/tmp/_lsposed_scope_restore.db "
                "/data/local/tmp/_lsposed_fixed.db",
                root=True, timeout=5,
            )

            logger.info(
                "[LSPosed] Scope wiederhergestellt: %s → %d Modul(e) (%s)",
                pkg, len(scope_entries),
                ", ".join(f"mid={e['mid']}" for e in scope_entries),
            )
            return True

        except Exception as e:
            logger.warning(
                "[LSPosed] Scope-Restore fehlgeschlagen (nicht kritisch): %s", e,
            )
            return False

    async def _reinstall_simple_fallback(
        self, pkg: str, backup_dir: str, apk_paths: list[str],
    ) -> bool:
        """
        Einfacher Reinstall-Fallback: pm install mit allen APKs auf einmal.

        Wird genutzt wenn Session-Install fehlschlägt. Funktioniert auf
        den meisten Android-Versionen, auch ohne Session-Support.
        """
        logger.info("[Reinstall-Fallback] Versuche einfachen pm install für %s...", pkg)

        # Alle lokalen APK-Pfade zusammenbauen
        local_apks = " ".join(
            f'"{backup_dir}/{p.rsplit("/", 1)[-1]}"' for p in apk_paths
        )

        # pm install mit mehreren APKs (Android 10+ unterstützt das)
        # Muss als shell-User laufen (wie Session-Install)
        res = await self._adb.shell(
            f"pm install -r {local_apks}",
            root=False, timeout=60,
        )

        if await self._verify_app_installed(pkg):
            logger.info("[Reinstall-Fallback] ERFOLG: %s ist wieder da ✓", pkg)
            return True

        # Letzter Versuch: Nur base.apk installieren
        base_apk = f"{backup_dir}/base.apk"
        base_check = await self._adb.shell(
            f"ls {base_apk}", root=True, timeout=5,
        )
        if base_check.success and "No such file" not in base_check.output:
            logger.warning(
                "[Reinstall-Fallback] Multi-APK fehlgeschlagen, "
                "versuche nur base.apk..."
            )
            await self._adb.shell(
                f"pm install -r \"{base_apk}\"",
                root=False, timeout=60,
            )
            if await self._verify_app_installed(pkg):
                logger.info(
                    "[Reinstall-Fallback] base.apk-Install ERFOLG "
                    "(Split-APKs fehlen, aber App funktioniert) ✓",
                )
                return True

        logger.error(
            "[Reinstall] FATAL: %s konnte NICHT wiederhergestellt werden! "
            "App muss manuell über den Play Store installiert werden.",
            pkg,
        )
        return False

    async def _pm_clear_fallback(self, pkg: str) -> bool:
        """
        Sicherer Fallback wenn Reinstall VOR dem Uninstall fehlschlägt.

        Nutzt pm clear um alle App-Daten zu löschen, ohne die App zu
        deinstallieren. Das ist weniger gründlich als Uninstall+Reinstall
        (Package-Manager-State wie install_time bleibt), aber garantiert
        dass die App danach im First-Launch-State ist und keine alten
        Login-Sessions überlebt haben.

        Returns:
            True wenn pm clear erfolgreich, False sonst
        """
        logger.info(
            "[Reinstall-pmclear] Fallback: pm clear %s (App bleibt installiert)", pkg,
        )
        try:
            res = await self._adb.shell(
                f"pm clear {pkg}", root=True, timeout=30,
            )
            if res.success and "Success" in res.output:
                logger.info(
                    "[Reinstall-pmclear] pm clear %s: ERFOLG — "
                    "App-Daten gelöscht, App bleibt installiert ✓",
                    pkg,
                )
                return True

            logger.error(
                "[Reinstall-pmclear] pm clear %s fehlgeschlagen: %s",
                pkg, res.output.strip()[:150],
            )
            return False
        except (ADBError, ADBTimeoutError) as e:
            logger.error("[Reinstall-pmclear] Fehler bei pm clear %s: %s", pkg, e)
            return False

    # =========================================================================
    # Deep Clean: Vollständige Sterilisierung
    # =========================================================================

    async def deep_clean(self, include_gms: bool = False) -> dict[str, bool]:
        """
        Führt eine Sterilisierung der Target-Apps durch.

        FLOW 1 (GENESIS), Schritt 1:
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
        # 1. v6.2: Robuste App-Reinstallation (Hard-Reset)
        # =====================================================================
        # Erzwingt echten "First Launch"-State via:
        #   1. Existenz-Check (kein Uninstall wenn App gar nicht da)
        #   2. pm uninstall --user 0 (behält APK auf System-Partition)
        #   3. cmd package install-existing --user 0 via su (primär)
        #   4. pm install-existing --user 0 via su (Legacy-Fallback)
        #   5. Finale Verifikation
        #
        # ALLE Befehle laufen zwingend über su -c um Permission-Fehler
        # zu vermeiden (häufigste Ursache für "install-existing failed").
        # =====================================================================
        for pkg in TIKTOK_PACKAGES:
            try:
                results[f"fresh_install_{pkg}"] = await self._reinstall_app(pkg)
            except ADBError as e:
                results[f"fresh_install_{pkg}"] = False
                logger.warning("TikTok Reinstall %s fehlgeschlagen: %s", pkg, e)

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

        # =====================================================================
        # v6.6: Spuren die pm clear + uninstall NICHT entfernen
        # =====================================================================
        for pkg in TIKTOK_PACKAGES:
            external_targets = [
                f"/data/misc/profiles/ref/{pkg}",
                f"/data/system_ce/0/shortcut_service/packages/{pkg}.xml",
                f"/data/system_ce/0/shortcut_service/packages/{pkg}.xml.reservecopy",
                f"/data/system/graphicsstats/*/{pkg}",
            ]
            for target in external_targets:
                try:
                    await self._adb.shell(
                        f"rm -rf {target}", root=True, timeout=5,
                    )
                    results[f"ext_{target.split('/')[-1]}_{pkg}"] = True
                except (ADBError, ADBTimeoutError):
                    results[f"ext_{target.split('/')[-1]}_{pkg}"] = False

        # v6.6: AAID Reset — TikTok verknüpft Advertising ID mit Profil
        try:
            await self._adb.shell(
                "rm -f /data/data/com.google.android.gms/shared_prefs/adid_settings.xml",
                root=True, timeout=5,
            )
            results["aaid_reset"] = True
            logger.info("AAID (Advertising ID) resetted")
        except (ADBError, ADBTimeoutError):
            results["aaid_reset"] = False

        # Zusammenfassung
        success_count = sum(1 for v in results.values() if v)
        total_count = len(results)
        logger.info(
            "Deep Clean abgeschlossen: %d/%d Operationen erfolgreich "
            "(inkl. MediaStore, Compiler-Cache, ART-Profile, Shortcuts, AAID, Settings)",
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

        # --- 1. TikTok App-Daten löschen (lib-Symlink bewahren!) ---
        # WICHTIG: rm -rf /data/data/<pkg> zerstört den lib-Symlink, der auf
        #   /data/app/<hash>/lib/arm64/ zeigt. Ohne ihn crasht TikTok sofort
        #   (SIGABRT — kann native .so nicht laden). Stattdessen nutzen wir
        #   find ... ! -name 'lib' um alles AUSSER lib zu löschen.
        for pkg in TIKTOK_PACKAGES:
            data_path = f"/data/data/{pkg}"
            try:
                # Smart Clean: Alles löschen ausser lib-Symlink
                await self._adb.shell(
                    f"find {data_path} -mindepth 1 -maxdepth 1 "
                    f"! -name 'lib' -exec rm -rf {{}} +",
                    root=True, timeout=15,
                )
                results[f"wipe_{pkg}"] = True
                logger.info(
                    "FIX-29: %s — Smart Clean (lib-Symlink bewahrt)", data_path,
                )
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
            "tiktok": True,  # v6.5: Immer True — TikTok wird in Step 8 separat behandelt
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

        # --- 3. TikTok NICHT hier restoren ---
        # v6.5 FIX: TikTok wird separat in Step 8 (restore_tiktok_dual) behandelt.
        # Vorher wurde TikTok hier UND in Step 8 restored → Doppel-Restore
        # zerstörte lib-Symlink und überschrieb sauberen State.
        logger.info("TikTok-Restore übersprungen — wird in Step 8 (Dual-Path) behandelt")

        # Zusammenfassung (v6.5: nur GMS+Accounts, TikTok separat in Step 8)
        gms_ok = results["gms"]
        acc_ok = results["accounts"]
        logger.info(
            "Full-State Restore abgeschlossen: GMS=%s, Accounts=%s (TikTok → Step 8)",
            "OK" if gms_ok else "FAIL",
            "OK" if acc_ok else "FAIL",
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

        # v6.6: Push-then-Extract (GMS tar)
        device_gms_tar = "/data/local/tmp/_titan_gms_restore.tar"
        await self._adb.push(
            str(tar_path), device_gms_tar, timeout=timeout,
        )
        restore_result = await self._adb.shell(
            f"tar -xf {device_gms_tar} -C /",
            root=True, timeout=timeout,
        )
        try:
            await self._adb.shell(
                f"rm -f {device_gms_tar}", root=True, timeout=10,
            )
        except (ADBError, ADBTimeoutError):
            pass

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

        # DroidGuard Sanitizing: Gecachte Attestierungs-Tokens löschen
        # die kryptografisch an die ALTE Hardware gebunden sind.
        # Ohne diese Löschung erkennt Google die Diskrepanz sofort.
        await self._sanitize_droidguard()

        logger.info("GMS Restore komplett: %d Pakete (DroidGuard sanitized)", len(GMS_BACKUP_PACKAGES))

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

        v4.0 "FBE-Safe" Strategie (2026-02-17):
          PROBLEM: tar -xf direkt in /data/system_ce/0/ (FBE-verschlüsselt)
          erzeugt Dateien deren SELinux-Xattr vom Kernel als 'unlabeled'
          aufgelöst wird → system_server crasht → BOOTLOOP!

          LÖSUNG: Zweistufiger Restore:
            1. tar in TEMP-Dir extrahieren (/data/local/tmp/ — nicht FBE)
            2. Inhalte per 'cat' in die FBE-Zone kopieren (frische Inodes)
            3. Permissions + SELinux setzen
            4. Kernel-Verify: dmesg auf SELinux-Denials prüfen
            5. BOOTLOOP-SCHUTZ: Bei Verify-Fehler Datei LÖSCHEN

        WARNUNG: Falsche Permissions = Bootloop-Gefahr!
        """
        TEMP_DIR = "/data/local/tmp/_acc_restore"
        CE_DIR = "/data/system_ce/0"
        DB_NAME = "accounts_ce.db"

        logger.info(
            "Account-DBs Restore v4.0 (FBE-Safe): %s (%d Bytes)",
            tar_path.name, tar_path.stat().st_size,
        )

        # --- Phase 0: Cleanup ---
        # Alte DB-Dateien + Journal/WAL/SHM löschen
        for suffix in ["", "-wal", "-shm", "-journal"]:
            try:
                await self._adb.shell(
                    f"rm -f {CE_DIR}/{DB_NAME}{suffix}",
                    root=True, timeout=5,
                )
            except (ADBError, ADBTimeoutError):
                pass

        await asyncio.sleep(1)

        # Temp-Dir vorbereiten (außerhalb FBE!)
        await self._adb.shell(
            f"rm -rf {TEMP_DIR} && mkdir -p {TEMP_DIR}",
            root=True,
        )

        try:
            # v6.6: Push-then-Extract (Account-DB tar)
            logger.debug("Phase 1: tar → %s", TEMP_DIR)
            device_acc_tar = "/data/local/tmp/_titan_acc_restore.tar"
            await self._adb.push(
                str(tar_path), device_acc_tar, timeout=30,
            )
            restore_result = await self._adb.shell(
                f"tar -xf {device_acc_tar} -C {TEMP_DIR}",
                root=True, timeout=30,
            )
            try:
                await self._adb.shell(
                    f"rm -f {device_acc_tar}", root=True, timeout=10,
                )
            except (ADBError, ADBTimeoutError):
                pass
            if not restore_result.success:
                raise ADBError(
                    f"Account-DB tar-Extract fehlgeschlagen: "
                    f"exit {restore_result.returncode}"
                )

            # Finde die extrahierte accounts_ce.db (Pfad im tar ist relativ)
            find_result = await self._adb.shell(
                f"find {TEMP_DIR} -name '{DB_NAME}' -type f",
                root=True, timeout=10,
            )
            if not find_result.success or not find_result.output.strip():
                raise ADBError("accounts_ce.db nicht im tar-Archiv gefunden")

            extracted_db = find_result.output.strip().split("\n")[0]
            logger.debug("Phase 1: Extrahiert → %s", extracted_db)

            # --- Phase 2: cat-Copy in FBE-Zone (frische Inodes!) ---
            # KRITISCH: 'cat > file' erzeugt einen neuen Inode im
            # FBE-verschlüsselten Verzeichnis mit korrekter Encryption.
            # tar -xf würde den Inode mit falschen Xattrs erstellen.
            logger.debug("Phase 2: cat-Copy → %s/%s", CE_DIR, DB_NAME)

            final_db = f"{CE_DIR}/{DB_NAME}"
            copy_result = await self._adb.shell(
                f"cat {extracted_db} > {final_db}",
                root=True, timeout=15,
            )
            if not copy_result.success:
                raise ADBError(
                    f"cat-Copy fehlgeschlagen: exit {copy_result.returncode}"
                )

            # Prüfe ob die kopierte Datei valide ist (SQLite Header)
            header_check = await self._adb.shell(
                f"xxd -l 16 {final_db} | head -1",
                root=True, timeout=5,
            )
            if header_check.success and "SQLite" not in header_check.output:
                logger.error(
                    "BOOTLOOP-SCHUTZ: Kopierte DB hat keinen SQLite-Header! "
                    "Lösche Datei um Bootloop zu verhindern."
                )
                await self._adb.shell(f"rm -f {final_db}", root=True)
                raise ADBError("Account-DB korrupt nach cat-Copy (kein SQLite-Header)")

            # --- Phase 3: Permissions + SELinux ---
            logger.debug("Phase 3: Permissions + SELinux")
            await self._adb.shell(
                f"chown {ACCOUNTS_DB_OWNER}:{ACCOUNTS_DB_GROUP} {final_db}",
                root=True,
            )
            await self._adb.shell(
                f"chmod {ACCOUNTS_DB_MODE} {final_db}",
                root=True,
            )
            await self._adb.shell(
                f"chcon {ACCOUNTS_DB_SELINUX} {final_db}",
                root=True,
            )

            # --- Phase 4: Kernel-Verify (BOOTLOOP-SCHUTZ!) ---
            verify = await self._adb.shell(
                f"ls -Z {final_db}",
                root=True,
            )
            if verify.success:
                context_line = verify.output.strip()
                logger.info("SELinux Verify: %s", context_line)

                if "accounts_data_file" not in context_line:
                    # LETZTE CHANCE: Datei löschen um Bootloop zu verhindern!
                    logger.error(
                        "BOOTLOOP-SCHUTZ AKTIV: SELinux-Kontext '%s' ist NICHT "
                        "accounts_data_file! Lösche DB um Bootloop zu verhindern. "
                        "Google-Account muss manuell neu eingeloggt werden.",
                        context_line,
                    )
                    await self._adb.shell(f"rm -f {final_db}", root=True)
                    await self._adb.shell("sync", root=True)
                    logger.warning(
                        "Account-DB gelöscht (Bootloop-Schutz). "
                        "Android erstellt eine leere DB beim nächsten Boot."
                    )
                    return
                else:
                    logger.info("SELinux OK: accounts_data_file korrekt gesetzt")

            # Filesystem sync
            await self._adb.shell("sync", root=True)
            logger.info(
                "Account-DBs Restore v4.0 komplett (FBE-Safe cat-Copy + Verify)"
            )

        finally:
            # Temp-Dir immer aufräumen
            try:
                await self._adb.shell(f"rm -rf {TEMP_DIR}", root=True)
            except ADBError:
                pass

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

    # _find_latest_tar ist oben definiert (mit optionalem prefix Parameter)

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

    # =========================================================================
    # verify_system_readiness: Boot + GMS Active Polling
    # =========================================================================

    async def verify_system_readiness(
        self,
        timeout: int = 180,
        poll_interval: int = 5,
    ) -> dict:
        """
        Wartet bis das System vollständig bereit ist:
          1. sys.boot_completed == 1
          2. GmsCore Service läuft (dumpsys activity services)

        Args:
            timeout:       Maximale Wartezeit in Sekunden
            poll_interval: Polling-Intervall in Sekunden

        Returns:
            {"boot_ready": bool, "gms_ready": bool, "elapsed_s": float, "detail": str}
        """
        import time
        start = time.monotonic()
        boot_ready = False
        gms_ready = False
        detail_parts = []

        # Phase 1: Boot-Completed
        logger.info("[Readiness] Warte auf sys.boot_completed=1...")
        while (time.monotonic() - start) < timeout:
            try:
                bc = await self._adb.shell("getprop sys.boot_completed", timeout=5)
                if bc.success and bc.output.strip() == "1":
                    boot_ready = True
                    elapsed = time.monotonic() - start
                    detail_parts.append(f"Boot: {elapsed:.0f}s")
                    logger.info("[Readiness] Boot bestätigt nach %.0fs", elapsed)
                    break
            except Exception:
                pass
            await asyncio.sleep(poll_interval)

        if not boot_ready:
            elapsed = time.monotonic() - start
            return {
                "boot_ready": False,
                "gms_ready": False,
                "elapsed_s": elapsed,
                "detail": f"Boot-Timeout nach {elapsed:.0f}s",
            }

        # Phase 2: GMS-Readiness (GmsCore Service aktiv)
        logger.info("[Readiness] Warte auf GmsCore Service...")
        while (time.monotonic() - start) < timeout:
            try:
                svc = await self._adb.shell(
                    "dumpsys activity services com.google.android.gms/.chimera.GmsIntentOperationService 2>/dev/null"
                    " | head -5",
                    root=True, timeout=10,
                )
                if svc.success and "ServiceRecord" in svc.output:
                    gms_ready = True
                    elapsed = time.monotonic() - start
                    detail_parts.append(f"GMS: {elapsed:.0f}s")
                    logger.info("[Readiness] GmsCore aktiv nach %.0fs", elapsed)
                    break
            except Exception:
                pass

            # Fallback: Prüfe ob gms Prozess überhaupt läuft
            try:
                ps = await self._adb.shell("pidof com.google.android.gms", timeout=5)
                if ps.success and ps.output.strip():
                    gms_ready = True
                    elapsed = time.monotonic() - start
                    detail_parts.append(f"GMS(pid): {elapsed:.0f}s")
                    logger.info("[Readiness] GMS-Prozess aktiv nach %.0fs", elapsed)
                    break
            except Exception:
                pass

            await asyncio.sleep(poll_interval)

        elapsed = time.monotonic() - start
        if not gms_ready:
            detail_parts.append(f"GMS-Timeout nach {elapsed:.0f}s")
            logger.warning("[Readiness] GMS nicht bereit nach %.0fs", elapsed)

        detail = " | ".join(detail_parts)
        if boot_ready and gms_ready:
            logger.info(
                "[Readiness] System bereit — %s (%s)",
                detail, "GMS Verbindung steht - Bereit zum Loslegen!",
            )

        return {
            "boot_ready": boot_ready,
            "gms_ready": gms_ready,
            "elapsed_s": elapsed,
            "detail": detail,
        }

    # =========================================================================
    # DroidGuard Sanitizing: dg.db + app_dg_cache löschen
    # =========================================================================

    async def _sanitize_droidguard(self) -> bool:
        """
        Löscht DroidGuard-Attestierungs-Caches nach GMS-Restore.

        DroidGuard (dg.db) enthält gecachte Tokens die kryptografisch
        an die alte Hardware gebunden sind. Nach einem Identity-Switch
        MUSS dieser Cache gelöscht werden, damit Google eine saubere
        Neu-Attestierung (Play Integrity) durchführt.

        Returns:
            True wenn mindestens eine Löschung erfolgreich war
        """
        targets = [
            "/data/data/com.google.android.gms/databases/dg.db",
            "/data/data/com.google.android.gms/databases/dg.db-wal",
            "/data/data/com.google.android.gms/databases/dg.db-shm",
            "/data/data/com.google.android.gms/databases/dg.db-journal",
            "/data/data/com.google.android.gms/app_dg_cache",
        ]
        deleted = 0
        for path in targets:
            try:
                result = await self._adb.shell(f"rm -rf {path}", root=True, timeout=5)
                if result.success:
                    deleted += 1
            except Exception:
                pass

        if deleted > 0:
            logger.info(
                "[DroidGuard] Sanitized: %d/%d Einträge gelöscht (Neu-Attestierung erzwungen)",
                deleted, len(targets),
            )
        else:
            logger.debug("[DroidGuard] Keine Einträge zum Löschen gefunden")
        return deleted > 0

    # =========================================================================
    # =========================================================================
    # v6.6: Nuclear Clean — Wie frisch installiert
    # =========================================================================

    async def _deep_clean_tiktok_storage(
        self, pkg: str = TIKTOK_PRIMARY,
    ) -> dict[str, bool]:
        """
        v6.6: Totale Sterilisierung — App-Zustand wie bei Erstinstallation.

        Getestet und verifiziert: Nur diese Kombination entfernt ALLE Spuren,
        inklusive TikToks Account-Authenticator im Android AccountManager.

        Ablauf:
          1. pm clear (löscht App-Daten + registered Accounts + Caches)
          2. Externe Spuren: Sandbox, ART Profiles, Shortcuts, Graphics
          3. AAID Reset (neue Google Advertising ID)

        pm clear ist der Schlüssel: Es entfernt auch den TikTok-Account
        aus dem Android AccountManager (com.zhiliaoapp.account), der sonst
        "Willkommen zurück <username>" triggert.
        """
        results: dict[str, bool] = {}

        # 1. Force-Stop (verhindert sofortige Neuerstellung)
        try:
            await self._adb.shell(
                f"am force-stop {pkg}", root=True, timeout=5,
            )
            results["force_stop"] = True
        except (ADBError, ADBTimeoutError):
            results["force_stop"] = False

        # 2. pm clear — der wichtigste Schritt
        # Löscht: /data/data/<pkg>/*, /data/user_de/0/<pkg>/*,
        # Android Accounts (com.zhiliaoapp.account), Runtime Permissions
        try:
            clear_res = await self._adb.shell(
                f"pm clear {pkg}", root=True, timeout=15,
            )
            results["pm_clear"] = "success" in (clear_res.output or "").lower()
            if results["pm_clear"]:
                logger.info("[v6.6 NuclearClean] pm clear %s: OK", pkg)
            else:
                logger.warning(
                    "[v6.6 NuclearClean] pm clear %s: %s",
                    pkg, clear_res.output.strip()[:100],
                )
        except (ADBError, ADBTimeoutError) as e:
            logger.error("[v6.6 NuclearClean] pm clear fehlgeschlagen: %s", e)
            results["pm_clear"] = False

        # 3. Externe Spuren entfernen (pm clear räumt diese NICHT auf)
        external_targets = [
            # Sandbox / External Storage
            f"/sdcard/Android/data/{pkg}",
            f"/data/media/0/Android/data/{pkg}",
            # ART Compiler Profiles
            f"/data/misc/profiles/cur/0/{pkg}",
            f"/data/misc/profiles/ref/{pkg}",
            # Shortcut Service (Launcher-Verknüpfungen)
            f"/data/system_ce/0/shortcut_service/packages/{pkg}.xml",
            f"/data/system_ce/0/shortcut_service/packages/{pkg}.xml.reservecopy",
            # Graphics Stats
            f"/data/system/graphicsstats/*/{pkg}",
        ]

        for target in external_targets:
            try:
                res = await self._adb.shell(
                    f"rm -rf {target}", root=True, timeout=5,
                )
                results[target.split("/")[-1]] = True
            except (ADBError, ADBTimeoutError):
                results[target.split("/")[-1]] = False

        # 4. AAID Reset (Google Advertising ID)
        # TikTok verknüpft die AAID mit dem Profil — muss bei Identity-Wechsel
        # ebenfalls rotiert werden.
        try:
            await self._adb.shell(
                "rm -f /data/data/com.google.android.gms/shared_prefs/adid_settings.xml",
                root=True, timeout=5,
            )
            results["aaid_reset"] = True
            logger.info("[v6.6 NuclearClean] AAID resetted")
        except (ADBError, ADBTimeoutError):
            results["aaid_reset"] = False

        # 5. KRITISCH: Bridge-Datei re-injizieren!
        # pm clear löscht /data/data/<pkg>/files/.hw_config — ohne die Datei
        # starten alle Xposed-Hooks mit NULL-Werten (kein Identity Spoofing!).
        # Die Bridge wird aus dem Module-Pfad zurückkopiert.
        bridge_source = BRIDGE_FILE_PATH
        bridge_target = f"/data/data/{pkg}/files/.hw_config"
        try:
            check_bridge = await self._adb.shell(
                f"test -f {bridge_source} && echo OK || echo MISSING",
                root=True, timeout=5,
            )
            if "OK" in (check_bridge.output or ""):
                uid_res = await self._adb.shell(
                    f"stat -c '%u' /data/data/{pkg} 2>/dev/null",
                    root=True, timeout=5,
                )
                uid = uid_res.output.strip("'\" \n\r")
                if not uid.isdigit():
                    uid = "10299"  # Fallback TikTok UID
                await self._adb.shell(
                    f"mkdir -p /data/data/{pkg}/files && "
                    f"cp {bridge_source} {bridge_target} && "
                    f"chown {uid}:{uid} /data/data/{pkg}/files && "
                    f"chown {uid}:{uid} {bridge_target} && "
                    f"chmod 600 {bridge_target} && "
                    f"restorecon -F {bridge_target}",
                    root=True, timeout=10,
                )
                results["bridge_reinject"] = True
                logger.info(
                    "[v6.6 NuclearClean] Bridge re-injiziert: %s → %s",
                    bridge_source, bridge_target,
                )
            else:
                results["bridge_reinject"] = False
                logger.warning(
                    "[v6.6 NuclearClean] Bridge-Quelle fehlt: %s — Hooks werden "
                    "ohne Identity starten!", bridge_source,
                )
        except (ADBError, ADBTimeoutError) as e:
            results["bridge_reinject"] = False
            logger.error("[v6.6 NuclearClean] Bridge re-inject fehlgeschlagen: %s", e)

        # 6. Nochmal Force-Stop (TikTok startet sich gerne via Broadcast neu)
        try:
            await self._adb.shell(
                f"am force-stop {pkg}", root=True, timeout=5,
            )
        except (ADBError, ADBTimeoutError):
            pass

        deleted = sum(1 for v in results.values() if v)
        total = len(results)
        logger.info(
            "[v6.6 NuclearClean] %s: %d/%d Operationen OK "
            "(pm clear + externe Spuren + AAID + Bridge — Zustand: wie Erstinstallation)",
            pkg, deleted, total,
        )
        return results

    # =========================================================================
    # TikTok Shared-Prefs Sanitizing: Instance-IDs entfernen
    # =========================================================================

    async def _sanitize_shared_prefs(self, pkg: str = TIKTOK_PRIMARY) -> int:
        """
        Entfernt TikTok-spezifische Instance-IDs aus shared_prefs XML-Dateien.

        Schlüssel wie install_id, client_udid, device_id sind unabhängig
        von der Hardware-Identität. Wenn sie 1:1 restored werden, erkennt
        TikTok: 'Neue Hardware, aber gleiche Install-ID' → Multi-Account Detection.

        Returns:
            Anzahl der entfernten Einträge
        """
        prefs_dir = f"/data/data/{pkg}/shared_prefs"
        dangerous_keys = [
            "install_id",
            "client_udid",
            "device_id",
            "tt_device_id",
            "iid",
            "install_id_",
            "google_aid",
            "device_register",
        ]
        pattern = "|".join(dangerous_keys)

        total_removed = 0
        try:
            # Alle XML-Dateien in shared_prefs auflisten
            ls_result = await self._adb.shell(
                f"find {prefs_dir} -name '*.xml' -type f 2>/dev/null",
                root=True, timeout=10,
            )
            if not ls_result.success or not ls_result.output.strip():
                logger.debug("[TikTok-Sanitize] Keine shared_prefs XMLs gefunden")
                return 0

            xml_files = [f.strip() for f in ls_result.output.strip().split("\n") if f.strip()]

            for xml_file in xml_files:
                # Prüfe ob die Datei gefährliche Keys enthält
                grep_result = await self._adb.shell(
                    f"grep -cE '{pattern}' '{xml_file}' 2>/dev/null",
                    root=True, timeout=5,
                )
                if not grep_result.success:
                    continue
                count = grep_result.output.strip()
                if not count.isdigit() or int(count) == 0:
                    continue

                # Entferne Zeilen mit gefährlichen Keys (sed in-place)
                for key in dangerous_keys:
                    try:
                        await self._adb.shell(
                            f"sed -i '/{key}/d' '{xml_file}'",
                            root=True, timeout=5,
                        )
                    except Exception:
                        pass

                total_removed += int(count)
                logger.debug(
                    "[TikTok-Sanitize] %s: %s Einträge entfernt",
                    xml_file.split("/")[-1], count,
                )

        except Exception as e:
            logger.warning("[TikTok-Sanitize] Fehler: %s", e)

        if total_removed > 0:
            logger.info(
                "[TikTok-Sanitize] %d Instance-ID Einträge aus shared_prefs entfernt",
                total_removed,
            )
        return total_removed

    # =========================================================================
    # TikTok install_id Extraktion (Anti-Duplicate Detection)
    # =========================================================================

    async def extract_tiktok_install_id(
        self, pkg: str = TIKTOK_PRIMARY,
    ) -> str | None:
        """
        Extrahiert die install_id aus TikToks shared_prefs.

        TikTok generiert beim ersten Start eine install_id (UUID-Format),
        die als primärer Identifikator für das Geräte-Profil dient.
        Wenn zwei verschiedene Identitäten dieselbe install_id haben,
        erkennt TikTok Multi-Accounting → Ban.

        Suchstrategie:
          1. grep in allen shared_prefs XMLs nach 'install_id'
          2. Parse den Wert aus dem XML-Tag

        Returns:
            install_id als String oder None wenn nicht gefunden
        """
        prefs_dir = f"/data/data/{pkg}/shared_prefs"
        try:
            result = await self._adb.shell(
                f"grep -rh 'install_id' {prefs_dir}/ 2>/dev/null"
                " | grep -oE '[0-9a-f]{{8}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{12}}'",
                root=True, timeout=10,
            )
            if result.success and result.output.strip():
                install_id = result.output.strip().splitlines()[0].strip()
                if len(install_id) == 36:
                    logger.info(
                        "[InstallID] Extrahiert: %s…%s (%s)",
                        install_id[:8], install_id[-4:], pkg,
                    )
                    return install_id

            # Fallback: MMKV binary grep (install_id ist als Klartext gespeichert)
            result2 = await self._adb.shell(
                f"strings /data/data/{pkg}/files/mmkv/* 2>/dev/null"
                " | grep -oE '[0-9a-f]{{8}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{12}}'"
                " | head -1",
                root=True, timeout=10,
            )
            if result2.success and result2.output.strip():
                install_id = result2.output.strip().splitlines()[0].strip()
                if len(install_id) == 36:
                    logger.info(
                        "[InstallID] Extrahiert aus MMKV: %s…%s (%s)",
                        install_id[:8], install_id[-4:], pkg,
                    )
                    return install_id

        except Exception as e:
            logger.warning("[InstallID] Extraktion fehlgeschlagen: %s", e)

        logger.debug("[InstallID] Keine install_id gefunden für %s", pkg)
        return None

    async def launch_and_extract_install_id(
        self, pkg: str = TIKTOK_PRIMARY, wait_seconds: int = 15,
    ) -> str | None:
        """
        Startet TikTok kurz, wartet auf ID-Generierung und extrahiert die install_id.

        Ablauf:
          1. am start (Launch Activity)
          2. Warte wait_seconds (TikTok generiert install_id beim ersten Start)
          3. am force-stop (kill)
          4. Extrahiere install_id aus shared_prefs/MMKV

        Returns:
            install_id oder None
        """
        logger.info("[SilentLaunch] Starte %s für ID-Generierung (%ds)...", pkg, wait_seconds)
        try:
            await self._adb.shell(
                f"am start -n {pkg}/com.ss.android.ugc.aweme.splash.SplashActivity"
                " -c android.intent.category.LAUNCHER"
                " -a android.intent.action.MAIN",
                root=True, timeout=10,
            )
        except Exception as e:
            logger.warning("[SilentLaunch] App-Start fehlgeschlagen: %s", e)
            return None

        await asyncio.sleep(wait_seconds)

        # Kill
        try:
            await self._adb.shell(f"am force-stop {pkg}", root=True, timeout=5)
        except Exception:
            pass

        await asyncio.sleep(2)

        return await self.extract_tiktok_install_id(pkg)

    # =========================================================================
    # Google Account Verifikation nach Restore
    # =========================================================================

    async def verify_google_account(self) -> dict:
        """
        Prüft via dumpsys account ob ein Google-Account vorhanden ist.

        Returns:
            {"has_account": bool, "account_name": str, "detail": str}
        """
        try:
            result = await self._adb.shell(
                "dumpsys account 2>/dev/null | grep -A2 'Account {name='",
                root=True, timeout=10,
            )
            if result.success and "name=" in result.output:
                lines = result.output.strip().split("\n")
                for line in lines:
                    if "name=" in line and "type=com.google" in line:
                        name_part = line.split("name=")[1].split(",")[0].strip()
                        logger.info("[Account-Check] Google-Account gefunden: %s", name_part)
                        return {
                            "has_account": True,
                            "account_name": name_part,
                            "detail": f"Google-Account: {name_part}",
                        }

            # Fallback: Einfacherer grep
            result2 = await self._adb.shell(
                "dumpsys account 2>/dev/null | grep 'type=com.google'",
                root=True, timeout=10,
            )
            if result2.success and "com.google" in result2.output:
                logger.info("[Account-Check] Google-Account vorhanden (Name nicht extrahierbar)")
                return {
                    "has_account": True,
                    "account_name": "unknown",
                    "detail": "Google-Account vorhanden",
                }

            logger.warning("[Account-Check] Kein Google-Account gefunden!")
            return {
                "has_account": False,
                "account_name": "",
                "detail": "Kein Google-Account — Login nötig!",
            }
        except Exception as e:
            logger.warning("[Account-Check] Fehler: %s", e)
            return {
                "has_account": False,
                "account_name": "",
                "detail": f"Check fehlgeschlagen: {e}",
            }
