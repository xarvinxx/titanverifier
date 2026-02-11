"""
Project Titan — TitanInjector v3.2
====================================

Verantwortlich für das Schreiben der Hardware-Identität auf das Gerät
UND die Software-Integrität (PIF) für Play Integrity.

Ablauf (2080-konform):
  1. IdentityBridge → Key=Value String → /data/adb/modules/.../titan_identity
  2. PIF Fingerprint → JSON → /data/adb/pif.json (MEETS_BASIC_INTEGRITY)
  3. Namespace-Nuke → su -M -c → GMS Auth-Token vernichten (SELinux-Bypass)
  4. GServices SQL-Cleanup → sqlite3 DELETE statt rm (verhindert Boot-Freeze)
  5. Permissions-Fix → chown auf GSF-Ordner
  6. Backup + Distribution

Schützt gegen Säule 1-5 (Property, IMEI, Network, DRM, ID-Correlation)
+ Säule 6 (Software-Integrität via PIF).
Quelle: TITAN_CONTEXT.md §3B, §3C
"""

from __future__ import annotations

import json
import logging
import random
import tempfile
from pathlib import Path
from typing import Optional

from host.adb.client import ADBClient, ADBError, ADBTimeoutError
from datetime import date

from host.config import (
    BRIDGE_APP_TEMPLATE,
    BRIDGE_FILE_PATH,
    BRIDGE_MODULE_PATH,
    BRIDGE_SDCARD_PATH,
    BRIDGE_TARGET_APPS,
    DEVICE_CODENAME,
    GMS_AUTH_DB,
    GMS_BACKUP_PACKAGES,
    GMS_DG_CACHE,
    GSF_GSERVICES_DB,
    KILL_SWITCH_PATH,
    PIF_JSON_PATH,
    PIF_SPOOF_POOL,
    SELINUX_CONTEXT,
    validate_pif_pool_integrity,
)
from host.models.identity import IdentityBridge

logger = logging.getLogger("titan.engine.injector")


class TitanInjector:
    """
    Schreibt eine Hardware-Identität auf das Pixel 6.

    Alle Operationen sind asynchron und nutzen den ADBClient.

    Usage:
        adb = ADBClient()
        injector = TitanInjector(adb)

        bridge = IdentityBridge(serial="ABC...", imei1="355543...", ...)
        await injector.inject(bridge, label="DE_Berlin_001")
    """

    # Temporärer Remote-Pfad für Push-Operationen
    _REMOTE_TMP = "/data/local/tmp/.titan_bridge_staging"

    def __init__(self, adb: ADBClient):
        self._adb = adb

    # =========================================================================
    # Hauptmethode: inject
    # =========================================================================

    async def inject(
        self,
        bridge: IdentityBridge,
        label: str = "",
        distribute: bool = True,
    ) -> None:
        """
        Schreibt eine Identität vollständig auf das Gerät.

        Schritte:
          1. Bridge-String generieren (Key=Value)
          2. Lokale temp-Datei schreiben
          3. Push nach /data/local/tmp/
          4. Root: Kopie nach BRIDGE_FILE_PATH
          5. Root: chmod 644 + chcon system_file:s0
          6. Root: Backup nach /sdcard/
          7. Optional: In App-Datenordner verteilen

        Args:
            bridge:     IdentityBridge Pydantic-Objekt
            label:      Label für den Bridge-File Header
            distribute: True = Bridge in alle Ziel-Apps kopieren

        Raises:
            ADBError: bei Kommunikationsfehler mit dem Gerät
        """
        logger.info(
            "Injecting identity: serial=%s imei1=%s…%s",
            bridge.serial, bridge.imei1[:6], bridge.imei1[-4:],
        )

        # 1. Bridge-Content generieren
        bridge_content = bridge.to_bridge_string(label=label)

        # 2. Lokale temp-Datei schreiben
        tmp_file = None
        try:
            tmp_file = tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".titan_bridge",
                delete=False,
                prefix="titan_",
            )
            tmp_file.write(bridge_content)
            tmp_file.flush()
            tmp_file.close()

            local_path = tmp_file.name

            # 3. Push nach /data/local/tmp/ (kein Root nötig für Push)
            await self._adb.push(local_path, self._REMOTE_TMP)

            # 4. Root: Erstelle Zielverzeichnis + Kopiere
            await self._adb.shell(
                f"mkdir -p {BRIDGE_MODULE_PATH}", root=True, check=True,
            )
            await self._adb.shell(
                f"cp {self._REMOTE_TMP} {BRIDGE_FILE_PATH}", root=True, check=True,
            )
            logger.info("Bridge geschrieben: %s", BRIDGE_FILE_PATH)

            # 5. Root: Permissions + SELinux Context
            await self._set_permissions(BRIDGE_FILE_PATH)

            # 6. Root: Backup nach /sdcard/ (World-readable für LSPosed)
            await self._adb.shell(
                f"cp {self._REMOTE_TMP} {BRIDGE_SDCARD_PATH}", root=True,
            )
            await self._adb.shell(
                f"chmod 644 {BRIDGE_SDCARD_PATH}", root=True,
            )
            logger.info("Backup: %s", BRIDGE_SDCARD_PATH)

            # 7. Optional: In App-Datenordner verteilen
            if distribute:
                await self._distribute_to_apps()

            # 8. Cleanup: Staging-Datei auf dem Gerät löschen
            await self._adb.shell(
                f"rm -f {self._REMOTE_TMP}", root=True,
            )

            logger.info("Injection komplett: %s", bridge.serial)

        finally:
            # Lokale temp-Datei aufräumen
            if tmp_file is not None:
                try:
                    Path(tmp_file.name).unlink(missing_ok=True)
                except OSError:
                    pass

    # =========================================================================
    # Permissions setzen
    # =========================================================================

    async def _set_permissions(self, remote_path: str) -> None:
        """
        Setzt die korrekten Permissions auf eine Bridge-Datei.

        KRITISCH für Zygisk-Zugriff:
          - chmod 644: Lesbar für alle Prozesse
          - chcon u:object_r:system_file:s0: SELinux Context für Zygote
        """
        await self._adb.shell(f"chmod 644 {remote_path}", root=True)
        await self._adb.shell(
            f"chcon {SELINUX_CONTEXT} {remote_path}", root=True,
        )
        logger.debug("Permissions gesetzt: %s (644, %s)", remote_path, SELINUX_CONTEXT)

    # =========================================================================
    # Bridge Distribution (in alle Ziel-App-Ordner)
    # =========================================================================

    async def _distribute_to_apps(self) -> None:
        """
        Kopiert die Bridge-Datei in die Datenordner aller Ziel-Apps.

        Für jede App:
          1. UID ermitteln (stat -c '%u')
          2. Bridge kopieren
          3. chown UID:UID (Magic Permissions)
          4. chmod 600 (nur App kann lesen)
        """
        distributed = 0
        for package in BRIDGE_TARGET_APPS:
            try:
                target_path = BRIDGE_APP_TEMPLATE.format(package=package)
                target_dir = target_path.rsplit("/", 1)[0]

                # Prüfe ob App installiert ist
                check = await self._adb.shell(
                    f"test -d /data/data/{package}", root=True,
                )
                if not check.success:
                    continue  # App nicht installiert

                # UID der App ermitteln
                uid_result = await self._adb.shell(
                    f"stat -c '%u' /data/data/{package}", root=True,
                )
                uid = uid_result.output.strip("'")
                if not uid.isdigit():
                    logger.warning("UID nicht ermittelbar für %s: %s", package, uid)
                    continue

                # Verzeichnis erstellen + Bridge kopieren
                await self._adb.shell(
                    f"mkdir -p {target_dir} && "
                    f"cp {BRIDGE_FILE_PATH} {target_path} && "
                    f"chown {uid}:{uid} {target_path} && "
                    f"chown {uid}:{uid} {target_dir} && "
                    f"chmod 600 {target_path}",
                    root=True,
                )
                distributed += 1

            except ADBError as e:
                logger.warning("Bridge-Distribution für %s fehlgeschlagen: %s", package, e)

        logger.info("Bridge verteilt an %d/%d Apps", distributed, len(BRIDGE_TARGET_APPS))

    # =========================================================================
    # *** NEU v3.0 *** GSF-ID Sync: Bridge-Datei auf dem Gerät patchen
    # =========================================================================

    async def update_bridge_gsf_id(self, real_gsf_id: str) -> None:
        """
        Aktualisiert die gsf_id in der Bridge-Datei auf dem Gerät.

        v3.0 "Golden Baseline" — GSF-ID Sync:
          Nach dem GMS-Checkin hat Google eine echte GSF-ID zugewiesen.
          Diese MUSS in die Bridge-Datei geschrieben werden, damit das
          Zygisk-Modul beim nächsten Start exakt diese ID spoofed.
          Hardware (GMS-DB) und Software (Bridge-File) müssen identisch sein.

        Methode: sed in-place Replacement auf dem Gerät.

        Args:
            real_gsf_id: Die echte GSF-ID vom GMS-Checkin (17 Dezimalziffern)

        Raises:
            ADBError: bei Schreibfehler
        """
        logger.info(
            "GSF-ID Sync: Bridge aktualisieren → %s...%s",
            real_gsf_id[:4], real_gsf_id[-4:],
        )

        # 1. Patch im primären Bridge-File
        sed_cmd = f"sed -i 's/^gsf_id=.*/gsf_id={real_gsf_id}/' {BRIDGE_FILE_PATH}"
        await self._adb.shell(sed_cmd, root=True, check=True)

        # 2. Patch auch im sdcard Backup
        sed_cmd_sd = f"sed -i 's/^gsf_id=.*/gsf_id={real_gsf_id}/' {BRIDGE_SDCARD_PATH}"
        try:
            await self._adb.shell(sed_cmd_sd, root=True)
        except ADBError:
            pass  # sdcard Backup ist nicht kritisch

        # 3. Patch in allen App-Datenordnern
        for package in BRIDGE_TARGET_APPS:
            target_path = BRIDGE_APP_TEMPLATE.format(package=package)
            try:
                check = await self._adb.shell(
                    f"test -f {target_path}", root=True,
                )
                if check.success:
                    await self._adb.shell(
                        f"sed -i 's/^gsf_id=.*/gsf_id={real_gsf_id}/' {target_path}",
                        root=True,
                    )
            except ADBError:
                pass

        logger.info("GSF-ID Sync: Bridge-Datei(en) aktualisiert")

    # =========================================================================
    # *** NEU v3.2 *** PIF Fingerprint Injection (MEETS_BASIC_INTEGRITY)
    # =========================================================================

    async def inject_pif_fingerprint(
        self,
        build_index: int | None = None,
    ) -> bool:
        """
        Generiert und pusht eine pif.json nach /data/adb/pif.json.

        KRITISCH für Play Integrity auf Android 14:
          TrickyStore liefert MEETS_DEVICE_INTEGRITY (Hardware-Ebene),
          aber MEETS_BASIC_INTEGRITY erfordert einen gültigen
          Software-Fingerprint. Ohne pif.json = BASIC_INTEGRITY FAIL.

        v3.2 SAFETY CONSTRAINT:
          Die pif.json darf NIEMALS echte Pixel 6 (oriole) Daten enthalten!
          Stattdessen wird ein ÄLTERES Pixel-Modell simuliert (Pixel 5, 5a, 4a 5G).
          Der PIF_SPOOF_POOL enthält nur verifizierte ältere Builds.

          Grund: Wenn Hardware-Attestation (Tensor G1 / oriole) und
          Software-Fingerprint dasselbe Gerät beschreiben, kann Google
          die Diskrepanz erkennen → FAIL. Mit einem älteren Modell ist
          die Software-Ebene plausibel entkoppelt vom TEE-Zertifikat.

        Schützt gegen: Säule 6 (Software-Integrität)

        Args:
            build_index: Optional — Index in PIF_SPOOF_POOL (für Konsistenz
                         mit dem gewählten Build in der Identity)

        Returns:
            True wenn erfolgreich gepusht
        """
        # =====================================================================
        # v3.2 TIME-TRAVEL PREVENTION — Dreistufige Pool-Validierung
        # =====================================================================
        #
        # Stufe 1: Statische Integrität (Pflichtfelder, Datums-Format,
        #          Zukunfts-Check, Alters-Warnung)
        # Stufe 2: Dynamischer Host-Patch-Filter (ADB getprop)
        #          → Pool-Einträge mit SECURITY_PATCH > Host-Patch = FAIL
        # Stufe 3: Oriole Safety Guard (kein echtes Gerät im Spoof)
        # =====================================================================

        # --- Stufe 1: Statische Pool-Validierung ---
        valid_pool = validate_pif_pool_integrity()

        if not valid_pool:
            logger.error(
                "PIF SAFETY CRITICAL: PIF_SPOOF_POOL ist leer oder alle "
                "Einträge ungültig — Abbruch. "
                "Prüfe host/config.py PIF_SPOOF_POOL auf korrekte Daten."
            )
            return False

        logger.debug(
            "PIF Stufe 1 (Statisch): %d/%d Einträge valide",
            len(valid_pool), len(PIF_SPOOF_POOL),
        )

        # --- Stufe 2: Dynamischer Host-Patch-Filter ---
        # Lies den echten Security-Patch-Level des Geräts.
        # Ein PIF mit SECURITY_PATCH > Host-Patch ist ein logischer Bruch:
        #   "Wie kann ein Gerät mit Kernel von 2024-10 einen Build
        #    von 2025-03 laufen haben?" → Instant Play Integrity FAIL.
        host_patch_str: str | None = None
        host_patch_date: date | None = None

        try:
            patch_result = await self._adb.shell(
                "getprop ro.build.version.security_patch", timeout=10,
            )
            if patch_result.success:
                raw = patch_result.output.strip()
                if raw:
                    host_patch_date = date.fromisoformat(raw)
                    host_patch_str = raw
                    logger.info(
                        "PIF Host-Patch gelesen: %s", host_patch_str,
                    )
        except (ValueError, ADBError, ADBTimeoutError) as e:
            logger.warning(
                "PIF Host-Patch konnte nicht gelesen werden: %s — "
                "Time-Travel-Filter wird übersprungen (Fallback: "
                "nur statische Validierung).",
                e,
            )

        if host_patch_date is not None:
            # Nur Einträge behalten, deren Patch <= Host-Patch.
            # "Downgrade" (alter Fingerprint auf neuem Kernel) ist plausibel,
            # "Upgrade" (neuer Fingerprint auf altem Kernel) ist unmöglich.
            time_safe_pool = [
                p for p in valid_pool
                if date.fromisoformat(p["SECURITY_PATCH"].strip())
                <= host_patch_date
            ]

            if not time_safe_pool:
                # Alle Pool-Einträge sind neuer als der Host-Patch.
                # Das sollte nicht passieren, aber wir brechen nicht ab —
                # wir warnen und fallen auf den statisch validierten Pool zurück.
                logger.warning(
                    "PIF TIME-TRAVEL WARNING: Alle %d validen Pool-Einträge "
                    "haben SECURITY_PATCH > Host-Patch %s! "
                    "Fallback auf statischen Pool.",
                    len(valid_pool), host_patch_str,
                )
            else:
                dropped = len(valid_pool) - len(time_safe_pool)
                if dropped > 0:
                    logger.info(
                        "PIF Stufe 2 (Time-Travel): %d Einträge gefiltert "
                        "(Patch > Host %s), %d verbleiben",
                        dropped, host_patch_str, len(time_safe_pool),
                    )
                valid_pool = time_safe_pool
        else:
            logger.debug(
                "PIF Stufe 2 (Time-Travel): Übersprungen (kein Host-Patch)"
            )

        # --- Stufe 3: Oriole Safety Guard ---
        # Filtere das echte Gerät (oriole) aus dem Pool.
        safe_pool = [
            p for p in valid_pool
            if p.get("DEVICE", "").lower() != DEVICE_CODENAME
        ]

        if not safe_pool:
            logger.error(
                "PIF SAFETY CRITICAL: Nach allen Filtern (Time-Travel + "
                "Oriole-Guard) sind 0 Einträge übrig! Abbruch."
            )
            return False

        if len(safe_pool) < len(valid_pool):
            logger.warning(
                "PIF Stufe 3 (Oriole Guard): %d Einträge mit echtem Gerät "
                "'%s' entfernt",
                len(valid_pool) - len(safe_pool), DEVICE_CODENAME,
            )

        valid_pool = safe_pool

        # --- Build-Auswahl ---
        if build_index is not None and 0 <= build_index < len(valid_pool):
            pif_data = valid_pool[build_index]
        else:
            pif_data = random.choice(valid_pool)

        logger.info(
            "PIF Injection v3.2: %s %s (Patch: %s) — Spoof-Gerät: %s",
            pif_data.get("MODEL", "?"),
            pif_data["BUILD_ID"],
            pif_data["SECURITY_PATCH"],
            pif_data.get("DEVICE", "?"),
        )

        # JSON generieren
        pif_json = json.dumps(pif_data, indent=2, ensure_ascii=False)

        # Lokale temp-Datei schreiben + Push
        tmp_file = None
        try:
            tmp_file = tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".json",
                delete=False,
                prefix="titan_pif_",
            )
            tmp_file.write(pif_json)
            tmp_file.flush()
            tmp_file.close()

            local_path = tmp_file.name
            staging_path = "/data/local/tmp/.titan_pif_staging.json"

            # Push nach /data/local/tmp/ (kein Root nötig)
            await self._adb.push(local_path, staging_path)

            # Root: Kopiere nach /data/adb/pif.json
            await self._adb.shell(
                f"cp {staging_path} {PIF_JSON_PATH}",
                root=True, check=True,
            )

            # Permissions: 644, SELinux system_file
            await self._adb.shell(
                f"chmod 644 {PIF_JSON_PATH}", root=True,
            )
            await self._adb.shell(
                f"chcon {SELINUX_CONTEXT} {PIF_JSON_PATH}", root=True,
            )

            # Staging aufräumen
            await self._adb.shell(
                f"rm -f {staging_path}", root=True,
            )

            logger.info(
                "PIF Injection OK: %s → %s",
                pif_data["FINGERPRINT"][:40] + "...", PIF_JSON_PATH,
            )
            return True

        except (ADBError, ADBTimeoutError) as e:
            logger.error("PIF Injection fehlgeschlagen: %s", e)
            return False

        finally:
            if tmp_file is not None:
                try:
                    Path(tmp_file.name).unlink(missing_ok=True)
                except OSError:
                    pass

    # =========================================================================
    # *** NEU v3.2 *** sqlite3 Dependency-Check
    # =========================================================================

    # Statisches sqlite3-Binary (arm64), wird nach /data/local/tmp/ gepusht
    # falls das Stock-ROM keines mitliefert.
    _SQLITE3_REMOTE_PATH = "/data/local/tmp/sqlite3"
    _SQLITE3_LOCAL_FALLBACK = Path(__file__).resolve().parent.parent.parent / "libs" / "sqlite3"

    async def ensure_sqlite_binary(self) -> bool:
        """
        Prüft, ob ``sqlite3`` auf dem Gerät verfügbar ist.

        Das Pixel 6 Stock-ROM (Android 14) liefert standardmäßig KEIN
        ``sqlite3``-Binary im PATH. Ohne dieses Binary scheitert der
        "Safe Cleanup" in ``namespace_nuke()`` (Phase 3: GServices DB)
        und das System fällt auf das riskantere ``rm`` zurück, was zu
        Boot-Hängern am Google-Logo führen kann.

        Ablauf:
          1. ``which sqlite3`` — ist es bereits im System-PATH?
          2. Prüfe ``/data/local/tmp/sqlite3`` — wurde es schon gepusht?
          3. Falls ``libs/sqlite3`` lokal existiert → Push + chmod 755
          4. Falls nichts hilft → Warning (Flow läuft weiter mit Fallback)

        Returns:
            True  wenn sqlite3 auf dem Gerät verfügbar ist
            False wenn nicht — der Caller sollte mit ``rm``-Fallback rechnen
        """
        # --- Check 1: System-PATH ---
        try:
            which_result = await self._adb.shell(
                "which sqlite3 2>/dev/null", timeout=5,
            )
            if which_result.success and which_result.output.strip():
                path = which_result.output.strip()
                logger.debug("sqlite3 im System-PATH gefunden: %s", path)
                return True
        except (ADBError, ADBTimeoutError):
            pass

        # --- Check 2: Bereits gepushtes Binary ---
        try:
            test_result = await self._adb.shell(
                f"test -x {self._SQLITE3_REMOTE_PATH} && "
                f"{self._SQLITE3_REMOTE_PATH} --version 2>/dev/null",
                timeout=5,
            )
            if test_result.success and test_result.output.strip():
                logger.info(
                    "sqlite3 bereits auf Gerät: %s (Version: %s)",
                    self._SQLITE3_REMOTE_PATH,
                    test_result.output.strip().split()[0],
                )
                return True
        except (ADBError, ADBTimeoutError):
            pass

        # --- Check 3: Lokales Binary pushen ---
        if self._SQLITE3_LOCAL_FALLBACK.is_file():
            logger.info(
                "sqlite3 nicht auf Gerät — pushe lokales Binary: %s",
                self._SQLITE3_LOCAL_FALLBACK,
            )
            try:
                await self._adb.push(
                    str(self._SQLITE3_LOCAL_FALLBACK),
                    self._SQLITE3_REMOTE_PATH,
                )
                await self._adb.shell(
                    f"chmod 755 {self._SQLITE3_REMOTE_PATH}",
                    root=True, timeout=5,
                )
                # Verifiziere, dass es funktioniert
                verify = await self._adb.shell(
                    f"{self._SQLITE3_REMOTE_PATH} --version 2>/dev/null",
                    timeout=5,
                )
                if verify.success and verify.output.strip():
                    logger.info(
                        "sqlite3 erfolgreich gepusht und verifiziert: %s",
                        verify.output.strip().split()[0],
                    )
                    return True
                else:
                    logger.warning(
                        "sqlite3 wurde gepusht, aber Verifikation fehlgeschlagen "
                        "(exit=%d). Binary möglicherweise inkompatibel (ABI-Mismatch?).",
                        verify.returncode,
                    )
                    return False
            except (ADBError, ADBTimeoutError) as e:
                logger.warning(
                    "sqlite3 Push fehlgeschlagen: %s — "
                    "namespace_nuke wird auf rm-Fallback zurückfallen.",
                    e,
                )
                return False
        else:
            logger.warning(
                "sqlite3 NICHT auf dem Gerät verfügbar und kein lokales "
                "Binary unter '%s' gefunden! "
                "namespace_nuke Phase 3 (GServices Safe Cleanup) wird auf "
                "das riskantere 'rm' zurückfallen. "
                "→ Empfehlung: Statisches sqlite3 arm64-Binary in libs/ ablegen.",
                self._SQLITE3_LOCAL_FALLBACK,
            )
            return False

    # =========================================================================
    # *** NEU v3.2 *** KernelSU Namespace-Nuke (GMS Auth-Token vernichten)
    # =========================================================================

    async def namespace_nuke(self) -> dict[str, bool]:
        """
        Bricht GMS-Blockaden via KernelSU Mount-Master Namespace.

        Problem:
          Nach einem Identity-Switch oder fehlgeschlagenem Login bleiben
          alte Auth-Token, DroidGuard-Caches und GServices-Einträge in
          den GMS-Datenbanken. Diese verursachen:
            - "Ewiges Laden" beim Google-Login
            - GMS-Lockdown (Zertifikats-Mismatch)
            - BASIC_INTEGRITY Fail trotz korrektem Fingerprint

        Lösung (v3.2):
          `su -M -c` nutzt den Mount-Master-Namespace von KernelSU,
          der SELinux-Sperren auf /data/data/com.google.android.gms
          umgeht. Normale `su -c` (root=True) scheitern oft an SELinux
          Domain-Transitions, weil der Kontext (u:r:su:s0) keinen
          Zugriff auf app_data_file hat. Mount-Master (-M) operiert
          im globalen Namespace — alle Mounts sichtbar, kein Domain-Wechsel.

          WICHTIG: Die Nuke-Befehle werden OHNE root=True gesendet,
          weil wir `su -M -c` manuell in den Command einbauen.
          root=True würde nochmal `su -c` darum wrappen → doppeltes su → Fehler.

        Ablauf:
          1. force-stop GMS + GSF (sauberer Zustand)
          2. rm auth.db* (veraltete Auth-Token) — via su -M -c
          3. rm app_dg_cache/* (DroidGuard-Module → erzwingt Neudownload) — via su -M -c
          4. sqlite3 gservices.db "DELETE FROM main;" (DB-Struktur erhalten!) — via su -M -c
          5. chown auf GSF-Ordner (verhindert "stuck" Services) — via su -M -c

        Schützt gegen: Säule 6 (Play Integrity), Login-Stabilität

        Returns:
            Dict mit Ergebnis pro Schritt
        """
        logger.info("=" * 50)
        logger.info("  NAMESPACE NUKE v3.2 (su -M -c): GMS Auth-Reset")
        logger.info("=" * 50)

        results: dict[str, bool] = {}

        # Pre-Flight: sqlite3 Dependency-Check
        # Phase 3 braucht sqlite3 für den Safe-Cleanup der GServices-DB.
        # Falls nicht vorhanden, wird der rm-Fallback verwendet.
        sqlite3_available = await self.ensure_sqlite_binary()
        results["sqlite3_available"] = sqlite3_available
        if not sqlite3_available:
            logger.warning(
                "sqlite3 nicht verfügbar — Phase 3 wird auf rm-Fallback "
                "zurückfallen (Boot-Hänger-Risiko erhöht)."
            )

        # Phase 1: Force-Stop GMS + GSF (normales su -c reicht hier)
        for pkg in ["com.google.android.gms", "com.google.android.gsf"]:
            try:
                await self._adb.shell(
                    f"am force-stop {pkg}", root=True, timeout=5,
                )
            except (ADBError, ADBTimeoutError):
                pass

        # Phase 2: Auth-DB + DroidGuard-Cache vernichten
        # KRITISCH: su -M -c (Mount-Master) statt su -c (root=True)!
        # root=True wird hier NICHT verwendet, weil wir su -M -c
        # manuell in den Command einbauen. Doppeltes su → Fehler.
        nuke_cmds = [
            (
                "auth_db_nuke",
                f"rm -rf {GMS_AUTH_DB}*",
                "Auth-Token DB gelöscht",
            ),
            (
                "dg_cache_nuke",
                f"rm -rf {GMS_DG_CACHE}/*",
                "DroidGuard-Cache gelöscht",
            ),
        ]

        for key, cmd, desc in nuke_cmds:
            try:
                # su -M -c = Mount-Master Namespace (KernelSU spezifisch)
                # -M: Globaler Mount-Namespace → voller Zugriff auf /data/data/*
                # Ohne -M: SELinux blockiert Zugriff auf app_data_file Domains
                escaped = cmd.replace("\\", "\\\\").replace('"', '\\"')
                result = await self._adb.shell(
                    f'su -M -c "{escaped}"', root=False, timeout=10,
                )
                results[key] = result.success
                if result.success:
                    logger.info("  [OK] %s (su -M -c)", desc)
                else:
                    # Fallback: Normales su -c (falls KernelSU -M nicht unterstützt)
                    logger.warning(
                        "  [WARN] %s via su -M -c exit=%d — Fallback: su -c",
                        desc, result.returncode,
                    )
                    result = await self._adb.shell(cmd, root=True, timeout=10)
                    results[key] = result.success
                    if result.success:
                        logger.info("  [OK] %s (Fallback su -c)", desc)
            except (ADBError, ADBTimeoutError) as e:
                results[key] = False
                logger.warning("  [FAIL] %s: %s", desc, e)

        # Phase 3: GServices DB — SQL statt rm!
        # rm auf gservices.db führt zum Boot-Hänger am Google-Logo.
        # DELETE FROM main leert die Tabelle, behält aber die DB-Struktur.
        # Auch hier su -M -c für SELinux-Bypass auf GSF-Datenordner.
        #
        # v3.2: sqlite3 Binary-Resolution — Nutze den gepushten Pfad als
        # Fallback, falls sqlite3 nicht im System-PATH ist.
        sqlite3_bin = "sqlite3"
        if not sqlite3_available:
            # Trotzdem versuchen — vielleicht wurde es manuell installiert
            logger.debug("sqlite3 nicht im PATH, versuche gepushten Pfad...")
            sqlite3_bin = self._SQLITE3_REMOTE_PATH

        try:
            sql_cmd = f'{sqlite3_bin} {GSF_GSERVICES_DB} "DELETE FROM main;"'
            result = await self._adb.shell(
                f"su -M -c '{sql_cmd}'", root=False, timeout=10,
            )
            results["gservices_sql_clean"] = result.success
            if result.success:
                logger.info("  [OK] GServices DB: main-Tabelle geleert (SQL, su -M -c)")
            else:
                # Fallback 1: Normales su -c + sqlite3 (gepushter Pfad)
                logger.warning(
                    "  [WARN] GServices SQL (su -M -c) exit=%d — Fallback: su -c",
                    result.returncode,
                )
                result = await self._adb.shell(
                    f'{sqlite3_bin} {GSF_GSERVICES_DB} "DELETE FROM main;"',
                    root=True, timeout=10,
                )
                results["gservices_sql_clean"] = result.success
                if not result.success:
                    # Fallback 2: rm (LETZTER Ausweg — kann Boot-Hänger verursachen!)
                    logger.error(
                        "  [CRITICAL] GServices SQL mit %s fehlgeschlagen — "
                        "Fallback: rm (Boot-Hänger möglich!)",
                        sqlite3_bin,
                    )
                    result = await self._adb.shell(
                        f"rm -rf {GSF_GSERVICES_DB}*", root=True, timeout=10,
                    )
                    results["gservices_sql_clean"] = result.success
        except (ADBError, ADBTimeoutError) as e:
            results["gservices_sql_clean"] = False
            logger.warning("  [FAIL] GServices DB: %s", e)

        # Phase 4: Permissions-Fix auf GSF-Ordner (su -M -c)
        # Nach dem Nuke müssen die Ordner-Permissions stimmen,
        # damit GMS-Services nicht "stuck" sind.
        gsf_packages = [
            ("com.google.android.gms", "gms"),
            ("com.google.android.gsf", "gsf"),
        ]
        for pkg, short in gsf_packages:
            try:
                data_path = f"/data/data/{pkg}"
                # UID ermitteln (su -M -c für konsistenten Namespace)
                uid_result = await self._adb.shell(
                    f"su -M -c \"stat -c '%u' {data_path} 2>/dev/null\"",
                    root=False, timeout=5,
                )
                uid = uid_result.output.strip("'").strip()

                if uid.isdigit() and int(uid) >= 1000:
                    await self._adb.shell(
                        f'su -M -c "chown -R {uid}:{uid} {data_path}"',
                        root=False, timeout=15,
                    )
                    await self._adb.shell(
                        f'su -M -c "chmod 700 {data_path}"',
                        root=False, timeout=5,
                    )
                    results[f"chown_{short}"] = True
                    logger.info("  [OK] chown %s → UID %s (su -M -c)", short, uid)
                else:
                    # Fallback: Normales root=True
                    uid_result = await self._adb.shell(
                        f"stat -c '%u' {data_path} 2>/dev/null",
                        root=True, timeout=5,
                    )
                    uid = uid_result.output.strip("'").strip()
                    if uid.isdigit() and int(uid) >= 1000:
                        await self._adb.shell(
                            f"chown -R {uid}:{uid} {data_path}",
                            root=True, timeout=15,
                        )
                        await self._adb.shell(
                            f"chmod 700 {data_path}", root=True,
                        )
                        results[f"chown_{short}"] = True
                        logger.info("  [OK] chown %s → UID %s (Fallback su -c)", short, uid)
                    else:
                        results[f"chown_{short}"] = False
                        logger.warning("  [WARN] UID für %s nicht ermittelbar: %r", pkg, uid)
            except (ADBError, ADBTimeoutError) as e:
                results[f"chown_{short}"] = False
                logger.warning("  [FAIL] chown %s: %s", pkg, e)

        success = sum(1 for v in results.values() if v)
        logger.info(
            "Namespace Nuke v3.2: %d/%d Operationen erfolgreich",
            success, len(results),
        )
        return results

    # =========================================================================
    # Kill-Switch Management
    # =========================================================================

    async def remove_kill_switch(self) -> None:
        """Entfernt den Kill-Switch (aktiviert Hooks)."""
        await self._adb.shell(f"rm -f {KILL_SWITCH_PATH}", root=True)
        logger.info("Kill-Switch entfernt: Hooks aktiv")

    async def set_kill_switch(self) -> None:
        """Setzt den Kill-Switch (deaktiviert Hooks — Safe-Mode)."""
        await self._adb.shell(
            f"touch {KILL_SWITCH_PATH} && chmod 644 {KILL_SWITCH_PATH}",
            root=True,
        )
        logger.info("Kill-Switch gesetzt: Hooks deaktiviert")

    # =========================================================================
    # Verify: Bridge-Datei auf Gerät lesen und prüfen
    # =========================================================================

    async def verify_bridge(self, expected_serial: Optional[str] = None) -> dict[str, str]:
        """
        Liest die Bridge-Datei vom Gerät und gibt die Key=Value Paare zurück.

        Args:
            expected_serial: Falls gesetzt, wird geprüft ob serial übereinstimmt

        Returns:
            Dict der Bridge-Felder

        Raises:
            ADBError: wenn Bridge nicht lesbar
            ValueError: wenn serial nicht übereinstimmt
        """
        result = await self._adb.shell(
            f"cat {BRIDGE_FILE_PATH}", root=True, check=True,
        )

        fields: dict[str, str] = {}
        for line in result.output.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, _, value = line.partition("=")
                fields[key.strip()] = value.strip()

        if expected_serial and fields.get("serial") != expected_serial:
            raise ValueError(
                f"Bridge serial mismatch: erwartet={expected_serial}, "
                f"gefunden={fields.get('serial', 'NICHT VORHANDEN')}"
            )

        logger.info("Bridge verifiziert: serial=%s, %d Felder", fields.get("serial"), len(fields))
        return fields
