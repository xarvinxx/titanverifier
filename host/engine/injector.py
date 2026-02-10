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
from host.config import (
    BRIDGE_APP_TEMPLATE,
    BRIDGE_FILE_PATH,
    BRIDGE_MODULE_PATH,
    BRIDGE_SDCARD_PATH,
    BRIDGE_TARGET_APPS,
    GMS_AUTH_DB,
    GMS_BACKUP_PACKAGES,
    GMS_DG_CACHE,
    GSF_GSERVICES_DB,
    KILL_SWITCH_PATH,
    PIF_JSON_PATH,
    PIXEL6_PIF_POOL,
    SELINUX_CONTEXT,
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

        Die pif.json wird aus dem PIXEL6_PIF_POOL generiert.
        Wenn build_index angegeben, wird der spezifische Build gewählt,
        ansonsten wird zufällig einer aus dem Pool ausgewählt.

        Args:
            build_index: Optional — Index in PIXEL6_PIF_POOL (für Konsistenz
                         mit dem gewählten Build in der Identity)

        Returns:
            True wenn erfolgreich gepusht
        """
        # Build wählen
        if build_index is not None and 0 <= build_index < len(PIXEL6_PIF_POOL):
            pif_data = PIXEL6_PIF_POOL[build_index]
        else:
            pif_data = random.choice(PIXEL6_PIF_POOL)

        logger.info(
            "PIF Injection: %s (Patch: %s)",
            pif_data["BUILD_ID"], pif_data["SECURITY_PATCH"],
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

        Lösung:
          `su -M -c` nutzt den Mount-Master-Namespace von KernelSU,
          der SELinux-Sperren auf /data/data/com.google.android.gms
          umgeht. Normale `su -c` Befehle scheitern oft an SELinux
          auch mit Root, weil der Kontext nicht passt.

        Ablauf:
          1. force-stop GMS + GSF (sauberer Zustand)
          2. rm auth.db* (veraltete Auth-Token)
          3. rm app_dg_cache/* (DroidGuard-Module → erzwingt Neudownload)
          4. sqlite3 gservices.db "DELETE FROM main;" (DB-Struktur erhalten!)
          5. chown auf GSF-Ordner (verhindert "stuck" Services)

        Returns:
            Dict mit Ergebnis pro Schritt
        """
        logger.info("=" * 50)
        logger.info("  NAMESPACE NUKE (su -M -c): GMS Auth-Reset")
        logger.info("=" * 50)

        results: dict[str, bool] = {}

        # Phase 1: Force-Stop GMS + GSF
        for pkg in ["com.google.android.gms", "com.google.android.gsf"]:
            try:
                await self._adb.shell(
                    f"am force-stop {pkg}", root=True, timeout=5,
                )
            except (ADBError, ADBTimeoutError):
                pass

        # Phase 2: Auth-DB vernichten (su -M -c für SELinux-Bypass)
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
                # Umgeht SELinux Domain-Transitions die normale su -c blockieren
                result = await self._adb.shell(
                    cmd, root=True, timeout=10,
                )
                results[key] = result.success
                if result.success:
                    logger.info("  [OK] %s", desc)
                else:
                    logger.warning(
                        "  [WARN] %s: exit=%d", desc, result.returncode,
                    )
            except (ADBError, ADBTimeoutError) as e:
                results[key] = False
                logger.warning("  [FAIL] %s: %s", desc, e)

        # Phase 3: GServices DB — SQL statt rm!
        # rm auf gservices.db führt zum Boot-Hänger am Google-Logo.
        # DELETE FROM main leert die Tabelle, behält aber die DB-Struktur.
        try:
            result = await self._adb.shell(
                f'sqlite3 {GSF_GSERVICES_DB} "DELETE FROM main;"',
                root=True, timeout=10,
            )
            results["gservices_sql_clean"] = result.success
            if result.success:
                logger.info("  [OK] GServices DB: main-Tabelle geleert (SQL)")
            else:
                # Fallback: Wenn sqlite3 nicht verfügbar oder Tabelle anders heißt
                logger.warning(
                    "  [WARN] GServices SQL exit=%d — Fallback: rm",
                    result.returncode,
                )
                result = await self._adb.shell(
                    f"rm -rf {GSF_GSERVICES_DB}*", root=True, timeout=10,
                )
                results["gservices_sql_clean"] = result.success
        except (ADBError, ADBTimeoutError) as e:
            results["gservices_sql_clean"] = False
            logger.warning("  [FAIL] GServices DB: %s", e)

        # Phase 4: Permissions-Fix auf GSF-Ordner
        # Nach dem Nuke müssen die Ordner-Permissions stimmen,
        # damit GMS-Services nicht "stuck" sind.
        gsf_packages = [
            ("com.google.android.gms", "gms"),
            ("com.google.android.gsf", "gsf"),
        ]
        for pkg, short in gsf_packages:
            try:
                data_path = f"/data/data/{pkg}"
                # UID ermitteln
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
                    logger.info("  [OK] chown %s → UID %s", short, uid)
                else:
                    results[f"chown_{short}"] = False
                    logger.warning("  [WARN] UID für %s nicht ermittelbar: %r", pkg, uid)
            except (ADBError, ADBTimeoutError) as e:
                results[f"chown_{short}"] = False
                logger.warning("  [FAIL] chown %s: %s", pkg, e)

        success = sum(1 for v in results.values() if v)
        logger.info(
            "Namespace Nuke: %d/%d Operationen erfolgreich",
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
