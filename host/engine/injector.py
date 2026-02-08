"""
Project Titan — TitanInjector
===============================

Verantwortlich für das Schreiben der Hardware-Identität auf das Gerät.

Ablauf:
  1. IdentityBridge → Key=Value String konvertieren
  2. Temporäre Datei lokal schreiben
  3. Via ADB auf das Gerät pushen (BRIDGE_FILE_PATH)
  4. Permissions setzen: chmod 644 + SELinux Context
  5. Backup-Kopie nach /sdcard/.titan_identity
  6. Optional: Bridge in alle Ziel-App-Datenordner verteilen

Schützt gegen Säule 1-5 (Property, IMEI, Network, DRM, ID-Correlation).
Quelle: TITAN_CONTEXT.md §3B, §3C
"""

from __future__ import annotations

import logging
import tempfile
from pathlib import Path
from typing import Optional

from host.adb.client import ADBClient, ADBError
from host.config import (
    BRIDGE_APP_TEMPLATE,
    BRIDGE_FILE_PATH,
    BRIDGE_MODULE_PATH,
    BRIDGE_SDCARD_PATH,
    BRIDGE_TARGET_APPS,
    KILL_SWITCH_PATH,
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
