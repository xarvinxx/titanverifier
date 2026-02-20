"""
Bridge Injector v3.2
=====================

Verantwortlich für das Schreiben der Hardware-Identität auf das Gerät
UND die Software-Integrität (PIF) für Play Integrity.

Ablauf (2080-konform):
  1. IdentityBridge → Key=Value String → Modul-Identity-Datei
  2. PIF Fingerprint → JSON → /data/adb/pif.json (MEETS_BASIC_INTEGRITY)
  3. Namespace-Nuke → su -M -c → GMS Auth-Token vernichten (SELinux-Bypass)
  4. GServices SQL-Cleanup → sqlite3 DELETE statt rm (verhindert Boot-Freeze)
  5. Permissions-Fix → chown auf GSF-Ordner
  6. Backup + Distribution

Schützt gegen Säule 1-5 (Property, IMEI, Network, DRM, ID-Correlation)
+ Säule 6 (Software-Integrität via PIF).
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
    BT_DATA_DIR,
    DEVICE_CODENAME,
    FAKE_ARP_PATH,
    FAKE_CPUINFO_PATH,
    FAKE_IF_INET6_PATH,
    FAKE_INPUT_PATH,
    FAKE_MAC_SYSFS_PATH,
    FAKE_VERSION_PATH,
    GMS_AAID_XML,
    GMS_AUTH_DB,
    GMS_BACKUP_PACKAGES,
    GMS_DG_CACHE,
    GSF_GSERVICES_DB,
    KILL_SWITCH_PATH,
    PIF_JSON_PATH,
    PIF_SPOOF_POOL,
    POST_FS_DATA_PATH,
    SELINUX_CONTEXT,
    SERVICE_SH_PATH,
    SOCIAL_MEDIA_PACKAGES,
    SSAID_XML_PATH,
    SUSFS_FAKE_DIR,
    validate_pif_pool_integrity,
)
from host.models.identity import IdentityBridge

logger = logging.getLogger("host.injector")


class BridgeInjector:
    """
    Schreibt eine Hardware-Identität auf das Gerät.

    Alle Operationen sind asynchron und nutzen den ADBClient.

    Usage:
        adb = ADBClient()
        injector = BridgeInjector(adb)

        bridge = IdentityBridge(serial="ABC...", imei1="355543...", ...)
        await injector.inject(bridge, label="DE_Berlin_001")
    """

    # Temporärer Remote-Pfad für Push-Operationen
    _REMOTE_TMP = "/data/local/tmp/.bridge_staging"

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
                suffix=".bridge",
                delete=False,
                prefix="bridge_",
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

            # 8. Phase 11.0: AAID in GMS Storage patchen
            #    Die AAID wird von GMS über IPC an Apps geliefert.
            #    Da wir GMS nicht hooken (GMS-Schutz), müssen wir die
            #    AAID direkt in GMS's SharedPrefs schreiben.
            await self._patch_gms_aaid(bridge)

            # 9. Cleanup: Staging-Datei auf dem Gerät löschen
            await self._adb.shell(
                f"rm -f {self._REMOTE_TMP}", root=True,
            )

            # 10. POST-INJECTION VERIFICATION
            # Lese die Bridge-Datei vom primären Pfad zurück und prüfe
            # ob der Serial korrekt geschrieben wurde. Dies erkennt
            # stille Fehler bei cp/push die sonst zu "gleiche Werte"
            # Problemen führen.
            await self._verify_bridge_written(bridge)

            logger.info("Injection komplett + verifiziert: %s", bridge.serial)

        finally:
            # Lokale temp-Datei aufräumen
            if tmp_file is not None:
                try:
                    Path(tmp_file.name).unlink(missing_ok=True)
                except OSError:
                    pass

    # =========================================================================
    # Post-Injection Verifikation
    # =========================================================================

    async def _verify_bridge_written(self, bridge: "IdentityBridge") -> None:
        """
        Verifiziert, dass die Bridge-Datei korrekt geschrieben wurde.

        Liest die primäre Bridge-Datei + App-Kopie zurück und vergleicht
        den Serial mit dem erwarteten Wert. Bei Mismatch → ERROR.

        Prüft folgende Pfade:
          1. BRIDGE_FILE_PATH (primär, von Zygisk gelesen)
          2. BRIDGE_SDCARD_PATH (Backup, von LSPosed gelesen)
          3. App-Daten-Kopie (BRIDGE_APP_TEMPLATE)
        """
        verify_paths = [
            BRIDGE_FILE_PATH,
            BRIDGE_SDCARD_PATH,
            BRIDGE_APP_TEMPLATE.format(package="com.oem.hardware.service"),
        ]

        for path in verify_paths:
            try:
                result = await self._adb.shell(
                    f"grep '^serial=' {path}", root=True, timeout=5,
                )
                if result.success and result.output.strip():
                    on_device = result.output.strip().split("=", 1)[-1]
                    if on_device == bridge.serial:
                        logger.debug("Verify OK: %s → serial=%s", path, on_device)
                    else:
                        logger.error(
                            "VERIFY MISMATCH: %s hat serial=%s, erwartet=%s! "
                            "Die Bridge-Datei wurde NICHT korrekt aktualisiert!",
                            path, on_device, bridge.serial,
                        )
                else:
                    logger.warning("Verify: %s nicht lesbar oder leer", path)
            except (ADBError, Exception) as e:
                logger.warning("Verify fehlgeschlagen für %s: %s", path, e)

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
    # Phase 11.0: AAID in GMS SharedPrefs patchen
    # =========================================================================

    async def _patch_gms_aaid(self, bridge: "IdentityBridge") -> None:
        """
        Schreibt die deterministische AAID in GMS's adid_settings.xml.

        Da wir GMS nicht hooken (GMS-Schutz für Play Integrity),
        müssen wir die AAID direkt in GMS's Storage schreiben.
        Das ist das Äquivalent von "Werbe-ID zurücksetzen" in den
        Google-Einstellungen — es bricht NICHT die Trust-Chain.

        Die AAID wird deterministisch aus der Identität generiert
        (SHA-256 von serial+imei+gsf_id), sodass jede Identität
        eine konsistente, aber einzigartige AAID hat.
        """
        import hashlib

        # Deterministische AAID generieren (identisch zu Xposed-Modul)
        seed = f"{bridge.serial}-{bridge.imei1}-{bridge.gsf_id}-aaid"
        h = hashlib.sha256(seed.encode()).hexdigest()
        fake_aaid = (
            f"{h[0:8]}-{h[8:12]}-4{h[13:16]}-"
            f"{hex(int(h[16], 16) & 0x3 | 0x8)[2:]}{h[17:20]}-"
            f"{h[20:32]}"
        )

        gms_prefs = "/data/data/com.google.android.gms/shared_prefs/adid_settings.xml"

        try:
            # Prüfe ob die Datei existiert
            check = await self._adb.shell(
                f"test -f {gms_prefs}", root=True,
            )
            if not check.success:
                logger.warning("GMS adid_settings.xml nicht gefunden — AAID-Patch übersprungen")
                return

            # Patch via sed
            sed_cmd = (
                f"sed -i 's|<string name=\"adid_key\">[^<]*</string>"
                f"|<string name=\"adid_key\">{fake_aaid}</string>|' "
                f"{gms_prefs}"
            )
            await self._adb.shell(sed_cmd, root=True)

            # GMS force-stop damit neue SharedPrefs geladen werden
            await self._adb.shell("am force-stop com.google.android.gms", root=True)

            logger.info("AAID gepatched: %s → %s", gms_prefs, fake_aaid)

        except ADBError as e:
            logger.warning("AAID-Patch fehlgeschlagen: %s", e)

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
                # chmod 644 statt 600: Damit auch Shared-User-Prozesse lesen können
                await self._adb.shell(
                    f"mkdir -p {target_dir} && "
                    f"cp {BRIDGE_FILE_PATH} {target_path} && "
                    f"chown {uid}:{uid} {target_path} && "
                    f"chown {uid}:{uid} {target_dir} && "
                    f"chmod 644 {target_path}",
                    root=True,
                )
                distributed += 1
                logger.debug("Bridge → %s (UID %s)", package, uid)

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
    # *** v5.0 *** PIF Fingerprint Injection (MEETS_BASIC_INTEGRITY)
    # =========================================================================
    # Strategie: "autopif4-First"
    #   1. Prüfe ob autopif4 einen aktuellen Canary-Fingerprint hat
    #   2. Wenn ja → übernehme ihn (nur spoofProvider=1 erzwingen)
    #   3. Wenn nein → Fallback auf statischen PIF_SPOOF_POOL
    # =========================================================================

    _AUTOPIF4_PROP = "/data/adb/modules/playintegrityfix/autopif4/custom.pif.prop"

    async def _read_autopif4_fingerprint(self) -> str | None:
        """
        Liest den von autopif4 generierten Canary-Fingerprint.

        Returns:
            Inhalt der autopif4 custom.pif.prop oder None wenn nicht vorhanden/ungültig.
        """
        try:
            result = await self._adb.shell(
                f"cat {self._AUTOPIF4_PROP}", root=True, timeout=10,
            )
            if not result.success or not result.output.strip():
                return None

            content = result.output.strip()

            has_fingerprint = False
            has_security_patch = False
            for line in content.splitlines():
                line_s = line.strip()
                if line_s.startswith("FINGERPRINT=") and len(line_s) > 15:
                    has_fingerprint = True
                if line_s.startswith("SECURITY_PATCH=") and len(line_s) > 18:
                    has_security_patch = True

            if has_fingerprint and has_security_patch:
                return content

            logger.warning(
                "autopif4 Datei vorhanden aber unvollständig "
                "(FP=%s, PATCH=%s)",
                has_fingerprint, has_security_patch,
            )
            return None

        except (ADBError, ADBTimeoutError) as e:
            logger.debug("autopif4 nicht verfügbar: %s", e)
            return None

    def _ensure_spoof_provider(self, prop_content: str) -> str:
        """
        Stellt sicher, dass spoofProvider=1 in der PIF-Prop gesetzt ist.

        Wenn spoofProvider=0 gefunden → auf 1 ändern.
        Wenn spoofProvider fehlt → anhängen.
        """
        lines = prop_content.splitlines()
        found = False
        new_lines = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("spoofProvider="):
                new_lines.append("spoofProvider=1")
                found = True
            else:
                new_lines.append(line)

        if not found:
            new_lines.extend(["", "# Injected by Titan", "spoofProvider=1"])

        return "\n".join(new_lines) + "\n"

    async def inject_pif_fingerprint(
        self,
        build_index: int | None = None,
    ) -> bool:
        """
        Stellt sicher, dass eine gültige custom.pif.prop im PIF Modul-Ordner liegt.

        v5.0 STRATEGIE — "autopif4-First":
          1. Prüfe ob autopif4 einen aktuellen Canary-Fingerprint generiert hat.
             Diese werden regelmäßig von Google rotiert und sind bekanntermaßen
             gültig für Play Integrity (Canary/Beta-Builds).
          2. Wenn ja → kopiere nach custom.pif.prop, erzwinge spoofProvider=1.
          3. Wenn nein → Fallback auf statischen PIF_SPOOF_POOL mit
             Time-Travel-Prävention und Oriole Safety Guard.

        KRITISCH: spoofProvider=1 ist PFLICHT für BASIC_INTEGRITY auf Android 13+!

        Schützt gegen: Säule 6 (Software-Integrität)

        Args:
            build_index: Optional — Index in PIF_SPOOF_POOL (nur für Fallback)

        Returns:
            True wenn erfolgreich
        """

        # =====================================================================
        # STUFE 0: autopif4-First — Canary-Fingerprint bevorzugen
        # =====================================================================
        autopif4_content = await self._read_autopif4_fingerprint()

        if autopif4_content is not None:
            logger.info(
                "PIF v5.0: autopif4 Canary-Fingerprint gefunden — "
                "verwende diesen (NICHT unseren statischen Pool)"
            )

            fp_line = ""
            patch_line = ""
            expiry_line = ""
            for line in autopif4_content.splitlines():
                ls = line.strip()
                if ls.startswith("FINGERPRINT="):
                    fp_line = ls.split("=", 1)[1][:50]
                if ls.startswith("SECURITY_PATCH="):
                    patch_line = ls.split("=", 1)[1]
                if "Estimated Expiry" in ls:
                    expiry_line = ls.strip("# ").strip()

            logger.info(
                "PIF autopif4: FP=%s… | Patch=%s | %s",
                fp_line, patch_line, expiry_line or "Kein Ablaufdatum",
            )

            patched_content = self._ensure_spoof_provider(autopif4_content)
            return await self._push_pif_prop(patched_content, source="autopif4-canary")

        # =====================================================================
        # STUFE 1-3: Fallback auf statischen PIF_SPOOF_POOL
        # =====================================================================
        logger.warning(
            "PIF v5.0: Kein autopif4-Fingerprint gefunden — "
            "Fallback auf statischen PIF_SPOOF_POOL"
        )

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
                "Time-Travel-Filter wird übersprungen.",
                e,
            )

        if host_patch_date is not None:
            time_safe_pool = [
                p for p in valid_pool
                if date.fromisoformat(p["SECURITY_PATCH"].strip())
                <= host_patch_date
            ]

            if not time_safe_pool:
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
            "PIF Fallback v4.1: %s %s (Patch: %s) — Spoof-Gerät: %s",
            pif_data.get("MODEL", "?"),
            pif_data["BUILD_ID"],
            pif_data["SECURITY_PATCH"],
            pif_data.get("DEVICE", "?"),
        )

        # custom.pif.prop generieren (Key=Value Format)
        prop_lines = [
            "# PIF — Auto-generated by Titan (FALLBACK — kein autopif4 verfügbar)",
            f"# Source: PIF_SPOOF_POOL ({pif_data.get('MODEL', '?')})",
            "",
            "# Build Fields",
        ]
        build_keys = [
            "MANUFACTURER", "MODEL", "FINGERPRINT", "BRAND", "PRODUCT",
            "DEVICE", "RELEASE", "ID", "INCREMENTAL", "TYPE", "TAGS",
            "SECURITY_PATCH", "DEVICE_INITIAL_SDK_INT",
        ]
        for key in build_keys:
            value = pif_data.get(key)
            if value:
                prop_lines.append(f"{key}={value}")
            elif key == "RELEASE":
                prop_lines.append("RELEASE=14")
            elif key == "ID":
                bid = pif_data.get("BUILD_ID", "")
                if bid:
                    prop_lines.append(f"ID={bid}")

        prop_lines.extend([
            "",
            "# System Properties",
            f"*.build.id={pif_data.get('BUILD_ID', '')}",
            f"*.security_patch={pif_data.get('SECURITY_PATCH', '')}",
            f"*api_level={pif_data.get('DEVICE_INITIAL_SDK_INT', '30')}",
        ])

        prop_lines.extend([
            "",
            "# Advanced Settings",
            "spoofBuild=1",
            "spoofProps=1",
            "spoofProvider=1",
            "spoofSignature=0",
            "spoofVendingFinger=0",
            "spoofVendingSdk=0",
            "verboseLogs=0",
        ])

        prop_content = "\n".join(prop_lines) + "\n"
        return await self._push_pif_prop(prop_content, source="PIF_SPOOF_POOL")

    async def _push_pif_prop(self, prop_content: str, source: str) -> bool:
        """
        Pusht den generierten PIF-Prop-Inhalt auf das Gerät.

        Args:
            prop_content: Vollständiger Inhalt der custom.pif.prop
            source: Quellbezeichnung für Logging (z.B. "autopif4-canary")

        Returns:
            True wenn erfolgreich
        """
        tmp_file = None
        try:
            tmp_file = tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".prop",
                delete=False,
                prefix="pif_",
            )
            tmp_file.write(prop_content)
            tmp_file.flush()
            tmp_file.close()

            local_path = tmp_file.name
            staging_path = "/data/local/tmp/.pif_staging.prop"

            await self._adb.push(local_path, staging_path)

            await self._adb.shell(
                f"cp {staging_path} {PIF_JSON_PATH}",
                root=True, check=True,
            )

            await self._adb.shell(
                f"chmod 644 {PIF_JSON_PATH}", root=True,
            )

            await self._adb.shell(
                f"rm -f {staging_path}", root=True,
            )

            await self._adb.shell(
                "rm -f /data/adb/pif.json", root=True,
            )

            logger.info(
                "PIF v5.0 OK [%s]: custom.pif.prop → %s",
                source, PIF_JSON_PATH,
            )
            return True

        except (ADBError, ADBTimeoutError) as e:
            logger.error("PIF Push fehlgeschlagen [%s]: %s", source, e)
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
        ⚠️ DEPRECATED (v4.0) — NICHT MEHR IM GENESIS-FLOW VERWENDEN!
        
        Diese Funktion zerstört die Google Trust-Chain und verursacht:
          - Play Integrity verliert BASIC (nur noch DEVICE)
          - Google-Login bricht ab (Auth-Tokens gelöscht)
          - DroidGuard muss komplett neu attestieren (30-50 Min)
          - Erfordert oft Factory Reset zum Reparieren

        Die Funktion existiert noch für manuelle Notfall-Recovery,
        wird aber NICHT mehr automatisch im Genesis- oder Switch-Flow aufgerufen.
        
        Ursprüngliche Beschreibung:
          Bricht GMS-Blockaden via KernelSU Mount-Master Namespace.
          Löscht Auth-DBs, DroidGuard-Cache und leert GServices-DB.

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
        logger.warning("⚠️  NAMESPACE NUKE v3.2 — DEPRECATED seit v4.0!")
        logger.warning("    Diese Funktion zerstört die Google Trust-Chain.")
        logger.warning("    Nur für manuelle Notfall-Recovery verwenden!")
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
    # Ghost Protocol v9.0 — Kernel-Level Identity Deployment
    # =========================================================================

    async def write_susfs_fakes(self, bridge: IdentityBridge) -> None:
        """
        Schreibt die SUSFS Fake-Dateien auf das Geraet.
        
        Diese Dateien werden von post-fs-data.sh via SUSFS open_redirect
        als Ersatz fuer die echten System-Dateien bereitgestellt.
        """
        logger.info("Ghost Protocol: SUSFS Fake-Dateien schreiben...")

        fake_files: list[tuple[str, str, str]] = [
            (
                FAKE_ARP_PATH,
                "IP address       HW type     Flags       HW address            Mask     Device\n",
                "ARP (leere Tabelle)",
            ),
            (
                FAKE_MAC_SYSFS_PATH,
                f"{bridge.wifi_mac}\n",
                f"WiFi MAC ({bridge.wifi_mac})",
            ),
        ]

        for remote_path, content, desc in fake_files:
            try:
                escaped = content.replace("'", "'\\''")
                await self._adb.shell(
                    f"mkdir -p {SUSFS_FAKE_DIR} && "
                    f"echo -n '{escaped}' > {remote_path} && "
                    f"chmod 644 {remote_path} && "
                    f"chown root:root {remote_path}",
                    root=True, check=True,
                )
                logger.info("  SUSFS Fake: %s → %s", desc, remote_path)
            except ADBError as e:
                logger.error("  SUSFS Fake FEHLER (%s): %s", desc, e)

        assets_dir = Path(__file__).resolve().parent.parent.parent / "module" / "assets"
        asset_files: list[tuple[str, str, str]] = [
            ("clean_input_devices.txt", FAKE_INPUT_PATH, "/proc/bus/input/devices"),
            ("fake_cpuinfo.txt", FAKE_CPUINFO_PATH, "/proc/cpuinfo"),
            ("fake_version.txt", FAKE_VERSION_PATH, "/proc/version"),
            ("fake_if_inet6.txt", FAKE_IF_INET6_PATH, "/proc/net/if_inet6"),
        ]
        for asset_name, remote_path, desc in asset_files:
            asset_path = assets_dir / asset_name
            if not asset_path.is_file():
                logger.warning("  Asset nicht gefunden: %s — %s nicht gespooft", asset_path, desc)
                continue
            try:
                staging = f"/data/local/tmp/.{asset_name}_staging"
                await self._adb.push(str(asset_path), staging)
                await self._adb.shell(
                    f"cp {staging} {remote_path} && "
                    f"chmod 644 {remote_path} && "
                    f"chown root:root {remote_path} && "
                    f"rm -f {staging}",
                    root=True, check=True,
                )
                logger.info("  SUSFS Fake: %s → %s", desc, remote_path)
            except ADBError as e:
                logger.error("  SUSFS Fake %s FEHLER: %s", desc, e)

    async def deploy_boot_scripts(self) -> None:
        """
        Deployt post-fs-data.sh und service.sh aus dem Projekt auf das Geraet.
        
        Diese Scripts enthalten die resetprop + SUSFS Logik die bei jedem
        Boot ausgefuehrt wird.
        """
        logger.info("Ghost Protocol: Boot-Scripts deployen...")
        scripts_dir = Path(__file__).resolve().parent.parent.parent / "module"

        for script_name, remote_path in [
            ("post-fs-data.sh", POST_FS_DATA_PATH),
            ("service.sh", SERVICE_SH_PATH),
        ]:
            local_path = scripts_dir / script_name
            if not local_path.is_file():
                logger.error("Boot-Script nicht gefunden: %s", local_path)
                continue

            try:
                staging = f"/data/local/tmp/.{script_name}_staging"
                await self._adb.push(str(local_path), staging)
                await self._adb.shell(
                    f"cp {staging} {remote_path} && "
                    f"chmod 755 {remote_path} && "
                    f"chcon u:object_r:system_file:s0 {remote_path} && "
                    f"rm -f {staging}",
                    root=True, check=True,
                )
                logger.info("  Boot-Script → %s", remote_path)
            except ADBError as e:
                logger.error("  Boot-Script Deploy FEHLER (%s): %s", script_name, e)

    async def patch_ssaid(
        self, android_id: str, packages: list[str] | None = None,
    ) -> None:
        """
        Setzt die Android ID (SSAID) pro App in settings_ssaid.xml.
        
        Seit Android 8 ist SSAID per App skoped. `settings put secure android_id`
        aendert nur den globalen Default — nicht den per-App Wert.
        """
        if packages is None:
            packages = SOCIAL_MEDIA_PACKAGES

        logger.info("Ghost Protocol: SSAID patchen fuer %d Apps...", len(packages))

        for package in packages:
            try:
                check = await self._adb.shell(
                    f"test -d /data/data/{package}", root=True,
                )
                if not check.success:
                    continue

                sed_cmd = (
                    f"sed -i '/<setting id=.*package=\"{package}\"/s/"
                    f'value="[^"]*"/value="{android_id}"/'
                    f"' {SSAID_XML_PATH}"
                )
                await self._adb.shell(sed_cmd, root=True)
                logger.debug("  SSAID: %s → %s…", package, android_id[:8])
            except ADBError as e:
                logger.warning("  SSAID Patch fuer %s fehlgeschlagen: %s", package, e)

        await self._adb.shell(
            "settings put secure android_id " + android_id, root=True,
        )
        logger.info("  SSAID global + per-App gesetzt: %s…", android_id[:8])

    async def reset_gaid(self) -> None:
        """Erzwingt eine neue Google Advertising ID durch Loeschen der XML + GMS Kill."""
        logger.info("Ghost Protocol: GAID Reset...")
        try:
            await self._adb.shell(f"rm -f {GMS_AAID_XML}", root=True)
            await self._adb.shell("am force-stop com.google.android.gms", root=True)
            logger.info("  GAID XML geloescht, GMS gestoppt → neue GAID bei naechstem Start")
        except ADBError as e:
            logger.warning("  GAID Reset fehlgeschlagen: %s", e)

    async def reset_gsf_id(self, new_gsf_id: str) -> None:
        """
        Setzt die GSF ID direkt in der GServices SQLite-DB.
        
        Alternative: GSF-Daten komplett loeschen (pm clear com.google.android.gsf)
        erzwingt Neugenerierung, aber wir wollen eine kontrollierte ID.
        """
        logger.info("Ghost Protocol: GSF ID setzen → %s…%s", new_gsf_id[:4], new_gsf_id[-4:])
        try:
            sqlite3_bin = "sqlite3"
            which = await self._adb.shell("which sqlite3 2>/dev/null")
            if not (which.success and which.output.strip()):
                sqlite3_bin = self._SQLITE3_REMOTE_PATH

            sql = f"UPDATE main SET value='{new_gsf_id}' WHERE name='android_id';"
            await self._adb.shell(
                f'{sqlite3_bin} {GSF_GSERVICES_DB} "{sql}"',
                root=True, check=True,
            )
            logger.info("  GSF ID in gservices.db aktualisiert")
        except ADBError as e:
            logger.warning("  GSF ID Update fehlgeschlagen: %s — GSF-Daten muessen manuell geloescht werden", e)

    async def cleanup_bluetooth(self) -> None:
        """Loescht BT Pairing-Daten fuer IRK-Reset bei Identitaetswechsel."""
        logger.info("Ghost Protocol: Bluetooth Pairing-Daten loeschen...")
        try:
            await self._adb.shell(f"rm -rf {BT_DATA_DIR}/*", root=True)
            logger.info("  BT Daten geloescht: %s", BT_DATA_DIR)
        except ADBError as e:
            logger.warning("  BT Cleanup fehlgeschlagen: %s", e)

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
