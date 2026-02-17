"""
Device Auditor ("The Judge")
=============================

Prüft ob eine Identitäts-Injektion erfolgreich war.

WICHTIG — Warum NICHT `getprop`:
  `adb shell getprop ro.serialno` zeigt die ECHTE Hardware-Serial.
  Zygisk-Hooks greifen nur innerhalb von App-Prozessen (TikTok, GMS),
  NICHT in der ADB-Shell. Deshalb prüft der Auditor stattdessen:

4 Audit-Checks:
  1. Bridge-Datei   — Liegt auf dem Gerät und enthält die erwarteten Werte?
  2. Bridge-Serial  — Stimmt serial in der Bridge mit der generierten überein?
  3. Input-Devices  — /proc/bus/input/devices nicht leer? (Hardware-Leak Check)
  4. Bridge-MAC     — Stimmt wifi_mac in der Bridge mit der generierten überein?

Jeder Check liefert PASS/FAIL/WARN mit Detail-Informationen.
Der Gesamtscore ist der Anteil bestandener kritischer Checks.

WICHTIG: Der Auditor führt NUR lesende Operationen aus.
Er verändert NICHTS auf dem Gerät.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime

from host.config import LOCAL_TZ
from enum import Enum
from typing import Optional

from host.adb.client import ADBClient, ADBError
from host.config import BRIDGE_FILE_PATH
from host.models.identity import IdentityRead

logger = logging.getLogger("host.auditor")


# =============================================================================
# Audit-Ergebnis Modelle
# =============================================================================

class CheckStatus(str, Enum):
    """Ergebnis eines einzelnen Audit-Checks."""
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"           # Nicht-kritisch, aber verdächtig
    SKIP = "skip"           # Check konnte nicht ausgeführt werden


@dataclass
class AuditCheck:
    """Ergebnis eines einzelnen Audit-Checks."""
    name: str                                   # z.B. "bridge_file"
    status: CheckStatus = CheckStatus.SKIP      # Default: SKIP
    expected: str = ""                           # Erwarteter Wert
    actual: str = ""                             # Tatsächlicher Wert auf dem Gerät
    detail: str = ""                             # Menschenlesbare Beschreibung
    critical: bool = True                        # Zählt für den Score?

    @property
    def passed(self) -> bool:
        return self.status == CheckStatus.PASS


@dataclass
class AuditResult:
    """
    Gesamtergebnis eines Device-Audits.

    score_percent: Anteil bestandener kritischer Checks (0-100).
    checks: Liste aller durchgeführten Einzelprüfungen.
    """
    identity_name: str
    identity_serial: str
    checks: list[AuditCheck] = field(default_factory=list)
    timestamp: str = field(
        default_factory=lambda: datetime.now(LOCAL_TZ).isoformat()
    )
    error: Optional[str] = None  # Globaler Fehler (z.B. Gerät nicht erreichbar)

    @property
    def score_percent(self) -> int:
        """Prozentualer Score (nur kritische Checks)."""
        critical = [c for c in self.checks if c.critical]
        if not critical:
            return 0
        passed = sum(1 for c in critical if c.passed)
        return round((passed / len(critical)) * 100)

    @property
    def passed(self) -> bool:
        """True wenn alle kritischen Checks bestanden."""
        return self.score_percent == 100

    @property
    def total_checks(self) -> int:
        return len(self.checks)

    @property
    def passed_checks(self) -> int:
        return sum(1 for c in self.checks if c.passed)

    @property
    def failed_checks(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.FAIL)

    def summary(self) -> str:
        """Einzeilige Zusammenfassung."""
        return (
            f"Audit [{self.identity_name}]: "
            f"{self.score_percent}% "
            f"({self.passed_checks}/{self.total_checks} passed)"
        )


# =============================================================================
# Auditor
# =============================================================================

class DeviceAuditor:
    """
    Führt Device-Audits nach Injektion durch.

    Prüft die Bridge-Datei auf dem Gerät (nicht getprop — das zeigt
    die echten Werte, Zygisk-Hooks greifen nur in App-Prozessen).

    Usage:
        adb = ADBClient()
        auditor = DeviceAuditor(adb)
        result = await auditor.audit_device(expected_identity)
        print(result.summary())  # "Audit [DE_001]: 100% (4/4 passed)"
    """

    def __init__(self, adb: ADBClient):
        self._adb = adb

    async def audit_device(self, expected: IdentityRead) -> AuditResult:
        """
        Führt den vollständigen 4-Punkte-Audit durch.

        Args:
            expected: Die Identität die auf dem Gerät aktiv sein sollte

        Returns:
            AuditResult mit Score und Einzelergebnissen
        """
        result = AuditResult(
            identity_name=expected.name,
            identity_serial=expected.serial,
        )

        logger.info(
            "Audit starten: %s (serial=%s)",
            expected.name, expected.serial,
        )

        try:
            # Prüfe erstmal ob das Gerät erreichbar ist
            if not await self._adb.is_connected():
                result.error = "Gerät nicht verbunden"
                logger.error("Audit abgebrochen: Gerät nicht verbunden")
                return result

            # Bridge-Datei vom Gerät lesen (Basis für alle Checks)
            bridge_fields = await self._read_bridge_file()

            # =================================================================
            # FIX-17: Erweiterter Full Audit — alle kritischen Spoofing-Felder
            # =================================================================
            # Basis-Checks (wie bisher)
            result.checks.append(self._check_bridge_exists(bridge_fields))
            result.checks.append(self._check_bridge_serial(bridge_fields, expected))
            result.checks.append(await self._check_input_devices())
            result.checks.append(self._check_bridge_mac(bridge_fields, expected))

            # Neue kritische Checks (FIX-17)
            result.checks.append(
                self._check_bridge_field(bridge_fields, expected, "imei1", critical=True)
            )
            result.checks.append(
                self._check_bridge_field(bridge_fields, expected, "imei2", critical=True)
            )
            result.checks.append(
                self._check_bridge_field(bridge_fields, expected, "gsf_id", critical=True)
            )
            result.checks.append(
                self._check_bridge_field(bridge_fields, expected, "android_id", critical=True)
            )
            result.checks.append(
                self._check_bridge_field(bridge_fields, expected, "widevine_id", critical=False)
            )
            result.checks.append(
                self._check_bridge_field(bridge_fields, expected, "imsi", critical=False)
            )
            result.checks.append(
                self._check_bridge_field(bridge_fields, expected, "sim_serial", critical=False)
            )
            result.checks.append(
                self._check_bridge_field(
                    bridge_fields, expected, "build_fingerprint", critical=False,
                )
            )

        except ADBError as e:
            result.error = f"ADB-Fehler während Audit: {e}"
            logger.error("Audit ADB-Fehler: %s", e)

        # Log-Ausgabe
        for check in result.checks:
            icon = {
                CheckStatus.PASS: "+",
                CheckStatus.FAIL: "!",
                CheckStatus.WARN: "~",
                CheckStatus.SKIP: "-",
            }.get(check.status, "?")
            logger.info(
                "  [%s] %s: %s%s",
                icon, check.name, check.status.value,
                f" — {check.detail}" if check.detail else "",
            )

        logger.info(result.summary())
        return result

    # =========================================================================
    # Quick Audit (nur Bridge-Serial — für Switch-Flow)
    # =========================================================================

    async def quick_audit(
        self,
        expected_serial: str,
        expected_identity: Optional[IdentityRead] = None,
    ) -> bool:
        """
        Schneller Audit: Prüft die 5 wichtigsten Bridge-Felder.

        FIX-17: Erweitert von nur Serial auf die 5 kritischsten Felder:
          serial, imei1, gsf_id, android_id, wifi_mac

        Falls expected_identity nicht angegeben wird, wird nur Serial geprüft
        (Rückwärtskompatibilität).

        Args:
            expected_serial:   Erwartete Serial Number
            expected_identity: Optionale vollständige Identity für erweiterten Check

        Returns:
            True wenn alle geprüften Felder übereinstimmen
        """
        try:
            bridge = await self._read_bridge_file()

            if expected_identity:
                # FIX-17: Erweiterter Quick Audit (5 Felder)
                fields_to_check = {
                    "serial": expected_identity.serial,
                    "imei1": expected_identity.imei1,
                    "gsf_id": expected_identity.gsf_id,
                    "android_id": expected_identity.android_id,
                    "wifi_mac": expected_identity.wifi_mac,
                }
                mismatches: list[str] = []
                for field_name, expected_val in fields_to_check.items():
                    actual = bridge.get(field_name, "")
                    if field_name == "wifi_mac":
                        # MAC case-insensitive vergleichen
                        if actual.lower() != expected_val.lower():
                            mismatches.append(f"{field_name}: erwartet={expected_val}, bridge={actual}")
                    elif actual != expected_val:
                        mismatches.append(f"{field_name}: erwartet={expected_val}, bridge={actual}")

                if not mismatches:
                    logger.info(
                        "Quick Audit: OK (5/5 Felder — serial=%s)",
                        expected_serial,
                    )
                    return True
                else:
                    logger.warning(
                        "Quick Audit: FAIL (%d/5 Mismatches: %s)",
                        len(mismatches), "; ".join(mismatches[:3]),
                    )
                    return False
            else:
                # Rückwärtskompatibel: Nur Serial prüfen
                actual = bridge.get("serial", "")
                match = actual == expected_serial

                if match:
                    logger.info("Quick Audit: OK (bridge serial=%s)", expected_serial)
                else:
                    logger.warning(
                        "Quick Audit: FAIL (erwartet=%s, bridge=%s)",
                        expected_serial, actual or "NICHT GEFUNDEN",
                    )
                return match

        except ADBError as e:
            logger.error("Quick Audit fehlgeschlagen: %s", e)
            return False

    # =========================================================================
    # Bridge-Datei lesen und parsen
    # =========================================================================

    async def _read_bridge_file(self) -> dict[str, str]:
        """
        Liest die Bridge-Datei vom Gerät und parst die Key=Value Paare.

        Returns:
            Dict der Bridge-Felder (leer wenn Datei nicht existiert)
        """
        result = await self._adb.shell(
            f"cat {BRIDGE_FILE_PATH}", root=True, timeout=5,
        )

        if not result.success:
            logger.warning("Bridge-Datei nicht lesbar: %s", result.stderr[:100])
            return {}

        fields: dict[str, str] = {}
        for line in result.output.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, _, value = line.partition("=")
                fields[key.strip()] = value.strip()

        return fields

    # =========================================================================
    # Check 1: Bridge-Datei existiert und hat Inhalt
    # =========================================================================

    def _check_bridge_exists(self, bridge: dict[str, str]) -> AuditCheck:
        """
        Prüft ob die Bridge-Datei auf dem Gerät liegt und Felder enthält.

        Ohne Bridge-Datei können die Zygisk-Hooks nichts spoofing.
        """
        check = AuditCheck(
            name="bridge_file",
            expected=f"exists at {BRIDGE_FILE_PATH}",
            critical=True,
        )

        if not bridge:
            check.status = CheckStatus.FAIL
            check.actual = "NICHT GEFUNDEN / LEER"
            check.detail = (
                f"Bridge-Datei nicht gefunden oder leer: {BRIDGE_FILE_PATH}"
            )
        elif len(bridge) < 5:
            check.status = CheckStatus.WARN
            check.actual = f"{len(bridge)} Felder"
            check.detail = (
                f"Bridge hat nur {len(bridge)} Felder — möglicherweise unvollständig"
            )
        else:
            check.status = CheckStatus.PASS
            check.actual = f"{len(bridge)} Felder"
            check.detail = f"Bridge OK: {len(bridge)} Felder auf dem Gerät"

        return check

    # =========================================================================
    # Check 2: Bridge-Serial stimmt überein
    # =========================================================================

    def _check_bridge_serial(
        self, bridge: dict[str, str], expected: IdentityRead,
    ) -> AuditCheck:
        """
        Prüft ob serial + boot_serial in der Bridge-Datei mit den
        generierten Werten übereinstimmen.

        WICHTIG: Wir prüfen die BRIDGE, nicht getprop!
        getprop zeigt die echte Hardware-Serial, weil die ADB-Shell
        nicht von Zygisk gehookt wird.
        """
        check = AuditCheck(
            name="bridge_serial",
            expected=expected.serial,
            critical=True,
        )

        if not bridge:
            check.status = CheckStatus.SKIP
            check.detail = "Bridge-Datei nicht verfügbar"
            return check

        actual_serial = bridge.get("serial", "")
        actual_boot = bridge.get("boot_serial", "")
        check.actual = actual_serial

        if actual_serial == expected.serial and actual_boot == expected.boot_serial:
            check.status = CheckStatus.PASS
            check.detail = (
                f"serial={actual_serial}, boot_serial={actual_boot} — korrekt"
            )
        elif actual_serial == expected.serial:
            check.status = CheckStatus.WARN
            check.detail = (
                f"serial OK, aber boot_serial mismatch: "
                f"erwartet='{expected.boot_serial}', gefunden='{actual_boot}'"
            )
        else:
            check.status = CheckStatus.FAIL
            check.detail = (
                f"Mismatch: erwartet='{expected.serial}', "
                f"bridge='{actual_serial}'"
            )

        return check

    # =========================================================================
    # Check 3: /proc/bus/input/devices (mit Root!)
    # =========================================================================

    async def _check_input_devices(self) -> AuditCheck:
        """
        Prüft ob /proc/bus/input/devices NICHT leer ist.

        WICHTIG: Muss mit root=True gelesen werden (Permission Denied ohne Root).

        Eine leere Datei bedeutet: Das Gerät hat keine Input-Devices,
        was für TikTok ein klares Zeichen für eine VM/Emulator ist.
        """
        check = AuditCheck(
            name="/proc/bus/input/devices",
            expected="non-empty",
            critical=False,  # Informativ — Zygisk-Modul ist verantwortlich
        )

        try:
            result = await self._adb.shell(
                "cat /proc/bus/input/devices", root=True, timeout=5,
            )
            content = result.output.strip()

            if content:
                device_count = content.count("I: Bus=")
                check.actual = f"{device_count} devices"
                check.status = CheckStatus.PASS
                check.detail = f"{device_count} Input-Devices gefunden"
            else:
                check.actual = "EMPTY"
                check.status = CheckStatus.WARN
                check.detail = (
                    "Input-Devices leer — Zygisk-Modul sollte dies fixen. "
                    "Kein Blocker für den Flow."
                )

        except ADBError as e:
            check.status = CheckStatus.SKIP
            check.detail = f"Nicht lesbar: {e}"

        return check

    # =========================================================================
    # Check 4: Bridge-MAC stimmt überein
    # =========================================================================

    # =========================================================================
    # FIX-17: Generischer Bridge-Feld Check
    # =========================================================================

    def _check_bridge_field(
        self,
        bridge: dict[str, str],
        expected: IdentityRead,
        field_name: str,
        critical: bool = True,
    ) -> AuditCheck:
        """
        Generischer Check: Prüft ob ein einzelnes Feld in der Bridge mit
        dem erwarteten Wert übereinstimmt.

        Args:
            bridge:     Geparstes Bridge-Dict
            expected:   Erwartete Identität
            field_name: Name des Felds (z.B. "imei1", "gsf_id")
            critical:   Zählt für den Score?
        """
        expected_val = getattr(expected, field_name, "")
        check = AuditCheck(
            name=f"bridge_{field_name}",
            expected=expected_val,
            critical=critical,
        )

        if not bridge:
            check.status = CheckStatus.SKIP
            check.detail = "Bridge-Datei nicht verfügbar"
            return check

        actual_val = bridge.get(field_name, "")
        check.actual = actual_val

        if not expected_val:
            check.status = CheckStatus.SKIP
            check.detail = f"{field_name} nicht in erwarteter Identity"
        elif actual_val == expected_val:
            check.status = CheckStatus.PASS
            check.detail = f"{field_name} korrekt"
        elif not actual_val:
            check.status = CheckStatus.FAIL
            check.detail = f"{field_name} fehlt in Bridge-Datei"
        else:
            check.status = CheckStatus.FAIL
            check.detail = (
                f"Mismatch: erwartet='{expected_val[:20]}...', "
                f"bridge='{actual_val[:20]}...'"
            )

        return check

    # =========================================================================
    # Check 4: Bridge-MAC stimmt überein
    # =========================================================================

    def _check_bridge_mac(
        self, bridge: dict[str, str], expected: IdentityRead,
    ) -> AuditCheck:
        """
        Prüft ob wifi_mac in der Bridge-Datei mit dem generierten Wert
        übereinstimmt.

        Wir prüfen die Bridge statt wlan0 direkt, weil:
          - Das Gerät möglicherweise nur Mobilfunk nutzt (kein wlan0)
          - Die MAC wird von Zygisk aus der Bridge gelesen und in-memory gespooft
        """
        check = AuditCheck(
            name="bridge_mac",
            expected=expected.wifi_mac,
            critical=True,
        )

        if not bridge:
            check.status = CheckStatus.SKIP
            check.detail = "Bridge-Datei nicht verfügbar"
            return check

        actual_mac = bridge.get("wifi_mac", "")
        check.actual = actual_mac

        if actual_mac.lower() == expected.wifi_mac.lower():
            check.status = CheckStatus.PASS
            check.detail = f"Bridge MAC korrekt: {actual_mac}"
        elif not actual_mac:
            check.status = CheckStatus.FAIL
            check.detail = "wifi_mac fehlt in Bridge-Datei"
        else:
            check.status = CheckStatus.FAIL
            check.detail = (
                f"Mismatch: erwartet='{expected.wifi_mac}', "
                f"bridge='{actual_mac}'"
            )

        return check
