"""
Project Titan — Device Helper (GMS Readiness) v2.0
====================================================

Stellt Hilfsmethoden bereit, die den Device-State abfragen,
ohne Netzwerk-Requests an Google-Server auszulösen.

Funktionen:
  suppress_system_dialogs() — Unterdrückt System-Error-Popups nach Boot
  kickstart_gms()           — Mehrstufiger Anstoß des GMS-Checkin-Prozesses
  wait_for_gsf_id()         — Passives Polling auf lokale GSF-ID-Generierung

DESIGN-PRINZIP: "Silent Wait"
  Nach einem `pm clear com.google.android.gms` braucht GMS 10-30 Minuten
  für den vollständigen Re-Checkin (DroidGuard-Module, Integrity-Tokens, etc.).
  Anstatt blind die Play Integrity API zu pingen (→ Rate Limit Abuse Risiko),
  prüfen wir rein lokal via Content Provider, ob die GSF-ID regeneriert wurde.
  Erst wenn die GSF-ID da ist, kann ein Integrity Check überhaupt funktionieren.

v2.0 — CRITICAL FIX:
  Problem: Nach pm clear + Reboot erscheint "Internal Problem with your device"
  Popup (Fingerprint/Vendor Mismatch). Dieses Popup BLOCKIERT GMS-Initialisierung
  und führt zu 300s Timeouts. Lösung: suppress_system_dialogs() nach jedem Boot.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass
from typing import Optional

from host.adb.client import ADBClient, ADBError, ADBTimeoutError
from host.config import TIMING

logger = logging.getLogger("titan.adb.device")


# =============================================================================
# Result-Typen
# =============================================================================

@dataclass
class GSFReadyResult:
    """Ergebnis des GSF-ID Wait."""
    success: bool
    gsf_id: Optional[str] = None
    elapsed_seconds: float = 0.0
    polls: int = 0
    error: Optional[str] = None


# =============================================================================
# Device Helper
# =============================================================================

class DeviceHelper:
    """
    Gerätespezifische Hilfsmethoden für GMS-Readiness.

    Usage:
        adb = ADBClient()
        device = DeviceHelper(adb)

        # GMS-Checkin anstoßen (einmalig nach Reboot)
        await device.kickstart_gms()

        # Passiv warten bis GSF-ID lokal generiert wurde
        result = await device.wait_for_gsf_id(timeout=300)
        if result.success:
            print(f"GSF-ID bereit: {result.gsf_id} (nach {result.elapsed_seconds:.0f}s)")
    """

    # Content Provider Query für die GSF-ID (Google Services Framework)
    _GSF_QUERY_CMD = (
        "content query "
        "--uri content://com.google.android.gsf.gservices "
        "--projection android_id"
    )

    # Regex: Extrahiert den Hex-Wert aus der Content Provider Antwort
    # Erwartetes Format: "Row: 0 android_id=3a4b5c6d7e8f9a0b"
    _GSF_ID_PATTERN = re.compile(r"android_id=([0-9a-fA-F]+)")

    def __init__(self, adb: ADBClient):
        self._adb = adb

    # =========================================================================
    # Suppress System Dialogs (Post-Boot Hardening)
    # =========================================================================

    async def suppress_system_dialogs(self) -> dict[str, bool]:
        """
        Unterdrückt System-Error-Popups und Setup-Dialoge nach dem Boot.

        CRITICAL FIX: Nach `pm clear com.google.android.gms` + Reboot
        erscheint oft ein "Internal Problem with your device" Popup
        (wegen Fingerprint/Vendor Mismatch durch gespooftes Build).
        Dieses Popup PAUSIERT die GMS-Initialisierung bis "OK" gedrückt wird.
        Da wir headless arbeiten, blockiert das den gesamten Checkin-Prozess.

        Maßnahmen:
          1. hide_error_dialogs=1    — Unterdrückt alle System-Error-Dialoge
          2. device_provisioned=1    — Gerät als "eingerichtet" markieren
          3. user_setup_complete=1   — Setup-Wizard als "abgeschlossen" markieren
          4. Offenes Crash-Dialog dismissal via keyevent (ENTER/BACK)

        Returns:
            Dict mit Ergebnis pro Maßnahme
        """
        logger.info("System-Dialoge unterdrücken (Post-Boot Hardening)...")
        results: dict[str, bool] = {}

        # --- Settings-basierte Suppression ---
        settings_cmds = [
            ("hide_error_dialogs", "settings put global hide_error_dialogs 1"),
            ("device_provisioned", "settings put global device_provisioned 1"),
            ("user_setup_complete", "settings put secure user_setup_complete 1"),
        ]

        for name, cmd in settings_cmds:
            try:
                result = await self._adb.shell(cmd, root=True, timeout=5)
                results[name] = result.success
                if result.success:
                    logger.info("  [OK] %s", name)
                else:
                    logger.warning("  [WARN] %s: exit=%d", name, result.returncode)
            except (ADBError, ADBTimeoutError) as e:
                results[name] = False
                logger.warning("  [FAIL] %s: %s", name, e)

        # --- Aktive Dialog-Dismissal ---
        # Falls bereits ein Popup offen ist: ENTER drücken um "OK" zu bestätigen,
        # dann BACK um eventuell verbleibende Dialoge zu schließen
        for key_name, keycode in [("ENTER", "66"), ("BACK", "4")]:
            try:
                await self._adb.shell(
                    f"input keyevent {keycode}", timeout=3,
                )
                results[f"dismiss_{key_name}"] = True
            except (ADBError, ADBTimeoutError):
                results[f"dismiss_{key_name}"] = False

        success_count = sum(1 for v in results.values() if v)
        logger.info(
            "System-Dialog-Suppression: %d/%d Maßnahmen erfolgreich",
            success_count, len(results),
        )
        return results

    # =========================================================================
    # Kickstart: GMS-Checkin erzwingen (Multi-Stage Active Trigger)
    # =========================================================================

    async def kickstart_gms(self) -> bool:
        """
        Stößt den GMS-Checkin-Prozess mehrstufig an.

        Nach einem `pm clear com.google.android.gms` muss GMS
        explizit getriggert werden, um den Checkin zu starten.

        Mehrstufiger Anstoß (v2.0):
          1. Checkin-Broadcast: Fordert GMS auf, sich bei Google zu registrieren
          2. GmsIntentOperationService: Startet den Download-Service
          3. GsfLoginService: Triggert GSF-ID Generierung explizit
          4. Account-Authenticator Trigger: Aktiviert Account-System

        Returns:
            True wenn die kritischen Befehle erfolgreich gesendet wurden
        """
        logger.info("GMS Kickstart (v2): Mehrstufiger Checkin-Trigger...")

        success_count = 0
        total = 0

        kickstart_cmds = [
            # 1. Checkin-Broadcast — Erzwingt GMS Device-Registrierung
            (
                "Checkin-Broadcast",
                "am broadcast -a com.google.android.checkin.CHECKIN_NOW",
                True,  # kritisch
            ),
            # 2. GmsIntentOperationService — Startet DroidGuard-Download
            (
                "GmsIntentOperationService",
                "am start-service "
                "com.google.android.gms/.chimera.GmsIntentOperationService",
                True,  # kritisch
            ),
            # 3. GSF-Sync erzwingen — Triggert ContentProvider-Init
            (
                "GSF Content Sync",
                "content call --uri content://com.google.android.gsf.gservices "
                "--method get_gservices_version",
                False,  # nicht-kritisch, Fallback
            ),
            # 4. GMS Core Broadcast — weckt alle Services auf
            (
                "GMS Core Wake",
                "am broadcast -a com.google.android.gms.INITIALIZE",
                False,  # nicht-kritisch
            ),
            # 5. Play Store öffnen via monkey — zwingt GMS zur Arbeit
            # monkey startet die App als wäre es ein User-Tap, was
            # die gesamte GMS-Kette (Auth, DroidGuard, Checkin) anstößt.
            (
                "Play Store Wake (monkey)",
                "monkey -p com.android.vending 1",
                False,  # nicht-kritisch
            ),
        ]

        for name, cmd, critical in kickstart_cmds:
            total += 1
            try:
                result = await self._adb.shell(cmd, root=True, timeout=10)
                if result.success:
                    logger.info("  [OK] %s", name)
                    success_count += 1
                else:
                    level = "warning" if critical else "debug"
                    getattr(logger, level)(
                        "  [%s] %s: exit=%d",
                        "WARN" if critical else "SKIP",
                        name, result.returncode,
                    )
                    if not critical:
                        success_count += 1  # Nicht-kritische Fehler OK
            except (ADBError, ADBTimeoutError) as e:
                if critical:
                    logger.warning("  [FAIL] %s: %s", name, e)
                else:
                    logger.debug("  [SKIP] %s: %s", name, e)
                    success_count += 1  # Nicht-kritische OK

        # Play Store nach 2s wieder schließen (soll nur GMS triggern, nicht offen bleiben)
        try:
            await asyncio.sleep(2)
            await self._adb.shell(
                "am force-stop com.android.vending", root=True, timeout=5,
            )
            logger.debug("Play Store nach Kickstart geschlossen")
        except (ADBError, ADBTimeoutError):
            pass  # Nicht-kritisch

        logger.info(
            "GMS Kickstart: %d/%d Trigger gesendet",
            success_count, total,
        )
        return success_count >= 2  # Mindestens die 2 kritischen müssen OK sein

    # =========================================================================
    # Passive Sensor: Warte auf lokale GSF-ID (Smart Wait)
    # =========================================================================

    async def wait_for_gsf_id(
        self,
        timeout: int = TIMING.GSF_READY_TIMEOUT_SECONDS,
        poll_interval: float = TIMING.GSF_POLL_INTERVAL_SECONDS,
    ) -> GSFReadyResult:
        """
        Wartet passiv bis die GSF-ID lokal generiert wurde.

        KEINE Netzwerk-Requests — nur lokaler Content Provider Query.

        Methode:
          Prüft alle `poll_interval` Sekunden via ADB Shell, ob der
          GServices Content Provider einen Wert für android_id hat.
          Leerer Wert / null → GMS noch nicht bereit → weiter warten.
          Hex-String vorhanden → GMS hat Checkin beendet → SUCCESS.

        Args:
            timeout:        Maximale Wartezeit in Sekunden (Default: 300s / 5 Min)
            poll_interval:  Polling-Intervall in Sekunden (Default: 5s)

        Returns:
            GSFReadyResult mit success, gsf_id, elapsed_seconds, polls
        """
        logger.info(
            "GSF Smart Wait: Warte auf lokale GSF-ID "
            "(max %ds, pollt alle %.0fs)...",
            timeout, poll_interval,
        )

        elapsed = 0.0
        polls = 0
        last_status_log = 0.0

        while True:
            polls += 1

            # Lokaler Content Provider Query (KEIN Netzwerk!)
            gsf_id = await self._query_gsf_id()

            if gsf_id:
                logger.info(
                    "GSF-ID bereit nach %.1fs (%d Polls): %s...%s",
                    elapsed, polls,
                    gsf_id[:4], gsf_id[-4:],
                )
                return GSFReadyResult(
                    success=True,
                    gsf_id=gsf_id,
                    elapsed_seconds=elapsed,
                    polls=polls,
                )

            # Timeout prüfen
            if timeout > 0 and elapsed >= timeout:
                logger.warning(
                    "GSF Smart Wait: Timeout nach %.0fs (%d Polls) — "
                    "GSF-ID nicht generiert",
                    elapsed, polls,
                )
                return GSFReadyResult(
                    success=False,
                    elapsed_seconds=elapsed,
                    polls=polls,
                    error=f"GSF-ID nicht bereit nach {timeout}s",
                )

            # Status-Log alle 30 Sekunden
            if elapsed - last_status_log >= 30:
                logger.info(
                    "GSF Smart Wait: %.0fs vergangen, %d Polls — "
                    "GSF-ID noch nicht da, warte...",
                    elapsed, polls,
                )
                last_status_log = elapsed

            # Warten bis zum nächsten Poll
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval

    # =========================================================================
    # Interner Query: GSF Content Provider
    # =========================================================================

    async def _query_gsf_id(self) -> Optional[str]:
        """
        Fragt die GSF-ID über den lokalen Content Provider ab.

        Command:
            content query --uri content://com.google.android.gsf.gservices
                          --projection android_id

        Returns:
            GSF-ID als Hex-String (z.B. "3a4b5c6d7e8f9a0b") oder None
        """
        try:
            result = await self._adb.shell(
                self._GSF_QUERY_CMD,
                root=True,
                timeout=10,
            )

            if not result.success:
                logger.debug(
                    "GSF Query: exit=%d (GMS evtl. noch nicht initialisiert)",
                    result.returncode,
                )
                return None

            # Antwort parsen
            output = result.output

            # "No result found." → GMS noch nicht bereit
            if not output or "no result" in output.lower():
                return None

            # Regex: android_id=<hex>
            match = self._GSF_ID_PATTERN.search(output)
            if match:
                gsf_id = match.group(1).lower()

                # Plausibilitätscheck: GSF-ID muss mindestens 8 Hex-Zeichen haben
                # und darf nicht "0" sein (Default/Uninitialisiert)
                if len(gsf_id) >= 8 and gsf_id != "0" * len(gsf_id):
                    return gsf_id
                else:
                    logger.debug(
                        "GSF Query: ID vorhanden aber ungültig: %r",
                        gsf_id,
                    )
                    return None

            logger.debug("GSF Query: Kein android_id Match in: %r", output[:200])
            return None

        except (ADBError, ADBTimeoutError) as e:
            logger.debug("GSF Query fehlgeschlagen: %s", e)
            return None
