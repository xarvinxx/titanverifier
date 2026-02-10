"""
Project Titan — Device Helper (GMS Readiness) v3.0
====================================================

Stellt Hilfsmethoden bereit, die den Device-State abfragen,
ohne Netzwerk-Requests an Google-Server auszulösen.

Funktionen:
  suppress_system_dialogs() — Unterdrückt System-Error-Popups nach Boot
  kickstart_gms()           — Mehrstufiger Anstoß des GMS-Checkin-Prozesses
  wait_for_gsf_id()         — Passives Polling auf lokale GSF-ID-Generierung
  check_connectivity()      — *** NEU v3.0 *** Schnelle Konnektivitätsprüfung

DESIGN-PRINZIP: "Silent Wait"
  Nach einem `pm clear com.google.android.gms` braucht GMS 10-30 Minuten
  für den vollständigen Re-Checkin (DroidGuard-Module, Integrity-Tokens, etc.).
  Anstatt blind die Play Integrity API zu pingen (→ Rate Limit Abuse Risiko),
  prüfen wir rein lokal via Content Provider, ob die GSF-ID regeneriert wurde.
  Erst wenn die GSF-ID da ist, kann ein Integrity Check überhaupt funktionieren.

v3.0 — TIMING FIXES:
  - GSF-Timeout auf 600s erhöht (war 300s)
  - Retry-Kickstart: Nach 180s ohne GSF-ID → zweiter kickstart_gms()
  - Network-First: check_connectivity() Gate vor GMS-Kickstart
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
    """
    Ergebnis des GSF-ID Wait.

    gsf_id:         Hex-String der GSF-ID (z.B. "3a4b5c6d7e8f9a0b")
    gsf_id_decimal: Dezimal-String der GSF-ID (z.B. "42068372154961xxxx")
                    → Das Format das in der titan.db / Bridge-Datei steht.
    """
    success: bool
    gsf_id: Optional[str] = None
    gsf_id_decimal: Optional[str] = None
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
    # *** NEU v3.0 *** Connectivity Check (Network-First Gate)
    # =========================================================================

    async def check_connectivity(self) -> bool:
        """
        Schnelle Konnektivitätsprüfung — bestätigt, dass das Gerät
        eine aktive Internetverbindung hat.

        v3.0 Network-First: kickstart_gms() darf erst starten, wenn
        diese Prüfung positiv ist. Ohne Netz kann GMS keinen Checkin
        durchführen und die GSF-ID wird nie generiert.

        Methode: ping auf Google Connectivity-Check-Server (1 Paket, 5s Timeout).
        Fallback: DNS-Lookup auf connectivitycheck.gstatic.com via nslookup.

        Returns:
            True wenn Konnektivität bestätigt
        """
        # Methode 1: Schneller Ping (bevorzugt)
        try:
            result = await self._adb.shell(
                "ping -c 1 -W 5 connectivitycheck.gstatic.com 2>/dev/null",
                root=False, timeout=10,
            )
            if result.success:
                logger.debug("Connectivity Check: Ping OK")
                return True
        except (ADBError, ADBTimeoutError):
            pass

        # Methode 2: DNS-Lookup Fallback
        try:
            result = await self._adb.shell(
                "nslookup connectivitycheck.gstatic.com 2>/dev/null",
                root=False, timeout=10,
            )
            if result.success and "Address" in result.output:
                logger.debug("Connectivity Check: DNS OK (nslookup)")
                return True
        except (ADBError, ADBTimeoutError):
            pass

        # Methode 3: Letzte Chance — HTTP via wget
        try:
            result = await self._adb.shell(
                "wget -q -O /dev/null --timeout=5 http://connectivitycheck.gstatic.com/generate_204 2>/dev/null",
                root=False, timeout=10,
            )
            if result.success:
                logger.debug("Connectivity Check: HTTP OK (wget)")
                return True
        except (ADBError, ADBTimeoutError):
            pass

        logger.warning("Connectivity Check: FEHLGESCHLAGEN — kein Netzwerk")
        return False

    # =========================================================================
    # Kickstart: GMS-Checkin erzwingen (Multi-Stage Active Trigger)
    # =========================================================================

    async def kickstart_gms(self) -> bool:
        """
        Stößt den GMS-Checkin-Prozess radial mehrstufig an.

        v3.1 Pixel 6 Hardened Kickstart:
          Nach `pm clear com.google.android.gms` auf dem Pixel 6 (Tensor G1)
          reichen einfache Broadcasts oft NICHT aus, um GMS aus dem Koma zu holen.
          Der erweiterte Kickstart initialisiert die GSF-Datenbank manuell,
          nutzt direkte Activity-Starts und erzwingt Cloud-Sync-Trigger.

        8-stufiger Anstoß:
          1. GServices DB Init:         Manueller Content-Insert → GSF-DB anlegen
          2. WebView Sync Trigger:      WebView-Implementation setzen → Cloud-Sync
          3. Checkin-Broadcast:         Fordert GMS auf, sich zu registrieren
          4. Force-Checkin-Intent:      Direkter Start des CheckinService
          5. GmsIntentOperationService: Startet DroidGuard-Download
          6. GSF Content Sync:          Triggert ContentProvider-Init
          7. GMS Core Wake:             Weckt alle Services auf
          8. Play Store Wake:           Öffnet Vending via monkey → GMS-Kette

        Returns:
            True wenn die kritischen Befehle erfolgreich gesendet wurden
        """
        logger.info("GMS Kickstart (v3.1 Pixel 6 Hardened): 8-Stufen-Trigger...")

        success_count = 0
        total = 0

        kickstart_cmds = [
            # ---------------------------------------------------------------
            # PHASE 1: Datenbank-Initialisierung (VOR dem Checkin!)
            # ---------------------------------------------------------------

            # 1. GServices DB Init — Legt die GSF-Datenbank manuell an.
            # Nach pm clear existiert die GServices-DB nicht mehr. Ohne sie
            # kann der Checkin-Broadcast nichts speichern. Dieser Insert
            # erzwingt die DB-Erstellung und setzt das Checkin-Intervall.
            (
                "GServices DB Init",
                "content insert "
                "--uri content://com.google.android.gsf.gservices "
                "--bind name:s:main_checkin_interval_ms "
                "--bind value:s:3600000",
                True,  # kritisch — ohne DB kein Checkin möglich
            ),

            # 2. WebView Sync Trigger — Setzt die WebView-Implementation.
            # Dies triggert oft die Google-Cloud-Synchronisation, weil
            # das System prüft ob die WebView-Version aktuell ist und
            # dabei GMS-Services aufweckt.
            (
                "WebView Sync Trigger",
                "cmd webviewupdate set-webview-implementation com.google.android.webview",
                False,  # nicht-kritisch, Seiteneffekt-Trigger
            ),

            # ---------------------------------------------------------------
            # PHASE 2: Checkin erzwingen
            # ---------------------------------------------------------------

            # 3. Checkin-Broadcast — Erzwingt GMS Device-Registrierung
            (
                "Checkin-Broadcast",
                "am broadcast -a com.google.android.checkin.CHECKIN_NOW",
                True,  # kritisch
            ),

            # 4. Force-Checkin-Intent — Direkter Activity-Start des CheckinService.
            # Radikaler als ein Broadcast: Startet den Service direkt als
            # Foreground-Activity, was Android zwingt ihn sofort auszuführen.
            (
                "Force-Checkin-Intent",
                "am start -a android.intent.action.MAIN "
                "-n com.google.android.gsf/.checkin.CheckinService",
                True,  # kritisch — der wichtigste neue Trigger
            ),

            # 5. GmsIntentOperationService — Startet DroidGuard-Download
            (
                "GmsIntentOperationService",
                "am start-service "
                "com.google.android.gms/.chimera.GmsIntentOperationService",
                True,  # kritisch
            ),

            # ---------------------------------------------------------------
            # PHASE 3: Sekundäre Trigger (Fallbacks)
            # ---------------------------------------------------------------

            # 6. GSF-Sync erzwingen — Triggert ContentProvider-Init
            (
                "GSF Content Sync",
                "content call --uri content://com.google.android.gsf.gservices "
                "--method get_gservices_version",
                False,  # nicht-kritisch, Fallback
            ),

            # 7. GMS Core Broadcast — weckt alle Services auf
            (
                "GMS Core Wake",
                "am broadcast -a com.google.android.gms.INITIALIZE",
                False,  # nicht-kritisch
            ),

            # 8. Play Store öffnen via monkey — zwingt GMS zur Arbeit
            (
                "Play Store Wake (monkey)",
                "monkey -p com.android.vending 1",
                False,  # nicht-kritisch
            ),
        ]

        for name, cmd, critical in kickstart_cmds:
            total += 1
            try:
                result = await self._adb.shell(cmd, root=True, timeout=15)
                if result.success:
                    logger.info("  [OK] %s", name)
                    success_count += 1
                else:
                    level = "warning" if critical else "debug"
                    getattr(logger, level)(
                        "  [%s] %s: exit=%d — %s",
                        "WARN" if critical else "SKIP",
                        name, result.returncode,
                        result.output.strip()[:80] if result.output else "",
                    )
                    if not critical:
                        success_count += 1  # Nicht-kritische Fehler OK
            except (ADBError, ADBTimeoutError) as e:
                if critical:
                    logger.warning("  [FAIL] %s: %s", name, e)
                else:
                    logger.debug("  [SKIP] %s: %s", name, e)
                    success_count += 1  # Nicht-kritische OK

        # Play Store nach 3s wieder schließen (soll nur GMS triggern)
        try:
            await asyncio.sleep(3)
            await self._adb.shell(
                "am force-stop com.android.vending", root=True, timeout=5,
            )
            logger.debug("Play Store nach Kickstart geschlossen")
        except (ADBError, ADBTimeoutError):
            pass  # Nicht-kritisch

        # DPC-Trigger: Device-Policy-Check erzwingen.
        # Simuliert einen Device-Owner-Check: GMS prüft dann sofort
        # die Geräte-Integrität, was den Checkin-Prozess anstößt.
        # Wird sofort wieder entfernt um keine Seiteneffekte zu hinterlassen.
        try:
            logger.info("  [DPC] Device-Policy Trigger...")
            await self._adb.shell(
                "dpm set-active-admin "
                "com.google.android.gms/.auth.managed.admin.DeviceAdminReceiver",
                root=True, timeout=10,
            )
            await asyncio.sleep(1)
            await self._adb.shell(
                "dpm remove-active-admin "
                "com.google.android.gms/.auth.managed.admin.DeviceAdminReceiver",
                root=True, timeout=10,
            )
            logger.info("  [OK] DPC-Trigger (set + remove)")
            success_count += 1
        except (ADBError, ADBTimeoutError) as e:
            logger.debug("  [SKIP] DPC-Trigger: %s (nicht-kritisch)", e)

        logger.info(
            "GMS Kickstart (v3.1): %d/%d Trigger gesendet",
            success_count, total + 1,  # +1 für DPC
        )
        return success_count >= 3  # Mindestens 3 kritische müssen OK sein

    # =========================================================================
    # GMS Core Repair: Interner Reparatur-Flow (MinuteMaid)
    # =========================================================================

    async def reset_gms_internal(self) -> bool:
        """
        Triggert den internen GMS-Reparatur-Flow via MinuteMaidActivity.

        MinuteMaid ist die interne GMS-"Reparatur-UI", die normalerweise
        bei Account-Problemen angezeigt wird. Der direkte Start dieser
        Activity zwingt GMS, seinen internen Auth-State zu validieren
        und ggf. Token/Zertifikate neu auszuhandeln.

        Einsatzzweck:
          - Play-Store-Login unmöglich (Zertifikats-Lockdown)
          - GMS meldet "Kontoaktion erforderlich" aber Login-UI hängt
          - Nach deep_clean / Identity-Switch zur Auth-Ketten-Reparatur

        Wird im Genesis-Flow Schritt 7 automatisch VOR dem Kickstart
        aufgerufen, um den GMS-Lockdown aufzuheben.

        Returns:
            True wenn die Activity erfolgreich gestartet wurde
        """
        logger.info("GMS Core Repair: Starte MinuteMaid-Reparatur-Flow...")

        try:
            result = await self._adb.shell(
                "am start -n "
                "com.google.android.gms/"
                ".auth.uiflows.minutemaid.MinuteMaidActivity",
                root=True, timeout=10,
            )
            if result.success:
                logger.info(
                    "  [OK] MinuteMaidActivity gestartet — "
                    "GMS Auth-Reparatur läuft"
                )
                return True
            else:
                logger.warning(
                    "  [WARN] MinuteMaidActivity exit=%d — %s",
                    result.returncode,
                    result.output.strip()[:100] if result.output else "",
                )
                return False
        except (ADBError, ADBTimeoutError) as e:
            logger.warning("  [FAIL] MinuteMaidActivity: %s", e)
            return False

    # =========================================================================
    # Finsky Kill: Play Store hart beenden (am kill + killall -9)
    # =========================================================================

    async def kill_finsky(self) -> None:
        """
        Beendet den Play Store (com.android.vending / Finsky) hart.

        Verwendet `am kill` statt `force-stop`. Während force-stop nur
        den ActivityManager bittet den Prozess zu beenden (kann ignoriert
        werden bei laufenden Zertifikats-Handshakes), terminiert `am kill`
        den Prozess auf Kernel-Ebene via SIGKILL.

        Wird VOR jedem GMS-Ready-Versuch aufgerufen, damit der
        Play Store nicht mit veralteten Auth-Sessions interferiert
        und hängende Zertifikats-Abfragen garantiert beendet werden.
        """
        try:
            # am kill — terminiert alle Prozesse der App sofort
            await self._adb.shell(
                "am kill com.android.vending", root=True, timeout=5,
            )
            # killall als Backup für persistente Child-Prozesse
            await self._adb.shell(
                "killall -9 com.android.vending 2>/dev/null || true",
                root=True, timeout=5,
            )
            logger.debug(
                "Finsky (Play Store) hart beendet (am kill + killall -9)"
            )
        except (ADBError, ADBTimeoutError):
            pass  # Best-effort, nicht kritisch

    # =========================================================================
    # Passive Sensor: Warte auf lokale GSF-ID (Smart Wait)
    # =========================================================================

    async def wait_for_gsf_id(
        self,
        timeout: int = TIMING.GSF_READY_TIMEOUT_SECONDS,
        poll_interval: float = TIMING.GSF_POLL_INTERVAL_SECONDS,
        retry_kickstart_after: int = TIMING.GSF_RETRY_KICKSTART_SECONDS,
    ) -> GSFReadyResult:
        """
        Wartet passiv bis die GSF-ID lokal generiert wurde.

        KEINE Netzwerk-Requests — nur lokaler Content Provider Query.

        v3.0 Retry-Logik:
          Nach `retry_kickstart_after` Sekunden ohne GSF-ID wird ein
          zweiter kickstart_gms() ausgeführt, um GMS nochmal anzustoßen.
          Das hilft wenn der erste Kickstart zu früh kam (Netz noch instabil).

        Methode:
          Prüft alle `poll_interval` Sekunden via ADB Shell, ob der
          GServices Content Provider einen Wert für android_id hat.
          Leerer Wert / null → GMS noch nicht bereit → weiter warten.
          Hex-String vorhanden → GMS hat Checkin beendet → SUCCESS.

        Args:
            timeout:                Maximale Wartezeit in Sekunden (Default: 600s / 10 Min)
            poll_interval:          Polling-Intervall in Sekunden (Default: 5s)
            retry_kickstart_after:  Nach X Sekunden zweiten Kickstart ausführen (Default: 180s)

        Returns:
            GSFReadyResult mit success, gsf_id, elapsed_seconds, polls
        """
        logger.info(
            "GSF Smart Wait: Warte auf lokale GSF-ID "
            "(max %ds, pollt alle %.0fs, Retry-Kickstart nach %ds)...",
            timeout, poll_interval, retry_kickstart_after,
        )

        elapsed = 0.0
        polls = 0
        last_status_log = 0.0
        retry_done = False          # v3.0: Nur ein Retry

        while True:
            polls += 1

            # Lokaler Content Provider Query (KEIN Netzwerk!)
            gsf_id = await self._query_gsf_id()

            if gsf_id:
                # Hex → Dezimal Konvertierung für DB/Bridge Kompatibilität
                gsf_decimal = str(int(gsf_id, 16))
                logger.info(
                    "GSF-ID bereit nach %.1fs (%d Polls): hex=%s...%s → dec=%s...%s",
                    elapsed, polls,
                    gsf_id[:4], gsf_id[-4:],
                    gsf_decimal[:4], gsf_decimal[-4:],
                )
                return GSFReadyResult(
                    success=True,
                    gsf_id=gsf_id,
                    gsf_id_decimal=gsf_decimal,
                    elapsed_seconds=elapsed,
                    polls=polls,
                )

            # ===================================================================
            # v3.0 RETRY-KICKSTART: Nach retry_kickstart_after Sekunden
            # ===================================================================
            # Wenn nach 180s immer noch keine GSF-ID da ist, war der
            # erste Kickstart möglicherweise zu früh (Netz noch instabil).
            # Zweiter Anlauf mit erneutem suppress_system_dialogs() + kickstart.
            # ===================================================================
            if (
                not retry_done
                and retry_kickstart_after > 0
                and elapsed >= retry_kickstart_after
            ):
                retry_done = True
                logger.warning(
                    "GSF Smart Wait: %.0fs ohne GSF-ID — RETRY KICKSTART...",
                    elapsed,
                )
                try:
                    # Popups nochmal wegdrücken (könnten zurückgekommen sein)
                    await self.suppress_system_dialogs()
                    await asyncio.sleep(1)

                    # Zweiter Kickstart
                    retry_ok = await self.kickstart_gms()
                    logger.info(
                        "Retry Kickstart: %s — warte weiter auf GSF-ID...",
                        "OK" if retry_ok else "WARN",
                    )
                except Exception as e:
                    logger.warning("Retry Kickstart fehlgeschlagen: %s", e)

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

            # Status-Log alle 60 Sekunden (v3.0: war 30s, jetzt 60s wegen längerem Timeout)
            if elapsed - last_status_log >= 60:
                logger.info(
                    "GSF Smart Wait: %.0fs / %ds vergangen, %d Polls — "
                    "GSF-ID noch nicht da, warte...%s",
                    elapsed, timeout, polls,
                    " (Retry-Kickstart ausstehend)" if not retry_done else "",
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
