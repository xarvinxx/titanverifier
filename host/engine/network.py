"""
NetworkChecker v4.1 (Cached IP-Ermittlung)
===========================================

Ermittelt die öffentliche IP des Android-Geräts über O2 Mobilfunk.

v4.1 — Performance-Optimierungen:
  - Tool-Detection wird EINMALIG ausgeführt und global gecacht
  - IP-Ergebnis wird mit 60s TTL gecacht (kein Spam bei Dashboard-Polls)
  - Detection-Fehlschläge werden als DEBUG geloggt (kein WARNING-Spam)
  - Erfolg wird nur einmal pro Cache-Zyklus geloggt

v4.0 — Automatische Tool-Erkennung:
  1. ares_curl  → /data/local/tmp/ares_curl (falls gepusht, DNS-Bypass)
  2. curl       → System curl (falls vorhanden)
  3. busybox    → /data/adb/ksu/bin/busybox wget (KernelSU — immer verfügbar)

Fallback-Kette (5 Services):
  1. api.ipify.org          (plain text, kein HTML)
  2. icanhazip.com          (plain text)
  3. ifconfig.me            (plain text)
  4. ifconfig.co            (plain text)
  5. checkip.amazonaws.com  (plain text)

IPv4 + IPv6 werden unterstützt.
Mobilfunk-optimierte Timeouts (15s pro Request).
"""

from __future__ import annotations

import logging
import re
import socket
import time
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from host.adb.client import ADBClient, ADBError

logger = logging.getLogger("host.network")

# =============================================================================
# Konstanten
# =============================================================================

ARES_CURL_PATH = "/data/local/tmp/ares_curl"
BUSYBOX_KSU_PATH = "/data/adb/ksu/bin/busybox"

# IP-Check Services (Fallback-Kette, zuverlässigste zuerst)
IP_SERVICES = [
    "api.ipify.org",
    "icanhazip.com",
    "ifconfig.me",
    "ifconfig.co",
    "checkip.amazonaws.com",
]

# Wartezeit nach Flugmodus-AUS bevor IP-Check (Mobilfunk braucht Zeit)
IP_AUDIT_WAIT_SECONDS = 15

# Timeout für einzelne Requests (Mobilfunk kann langsam sein)
REQUEST_TIMEOUT_SECONDS = 15

# Cache-TTL für IP-Ergebnis (Sekunden)
IP_CACHE_TTL_SECONDS = 60

# Regex für IP-Validierung
_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_IPV6_RE = re.compile(
    r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$"
)


# =============================================================================
# HTTP-Tool Enum
# =============================================================================

class HttpTool(str, Enum):
    """Verfügbare HTTP-Tools auf dem Android-Gerät."""
    ARES_CURL = "ares_curl"
    CURL = "curl"
    BUSYBOX_WGET = "busybox_wget"
    NONE = "none"


# =============================================================================
# Result
# =============================================================================

@dataclass
class IPCheckResult:
    """Ergebnis einer IP-Ermittlung."""
    success: bool
    ip: Optional[str] = None
    service: Optional[str] = None
    tool: Optional[str] = None
    error: Optional[str] = None
    cached: bool = False              # True wenn aus Cache


# =============================================================================
# Globaler Cache (Modul-Level — überlebt Instanzen)
# =============================================================================

class _ToolCache:
    """
    Globaler Cache für Tool-Detection und IP-Ergebnis.

    Wird auf Modul-Ebene gehalten, damit nicht jede NetworkChecker-Instanz
    die Tool-Detection neu ausführt. Besonders wichtig für den Dashboard-
    Endpoint der alle 3 Sekunden pollt.
    """
    tool: HttpTool = HttpTool.NONE
    tool_path: str = ""
    detected: bool = False

    # IP-Cache
    last_ip_result: Optional[IPCheckResult] = None
    last_ip_time: float = 0.0         # time.monotonic()


_cache = _ToolCache()


# =============================================================================
# NetworkChecker v4.1
# =============================================================================

class NetworkChecker:
    """
    Ermittelt die öffentliche IP des Android-Geräts.

    v4.1 Verbesserungen:
      - Globaler Tool-Detection-Cache (einmalig pro Session)
      - IP-Cache mit 60s TTL (kein Spam bei Dashboard-Polls)
      - Leise Detection (DEBUG statt WARNING für fehlende Tools)

    Usage:
        adb = ADBClient()
        checker = NetworkChecker(adb)
        result = await checker.get_public_ip()
        print(result.ip)  # "176.x.x.x"
    """

    def __init__(self, adb: ADBClient):
        self._adb = adb

    @property
    def active_tool(self) -> HttpTool:
        """Aktuell verwendetes HTTP-Tool."""
        return _cache.tool

    # =========================================================================
    # Tool-Erkennung (einmalig, global gecacht)
    # =========================================================================

    async def detect_tool(self, force: bool = False) -> HttpTool:
        """
        Erkennt das beste verfügbare HTTP-Tool auf dem Gerät.

        Ergebnis wird global gecacht — nachfolgende Aufrufe returnen sofort.
        Mit force=True kann ein Re-Detect erzwungen werden.

        Reihenfolge (Priorität):
          1. ares_curl  — Custom binary mit vollem TLS + DNS-Bypass
          2. curl       — System curl (falls vorhanden)
          3. busybox    — KSU busybox wget (immer verfügbar bei KernelSU)

        Returns:
            Erkanntes HttpTool
        """
        if _cache.detected and not force:
            return _cache.tool

        # --- 1. ares_curl ---
        try:
            result = await self._adb.shell(
                f"test -x {ARES_CURL_PATH} && {ARES_CURL_PATH} --version 2>&1 | head -1",
                root=False, timeout=5,
            )
            if result.success and "curl" in result.stdout.lower():
                _cache.tool = HttpTool.ARES_CURL
                _cache.tool_path = ARES_CURL_PATH
                _cache.detected = True
                logger.info("HTTP-Tool erkannt: ares_curl (%s)", result.stdout.strip()[:60])
                return _cache.tool
        except (ADBError, Exception):
            pass
        logger.debug("Tool-Detection: ares_curl nicht verfügbar")

        # --- 2. System curl ---
        try:
            result = await self._adb.shell(
                "which curl 2>/dev/null && curl --version 2>&1 | head -1",
                root=False, timeout=5,
            )
            if result.success and "curl" in result.stdout.lower():
                curl_path = result.stdout.strip().split("\n")[0].strip()
                _cache.tool = HttpTool.CURL
                _cache.tool_path = curl_path
                _cache.detected = True
                logger.info("HTTP-Tool erkannt: system curl (%s)", curl_path)
                return _cache.tool
        except (ADBError, Exception):
            pass
        logger.debug("Tool-Detection: system curl nicht verfügbar")

        # --- 3. KSU busybox wget ---
        try:
            result = await self._adb.shell(
                f"test -x {BUSYBOX_KSU_PATH} && {BUSYBOX_KSU_PATH} wget 2>&1 | head -1",
                root=True, timeout=5,
            )
            if result.success or "wget" in (result.output or "").lower():
                _cache.tool = HttpTool.BUSYBOX_WGET
                _cache.tool_path = BUSYBOX_KSU_PATH
                _cache.detected = True
                logger.info("HTTP-Tool erkannt: busybox wget (%s)", BUSYBOX_KSU_PATH)
                return _cache.tool
        except (ADBError, Exception):
            pass
        logger.debug("Tool-Detection: busybox wget nicht verfügbar")

        # --- Kein Tool gefunden ---
        _cache.tool = HttpTool.NONE
        _cache.tool_path = ""
        _cache.detected = True
        logger.error(
            "KEIN HTTP-Tool auf Gerät gefunden! "
            "Benötigt: ares_curl, curl, oder busybox (KSU)."
        )
        return _cache.tool

    # =========================================================================
    # Legacy: ensure_tool (Kompatibilität)
    # =========================================================================

    async def ensure_tool(self) -> bool:
        """Kompatibilitäts-Wrapper. Prüft ob ein HTTP-Tool verfügbar ist."""
        if not _cache.detected:
            await self.detect_tool()
        return _cache.tool != HttpTool.NONE

    # =========================================================================
    # Cache invalidieren (nach Flugmodus-Cycle oder Reboot)
    # =========================================================================

    @staticmethod
    def invalidate_ip_cache() -> None:
        """
        Invalidiert den IP-Cache.

        Sollte aufgerufen werden wenn sich die IP sicher geändert hat:
          - Nach Flugmodus-Cycle (neue Mobilfunk-IP)
          - Nach Reboot
          - Nach Identity-Switch
        """
        _cache.last_ip_result = None
        _cache.last_ip_time = 0.0
        logger.debug("IP-Cache invalidiert")

    @staticmethod
    def invalidate_tool_cache() -> None:
        """Invalidiert den Tool-Cache (z.B. nach Push von ares_curl)."""
        _cache.detected = False
        logger.debug("Tool-Cache invalidiert")

    # =========================================================================
    # IP ermitteln (Hauptmethode, mit Cache)
    # =========================================================================

    async def get_public_ip(self, skip_cache: bool = False) -> IPCheckResult:
        """
        Ermittelt die öffentliche IP des Geräts.

        Cached das Ergebnis für IP_CACHE_TTL_SECONDS (Default: 60s).
        Bei skip_cache=True wird immer frisch abgefragt.

        Returns:
            IPCheckResult mit IP oder Fehler
        """
        # --- Cache-Check ---
        if not skip_cache and _cache.last_ip_result and _cache.last_ip_result.success:
            age = time.monotonic() - _cache.last_ip_time
            if age < IP_CACHE_TTL_SECONDS:
                return IPCheckResult(
                    success=True,
                    ip=_cache.last_ip_result.ip,
                    service=_cache.last_ip_result.service,
                    tool=_cache.last_ip_result.tool,
                    cached=True,
                )

        # --- Tool-Detection (einmalig) ---
        if not _cache.detected:
            await self.detect_tool()

        if _cache.tool == HttpTool.NONE:
            return IPCheckResult(
                success=False,
                error="Kein HTTP-Tool auf Gerät verfügbar (ares_curl/curl/busybox fehlt)",
            )

        # --- Frische IP-Abfrage ---
        errors: list[str] = []
        for service in IP_SERVICES:
            try:
                result = await self._check_service(service)
                if result.success:
                    # In Cache speichern
                    _cache.last_ip_result = result
                    _cache.last_ip_time = time.monotonic()
                    logger.info(
                        "Öffentliche IP: %s (via %s, %s) — Cache für %ds",
                        result.ip, result.service, _cache.tool.value,
                        IP_CACHE_TTL_SECONDS,
                    )
                    return result
                if result.error:
                    errors.append(result.error)
            except Exception as e:
                logger.debug("Service %s Exception: %s", service, e)
                errors.append(f"{service}: {e}")
                continue

        return IPCheckResult(
            success=False,
            error=(
                f"Alle {len(IP_SERVICES)} Services fehlgeschlagen "
                f"(Tool: {_cache.tool.value}). "
                f"Letzter Fehler: {errors[-1] if errors else 'unbekannt'}"
            ),
        )

    # =========================================================================
    # Service-Check (Dispatcher)
    # =========================================================================

    async def _check_service(self, hostname: str) -> IPCheckResult:
        """Fragt einen einzelnen IP-Service ab."""
        if _cache.tool == HttpTool.ARES_CURL:
            return await self._check_via_ares_curl(hostname)
        elif _cache.tool == HttpTool.CURL:
            return await self._check_via_curl(hostname)
        elif _cache.tool == HttpTool.BUSYBOX_WGET:
            return await self._check_via_busybox_wget(hostname)
        else:
            return IPCheckResult(success=False, error="Kein Tool verfügbar")

    # =========================================================================
    # ares_curl (DNS-Bypass via Mac)
    # =========================================================================

    async def _check_via_ares_curl(self, hostname: str) -> IPCheckResult:
        """IP-Check via ares_curl mit DNS-Bypass."""
        try:
            resolved_ip = socket.gethostbyname(hostname)
        except socket.gaierror as e:
            return IPCheckResult(success=False, error=f"DNS: {hostname} → {e}")

        cmd = (
            f"{_cache.tool_path} -s --max-time {REQUEST_TIMEOUT_SECONDS} "
            f"-H 'Host: {hostname}' "
            f"http://{resolved_ip}/"
        )
        return await self._execute_and_parse(cmd, hostname, root=False)

    # =========================================================================
    # System curl (direkter HTTPS-Request)
    # =========================================================================

    async def _check_via_curl(self, hostname: str) -> IPCheckResult:
        """IP-Check via system curl mit HTTPS."""
        cmd = (
            f"{_cache.tool_path} -s --max-time {REQUEST_TIMEOUT_SECONDS} "
            f"https://{hostname}/"
        )
        return await self._execute_and_parse(cmd, hostname, root=False)

    # =========================================================================
    # busybox wget (KernelSU)
    # =========================================================================

    async def _check_via_busybox_wget(self, hostname: str) -> IPCheckResult:
        """IP-Check via KSU busybox wget (HTTP, root)."""
        cmd = (
            f"{_cache.tool_path} wget -qO- "
            f"-T {REQUEST_TIMEOUT_SECONDS} "
            f"http://{hostname}/ 2>/dev/null"
        )
        return await self._execute_and_parse(cmd, hostname, root=True)

    # =========================================================================
    # Gemeinsame Ausführung + Parsing
    # =========================================================================

    async def _execute_and_parse(
        self, cmd: str, hostname: str, root: bool = False,
    ) -> IPCheckResult:
        """Führt den HTTP-Befehl aus und parst die Antwort."""
        try:
            result = await self._adb.shell(
                cmd, root=root, timeout=REQUEST_TIMEOUT_SECONDS + 5,
            )
        except ADBError as e:
            return IPCheckResult(
                success=False,
                error=f"{hostname}: ADB-Fehler: {e}",
                tool=_cache.tool.value,
            )

        if not result.success:
            return IPCheckResult(
                success=False,
                error=f"{hostname}: exit={result.returncode} ({_cache.tool.value})",
                tool=_cache.tool.value,
            )

        # Antwort parsen
        raw = result.output.strip()
        raw = re.sub(r"<[^>]+>", "", raw).strip()
        ip_str = raw.split("\n")[0].strip()

        if self._is_valid_ip(ip_str):
            return IPCheckResult(
                success=True,
                ip=ip_str,
                service=hostname,
                tool=_cache.tool.value,
            )

        return IPCheckResult(
            success=False,
            error=f"{hostname}: Ungültige Antwort: '{ip_str[:80]}'",
            tool=_cache.tool.value,
        )

    # =========================================================================
    # IP-Validierung (IPv4 + IPv6)
    # =========================================================================

    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        """Prüft ob ein String eine gültige IPv4- oder IPv6-Adresse ist."""
        if _IPV4_RE.match(ip):
            return True
        if _IPV6_RE.match(ip):
            return True
        try:
            socket.inet_pton(socket.AF_INET, ip)
            return True
        except OSError:
            pass
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            return True
        except OSError:
            pass
        return False

    # =========================================================================
    # IP-Rotation mit Verifikation (Flugmodus-Cycle + Retry)
    # =========================================================================

    async def rotate_ip(
        self,
        old_ip: Optional[str] = None,
        max_retries: int = 5,
        reconnect_wait: int = 15,
        lease_wait: int = 12,
    ) -> IPCheckResult:
        """
        Rotiert die IP via Flugmodus-Cycle und verifiziert den Wechsel.

        Ablauf pro Versuch:
          1. Flugmodus AN → lease_wait Sekunden → Flugmodus AUS
          2. reconnect_wait Sekunden warten (Mobilfunk-Reconnect)
          3. Neue IP abfragen (skip_cache=True)
          4. Vergleich: neue_IP != alte_IP → Erfolg
          5. Sonst: Retry (max max_retries Versuche)

        Nach erfolgreichem IP-Wechsel wird zusätzlich ein IPv6-Leak-Check
        durchgeführt.

        Args:
            old_ip:          Bisherige IP (wenn None, wird sie zuerst ermittelt)
            max_retries:     Max. Anzahl Flugmodus-Toggles (Default: 5)
            reconnect_wait:  Sekunden nach Flugmodus-AUS bis IP-Check
            lease_wait:      Sekunden mit Flugmodus-AN (DHCP-Lease-Reset)

        Returns:
            IPCheckResult mit der neuen IP (oder Fehler nach max_retries)
        """
        # Alte IP ermitteln falls nicht übergeben
        if old_ip is None:
            old_result = await self.get_public_ip(skip_cache=True)
            if old_result.success:
                old_ip = old_result.ip
                logger.info("[IP-Rotation] Aktuelle IP: %s", old_ip)
            else:
                logger.warning(
                    "[IP-Rotation] Konnte aktuelle IP nicht ermitteln — "
                    "Rotation wird trotzdem versucht"
                )

        for attempt in range(1, max_retries + 1):
            logger.info(
                "[IP-Rotation] Versuch %d/%d — Flugmodus-Cycle starten...",
                attempt, max_retries,
            )

            # Flugmodus AN
            await self._adb.shell(
                "settings put global airplane_mode_on 1", root=True,
            )
            await self._adb.shell(
                "am broadcast -a android.intent.action.AIRPLANE_MODE "
                "--ez state true",
                root=True,
            )
            logger.debug("[IP-Rotation] Flugmodus AN — warte %ds (Lease-Reset)...", lease_wait)

            # Lease-Wait (DHCP-Lease verfallen lassen)
            import asyncio
            await asyncio.sleep(lease_wait)

            # Flugmodus AUS
            await self._adb.shell(
                "settings put global airplane_mode_on 0", root=True,
            )
            await self._adb.shell(
                "am broadcast -a android.intent.action.AIRPLANE_MODE "
                "--ez state false",
                root=True,
            )

            # IP-Cache invalidieren
            self.invalidate_ip_cache()

            # Mobilfunk-Reconnect abwarten
            logger.debug(
                "[IP-Rotation] Flugmodus AUS — warte %ds auf Reconnect...",
                reconnect_wait,
            )
            await asyncio.sleep(reconnect_wait)

            # Neue IP abfragen
            new_result = await self.get_public_ip(skip_cache=True)

            if not new_result.success:
                logger.warning(
                    "[IP-Rotation] Versuch %d: IP-Check fehlgeschlagen: %s",
                    attempt, new_result.error,
                )
                continue

            new_ip = new_result.ip

            if old_ip and new_ip == old_ip:
                logger.warning(
                    "[IP-Rotation] Versuch %d: IP NICHT gewechselt! "
                    "%s == %s — Retry...",
                    attempt, new_ip, old_ip,
                )
                continue

            # IP hat sich geändert!
            logger.info(
                "[IP-Rotation] Erfolg nach %d Versuch(en): %s → %s",
                attempt, old_ip or "?", new_ip,
            )

            # IPv6-Leak-Check nach erfolgreichem IP-Wechsel
            await self.check_ipv6_leak()

            return new_result

        # Alle Versuche fehlgeschlagen
        logger.error(
            "[IP-Rotation] IP-Wechsel nach %d Versuchen FEHLGESCHLAGEN! "
            "IP bleibt: %s — Carrier throttling?",
            max_retries, old_ip or "unbekannt",
        )
        return IPCheckResult(
            success=False,
            error=(
                f"IP-Rotation fehlgeschlagen nach {max_retries} Versuchen. "
                f"IP unverändert: {old_ip or 'unbekannt'}. "
                f"Mögliche Ursache: Carrier-Throttling oder feste IP-Zuweisung."
            ),
        )

    # =========================================================================
    # IPv6-Leak-Detection
    # =========================================================================

    async def check_ipv6_leak(self) -> dict:
        """
        Prüft ob das Gerät über IPv6 erreichbar ist (Leak-Detection).

        Viele Carrier vergeben zusätzlich eine IPv6-Adresse. Da TikTok und
        andere Apps bevorzugt IPv6 nutzen, kann die IPv6-Adresse über
        Flugmodus-Cycles hinweg STABIL bleiben, auch wenn sich die IPv4
        ändert. Das ist ein Tracking-Vektor.

        Prüfung:
          1. `ip -6 addr show rmnet_data0` → Hat das Mobilfunk-Interface IPv6?
          2. Falls ja: Warnung ausgeben (IPv6 sollte deaktiviert werden)

        Returns:
            {"has_ipv6": bool, "ipv6_address": str|None, "warning": str|None}
        """
        result = {"has_ipv6": False, "ipv6_address": None, "warning": None}

        try:
            # Prüfe IPv6 auf Mobilfunk-Interfaces (rmnet_data*, ccmni*)
            ipv6_check = await self._adb.shell(
                "ip -6 addr show scope global 2>/dev/null "
                "| grep 'inet6' | grep -v '::1' | head -3",
                root=False, timeout=5,
            )

            if ipv6_check.success and ipv6_check.output.strip():
                lines = ipv6_check.output.strip().split("\n")
                for line in lines:
                    line = line.strip()
                    if "inet6" in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            ipv6_addr = parts[1].split("/")[0]
                            result["has_ipv6"] = True
                            result["ipv6_address"] = ipv6_addr
                            result["warning"] = (
                                f"IPv6-LEAK ERKANNT: {ipv6_addr} — "
                                f"IPv6 kann über IP-Rotation hinweg stabil "
                                f"bleiben und als Tracking-Vektor dienen! "
                                f"Empfehlung: IPv6 auf dem Carrier deaktivieren "
                                f"oder APN auf IPv4-only setzen."
                            )
                            logger.warning(
                                "[IPv6-Leak] %s", result["warning"],
                            )
                            break

            if not result["has_ipv6"]:
                logger.debug("[IPv6-Leak] Kein globaler IPv6-Scope — sauber")

        except (ADBError, Exception) as e:
            logger.debug("[IPv6-Leak] Check fehlgeschlagen: %s", e)

        return result

    @staticmethod
    def _is_valid_ipv4(ip: str) -> bool:
        """Legacy: Prüft ob ein String eine gültige IPv4-Adresse ist."""
        return bool(_IPV4_RE.match(ip))
