"""
Project Titan — NetworkChecker (IP-Ermittlung via ares_curl)
==============================================================

Ermittelt die öffentliche IP des Geräts (O2 Mobilfunk) über
einen DNS-Bypass-Trick:

  1. Mac löst DNS auf (socket.gethostbyname) → IP-Adresse
  2. Android führt ares_curl mit direkter IP + Host-Header aus
  3. Kein DNS auf dem Gerät nötig → keine DNS-Leaks

Binary: /data/local/tmp/ares_curl (ARM64, muss vorher gepusht sein)

Fallback-Kette (4 Services):
  1. ifconfig.me
  2. icanhazip.com
  3. api.ipify.org
  4. ifconfig.co
"""

from __future__ import annotations

import logging
import re
import socket
from dataclasses import dataclass
from typing import Optional

from host.adb.client import ADBClient, ADBError

logger = logging.getLogger("titan.engine.network")

# =============================================================================
# Konstanten
# =============================================================================

ARES_CURL_PATH = "/data/local/tmp/ares_curl"

# IP-Check Services (Fallback-Kette)
IP_SERVICES = [
    "ifconfig.me",
    "icanhazip.com",
    "api.ipify.org",
    "ifconfig.co",
]

# Wartezeit nach Flugmodus-AUS bevor IP-Check (Mobilfunk braucht Zeit)
IP_AUDIT_WAIT_SECONDS = 15

# Regex für IPv4 Validierung
_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)


# =============================================================================
# Result
# =============================================================================

@dataclass
class IPCheckResult:
    """Ergebnis einer IP-Ermittlung."""
    success: bool
    ip: Optional[str] = None
    service: Optional[str] = None   # Welcher Service hat geantwortet
    error: Optional[str] = None


# =============================================================================
# NetworkChecker
# =============================================================================

class NetworkChecker:
    """
    Ermittelt die öffentliche IP des Android-Geräts.

    Trick: DNS wird auf dem Mac aufgelöst, nicht auf Android.
    Das vermeidet DNS-Leaks über den O2-Mobilfunk-Tunnel.

    Usage:
        adb = ADBClient()
        checker = NetworkChecker(adb)

        # Prüfe ob ares_curl auf dem Gerät liegt
        await checker.ensure_tool()

        # IP ermitteln
        result = await checker.get_public_ip()
        print(result.ip)  # "185.xxx.xxx.xxx"
    """

    def __init__(self, adb: ADBClient):
        self._adb = adb

    # =========================================================================
    # Tool-Check: ares_curl muss auf dem Gerät liegen
    # =========================================================================

    async def ensure_tool(self) -> bool:
        """
        Prüft ob ares_curl auf dem Gerät existiert und ausführbar ist.

        Returns:
            True wenn Tool bereit
        """
        try:
            result = await self._adb.shell(
                f"test -x {ARES_CURL_PATH} && {ARES_CURL_PATH} --version",
                root=False,
                timeout=5,
            )
            if result.success and "curl" in result.stdout.lower():
                logger.debug("ares_curl bereit: %s", result.output.split("\n")[0])
                return True

            logger.warning(
                "ares_curl nicht funktionsfähig: exit=%d, output=%s",
                result.returncode, result.output[:100],
            )
            return False

        except ADBError as e:
            logger.error("ares_curl Check fehlgeschlagen: %s", e)
            return False

    # =========================================================================
    # IP ermitteln (Hauptmethode)
    # =========================================================================

    async def get_public_ip(self) -> IPCheckResult:
        """
        Ermittelt die öffentliche IP des Geräts.

        Ablauf pro Service:
          1. Mac: DNS auflösen (socket.gethostbyname)
          2. Android: ares_curl -s --max-time 10 -H 'Host: <service>' http://<ip>/

        Probiert alle Services der Fallback-Kette durch.

        Returns:
            IPCheckResult mit IP oder Fehler
        """
        for service in IP_SERVICES:
            try:
                result = await self._check_service(service)
                if result.success:
                    return result
            except Exception as e:
                logger.debug("Service %s fehlgeschlagen: %s", service, e)
                continue

        return IPCheckResult(
            success=False,
            error=f"Alle {len(IP_SERVICES)} Services fehlgeschlagen",
        )

    # =========================================================================
    # Einzelnen Service abfragen
    # =========================================================================

    async def _check_service(self, hostname: str) -> IPCheckResult:
        """
        Fragt einen einzelnen IP-Service ab.

        Schritt A: DNS auf dem Mac auflösen (NICHT auf Android!)
        Schritt B: ares_curl auf Android mit direkter IP + Host-Header
        Schritt C: Antwort validieren (IPv4-Format)
        """
        # --- Schritt A: DNS auf dem Mac ---
        try:
            ip_address = socket.gethostbyname(hostname)
            logger.debug("DNS (Mac): %s → %s", hostname, ip_address)
        except socket.gaierror as e:
            logger.debug("DNS Fehler für %s: %s", hostname, e)
            return IPCheckResult(success=False, error=f"DNS: {hostname} → {e}")

        # --- Schritt B: ares_curl auf Android ---
        cmd = (
            f"{ARES_CURL_PATH} -s --max-time 10 "
            f"-H 'Host: {hostname}' "
            f"http://{ip_address}/"
        )

        try:
            result = await self._adb.shell(cmd, root=False, timeout=15)
        except ADBError as e:
            return IPCheckResult(success=False, error=f"ADB: {e}")

        if not result.success:
            return IPCheckResult(
                success=False,
                error=f"{hostname}: exit={result.returncode}",
            )

        # --- Schritt C: Antwort parsen + validieren ---
        raw = result.output.strip()

        # HTML-Tags entfernen falls vorhanden
        raw = re.sub(r"<[^>]+>", "", raw).strip()

        # Nur die erste Zeile (manche Services geben Extras aus)
        ip_str = raw.split("\n")[0].strip()

        if self._is_valid_ipv4(ip_str):
            logger.info("Öffentliche IP via %s: %s", hostname, ip_str)
            return IPCheckResult(success=True, ip=ip_str, service=hostname)

        return IPCheckResult(
            success=False,
            error=f"{hostname}: Ungültige Antwort: {ip_str[:50]}",
        )

    # =========================================================================
    # IPv4 Validierung
    # =========================================================================

    @staticmethod
    def _is_valid_ipv4(ip: str) -> bool:
        """Prüft ob ein String eine gültige IPv4-Adresse ist."""
        return bool(_IPV4_RE.match(ip))
