"""
Async ADB Client v4.0
======================

Robuster, asynchroner Wrapper um das `adb` CLI-Tool.

Features:
  - Vollständig async (asyncio.create_subprocess_exec)
  - Automatische Retry-Logik (3 Versuche, exponential backoff)
  - Strukturierte Ergebnisse (ADBResult)
  - Root-Shell via `su -c` (KernelSU kompatibel)
  - Timeout-Protection für jeden Befehl
  - Device-State Monitoring (connected, booted, ...)
  - *** v4.0 *** Auto-Reconnect bei ADB-Verbindungsverlust
    Bei "no devices/emulators found" wird automatisch
    `adb wait-for-device` ausgeführt + ADB-Daemon neugestartet.
    Kein manuelles Eingreifen nötig, auch nicht nach Reboot.

Alle ADB-Befehle werden über diese Klasse geroutet.
Kein direkter subprocess-Aufruf an anderer Stelle im Projekt.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Optional

from host.config import TIMING

logger = logging.getLogger("host.adb")


# =============================================================================
# Exceptions
# =============================================================================

class ADBError(Exception):
    """Basis-Exception für ADB-Fehler."""

    def __init__(self, message: str, returncode: int = -1, stderr: str = ""):
        self.returncode = returncode
        self.stderr = stderr
        super().__init__(message)


class ADBConnectionError(ADBError):
    """Gerät nicht verbunden oder ADB-Daemon nicht erreichbar."""
    pass


class ADBTimeoutError(ADBError):
    """Befehl hat das Timeout überschritten."""
    pass


# =============================================================================
# Result
# =============================================================================

@dataclass
class ADBResult:
    """Strukturiertes Ergebnis eines ADB-Befehls."""
    returncode: int
    stdout: str = ""
    stderr: str = ""
    command: str = ""
    attempts: int = 1

    @property
    def success(self) -> bool:
        return self.returncode == 0

    @property
    def output(self) -> str:
        """Gibt stdout zurück, gestripped."""
        return self.stdout.strip()


# =============================================================================
# ADB Client
# =============================================================================

class ADBClient:
    """
    Asynchroner ADB-Client mit Retry-Logik.

    Usage:
        adb = ADBClient()

        # Einfacher Shell-Befehl
        result = await adb.shell("id")

        # Root-Shell (via su -c)
        result = await adb.shell("cat /data/adb/modules/hw_overlay/.hw_config",
                                 root=True)

        # Datei pushen
        await adb.push("/tmp/bridge.txt", "/data/local/tmp/bridge.txt")

        # Reboot
        await adb.reboot()
    """

    # Maximale Zeit die ensure_connection auf das Gerät wartet (Sekunden)
    ADB_RECONNECT_TIMEOUT = 120

    def __init__(
        self,
        max_retries: int = 3,
        retry_delay: float = 2.0,
        timeout: int = TIMING.ADB_COMMAND_TIMEOUT,
    ):
        self._max_retries = max_retries
        self._retry_delay = retry_delay
        self._timeout = timeout
        self._reconnecting: bool = False

    # =========================================================================
    # v4.0: Auto-Reconnect — ADB-Verbindung garantieren
    # =========================================================================

    async def ensure_connection(self, timeout: int = 0) -> bool:
        """
        Stellt sicher, dass ein ADB-Gerät verbunden und erreichbar ist.

        Ablauf:
          1. Schneller Check: `adb get-state` → wenn "device" → sofort OK
          2. ADB-Daemon Kill + Restart (behebt hängende Daemons)
          3. `adb wait-for-device` (wartet bis USB/TCP-Verbindung steht)
          4. Verify: `adb get-state` nochmal prüfen

        Wird automatisch von _exec() aufgerufen bei Connection-Errors.
        Kann auch manuell aufgerufen werden (z.B. nach Reboot).

        Args:
            timeout: Maximale Wartezeit in Sekunden (0 = ADB_RECONNECT_TIMEOUT)

        Returns:
            True wenn Gerät verbunden
        """
        effective_timeout = timeout or self.ADB_RECONNECT_TIMEOUT

        # --- 1. Quick-Check ---
        try:
            proc = await asyncio.create_subprocess_exec(
                "adb", "get-state",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
            if proc.returncode == 0 and "device" in stdout.decode():
                return True
        except (asyncio.TimeoutError, OSError):
            pass

        # --- 2. ADB-Daemon Kill + Restart ---
        logger.warning(
            "ADB-Verbindung verloren — starte Reconnect "
            "(max %ds)...", effective_timeout,
        )

        try:
            # kill-server beendet den ADB-Daemon sauber
            proc = await asyncio.create_subprocess_exec(
                "adb", "kill-server",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=5)
            logger.info("ADB Daemon gestoppt")
        except (asyncio.TimeoutError, OSError):
            pass

        await asyncio.sleep(1)

        try:
            # start-server startet den Daemon neu
            proc = await asyncio.create_subprocess_exec(
                "adb", "start-server",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=10)
            logger.info("ADB Daemon gestartet")
        except (asyncio.TimeoutError, OSError):
            pass

        await asyncio.sleep(1)

        # --- 3. wait-for-device (blockiert bis Gerät da ist) ---
        logger.info("ADB wait-for-device (max %ds)...", effective_timeout)
        try:
            proc = await asyncio.create_subprocess_exec(
                "adb", "wait-for-device",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=effective_timeout)
            logger.info("ADB wait-for-device: Gerät gefunden")
        except asyncio.TimeoutError:
            logger.error(
                "ADB wait-for-device: Timeout nach %ds — "
                "Gerät nicht erreichbar!", effective_timeout,
            )
            return False
        except OSError:
            return False

        # --- 4. Verify ---
        await asyncio.sleep(2)  # Kurz warten bis ADB-Auth abgeschlossen
        try:
            proc = await asyncio.create_subprocess_exec(
                "adb", "get-state",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
            if proc.returncode == 0 and "device" in stdout.decode():
                logger.info("ADB Reconnect erfolgreich — Gerät verbunden")
                return True
            else:
                state = stdout.decode().strip()
                logger.warning("ADB Reconnect: Gerät-State = '%s' (nicht 'device')", state)
                # Auch "unauthorized" loggen
                if "unauthorized" in state:
                    logger.error(
                        "ADB UNAUTHORIZED — bitte USB-Debugging auf dem Gerät bestätigen! "
                        "(Dialog 'USB-Debugging erlauben?')"
                    )
        except (asyncio.TimeoutError, OSError):
            pass

        # =================================================================
        # FIX-6: USB-Reconnect Simulation als letzter Fallback
        # =================================================================
        # Wenn normaler kill-server/start-server/wait-for-device nicht hilft,
        # liegt das Problem oft an einem "Zombie-State" des USB-Stacks.
        # Ein USB-Modus-Toggle erzwingt ein Hardware-Reconnect.
        # =================================================================
        logger.warning(
            "FIX-6: Standard-Reconnect fehlgeschlagen — "
            "versuche USB-Modus-Toggle (Fallback)..."
        )
        try:
            # Schritt 1: USB-Modus auf "none" (trennt Verbindung)
            proc = await asyncio.create_subprocess_exec(
                "adb", "shell", "su -c 'setprop sys.usb.config none'",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=5)
            logger.info("FIX-6: USB-Modus auf 'none' gesetzt")
            await asyncio.sleep(2)

            # Schritt 2: USB-Modus auf "mtp,adb" (verbindet neu)
            proc = await asyncio.create_subprocess_exec(
                "adb", "shell", "su -c 'setprop sys.usb.config mtp,adb'",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=5)
            logger.info("FIX-6: USB-Modus auf 'mtp,adb' gesetzt")
            await asyncio.sleep(3)

            # Schritt 3: Erneut wait-for-device
            proc = await asyncio.create_subprocess_exec(
                "adb", "wait-for-device",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=30)

            # Schritt 4: Finaler Verify
            await asyncio.sleep(2)
            proc = await asyncio.create_subprocess_exec(
                "adb", "get-state",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
            if proc.returncode == 0 and "device" in stdout.decode():
                logger.info("FIX-6: USB-Reconnect erfolgreich — Gerät verbunden")
                return True
            else:
                logger.error(
                    "FIX-6: USB-Reconnect fehlgeschlagen — State: %s",
                    stdout.decode().strip(),
                )
        except (asyncio.TimeoutError, OSError) as e:
            logger.error("FIX-6: USB-Reconnect Fehler: %s", e)

        return False

    # =========================================================================
    # Core: Befehl ausführen mit Retry + Auto-Reconnect
    # =========================================================================

    async def _exec(
        self,
        args: list[str],
        timeout: Optional[int] = None,
        retries: Optional[int] = None,
        binary: bool = False,
    ) -> ADBResult:
        """
        Führt `adb <args>` asynchron aus mit automatischem Retry.

        v4.0: Bei ADB-Verbindungsfehler wird automatisch ensure_connection()
        aufgerufen (ADB-Daemon Restart + wait-for-device), bevor der Retry
        startet. Das garantiert, dass ein Reboot oder USB-Disconnect den
        Flow nicht permanent zerstört.

        Args:
            args:    Argumente für adb (z.B. ["shell", "id"])
            timeout: Timeout in Sekunden (None = Default)
            retries: Anzahl Retries (None = Default)
            binary:  True = stdout als bytes lesen (für tar-Streams)

        Returns:
            ADBResult mit returncode, stdout, stderr

        Raises:
            ADBTimeoutError:     nach Timeout
            ADBConnectionError:  nach allen Retries + Reconnect gescheitert
            ADBError:            sonstiger Fehler
        """
        effective_timeout = timeout or self._timeout
        effective_retries = retries if retries is not None else self._max_retries
        cmd_str = f"adb {' '.join(args)}"
        last_error: Optional[Exception] = None

        for attempt in range(1, effective_retries + 1):
            try:
                logger.debug("ADB [%d/%d]: %s", attempt, effective_retries, cmd_str)

                proc = await asyncio.create_subprocess_exec(
                    "adb", *args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

                try:
                    stdout_raw, stderr_raw = await asyncio.wait_for(
                        proc.communicate(),
                        timeout=effective_timeout,
                    )
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
                    raise ADBTimeoutError(
                        f"Timeout ({effective_timeout}s) bei: {cmd_str}",
                        returncode=-1,
                    )

                stdout_str = "" if binary else stdout_raw.decode("utf-8", errors="replace")
                stderr_str = stderr_raw.decode("utf-8", errors="replace")

                result = ADBResult(
                    returncode=proc.returncode or 0,
                    stdout=stdout_str,
                    stderr=stderr_str,
                    command=cmd_str,
                    attempts=attempt,
                )

                # Prüfe auf ADB-Verbindungsfehler (retry-worthy)
                if self._is_connection_error(stderr_str):
                    raise ADBConnectionError(
                        f"ADB Verbindungsfehler: {stderr_str.strip()}",
                        returncode=proc.returncode or -1,
                        stderr=stderr_str,
                    )

                if result.success:
                    if attempt > 1:
                        logger.info("ADB Erfolg nach %d Versuchen: %s", attempt, cmd_str)
                    return result

                # Nicht-Null Exit, aber kein Verbindungsfehler → kein Retry
                # DEBUG statt WARNING: viele Shell-Befehle (test, which, grep)
                # haben legitimerweise non-zero exit codes.
                logger.debug(
                    "ADB exit=%d: %s | stderr: %s",
                    result.returncode, cmd_str, stderr_str.strip()[:200],
                )
                return result

            except ADBTimeoutError:
                raise  # Timeouts nicht retrien

            except ADBConnectionError as e:
                last_error = e

                if attempt < effective_retries:
                    # =========================================================
                    # v4.0 AUTO-RECONNECT: Bei Connection-Error ADB reparieren
                    # =========================================================
                    # Statt nur zu warten, aktiv den ADB-Daemon neu starten
                    # und auf das Gerät warten. Das überbrückt Reboots,
                    # USB-Disconnects und Auth-Probleme.
                    # =========================================================
                    if not self._reconnecting:
                        self._reconnecting = True
                        try:
                            logger.warning(
                                "ADB Verbindungsfehler (Versuch %d/%d) — "
                                "starte Auto-Reconnect...",
                                attempt, effective_retries,
                            )
                            reconnected = await self.ensure_connection()
                            if reconnected:
                                logger.info(
                                    "Auto-Reconnect erfolgreich — "
                                    "wiederhole Befehl: %s", cmd_str,
                                )
                            else:
                                logger.warning(
                                    "Auto-Reconnect fehlgeschlagen — "
                                    "versuche trotzdem Retry %d/%d",
                                    attempt + 1, effective_retries,
                                )
                        finally:
                            self._reconnecting = False
                    else:
                        # Bereits im Reconnect — einfach kurz warten
                        delay = self._retry_delay * (2 ** (attempt - 1))
                        await asyncio.sleep(delay)

                    continue

                # Alle Retries aufgebraucht
                raise

            except OSError as e:
                # adb binary nicht gefunden
                raise ADBError(f"ADB nicht gefunden: {e}") from e

        # Sollte nie erreicht werden, aber safety net
        raise last_error or ADBError(f"ADB fehlgeschlagen nach {effective_retries} Versuchen")

    @staticmethod
    def _is_connection_error(stderr: str) -> bool:
        """
        Erkennt ADB-Verbindungsfehler die einen Retry + Reconnect rechtfertigen.

        v4.0: Erweitert um alle bekannten ADB-Disconnection-Patterns,
        insbesondere "no devices/emulators found" (häufig nach Reboot).
        """
        indicators = [
            "error: device not found",
            "error: no devices",
            "no devices/emulators found",
            "error: device offline",
            "error: closed",
            "cannot connect to daemon",
            "connection refused",
            "adb: error: failed to get feature set",
            "protocol fault",
            "error: device unauthorized",
            "error: device still authorizing",
            "more than one device",
        ]
        stderr_lower = stderr.lower()
        return any(ind.lower() in stderr_lower for ind in indicators)

    # =========================================================================
    # Public API: Shell
    # =========================================================================

    async def shell(
        self,
        command: str,
        root: bool = False,
        timeout: Optional[int] = None,
        check: bool = False,
    ) -> ADBResult:
        """
        Führt einen Shell-Befehl auf dem Gerät aus.

        Args:
            command: Shell-Befehl (z.B. "id", "cat /proc/version")
            root:    True = via `su -c "..."` ausführen (KernelSU)
            timeout: Optionales Timeout (Sekunden)
            check:   True = ADBError bei non-zero exit

        Returns:
            ADBResult

        Raises:
            ADBError: wenn check=True und exit != 0
        """
        # v3.2 ANTI-DOUBLE-SU:
        # Wenn der Command bereits mit 'su ' beginnt (z.B. 'su -M -c "..."'),
        # darf root=True NICHT nochmal su -c wrappen. Das würde zu
        # su -c "su -M -c ..." führen → Permission Error / Hänger.
        # Automatische Korrektur: root intern auf False setzen.
        if root and command.lstrip().startswith("su "):
            logger.debug(
                "Anti-Double-SU: Command beginnt mit 'su', "
                "root=True → False korrigiert: %s",
                command[:60],
            )
            root = False

        if root:
            # Escaping für su -c (doppelte Anführungszeichen im Befehl)
            escaped = command.replace("\\", "\\\\").replace('"', '\\"')
            shell_cmd = f'su -c "{escaped}"'
        else:
            shell_cmd = command

        result = await self._exec(["shell", shell_cmd], timeout=timeout)

        if check and not result.success:
            raise ADBError(
                f"Shell-Befehl fehlgeschlagen (exit {result.returncode}): {command}",
                returncode=result.returncode,
                stderr=result.stderr,
            )

        return result

    # =========================================================================
    # Public API: Push / Pull
    # =========================================================================

    async def push(
        self,
        local_path: str,
        remote_path: str,
        timeout: Optional[int] = None,
    ) -> ADBResult:
        """
        Pusht eine lokale Datei auf das Gerät.

        Args:
            local_path:  Lokaler Dateipfad
            remote_path: Zielpfad auf dem Gerät

        Returns:
            ADBResult
        """
        logger.info("Push: %s → %s", local_path, remote_path)
        result = await self._exec(
            ["push", local_path, remote_path],
            timeout=timeout or 60,
        )
        if not result.success:
            combined = f"{result.stdout} {result.stderr}"
            if "file pushed" in combined and "0 skipped" in combined:
                logger.warning(
                    "Push ADB-Bug: returncode=%d but '%s' — treating as success",
                    result.returncode,
                    combined.strip()[:200],
                )
                return ADBResult(
                    returncode=0,
                    stdout=result.stdout,
                    stderr=result.stderr,
                    command=result.command,
                    attempts=result.attempts,
                )
            raise ADBError(
                f"Push fehlgeschlagen: {local_path} → {remote_path}: {result.stderr}",
                returncode=result.returncode,
                stderr=result.stderr,
            )
        return result

    async def pull(
        self,
        remote_path: str,
        local_path: str,
        timeout: Optional[int] = None,
    ) -> ADBResult:
        """
        Zieht eine Datei vom Gerät auf den Host.

        Args:
            remote_path: Quellpfad auf dem Gerät
            local_path:  Lokaler Zielpfad

        Returns:
            ADBResult
        """
        logger.info("Pull: %s → %s", remote_path, local_path)
        result = await self._exec(
            ["pull", remote_path, local_path],
            timeout=timeout or 60,
        )
        if not result.success:
            combined = f"{result.stdout} {result.stderr}"
            if "file pulled" in combined and "0 skipped" in combined:
                logger.warning(
                    "Pull ADB-Bug: returncode=%d but '%s' — treating as success",
                    result.returncode,
                    combined.strip()[:200],
                )
                return ADBResult(
                    returncode=0,
                    stdout=result.stdout,
                    stderr=result.stderr,
                    command=result.command,
                    attempts=result.attempts,
                )
            raise ADBError(
                f"Pull fehlgeschlagen: {remote_path} → {local_path}: {result.stderr}",
                returncode=result.returncode,
                stderr=result.stderr,
            )
        return result

    # =========================================================================
    # Public API: Exec-Out (Binary Streaming)
    # =========================================================================

    async def exec_out_to_file(
        self,
        command: str,
        local_path: str,
        timeout: Optional[int] = None,
    ) -> int:
        """
        Führt `adb exec-out <command>` aus und streamt stdout in eine lokale Datei.

        Wird für tar-Backups verwendet:
            await adb.exec_out_to_file(
                "tar -cf - /data/data/com.zhiliaoapp.musically",
                "/backups/profile_001.tar"
            )

        Args:
            command:    Shell-Befehl dessen stdout gestreamt wird
            local_path: Lokaler Zielpfad für die Binärdaten

        Returns:
            Anzahl geschriebener Bytes

        Raises:
            ADBError: bei Fehler
        """
        effective_timeout = timeout or 300  # 5 Min für große Backups
        logger.info("Exec-Out Stream: %s → %s", command, local_path)

        proc = await asyncio.create_subprocess_exec(
            "adb", "exec-out", command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        bytes_written = 0
        try:
            with open(local_path, "wb") as f:
                while True:
                    try:
                        chunk = await asyncio.wait_for(
                            proc.stdout.read(65536),  # 64KB chunks
                            timeout=effective_timeout,
                        )
                    except asyncio.TimeoutError:
                        proc.kill()
                        raise ADBTimeoutError(
                            f"Exec-Out Timeout ({effective_timeout}s): {command}"
                        )

                    if not chunk:
                        break
                    f.write(chunk)
                    bytes_written += len(chunk)

        except (OSError, ADBTimeoutError):
            # Stream abgebrochen — Datei könnte korrupt sein
            logger.error("Exec-Out Stream abgebrochen bei %d Bytes", bytes_written)
            raise

        await proc.wait()
        stderr = (await proc.stderr.read()).decode("utf-8", errors="replace")

        if proc.returncode != 0:
            logger.warning("Exec-Out exit=%d, stderr: %s", proc.returncode, stderr[:200])

        logger.info("Exec-Out fertig: %d Bytes geschrieben", bytes_written)
        return bytes_written

    # =========================================================================
    # Public API: Exec-In (Binary Streaming zum Gerät)
    # =========================================================================

    async def exec_in_from_file(
        self,
        command: str,
        local_path: str,
        timeout: Optional[int] = None,
    ) -> ADBResult:
        """
        Streamt eine lokale Datei via stdin an `adb exec-out <command>`.

        Wird für tar-Restores verwendet:
            await adb.exec_in_from_file(
                "tar -xf - -C /",
                "/backups/profile_001.tar"
            )

        Args:
            command:    Shell-Befehl der stdin liest
            local_path: Lokale Quelldatei

        Returns:
            ADBResult
        """
        effective_timeout = timeout or 300
        logger.info("Exec-In Stream: %s → %s", local_path, command)

        proc = await asyncio.create_subprocess_exec(
            "adb", "shell", f'su -c "{command}"',
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            with open(local_path, "rb") as f:
                data = f.read()

            stdout_raw, stderr_raw = await asyncio.wait_for(
                proc.communicate(input=data),
                timeout=effective_timeout,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise ADBTimeoutError(f"Exec-In Timeout ({effective_timeout}s): {command}")

        return ADBResult(
            returncode=proc.returncode or 0,
            stdout=stdout_raw.decode("utf-8", errors="replace"),
            stderr=stderr_raw.decode("utf-8", errors="replace"),
            command=f"exec-in: {command}",
        )

    # =========================================================================
    # Public API: Reboot
    # =========================================================================

    async def reboot(self, mode: str = "") -> ADBResult:
        """
        Startet das Gerät neu.

        Args:
            mode: "" = normal, "recovery", "bootloader"

        Returns:
            ADBResult
        """
        args = ["reboot"]
        if mode:
            args.append(mode)

        logger.info("Reboot: mode=%s", mode or "normal")
        return await self._exec(args, timeout=10, retries=1)

    # =========================================================================
    # Public API: Device State
    # =========================================================================

    async def is_connected(self) -> bool:
        """Prüft ob ein Gerät verbunden und online ist."""
        try:
            result = await self._exec(["get-state"], timeout=5, retries=1)
            return result.success and "device" in result.stdout
        except (ADBError, ADBTimeoutError):
            return False

    async def check_wadbd_available(self) -> dict:
        """
        Prüft ob ADB over WiFi via wadbd (Magisk-Modul) verfügbar ist.

        Wadbd ermöglicht drahtlose ADB-Verbindung als Fallback wenn
        USB-Kabel getrennt wird. Prüft:
          1. Ob das wadbd-Modul installiert ist
          2. Ob der adbd-Daemon auf TCP lauscht
          3. Die aktuelle WiFi-IP des Geräts

        Returns:
            {"available": bool, "ip": str, "port": int, "detail": str}
        """
        result = {
            "available": False,
            "ip": "",
            "port": 5555,
            "detail": "",
        }

        try:
            # 1. Prüfe ob wadbd-Modul installiert ist
            mod_check = await self.shell(
                "test -d /data/adb/modules/wadbd && echo OK",
                root=True, timeout=5,
            )
            has_module = mod_check.success and "OK" in mod_check.output

            # 2. Prüfe ob TCP-Port aktiv ist (adbd lauscht)
            port_check = await self.shell(
                "getprop service.adb.tcp.port", timeout=5,
            )
            tcp_port = 0
            if port_check.success and port_check.output.strip().isdigit():
                tcp_port = int(port_check.output.strip())

            # 3. WiFi-IP ermitteln
            ip_check = await self.shell(
                "ip -4 addr show wlan0 2>/dev/null"
                " | grep -oP '(?<=inet )\\d+\\.\\d+\\.\\d+\\.\\d+'",
                timeout=5,
            )
            wifi_ip = ""
            if ip_check.success and ip_check.output.strip():
                wifi_ip = ip_check.output.strip().split("\n")[0]

            if has_module and tcp_port > 0 and wifi_ip:
                result["available"] = True
                result["ip"] = wifi_ip
                result["port"] = tcp_port
                result["detail"] = (
                    f"wadbd aktiv: {wifi_ip}:{tcp_port}"
                )
                logger.info(
                    "[wadbd] Wireless ADB verfügbar: %s:%d",
                    wifi_ip, tcp_port,
                )
            elif has_module and wifi_ip:
                result["ip"] = wifi_ip
                result["detail"] = (
                    f"wadbd installiert aber TCP-Port nicht aktiv "
                    f"(port={tcp_port}, ip={wifi_ip})"
                )
                logger.debug("[wadbd] Modul vorhanden, TCP nicht aktiv")
            elif has_module:
                result["detail"] = "wadbd installiert, kein WiFi"
            else:
                result["detail"] = "wadbd-Modul nicht installiert"

        except (ADBError, ADBTimeoutError) as e:
            result["detail"] = f"Prüfung fehlgeschlagen: {e}"
            logger.debug("[wadbd] Check fehlgeschlagen: %s", e)

        return result

    async def connect_wireless(self, ip: str, port: int = 5555) -> bool:
        """
        Verbindet sich via TCP/IP mit dem Gerät (wadbd Fallback).

        Args:
            ip:   WiFi-IP des Geräts
            port: TCP-Port (Standard: 5555)

        Returns:
            True wenn Verbindung hergestellt
        """
        target = f"{ip}:{port}"
        try:
            result = await self._exec(
                ["connect", target], timeout=10, retries=1,
            )
            connected = result.success and "connected" in result.stdout.lower()
            if connected:
                logger.info("[wadbd] Wireless ADB verbunden: %s", target)
            else:
                logger.warning(
                    "[wadbd] Verbindung fehlgeschlagen: %s — %s",
                    target, result.stdout,
                )
            return connected
        except (ADBError, ADBTimeoutError) as e:
            logger.warning("[wadbd] Connect Fehler: %s", e)
            return False

    async def wait_for_device(
        self,
        timeout: int = TIMING.BOOT_WAIT_SECONDS,
        poll_interval: float = TIMING.BOOT_POLL_INTERVAL,
    ) -> bool:
        """
        Wartet bis das Gerät verbunden und gebootet ist.

        Pollt wiederholt `sys.boot_completed` Property.
        Bei timeout=0 wird unbegrenzt gewartet (bis das Gerät tatsächlich bootet).

        Args:
            timeout:       Maximale Wartezeit in Sekunden (0 = unbegrenzt)
            poll_interval: Polling-Intervall in Sekunden

        Returns:
            True wenn Gerät bereit, False bei Timeout (nur wenn timeout > 0)
        """
        if timeout > 0:
            logger.info("Warte auf Gerät (max %ds)...", timeout)
        else:
            logger.info("Warte auf Gerät (unbegrenzt, pollt alle %.0fs)...", poll_interval)

        elapsed = 0.0
        last_status_log = 0.0

        while True:
            try:
                result = await self._exec(
                    ["shell", "getprop sys.boot_completed"],
                    timeout=5,
                    retries=1,
                )
                if result.success and result.output == "1":
                    logger.info("Gerät gebootet nach %.1fs", elapsed)
                    return True
            except (ADBError, ADBTimeoutError):
                pass  # Noch nicht bereit

            await asyncio.sleep(poll_interval)
            elapsed += poll_interval

            # Status-Log alle 30 Sekunden
            if elapsed - last_status_log >= 30:
                logger.info("Warte auf Boot... (%.0fs vergangen)", elapsed)
                last_status_log = elapsed

            # Timeout prüfen (nur wenn timeout > 0)
            if timeout > 0 and elapsed >= timeout:
                logger.error("Timeout: Gerät nicht bereit nach %ds", timeout)
                return False

    async def has_root(self) -> bool:
        """Prüft ob Root-Zugriff via su verfügbar ist."""
        try:
            result = await self.shell("id", root=True, timeout=5)
            return result.success and "uid=0" in result.stdout
        except ADBError:
            return False

    async def unlock_device(self) -> bool:
        """
        Entsperrt das Gerät (Wakeup + Swipe + Keyguard Dismiss).

        Ablauf:
          1. Bildschirm aufwecken (KEYCODE_WAKEUP)
          2. 1s warten
          3. Swipe nach oben (Lock-Screen dismiss)
          4. FIX-7: `wm dismiss-keyguard` als Fallback
             (umgeht trägen WindowManager nach Reboot)
          5. Verifizierung: Prüfe ob Keyguard noch aktiv ist

        Returns:
            True wenn Befehle erfolgreich, False bei Fehler
        """
        try:
            # 1. Wakeup (Bildschirm einschalten)
            await self.shell("input keyevent KEYCODE_WAKEUP")
            await asyncio.sleep(1)

            # 2. Swipe Up (Lockscreen wegwischen — 500ms Dauer)
            await self.shell("input swipe 540 1800 540 600 500")
            await asyncio.sleep(0.5)

            # =================================================================
            # FIX-7: wm dismiss-keyguard als Fallback
            # Nach Reboot kann der WindowManager träge sein und Swipes
            # ignorieren. dismiss-keyguard umgeht das komplett über die
            # WindowManager API (kein Swipe nötig).
            # =================================================================
            try:
                await self.shell("wm dismiss-keyguard", root=True, timeout=5)
                logger.debug("FIX-7: wm dismiss-keyguard ausgeführt")
            except ADBError:
                # Nicht kritisch — Swipe hat möglicherweise bereits funktioniert
                logger.debug("FIX-7: wm dismiss-keyguard fehlgeschlagen (nicht kritisch)")

            await asyncio.sleep(0.5)

            # 3. Verifizierung: Prüfe ob Keyguard noch aktiv ist
            unlocked = await self._check_keyguard_dismissed()
            if unlocked:
                logger.info("Gerät entsperrt (Wakeup + Swipe + Keyguard Dismiss)")
            else:
                # Letzter Versuch: Nochmal Swipe + dismiss
                logger.warning("Keyguard noch aktiv — zweiter Unlock-Versuch...")
                await self.shell("input keyevent KEYCODE_WAKEUP")
                await asyncio.sleep(0.5)
                await self.shell("input swipe 540 1800 540 600 300")
                await asyncio.sleep(0.5)
                try:
                    await self.shell("wm dismiss-keyguard", root=True, timeout=5)
                except ADBError:
                    pass
                unlocked = await self._check_keyguard_dismissed()
                if unlocked:
                    logger.info("Gerät entsperrt (zweiter Versuch)")
                else:
                    logger.warning(
                        "Keyguard möglicherweise noch aktiv — "
                        "CE-Storage Check wird entscheiden"
                    )

            return True
        except ADBError as e:
            logger.warning("Unlock fehlgeschlagen: %s", e)
            return False

    async def _check_keyguard_dismissed(self) -> bool:
        """
        FIX-5 (Teil): Prüft via dumpsys window ob der Keyguard dismisst ist.

        Wenn mCurrentFocus "Keyguard" oder "StatusBar" enthält, ist das
        Gerät noch gesperrt. Bei "Launcher", "Activity" oder anderem ist
        es entsperrt.

        Returns:
            True wenn Gerät entsperrt scheint
        """
        try:
            result = await self.shell(
                "dumpsys window windows | grep -i mCurrentFocus",
                timeout=5,
            )
            if result.success:
                focus = result.output.lower()
                if "keyguard" in focus or "lockscreen" in focus:
                    logger.debug("Keyguard aktiv: %s", result.output.strip())
                    return False
                else:
                    logger.debug("Kein Keyguard: %s", result.output.strip())
                    return True
        except ADBError:
            pass
        # Im Zweifel: True (nicht blockieren)
        return True
