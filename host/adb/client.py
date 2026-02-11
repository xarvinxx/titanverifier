"""
Project Titan — Async ADB Client
==================================

Robuster, asynchroner Wrapper um das `adb` CLI-Tool.

Features:
  - Vollständig async (asyncio.create_subprocess_exec)
  - Automatische Retry-Logik (3 Versuche, exponential backoff)
  - Strukturierte Ergebnisse (ADBResult)
  - Root-Shell via `su -c` (KernelSU kompatibel)
  - Timeout-Protection für jeden Befehl
  - Device-State Monitoring (connected, booted, ...)

Alle ADB-Befehle werden über diese Klasse geroutet.
Kein direkter subprocess-Aufruf an anderer Stelle im Projekt.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Optional

from host.config import TIMING

logger = logging.getLogger("titan.adb")


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
        result = await adb.shell("cat /data/adb/modules/titan_verifier/titan_identity",
                                 root=True)

        # Datei pushen
        await adb.push("/tmp/bridge.txt", "/data/local/tmp/bridge.txt")

        # Reboot
        await adb.reboot()
    """

    def __init__(
        self,
        max_retries: int = 3,
        retry_delay: float = 2.0,
        timeout: int = TIMING.ADB_COMMAND_TIMEOUT,
    ):
        self._max_retries = max_retries
        self._retry_delay = retry_delay
        self._timeout = timeout

    # =========================================================================
    # Core: Befehl ausführen mit Retry
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

        Args:
            args:    Argumente für adb (z.B. ["shell", "id"])
            timeout: Timeout in Sekunden (None = Default)
            retries: Anzahl Retries (None = Default)
            binary:  True = stdout als bytes lesen (für tar-Streams)

        Returns:
            ADBResult mit returncode, stdout, stderr

        Raises:
            ADBTimeoutError:     nach Timeout
            ADBConnectionError:  nach allen Retries gescheitert
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
                logger.warning(
                    "ADB exit=%d: %s | stderr: %s",
                    result.returncode, cmd_str, stderr_str.strip()[:200],
                )
                return result

            except ADBTimeoutError:
                raise  # Timeouts nicht retrien

            except ADBConnectionError as e:
                last_error = e
                if attempt < effective_retries:
                    delay = self._retry_delay * (2 ** (attempt - 1))  # Exponential backoff
                    logger.warning(
                        "ADB Verbindungsfehler (Versuch %d/%d), Retry in %.1fs: %s",
                        attempt, effective_retries, delay, e,
                    )
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
        """Erkennt ADB-Verbindungsfehler die einen Retry rechtfertigen."""
        indicators = [
            "error: device not found",
            "error: no devices",
            "error: device offline",
            "error: closed",
            "cannot connect to daemon",
            "Connection refused",
            "adb: error: failed to get feature set",
            "protocol fault",
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
        Entsperrt das Gerät (Wakeup + Swipe).

        Ablauf:
          1. Bildschirm aufwecken (KEYCODE_WAKEUP)
          2. 1s warten
          3. Swipe nach oben (Lock-Screen dismiss)

        Returns:
            True wenn Befehle erfolgreich, False bei Fehler
        """
        try:
            # Wakeup (Bildschirm einschalten)
            await self.shell("input keyevent KEYCODE_WAKEUP")
            await asyncio.sleep(1)

            # Swipe Up (Lockscreen wegwischen — 500ms Dauer)
            await self.shell("input swipe 540 1800 540 600 500")
            await asyncio.sleep(0.5)

            logger.info("Gerät entsperrt (Wakeup + Swipe)")
            return True
        except ADBError as e:
            logger.warning("Unlock fehlgeschlagen: %s", e)
            return False
