"""
Local Shell Client v1.0 — On-Device Ersatz für ADBClient
=========================================================

Drop-in-Ersatz für ADBClient, der Befehle direkt auf dem Gerät
ausführt statt über USB-ADB. Für den Einsatz in Termux auf dem
Pixel 6 selbst.

Alle Methoden haben die identische Signatur wie ADBClient und
geben ADBResult zurück. Der Rest des Codes merkt keinen Unterschied.

Unterschiede zu ADBClient:
  - shell()           → su -c "..." via asyncio subprocess (kein adb)
  - push(local, dest) → cp (selbes Filesystem, kein USB-Transfer)
  - pull(src, local)  → cp
  - exec_out_to_file  → su -c "cmd" > file
  - is_connected()    → immer True (wir SIND das Gerät)
  - ensure_connection → immer True
  - reboot()          → su -c "svc power reboot" (VORSICHT: killt Termux!)
  - wait_for_device   → wartet auf sys.boot_completed Property
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
from dataclasses import dataclass
from typing import Optional

from host.adb.client import ADBError, ADBResult, ADBTimeoutError

logger = logging.getLogger("host.adb.local")


class LocalShellClient:
    """
    On-Device Shell Client — Drop-in-Ersatz für ADBClient.

    Führt alle Befehle direkt auf dem Gerät aus (kein ADB nötig).
    Benötigt Root-Zugriff via KernelSU/Magisk `su`.
    """

    ADB_RECONNECT_TIMEOUT = 120  # API-Kompatibilität

    def __init__(
        self,
        max_retries: int = 2,
        retry_delay: float = 1.0,
        timeout: int = 30,
    ):
        self._max_retries = max_retries
        self._retry_delay = retry_delay
        self._timeout = timeout

    # =========================================================================
    # Connection — auf dem Gerät immer verfügbar
    # =========================================================================

    async def ensure_connection(self, timeout: int = 0) -> bool:
        """Immer True — wir laufen auf dem Gerät selbst."""
        return True

    async def is_connected(self) -> bool:
        """Immer True — wir SIND das Gerät."""
        return True

    # =========================================================================
    # Core: Shell-Befehl ausführen
    # =========================================================================

    async def shell(
        self,
        command: str,
        root: bool = False,
        timeout: Optional[int] = None,
        check: bool = False,
    ) -> ADBResult:
        """
        Führt einen Shell-Befehl direkt auf dem Gerät aus.

        Args:
            command: Shell-Befehl
            root:    True = via su -c ausführen
            timeout: Timeout in Sekunden
            check:   True = ADBError bei non-zero exit
        """
        effective_timeout = timeout or self._timeout

        if root and command.lstrip().startswith("su "):
            root = False

        if root:
            escaped = command.replace("\\", "\\\\").replace('"', '\\"')
            args = ["su", "-c", escaped]
        else:
            args = ["sh", "-c", command]

        cmd_str = f"local:{'su' if root else 'sh'} {command[:80]}"
        last_error: Optional[Exception] = None

        for attempt in range(1, self._max_retries + 1):
            try:
                logger.debug("[%d/%d] %s", attempt, self._max_retries, cmd_str)

                proc = await asyncio.create_subprocess_exec(
                    *args,
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
                        f"Timeout ({effective_timeout}s): {cmd_str}",
                        returncode=-1,
                    )

                stdout_str = stdout_raw.decode("utf-8", errors="replace")
                stderr_str = stderr_raw.decode("utf-8", errors="replace")

                result = ADBResult(
                    returncode=proc.returncode or 0,
                    stdout=stdout_str,
                    stderr=stderr_str,
                    command=cmd_str,
                    attempts=attempt,
                )

                if result.success and attempt > 1:
                    logger.info("Erfolg nach %d Versuchen: %s", attempt, cmd_str)

                if check and not result.success:
                    raise ADBError(
                        f"Shell-Befehl fehlgeschlagen (exit {result.returncode}): {command}",
                        returncode=result.returncode,
                        stderr=result.stderr,
                    )

                return result

            except ADBTimeoutError:
                raise

            except OSError as e:
                last_error = ADBError(f"Prozess-Fehler: {e}")
                if attempt < self._max_retries:
                    await asyncio.sleep(self._retry_delay)
                    continue
                raise last_error

        raise last_error or ADBError("Shell fehlgeschlagen nach Retries")

    # =========================================================================
    # Push / Pull — lokale Dateikopie statt USB-Transfer
    # =========================================================================

    async def push(
        self,
        local_path: str,
        remote_path: str,
        timeout: Optional[int] = None,
    ) -> ADBResult:
        """
        Kopiert eine Datei zum Zielpfad (alles lokal auf dem Gerät).

        In Termux: local_path ist ein Pfad in Termux' Filesystem,
        remote_path ist ein Android-Systempfad. Da beides auf dem
        selben Gerät liegt, wird einfach kopiert.
        """
        logger.info("Local-Push: %s → %s", local_path, remote_path)
        try:
            result = await self.shell(
                f"cp '{local_path}' '{remote_path}'",
                root=True,
                timeout=timeout or 60,
            )
            if not result.success:
                raise ADBError(
                    f"Push fehlgeschlagen: {local_path} → {remote_path}: {result.stderr}",
                    returncode=result.returncode,
                    stderr=result.stderr,
                )
            return result
        except OSError as e:
            raise ADBError(f"Push Dateifehler: {e}") from e

    async def pull(
        self,
        remote_path: str,
        local_path: str,
        timeout: Optional[int] = None,
    ) -> ADBResult:
        """Kopiert eine Datei vom Android-System in Termux' Filesystem."""
        logger.info("Local-Pull: %s → %s", remote_path, local_path)
        try:
            result = await self.shell(
                f"cp '{remote_path}' '{local_path}'",
                root=True,
                timeout=timeout or 60,
            )
            if not result.success:
                raise ADBError(
                    f"Pull fehlgeschlagen: {remote_path} → {local_path}: {result.stderr}",
                    returncode=result.returncode,
                    stderr=result.stderr,
                )
            return result
        except OSError as e:
            raise ADBError(f"Pull Dateifehler: {e}") from e

    # =========================================================================
    # Exec-Out: Shell-Befehl → lokale Datei (Backup-Streaming)
    # =========================================================================

    async def exec_out_to_file(
        self,
        command: str,
        local_path: str,
        timeout: Optional[int] = None,
    ) -> int:
        """
        Führt einen Root-Shell-Befehl aus und streamt stdout in eine Datei.

        Ersetzt `adb exec-out` — der Befehl wird direkt via su ausgeführt
        und stdout wird in die lokale Datei geschrieben.
        """
        effective_timeout = timeout or 300
        logger.info("Exec-Out Stream: %s → %s", command, local_path)

        escaped = command.replace("\\", "\\\\").replace('"', '\\"')
        proc = await asyncio.create_subprocess_exec(
            "su", "-c", escaped,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        bytes_written = 0
        try:
            with open(local_path, "wb") as f:
                while True:
                    try:
                        chunk = await asyncio.wait_for(
                            proc.stdout.read(65536),
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
            logger.error("Exec-Out abgebrochen bei %d Bytes", bytes_written)
            raise

        await proc.wait()
        stderr = (await proc.stderr.read()).decode("utf-8", errors="replace")

        if proc.returncode != 0:
            logger.warning("Exec-Out exit=%d, stderr: %s", proc.returncode, stderr[:200])

        logger.info("Exec-Out fertig: %d Bytes", bytes_written)
        return bytes_written

    # =========================================================================
    # Exec-In: Lokale Datei → Shell-Befehl stdin
    # =========================================================================

    async def exec_in_from_file(
        self,
        command: str,
        local_path: str,
        timeout: Optional[int] = None,
    ) -> ADBResult:
        """Streamt eine lokale Datei via stdin an einen Root-Shell-Befehl."""
        effective_timeout = timeout or 300
        logger.info("Exec-In Stream: %s → %s", local_path, command)

        escaped = command.replace("\\", "\\\\").replace('"', '\\"')
        proc = await asyncio.create_subprocess_exec(
            "su", "-c", escaped,
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
    # Reboot — WARNUNG: killt Termux!
    # =========================================================================

    async def reboot(self, mode: str = "") -> ADBResult:
        """
        Startet das Gerät neu.

        WARNUNG: Im On-Device Modus killt ein Reboot auch Termux
        und damit diesen Server. Der Flow muss nach dem Reboot
        manuell oder via Termux:Boot fortgesetzt werden.
        """
        if mode == "bootloader":
            cmd = "reboot bootloader"
        elif mode == "recovery":
            cmd = "reboot recovery"
        else:
            cmd = "svc power reboot"

        logger.warning("REBOOT (%s) — Server wird beendet!", mode or "normal")
        return await self.shell(cmd, root=True, timeout=10)

    # =========================================================================
    # Device State
    # =========================================================================

    async def wait_for_device(
        self,
        timeout: int = 120,
        poll_interval: float = 3.0,
    ) -> bool:
        """
        Wartet bis sys.boot_completed = 1.

        Im On-Device Modus: Wenn wir laufen, ist das Gerät bereits
        gebootet. Trotzdem prüfen wir die Property für Konsistenz
        (z.B. nach Zygote-Restart).
        """
        elapsed = 0.0
        while True:
            try:
                result = await self.shell(
                    "getprop sys.boot_completed",
                    root=False, timeout=5,
                )
                if result.success and result.output.strip() == "1":
                    logger.info("Gerät gebootet (%.1fs)", elapsed)
                    return True
            except (ADBError, ADBTimeoutError):
                pass

            await asyncio.sleep(poll_interval)
            elapsed += poll_interval

            if timeout > 0 and elapsed >= timeout:
                logger.error("Boot-Timeout nach %ds", timeout)
                return False

    async def has_root(self) -> bool:
        """Prüft ob Root via su verfügbar ist."""
        try:
            result = await self.shell("id", root=True, timeout=5)
            return result.success and "uid=0" in result.stdout
        except ADBError:
            return False

    async def unlock_device(self) -> bool:
        """
        Entsperrt das Gerät (Wakeup + Swipe + Keyguard Dismiss).
        Identisch zum ADBClient — Befehle laufen nur lokal statt via ADB.
        """
        try:
            await self.shell("input keyevent KEYCODE_WAKEUP")
            await asyncio.sleep(1)
            await self.shell("input swipe 540 1800 540 600 500")
            await asyncio.sleep(0.5)
            try:
                await self.shell("wm dismiss-keyguard", root=True, timeout=5)
            except ADBError:
                pass
            await asyncio.sleep(0.5)
            return True
        except ADBError as e:
            logger.warning("Unlock fehlgeschlagen: %s", e)
            return False

    # =========================================================================
    # Wireless ADB — nicht relevant im On-Device Modus
    # =========================================================================

    async def check_wadbd_available(self) -> dict:
        """Nicht relevant — wir laufen auf dem Gerät."""
        return {
            "available": False,
            "ip": "",
            "port": 0,
            "detail": "On-Device Modus — kein ADB nötig",
        }

    async def connect_wireless(self, ip: str, port: int = 5555) -> bool:
        """Nicht relevant im On-Device Modus."""
        return False
