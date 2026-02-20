"""
HookGuard v2 – Live Zygisk module monitoring with Kill-Switch.

Reads XOR-encrypted guard status files written by the native Zygisk module
after postAppSpecialize. Each target app writes its status to:
  /data/data/<pkg>/files/.gms_cache

Monitors:
  - Guard status: bridge loaded, LSPlant ok, hook counts, heartbeat
  - Bridge file integrity via MD5 comparison
  - /proc/maps for suspicious libraries (via run-as)
  - TikTok process liveness

Kill-Switch triggers:
  - LSPlant failed (ART hooks missing → Java APIs return real values)
  - Bridge not loaded by module (no identity data)
  - Bridge file missing on device
  - Hook count critically low
"""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from host.adb.client import ADBClient, ADBError
from host.config import BRIDGE_FILE_PATH, KILL_SWITCH_PATH, TIKTOK_PACKAGES

log = logging.getLogger("hookguard")

_GUARD_XOR_KEY = bytes([
    0x54, 0x69, 0x74, 0x61, 0x6E, 0x47, 0x75, 0x61,
    0x72, 0x64, 0x32, 0x30, 0x32, 0x36
])

GUARD_FILENAME = ".gms_cache"


def _guard_decrypt(data: bytes) -> str:
    key = _GUARD_XOR_KEY
    klen = len(key)
    return bytes(b ^ key[i % klen] for i, b in enumerate(data)).decode("utf-8", errors="replace")


def _parse_guard_kv(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.strip().split("\n"):
        if "=" in line:
            k, _, v = line.partition("=")
            result[k.strip()] = v.strip()
    return result


class GuardStatus(str, Enum):
    IDLE = "idle"
    MONITORING = "monitoring"
    WARNING = "warning"
    KILLED = "killed"


@dataclass
class HookState:
    status: GuardStatus = GuardStatus.IDLE

    guard_loaded: bool = False
    bridge_loaded: bool = False
    lsplant_ok: bool = False
    native_hooks: int = 0
    art_hooks: int = 0
    expected_native: int = 11
    expected_art: int = 8
    privatized_regions: int = 0
    guard_pid: int = 0
    guard_timestamp_ms: int = 0
    init_timestamp_ms: int = 0
    heartbeat_counter: int = 0
    identity_serial: str = ""
    identity_mac: str = ""
    identity_imei1: str = ""
    identity_imei2: str = ""
    identity_imsi: str = ""
    identity_sim_serial: str = ""
    identity_android_id: str = ""
    identity_gsf_id: str = ""

    tiktok_running: bool = False
    bridge_intact: bool = False
    bridge_verified: bool = False
    bridge_hash: str = ""

    maps_clean: bool = False
    maps_verified: bool = False
    maps_leaks: list = field(default_factory=list)

    kill_history: list = field(default_factory=list)
    device_kill_events: list = field(default_factory=list)

    last_check_ts: float = 0.0


class HookGuard:
    POLL_INTERVAL = 3.0
    HEARTBEAT_TIMEOUT_S = 90
    BRIDGE_CHECK_INTERVAL = 30.0
    MAPS_CHECK_INTERVAL = 10.0
    MAX_KILL_HISTORY = 50

    SUSPICIOUS_MAPS_PATTERNS = [
        "libxposed", "XposedBridge", "lspd", "edxposed",
        "magisk", "ksu", "kernelsu",
        "frida", "substrate", "gadget",
    ]

    AUTOSTART_COMPONENTS = [
        ".common.boot.BootReceiver",
        ".push.PushReceiver",
        ".service.push.PushService",
    ]

    def __init__(self, adb: ADBClient):
        self._adb = adb
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._state = HookState()
        self._ws_clients: list = []
        self._last_bridge_check = 0.0
        self._last_maps_check = 0.0
        self._expected_bridge_hash: Optional[str] = None
        self._tiktok_running_since: float = 0.0

    @property
    def state(self) -> HookState:
        return self._state

    @property
    def is_running(self) -> bool:
        return self._running

    # ── Lifecycle ──────────────────────────────────────────────────

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._state.status = GuardStatus.MONITORING
        self._expected_bridge_hash = await self._compute_bridge_content_hash(
            str(BRIDGE_FILE_PATH)
        )
        self._task = asyncio.create_task(self._monitor_loop())
        log.info(
            "HookGuard v2 started (expected bridge hash: %s)",
            self._expected_bridge_hash or "none",
        )

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self._state.status = GuardStatus.IDLE
        log.info("HookGuard stopped")

    async def refresh_bridge_hash(self) -> None:
        """Re-compute expected bridge hash (nach Genesis / Bridge-Rewrite)."""
        self._expected_bridge_hash = await self._compute_bridge_content_hash(
            str(BRIDGE_FILE_PATH)
        )
        log.info(
            "HookGuard bridge hash refreshed: %s",
            self._expected_bridge_hash or "none",
        )

    def register_ws(self, ws: object) -> None:
        self._ws_clients.append(ws)

    def unregister_ws(self, ws: object) -> None:
        if ws in self._ws_clients:
            self._ws_clients.remove(ws)

    # ── Main Loop ──────────────────────────────────────────────────

    async def _monitor_loop(self) -> None:
        while self._running:
            try:
                await self._poll_once()
            except Exception as e:
                log.error("HookGuard poll error: %s", e)
            await asyncio.sleep(self.POLL_INTERVAL)

    async def _poll_once(self) -> None:
        now = time.time()
        self._state.last_check_ts = now

        self._state.tiktok_running = await self._is_tiktok_running()

        if not self._state.tiktok_running:
            self._tiktok_running_since = 0.0
            if self._state.status != GuardStatus.KILLED:
                self._state.status = GuardStatus.MONITORING
                self._state.guard_loaded = False
                self._state.bridge_loaded = False
                self._state.lsplant_ok = False
                self._state.native_hooks = 0
                self._state.art_hooks = 0
                self._state.guard_pid = 0
                self._state.guard_timestamp_ms = 0
                self._state.heartbeat_counter = 0
                self._state.maps_clean = False
                self._state.maps_verified = False
                self._state.maps_leaks = []
                self._state.bridge_verified = False
            await self._broadcast_state()
            return

        if self._tiktok_running_since == 0.0:
            self._tiktok_running_since = now

        # 1. Read guard status files from all target packages
        await self._read_guard_status()

        # 2. Bridge integrity check (every 30s)
        if now - self._last_bridge_check >= self.BRIDGE_CHECK_INTERVAL:
            await self._check_bridge_integrity()
            self._last_bridge_check = now

        # 3. /proc/maps check (every 10s)
        if now - self._last_maps_check >= self.MAPS_CHECK_INTERVAL:
            await self._check_proc_maps()
            self._last_maps_check = now

        # 4. Read device-side kill-switch events from logcat
        await self._read_device_kill_events()

        # 5. Evaluate → kill-switch if needed
        kill_reason = self._evaluate_threats()
        if kill_reason:
            await self._execute_kill_switch(kill_reason)

        # 6. Broadcast
        await self._broadcast_state()

    # ── Guard Status Reader ────────────────────────────────────────

    async def _read_guard_status(self) -> None:
        best: Optional[dict[str, str]] = None

        for pkg in TIKTOK_PACKAGES:
            try:
                result = await self._adb.shell(
                    f"base64 /data/data/{pkg}/files/{GUARD_FILENAME} 2>/dev/null",
                    root=True,
                    timeout=5,
                )
                if not result.success or not result.output or not result.output.strip():
                    continue

                raw = base64.b64decode(result.output.strip())
                text = _guard_decrypt(raw)
                kv = _parse_guard_kv(text)

                if kv.get("v") not in ("1", "2", "3"):
                    log.warning("Unknown guard version from %s: %s", pkg, kv.get("v"))
                    continue

                if best is None:
                    best = kv
                else:
                    if int(kv.get("ts", "0")) > int(best.get("ts", "0")):
                        best = kv
            except (ADBError, Exception) as e:
                log.debug("Guard read failed for %s: %s", pkg, e)

        if best is None:
            self._state.guard_loaded = False
            self._state.bridge_loaded = False
            self._state.lsplant_ok = False
            self._state.native_hooks = 0
            self._state.art_hooks = 0
            self._state.privatized_regions = 0
            self._state.guard_pid = 0
            self._state.guard_timestamp_ms = 0
            self._state.heartbeat_counter = 0
            self._state.identity_serial = ""
            self._state.identity_mac = ""
            self._state.identity_imei1 = ""
            self._state.identity_imei2 = ""
            self._state.identity_imsi = ""
            self._state.identity_sim_serial = ""
            self._state.identity_android_id = ""
            self._state.identity_gsf_id = ""
            return

        self._state.guard_loaded = True
        self._state.bridge_loaded = best.get("bl") == "1"
        self._state.lsplant_ok = best.get("lp") == "1"
        self._state.native_hooks = int(best.get("nh", "0"))
        self._state.art_hooks = int(best.get("ah", "0"))
        self._state.privatized_regions = int(best.get("rg", "0"))
        self._state.guard_pid = int(best.get("pid", "0"))
        self._state.guard_timestamp_ms = int(best.get("ts", "0"))
        self._state.init_timestamp_ms = int(best.get("it", "0"))
        self._state.heartbeat_counter = int(best.get("hb", "0"))
        self._state.identity_serial = best.get("sr", "")
        self._state.identity_mac = best.get("mc", "")
        self._state.identity_imei1 = best.get("i1", best.get("im", ""))
        self._state.identity_imei2 = best.get("i2", "")
        self._state.identity_imsi = best.get("is", "")
        self._state.identity_sim_serial = best.get("ss", "")
        self._state.identity_android_id = best.get("ai", "")
        self._state.identity_gsf_id = best.get("gs", "")

    # ── Device Kill-Event Monitor ────────────────────────────────

    async def _read_device_kill_events(self) -> None:
        try:
            result = await self._adb.shell(
                "logcat -d -s TitanKillSwitch:* -v time 2>/dev/null | tail -20",
                root=True,
                timeout=5,
            )
            if not result.success or not result.output:
                return
            events: list[dict] = []
            for line in result.output.strip().split("\n"):
                line = line.strip()
                if not line or "TitanKillSwitch" not in line:
                    continue
                event_type = "UNKNOWN"
                if "INSTANT KILL" in line:
                    event_type = "INSTANT_KILL"
                elif "DEFERRED KILL" in line:
                    event_type = "DEFERRED_KILL"
                elif "CRITICAL LEAK" in line:
                    event_type = "CRITICAL_LEAK"
                elif "FATAL" in line or "Bridge missing" in line:
                    event_type = "PRE_FLIGHT_KILL"
                elif "Kill-Flag cleared" in line:
                    event_type = "FLAG_CLEARED"
                timestamp = line[:18].strip() if len(line) > 18 else ""
                events.append({
                    "time": timestamp,
                    "type": event_type,
                    "message": line,
                })
            self._state.device_kill_events = events[-10:]
        except ADBError:
            pass

    # ── Bridge Integrity ──────────────────────────────────────────

    async def _compute_bridge_content_hash(self, path: str) -> Optional[str]:
        try:
            result = await self._adb.shell(
                f"grep -v '^#' {path} | grep -v '^$' | md5sum 2>/dev/null",
                root=True,
                timeout=5,
            )
            if result.success and result.output:
                return result.output.strip().split()[0]
        except ADBError:
            pass
        return None

    async def _check_bridge_integrity(self) -> None:
        if not self._expected_bridge_hash:
            self._expected_bridge_hash = await self._compute_bridge_content_hash(
                str(BRIDGE_FILE_PATH)
            )
        if not self._expected_bridge_hash:
            self._state.bridge_intact = False
            self._state.bridge_verified = False
            self._state.bridge_hash = "UNVERIFIED"
            log.warning("Bridge reference hash could not be computed")
            return

        checked_any = False
        for pkg in TIKTOK_PACKAGES:
            try:
                pkg_check = await self._adb.shell(
                    f"pm path {pkg} 2>/dev/null", root=True, timeout=5,
                )
                if not pkg_check.success or not pkg_check.output or "package:" not in pkg_check.output:
                    continue

                checked_any = True
                bridge_path = f"/data/data/{pkg}/files/.hw_config"
                result = await self._adb.shell(
                    f"ls {bridge_path} 2>/dev/null",
                    root=True,
                    timeout=5,
                )
                if not result.success or not result.output or "No such file" in result.output:
                    self._state.bridge_intact = False
                    self._state.bridge_verified = True
                    self._state.bridge_hash = "MISSING"
                    log.warning("Bridge file missing for %s!", pkg)
                    return

                current_hash = await self._compute_bridge_content_hash(bridge_path)
                self._state.bridge_hash = current_hash or "ERROR"
                if not current_hash:
                    self._state.bridge_intact = False
                    self._state.bridge_verified = False
                    log.warning("Bridge hash computation failed for %s!", pkg)
                    return
                if current_hash != self._expected_bridge_hash:
                    self._state.bridge_intact = False
                    self._state.bridge_verified = True
                    log.warning(
                        "Bridge TAMPERED for %s! expected=%s got=%s",
                        pkg, self._expected_bridge_hash, current_hash,
                    )
                    return
            except ADBError:
                pass

        if checked_any:
            self._state.bridge_intact = True
            self._state.bridge_verified = True
        else:
            self._state.bridge_intact = False
            self._state.bridge_verified = False
            self._state.bridge_hash = "NO_PKG"

    # ── /proc/maps Detection ──────────────────────────────────────

    async def _check_proc_maps(self) -> None:
        leaks: list[str] = []
        checked_any = False
        for pkg in TIKTOK_PACKAGES:
            try:
                pid_result = await self._adb.shell(
                    f"pidof {pkg}", root=True, timeout=5,
                )
                if not pid_result.success or not pid_result.output or not pid_result.output.strip():
                    continue
                pid = pid_result.output.strip().split()[0]
                maps_result = await self._adb.shell(
                    f"run-as {pkg} cat /proc/{pid}/maps 2>/dev/null | head -500",
                    root=False,
                    timeout=10,
                )
                if not maps_result.success or not maps_result.output:
                    continue
                checked_any = True
                maps_lower = maps_result.output.lower()
                for pattern in self.SUSPICIOUS_MAPS_PATTERNS:
                    if pattern.lower() in maps_lower:
                        leaks.append(f"{pkg}:{pattern}")
                        log.warning("MAPS LEAK: '%s' in /proc/%s/maps", pattern, pid)
            except ADBError:
                pass

        self._state.maps_leaks = leaks
        if checked_any:
            self._state.maps_clean = len(leaks) == 0
            self._state.maps_verified = True
        else:
            self._state.maps_clean = False
            self._state.maps_verified = False

    # ── TikTok Process Check ──────────────────────────────────────

    async def _is_tiktok_running(self) -> bool:
        for pkg in TIKTOK_PACKAGES:
            try:
                result = await self._adb.shell(
                    f"pidof {pkg}", root=True, timeout=5,
                )
                if result.success and result.output and result.output.strip():
                    return True
            except ADBError:
                pass
        return False

    # ── Threat Evaluation ─────────────────────────────────────────

    def _evaluate_threats(self) -> Optional[str]:
        has_warning = False

        # CRITICAL: Module not injecting — TikTok running but no guard file
        if not self._state.guard_loaded:
            running_for = time.time() - self._tiktok_running_since
            if running_for > self.HEARTBEAT_TIMEOUT_S:
                return "MODULE_NOT_INJECTING: no guard status after %.0fs" % running_for
            has_warning = True

        # CRITICAL: Bridge not loaded by native module
        if self._state.guard_loaded and not self._state.bridge_loaded:
            return "BRIDGE_NOT_LOADED: native module reports bl=0"

        # CRITICAL: LSPlant failed → ART hooks not working → Java APIs leak
        if self._state.guard_loaded and not self._state.lsplant_ok:
            return "LSPLANT_FAILED: ART hooks inactive, Java APIs may leak real values"

        # CRITICAL: Bridge file missing on device
        if not self._state.bridge_intact and self._state.bridge_hash == "MISSING":
            return "BRIDGE_MISSING: bridge file not found on device"

        # WARNING: Heartbeat stale (guard file timestamp too old)
        if self._state.guard_loaded and self._state.guard_timestamp_ms > 0:
            now_ms = int(time.time() * 1000)
            delta_s = (now_ms - self._state.guard_timestamp_ms) / 1000.0
            if delta_s > self.HEARTBEAT_TIMEOUT_S:
                has_warning = True
                log.warning("Guard heartbeat stale: %.0fs since last update", delta_s)

        # WARNING: Native hook count too low
        if self._state.guard_loaded and self._state.native_hooks < self._state.expected_native:
            has_warning = True
            log.warning(
                "Native hook deficit: %d/%d",
                self._state.native_hooks, self._state.expected_native,
            )

        # WARNING: ART hook count mismatch
        if self._state.guard_loaded and self._state.art_hooks < self._state.expected_art:
            has_warning = True
            log.warning(
                "ART hook deficit: %d/%d",
                self._state.art_hooks, self._state.expected_art,
            )

        # WARNING: Bridge hash mismatch
        if not self._state.bridge_intact and self._state.bridge_verified:
            has_warning = True
            log.warning("Bridge mismatch (warning): hash=%s", self._state.bridge_hash)

        # WARNING: Maps leak
        if not self._state.maps_clean and self._state.maps_verified:
            has_warning = True
            log.warning("Maps leak (warning): %s", self._state.maps_leaks[:3])

        self._state.status = GuardStatus.WARNING if has_warning else GuardStatus.MONITORING
        return None

    # ── Kill-Switch ───────────────────────────────────────────────

    async def _execute_kill_switch(self, reason: str) -> None:
        log.critical("KILL-SWITCH ACTIVATED: %s", reason)
        self._state.status = GuardStatus.KILLED

        is_data_leak = any(reason.startswith(p) for p in (
            "BRIDGE_NOT_LOADED", "LSPLANT_FAILED", "BRIDGE_MISSING",
        ))

        kill_entry = {
            "timestamp": time.time(),
            "reason": reason,
            "severity": "critical" if is_data_leak else "warning",
        }

        # 1. Set device-side kill-switch file (prevents module hooks on next launch)
        try:
            await self._adb.shell(
                f"touch {KILL_SWITCH_PATH}",
                root=True,
                timeout=5,
            )
            log.info("Device kill-switch file set: %s", KILL_SWITCH_PATH)
        except ADBError:
            log.error("Failed to set device kill-switch file!")

        # 2. Force-stop TikTok
        for pkg in TIKTOK_PACKAGES:
            try:
                await self._adb.shell(f"am force-stop {pkg}", root=True, timeout=5)
            except ADBError:
                pass

        # 3. Airplane mode ON for confirmed data leaks
        if is_data_leak:
            log.critical("DATA LEAK confirmed — activating airplane mode")
            try:
                await self._adb.shell(
                    "cmd connectivity airplane-mode enable",
                    root=True,
                    timeout=5,
                )
            except ADBError:
                pass
            await self._disable_autostart()
        else:
            log.warning("Non-leak kill (%s) — skipping airplane mode", reason)

        # 4. Record
        self._state.kill_history.append(kill_entry)
        if len(self._state.kill_history) > self.MAX_KILL_HISTORY:
            self._state.kill_history = self._state.kill_history[-self.MAX_KILL_HISTORY:]

        await self._broadcast_state()

    async def _disable_autostart(self) -> None:
        for pkg in TIKTOK_PACKAGES:
            for comp in self.AUTOSTART_COMPONENTS:
                try:
                    await self._adb.shell(
                        f"pm disable-component {pkg}/{comp}",
                        root=True,
                        timeout=5,
                    )
                except ADBError:
                    pass
        log.info("TikTok autostart components disabled")

    async def reactivate(self) -> None:
        """Re-enable after kill-switch: remove device flag, re-enable components."""
        # Remove device-side kill-switch file
        try:
            await self._adb.shell(
                f"rm -f {KILL_SWITCH_PATH}",
                root=True,
                timeout=5,
            )
            log.info("Device kill-switch file removed: %s", KILL_SWITCH_PATH)
        except ADBError:
            log.error("Failed to remove device kill-switch file!")

        for pkg in TIKTOK_PACKAGES:
            for comp in self.AUTOSTART_COMPONENTS:
                try:
                    await self._adb.shell(
                        f"pm enable-component {pkg}/{comp}",
                        root=True,
                        timeout=5,
                    )
                except ADBError:
                    pass

        try:
            await self._adb.shell(
                "cmd connectivity airplane-mode disable",
                root=True,
                timeout=5,
            )
        except ADBError:
            pass

        self._state.status = GuardStatus.MONITORING
        self._state.guard_loaded = False
        self._state.bridge_loaded = False
        self._state.lsplant_ok = False
        self._state.maps_leaks = []
        self._state.maps_clean = False
        self._state.maps_verified = False
        self._state.bridge_verified = False
        self._tiktok_running_since = 0.0
        log.info("HookGuard reactivated — kill-switch file removed, TikTok re-enabled")

    # ── WebSocket Broadcast ───────────────────────────────────────

    async def _broadcast_state(self) -> None:
        state_dict = dataclasses.asdict(self._state)
        state_dict["status"] = self._state.status.value
        msg = json.dumps({"type": "hookguard", **state_dict})
        dead: list = []
        for ws in self._ws_clients:
            try:
                await ws.send_text(msg)
            except Exception:
                dead.append(ws)
        for ws in dead:
            if ws in self._ws_clients:
                self._ws_clients.remove(ws)
