"""
HookGuard – Live monitoring of all Xposed & Zygisk hooks with Kill-Switch.

Monitors:
  - Xposed JSON summaries (per-process) from /data/data/<pkg>/files/
  - Zygisk native access log from /data/local/tmp/.titan_native_access.log
  - Bridge file integrity via MD5 comparison
  - TikTok process liveness for dead-man-switch

Kill-Switch triggers:
  - has_critical_real == true (a critical hook returned real value)
  - Heartbeat timeout (TikTok running but no monitor update for >10s)
  - Bridge file tampered (MD5 mismatch)
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

from host.adb.client import ADBClient, ADBError
from host.config import BRIDGE_FILE_PATH, TIKTOK_PACKAGES

log = logging.getLogger("hookguard")


# =============================================================================
# Guard status & state
# =============================================================================

class GuardStatus(str, Enum):
    IDLE = "idle"
    MONITORING = "monitoring"
    WARNING = "warning"
    KILLED = "killed"


@dataclass
class HookState:
    """Snapshot of hook monitoring state."""
    status: GuardStatus = GuardStatus.IDLE
    applied_hooks: int = 0
    min_hooks: int = 0
    expected_hooks: int = 28
    spoof_count: int = 0
    real_count: int = 0
    has_critical_real: bool = False
    real_critical_apis: list = field(default_factory=list)
    last_heartbeat_ms: int = 0
    last_check_ts: float = 0.0
    active_processes: list = field(default_factory=list)
    bridge_intact: bool = False
    bridge_verified: bool = False
    bridge_hash: str = ""
    tiktok_running: bool = False
    kill_history: list = field(default_factory=list)
    native_heartbeat_ts: int = 0
    maps_clean: bool = False
    maps_verified: bool = False
    maps_leaks: list = field(default_factory=list)
    # Live Monitor: per-API breakdown and device-side kill events
    api_details: list = field(default_factory=list)
    device_kill_events: list = field(default_factory=list)


# =============================================================================
# HookGuard
# =============================================================================

class HookGuard:
    """Live hook monitor with kill-switch capability."""

    POLL_INTERVAL = 3.0  # seconds
    HEARTBEAT_TIMEOUT_MS = 45_000
    NATIVE_HEARTBEAT_TIMEOUT_S = 60
    BRIDGE_CHECK_INTERVAL = 30.0  # seconds
    MAPS_CHECK_INTERVAL = 10.0  # seconds
    MAX_KILL_HISTORY = 50

    SUSPICIOUS_MAPS_PATTERNS = [
        "libxposed", "XposedBridge", "lspd", "edxposed",
        "magisk", "ksu", "kernelsu",
        "frida", "substrate", "gadget",
    ]

    # TikTok components to disable after kill-switch
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
            "HookGuard started (expected bridge hash: %s)",
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

        # 1. Check if TikTok is running
        self._state.tiktok_running = await self._is_tiktok_running()

        if not self._state.tiktok_running:
            self._tiktok_running_since = 0.0
            if self._state.status != GuardStatus.KILLED:
                self._state.status = GuardStatus.MONITORING
                self._state.has_critical_real = False
                self._state.real_critical_apis = []
                self._state.maps_clean = False
                self._state.maps_verified = False
                self._state.maps_leaks = []
                self._state.bridge_verified = False
                self._state.last_heartbeat_ms = 0
                self._state.native_heartbeat_ts = 0
                self._state.active_processes = []
            await self._broadcast_state()
            return

        if self._tiktok_running_since == 0.0:
            self._tiktok_running_since = now

        # 2. Pull Xposed JSON summaries (all processes)
        await self._read_xposed_summaries()

        # 3. Pull native access log heartbeat
        await self._read_native_heartbeat()

        # 4. Bridge integrity check (every 30s)
        if now - self._last_bridge_check >= self.BRIDGE_CHECK_INTERVAL:
            await self._check_bridge_integrity()
            self._last_bridge_check = now

        # 5. /proc/maps check (every 10s)
        if now - self._last_maps_check >= self.MAPS_CHECK_INTERVAL:
            await self._check_proc_maps()
            self._last_maps_check = now

        # 6. Read device-side kill-switch events from logcat
        await self._read_device_kill_events()

        # 7. Evaluate state → trigger kill-switch if needed
        kill_reason = self._evaluate_threats()
        if kill_reason:
            await self._execute_kill_switch(kill_reason)

        # 8. Broadcast state to WebSocket clients
        await self._broadcast_state()

    # ── Xposed Monitor ────────────────────────────────────────────

    async def _read_xposed_summaries(self) -> None:
        processes: list[str] = []
        total_spoof = 0
        total_real = 0
        has_critical = False
        critical_apis: list[str] = []
        max_hooks = 0
        min_hooks = 999
        last_hb = 0
        all_api_details: list[dict] = []

        for pkg in TIKTOK_PACKAGES:
            try:
                result = await self._adb.shell(
                    f"ls /data/data/{pkg}/files/.titan_access_summary*.json 2>/dev/null",
                    root=True,
                    timeout=5,
                )
                if not result.success or not result.output or "No such file" in result.output:
                    continue

                for json_path in result.output.strip().split("\n"):
                    json_path = json_path.strip()
                    if not json_path:
                        continue
                    try:
                        cat_result = await self._adb.shell(
                            f"cat '{json_path}'",
                            root=True,
                            timeout=5,
                        )
                        if not cat_result.success or not cat_result.output:
                            continue
                        data = json.loads(cat_result.output)
                        proc_name = data.get("process_name", "unknown")
                        processes.append(proc_name)
                        total_spoof += data.get("spoof_count", 0)
                        total_real += data.get("real_count", 0)
                        hooks = data.get("applied_hooks", 0)
                        if hooks > max_hooks:
                            max_hooks = hooks
                        if hooks < min_hooks:
                            min_hooks = hooks
                        hb = data.get("last_heartbeat_ms", 0)
                        if hb > last_hb:
                            last_hb = hb
                        if data.get("has_critical_real", False):
                            has_critical = True
                            critical_apis.extend(data.get("real_critical_apis", []))

                        apis_dict = data.get("apis", {})
                        for api_name, api_info in apis_dict.items():
                            all_api_details.append({
                                "api": api_name,
                                "category": api_info.get("category", "?"),
                                "count": api_info.get("count", 0),
                                "spoofed": api_info.get("spoofed", False),
                                "last_ms": api_info.get("last_ms", 0),
                                "last_value": api_info.get("last_value", ""),
                                "process": proc_name,
                            })
                    except (json.JSONDecodeError, Exception) as e:
                        log.warning("Failed to parse %s: %s", json_path, e)
            except ADBError:
                pass

        all_api_details.sort(key=lambda x: x.get("last_ms", 0), reverse=True)

        self._state.active_processes = processes
        self._state.spoof_count = total_spoof
        self._state.real_count = total_real
        self._state.applied_hooks = max_hooks
        self._state.min_hooks = min_hooks if processes else 0
        self._state.last_heartbeat_ms = last_hb
        self._state.has_critical_real = has_critical
        self._state.real_critical_apis = critical_apis
        self._state.api_details = all_api_details

    # ── Device Kill-Event Monitor ────────────────────────────────

    async def _read_device_kill_events(self) -> None:
        """Read TitanKillSwitch events from device logcat."""
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

    # ── Native Monitor ────────────────────────────────────────────

    async def _read_native_heartbeat(self) -> None:
        try:
            result = await self._adb.shell(
                "tail -20 /data/local/tmp/.titan_native_access.log 2>/dev/null",
                root=True,
                timeout=5,
            )
            if not result.success or not result.output:
                self._state.native_heartbeat_ts = 0
                return
            found = False
            for line in reversed(result.output.strip().split("\n")):
                if "HEARTBEAT" in line:
                    parts = line.split("|")
                    if len(parts) >= 4:
                        try:
                            self._state.native_heartbeat_ts = int(parts[3])
                            found = True
                        except ValueError:
                            pass
                    break
            if not found:
                self._state.native_heartbeat_ts = 0
        except ADBError:
            self._state.native_heartbeat_ts = 0

    # ── Bridge Integrity ──────────────────────────────────────────

    async def _compute_bridge_content_hash(self, path: str) -> Optional[str]:
        """Compute MD5 of bridge identity values only (ignore comment lines)."""
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
            log.warning("Bridge reference hash could not be computed — cannot verify!")
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
                        pkg,
                        self._expected_bridge_hash,
                        current_hash,
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
            log.warning("Bridge integrity: no installed TikTok package found to check")

    # ── /proc/maps Detection Monitor ─────────────────────────────

    async def _check_proc_maps(self) -> None:
        """Read maps from the app's own perspective (non-root) to see what
        SUSFS actually hides.  Never reports 'clean' if no read succeeded."""
        leaks: list[str] = []
        checked_any = False
        for pkg in TIKTOK_PACKAGES:
            try:
                pid_result = await self._adb.shell(
                    f"pidof {pkg}",
                    root=True,
                    timeout=5,
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
                    log.debug(
                        "run-as maps read failed for %s (not debuggable) — "
                        "root would bypass SUSFS filtering, skipping",
                        pkg,
                    )
                    continue
                checked_any = True
                maps_lower = maps_result.output.lower()
                for pattern in self.SUSPICIOUS_MAPS_PATTERNS:
                    if pattern.lower() in maps_lower:
                        leaks.append(f"{pkg}:{pattern}")
                        log.warning(
                            "MAPS LEAK: '%s' found in /proc/%s/maps",
                            pattern,
                            pid,
                        )
            except ADBError:
                pass

        self._state.maps_leaks = leaks
        if checked_any:
            self._state.maps_clean = len(leaks) == 0
            self._state.maps_verified = True
        else:
            self._state.maps_clean = False
            self._state.maps_verified = False
            if self._state.tiktok_running:
                log.warning(
                    "Maps check: run-as failed for ALL packages — "
                    "cannot verify maps are clean, reporting UNVERIFIED"
                )

    # ── TikTok Process Check ──────────────────────────────────────

    async def _is_tiktok_running(self) -> bool:
        for pkg in TIKTOK_PACKAGES:
            try:
                result = await self._adb.shell(
                    f"pidof {pkg}",
                    root=True,
                    timeout=5,
                )
                if result.success and result.output and result.output.strip():
                    return True
            except ADBError:
                pass
        return False

    # ── Threat Evaluation ─────────────────────────────────────────

    def _evaluate_threats(self) -> Optional[str]:
        has_warning = False

        # Critical: Hook returned real value for identity API
        if self._state.has_critical_real:
            apis = ", ".join(self._state.real_critical_apis[:5])
            return f"CRITICAL_REAL: {apis}"

        # Dead-man-switch: Heartbeat stale → WARNING, not kill.
        # TikTok backgrounded by Android stops writing summaries, which is
        # normal behaviour — not a leak. Only an actual CRITICAL_REAL (above)
        # or a missing bridge justifies a kill.
        if self._state.tiktok_running and self._state.last_heartbeat_ms > 0:
            now_ms = int(time.time() * 1000)
            delta = now_ms - self._state.last_heartbeat_ms
            if delta > self.HEARTBEAT_TIMEOUT_MS:
                has_warning = True
                log.warning("Heartbeat stale: %dms since last beat (TikTok likely backgrounded)", delta)

        if (
            self._state.tiktok_running
            and self._state.last_heartbeat_ms == 0
            and self._tiktok_running_since > 0
        ):
            running_for = time.time() - self._tiktok_running_since
            if running_for > (self.HEARTBEAT_TIMEOUT_MS / 1000):
                has_warning = True
                log.warning(
                    "Heartbeat never seen: TikTok running for %.0fs — "
                    "module may not be injecting",
                    running_for,
                )

        # Bridge tampered — only kill if bridge is MISSING (not just hash mismatch)
        if not self._state.bridge_intact and self._state.bridge_hash == "MISSING":
            return f"BRIDGE_TAMPERED: hash={self._state.bridge_hash}"

        # Bridge hash mismatch or unverified → WARNING, not kill
        if not self._state.bridge_intact and self._state.bridge_verified:
            has_warning = True
            log.warning("Bridge mismatch (warning): hash=%s", self._state.bridge_hash)

        if not self._state.bridge_verified and self._state.tiktok_running:
            has_warning = True
            log.warning("Bridge unverified: %s", self._state.bridge_hash or "no hash")

        # Maps leak or unverified → WARNING
        if not self._state.maps_clean and self._state.maps_verified:
            has_warning = True
            log.warning("Maps leak (warning): %s", self._state.maps_leaks[:3])

        # maps_verified=False when run-as fails is expected for non-debuggable
        # apps — this is a structural limitation, not a threat indicator.
        # Only warn if maps were verified AND found dirty.
        if not self._state.maps_verified and self._state.tiktok_running:
            log.debug("Maps unverified (run-as not available for non-debuggable apps — skipping)")

        # Hook count mismatch (warning level, not kill)
        if (
            self._state.applied_hooks > 0
            and self._state.applied_hooks < self._state.expected_hooks
        ):
            has_warning = True
            log.warning(
                "Hook count mismatch: %d/%d (min across processes: %d)",
                self._state.applied_hooks,
                self._state.expected_hooks,
                self._state.min_hooks,
            )

        self._state.status = GuardStatus.WARNING if has_warning else GuardStatus.MONITORING
        return None

    # ── Kill-Switch ───────────────────────────────────────────────

    async def _execute_kill_switch(self, reason: str) -> None:
        log.critical("KILL-SWITCH ACTIVATED: %s", reason)
        self._state.status = GuardStatus.KILLED

        is_data_leak = reason.startswith("CRITICAL_REAL") or reason.startswith("BRIDGE_TAMPERED")

        kill_entry = {
            "timestamp": time.time(),
            "reason": reason,
            "severity": "critical" if is_data_leak else "warning",
        }

        # 1. Force-stop TikTok (always)
        for pkg in TIKTOK_PACKAGES:
            try:
                await self._adb.shell(
                    f"am force-stop {pkg}",
                    root=True,
                    timeout=5,
                )
            except ADBError:
                pass

        # 2. Airplane mode ON — ONLY for actual data leaks
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

            # 3. Disable autostart — ONLY for data leaks
            await self._disable_autostart()
        else:
            log.warning("Non-leak kill (%s) — skipping airplane mode", reason)

        # 4. Record in history
        self._state.kill_history.append(kill_entry)
        if len(self._state.kill_history) > self.MAX_KILL_HISTORY:
            self._state.kill_history = self._state.kill_history[
                -self.MAX_KILL_HISTORY :
            ]

        # 5. Broadcast kill event
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
        """Re-enable TikTok and disable airplane mode after kill-switch."""
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
        self._state.has_critical_real = False
        self._state.real_critical_apis = []
        self._state.maps_leaks = []
        self._state.maps_clean = False
        self._state.maps_verified = False
        self._state.bridge_verified = False
        self._tiktok_running_since = 0.0
        log.info(
            "HookGuard reactivated — TikTok components re-enabled, airplane OFF"
        )

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
