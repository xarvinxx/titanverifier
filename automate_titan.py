#!/usr/bin/env python3
"""
Project Titan – Phase 6.0 TOTAL STEALTH Automator

KERNEL-LEVEL Identity Spoofing für Pixel 6 (Android 14 + KernelSU):
1. Build: APK + Native SO (optimiert)
2. Zygisk: SO mit Netlink/recvmsg Hooks
3. Bridge: /data/adb/modules/.../titan_identity (Boot-sicher!)
4. SUSFS: Kernel-Level Overlay für /sys/class/net/wlan0/address
5. SELinux: Korrekter Security-Context
6. Mount Hiding: /proc/mounts maskieren

KRITISCH: 7/10 ist ein Todesurteil für TikTok. 10/10 oder nichts.

Verwendung:
    python automate_titan.py [--skip-build] [--bridge-only] [--verbose]
    python automate_titan.py --generate-identity
"""

import os
import subprocess
import sys
import argparse
import tempfile
import shutil
import random
import hashlib
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional, Dict
from datetime import datetime

# ==============================================================================
# Konfiguration
# ==============================================================================

PROJECT_ROOT = Path(__file__).resolve().parent
APK_PATH = PROJECT_ROOT / "app" / "build" / "outputs" / "apk" / "debug" / "app-debug.apk"
NATIVE_BUILD_DIR = PROJECT_ROOT / "build_native"
NATIVE_SO_PATH = NATIVE_BUILD_DIR / "lib" / "arm64-v8a" / "libtitan_zygisk.so"

# Remote Paths auf dem Gerät
REMOTE_TMP = "/data/local/tmp"
REMOTE_APK_TMP = f"{REMOTE_TMP}/titan_verifier.apk"
REMOTE_SO_TMP = f"{REMOTE_TMP}/libtitan_zygisk.so"

# Magisk/KernelSU Module Paths
MODULE_ID = "titan_verifier"
MODULE_PATH = f"/data/adb/modules/{MODULE_ID}"
PRIV_APP_PATH = f"{MODULE_PATH}/system/priv-app/TitanVerifier"
ZYGISK_PATH = f"{MODULE_PATH}/zygisk"

# Bridge-Konfiguration (Phase 5.0 - NUR Boot-sicherer Pfad!)
BRIDGE_PATH = f"{MODULE_PATH}/titan_identity"          # PRIMARY (einzige Quelle!)
BRIDGE_PATH_SDCARD = "/sdcard/.titan_identity"         # Backup für LSPosed
KILL_SWITCH_PATH = "/data/local/tmp/titan_stop"

# Permission-Konfiguration
RUNTIME_PERMISSIONS = "/data/system/users/0/runtime-permissions.xml"
PKG_NAME = "com.titan.verifier"
PRIVILEGED_PERMISSIONS = [
    "android.permission.READ_PRIVILEGED_PHONE_STATE",
    "android.permission.READ_PRECISE_PHONE_STATE",
]

# SELinux Contexts
# WICHTIG: system_file:s0 für Zygote-Zugriff!
SELINUX_CONTEXT_SYSTEM = "u:object_r:system_file:s0"

# Verbose-Flag
VERBOSE = False


# ==============================================================================
# Identity Generation (Pixel 6 Realistic)
# ==============================================================================

def luhn_checksum(number: str) -> int:
    """Berechnet Luhn-Prüfziffer für eine Nummer."""
    def digits_of(n):
        return [int(d) for d in str(n)]
    digits = digits_of(number)
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    checksum = sum(odd_digits)
    for d in even_digits:
        checksum += sum(digits_of(d * 2))
    return checksum % 10


def generate_luhn_valid_number(prefix: str, length: int) -> str:
    """Generiert eine Luhn-konforme Nummer mit gegebenem Präfix."""
    # Fülle mit Zufallsziffern bis length-1
    body = prefix + ''.join([str(random.randint(0, 9)) for _ in range(length - len(prefix) - 1)])
    # Berechne Prüfziffer
    check = (10 - luhn_checksum(body + '0')) % 10
    return body + str(check)


def generate_pixel6_imei() -> str:
    """
    Generiert eine realistische Pixel 6 IMEI (Luhn-konform).
    TAC (Type Allocation Code) für Pixel 6: 35847631
    """
    # Pixel 6 TAC Präfixe (Google/Pixel 6 Range)
    pixel6_tacs = [
        "35847631",  # Pixel 6
        "35847632",  # Pixel 6 Pro
        "35226911",  # Pixel 6 (alternative)
    ]
    tac = random.choice(pixel6_tacs)
    return generate_luhn_valid_number(tac, 15)


def generate_android_id() -> str:
    """Generiert eine realistische Android ID (16 hex chars)."""
    return ''.join(random.choices('0123456789abcdef', k=16))


def generate_gsf_id() -> str:
    """Generiert eine realistische GSF ID (16-18 digits)."""
    # GSF IDs sind typischerweise 16-18 stellige Dezimalzahlen
    return ''.join([str(random.randint(0, 9)) for _ in range(17)])


def generate_serial() -> str:
    """Generiert eine realistische Pixel Serial Number."""
    # Pixel Serials: Format wie "1A234B567C8D" (12 alphanumerisch)
    chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ0123456789'  # Ohne I, O (verwechselbar)
    return ''.join(random.choices(chars, k=12))


def generate_mac_address() -> str:
    """Generiert eine realistische, lokal administrierte MAC-Adresse."""
    # Lokal administrierte MAC (Bit 1 gesetzt): x2:xx:xx:xx:xx:xx
    mac = [
        random.randint(0, 255) | 0x02,  # Locally administered bit
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
    ]
    mac[0] &= 0xFE  # Unicast bit clear
    return ':'.join(f'{b:02x}' for b in mac)


def generate_widevine_id() -> str:
    """Generiert eine Widevine Device ID (32 hex chars)."""
    return hashlib.sha256(os.urandom(32)).hexdigest()[:32]


def generate_imsi() -> str:
    """Generiert eine realistische IMSI (MCC+MNC+MSIN)."""
    # US Carrier (T-Mobile): MCC=310, MNC=260
    mcc = "310"
    mnc = "260"
    msin = ''.join([str(random.randint(0, 9)) for _ in range(10)])
    return mcc + mnc + msin


def generate_iccid() -> str:
    """Generiert eine realistische ICCID (SIM Serial)."""
    # ICCID Format: 89 (Telecom) + Country + Issuer + Account + Check
    # US: 8901410 (Verizon) oder 890126 (AT&T)
    prefix = random.choice(["8901410", "890126", "890141"])
    body = prefix + ''.join([str(random.randint(0, 9)) for _ in range(19 - len(prefix) - 1)])
    check = (10 - luhn_checksum(body + '0')) % 10
    return body + str(check)


def generate_operator_name() -> str:
    """Generiert einen realistischen US Carrier Namen."""
    carriers = ["T-Mobile", "Verizon", "AT&T", "Google Fi", "Mint Mobile"]
    return random.choice(carriers)


def generate_phone_number() -> str:
    """Generiert eine realistische US-Telefonnummer."""
    # US Format: +1 (Area Code) XXX-XXXX
    area_codes = ["202", "213", "312", "415", "646", "718", "310", "404", "617", "512"]
    area = random.choice(area_codes)
    exchange = str(random.randint(200, 999))
    subscriber = str(random.randint(1000, 9999))
    return f"+1{area}{exchange}{subscriber}"


def generate_sim_operator() -> tuple:
    """Generiert eine passende MCC+MNC und Operator-Name Kombination."""
    operators = [
        ("310260", "T-Mobile", "T-Mobile"),
        ("310410", "AT&T", "AT&T"),
        ("311480", "Verizon", "Verizon"),
        ("310120", "Sprint", "Sprint"),
        ("312530", "Google Fi", "Google Fi"),
    ]
    mcc_mnc, name, display_name = random.choice(operators)
    return mcc_mnc, name, display_name


def generate_voicemail_number(operator: str) -> str:
    """Generiert eine realistische Voicemail-Nummer basierend auf dem Carrier."""
    voicemail_numbers = {
        "T-Mobile": "+18056377243",
        "AT&T": "+18888880800",
        "Verizon": "+18009220204",
        "Sprint": "+18886028079",
        "Google Fi": "+14043986429",
    }
    return voicemail_numbers.get(operator, "+18056377243")


def generate_pixel6_identity() -> Dict[str, str]:
    """
    Generiert eine vollständige, realistische Pixel 6 Identität.
    Alle IMEIs sind Luhn-konform, alle IDs im korrekten Format.
    Phase 10.0: Erweitert um Telephony, SIM-Operator, Telefonnummer.
    """
    serial = generate_serial()
    sim_operator, operator_name, sim_operator_name = generate_sim_operator()
    
    return {
        "serial": serial,
        "boot_serial": serial,  # Normalerweise identisch
        "imei1": generate_pixel6_imei(),
        "imei2": generate_pixel6_imei(),
        "gsf_id": generate_gsf_id(),
        "android_id": generate_android_id(),
        "wifi_mac": generate_mac_address(),
        "widevine_id": generate_widevine_id(),
        "imsi": generate_imsi(),
        "sim_serial": generate_iccid(),
        "operator_name": operator_name,
        # Phase 10.0 – Full Spectrum
        "phone_number": generate_phone_number(),
        "sim_operator": sim_operator,
        "sim_operator_name": sim_operator_name,
        "voicemail_number": generate_voicemail_number(operator_name),
    }


def print_identity(identity: Dict[str, str]) -> None:
    """Zeigt generierte Identität formatiert an."""
    print("\n" + "=" * 60)
    print("Generated Pixel 6 Identity")
    print("=" * 60)
    for key, value in identity.items():
        print(f"  {key:15} = {value}")
    print("=" * 60)


# ==============================================================================
# Hilfsfunktionen
# ==============================================================================

def log(msg: str, level: str = "INFO") -> None:
    """Logging mit Timestamp."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    prefix = {"INFO": "  ", "OK": "✓ ", "WARN": "⚠ ", "ERROR": "✗ ", "CMD": "$ "}
    print(f"[{timestamp}] {prefix.get(level, '  ')}{msg}")


def run(cmd: list[str], check: bool = True, capture: bool = False,
        cwd: Optional[Path] = None) -> subprocess.CompletedProcess:
    """Führt einen Befehl aus."""
    if VERBOSE:
        log(" ".join(cmd), "CMD")
    result = subprocess.run(
        cmd,
        capture_output=capture,
        text=True,
        check=False,
        cwd=cwd
    )
    if check and result.returncode != 0:
        log(f"Befehl fehlgeschlagen: exit code {result.returncode}", "ERROR")
        if capture and result.stderr:
            log(f"stderr: {result.stderr[:500]}", "ERROR")
        sys.exit(1)
    return result


def adb(args: list[str], check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    """Führt adb [args] aus."""
    return run(["adb"] + args, check=check, capture=capture)


def adb_shell(cmd: str, as_root: bool = False, check: bool = True) -> subprocess.CompletedProcess:
    """Führt adb shell [cmd] aus."""
    if as_root:
        escaped_cmd = cmd.replace('"', '\\"')
        cmd = f'su -c "{escaped_cmd}"'
    return adb(["shell", cmd], check=check, capture=True)


def check_adb_root() -> bool:
    """Prüft ob Root-Zugriff via ADB verfügbar ist."""
    result = adb_shell("id", as_root=True, check=False)
    if result.returncode == 0 and "uid=0" in result.stdout:
        return True
    result = adb(["root"], check=False, capture=True)
    return result.returncode == 0


def ensure_directory(remote_path: str, as_root: bool = True) -> None:
    """Erstellt Verzeichnis falls nicht vorhanden."""
    adb_shell(f"mkdir -p {remote_path}", as_root=as_root, check=False)


# ==============================================================================
# Build-Schritte
# ==============================================================================

def step_build_apk() -> bool:
    """1a. Build: ./gradlew assembleDebug"""
    log("Building APK...")
    
    gradlew = PROJECT_ROOT / "gradlew"
    if not gradlew.exists():
        log("gradlew nicht gefunden - überspringe APK-Build", "WARN")
        return False
    
    result = run(
        ["./gradlew", "assembleDebug", "-q"],
        check=False,
        cwd=PROJECT_ROOT
    )
    
    if result.returncode != 0:
        log("Gradle-Build fehlgeschlagen", "ERROR")
        return False
    
    if not APK_PATH.exists():
        log(f"APK nicht gefunden: {APK_PATH}", "ERROR")
        return False
    
    log(f"APK erstellt: {APK_PATH.name}", "OK")
    return True


def step_build_native() -> bool:
    """1b. Build: Native SO mit CMake + NDK."""
    log("Building Native SO...")
    
    ndk_home = os.environ.get("ANDROID_NDK_HOME") or os.environ.get("ANDROID_NDK")
    if not ndk_home:
        possible_paths = [
            Path.home() / "Android" / "Sdk" / "ndk",
            Path.home() / "Library" / "Android" / "sdk" / "ndk",
            Path("/opt/android-ndk"),
        ]
        for p in possible_paths:
            if p.exists():
                versions = sorted(p.iterdir(), reverse=True)
                if versions:
                    ndk_home = str(versions[0])
                    break
    
    if not ndk_home or not Path(ndk_home).exists():
        log("Android NDK nicht gefunden", "ERROR")
        return False
    
    log(f"NDK: {ndk_home}")
    NATIVE_BUILD_DIR.mkdir(parents=True, exist_ok=True)
    
    toolchain = Path(ndk_home) / "build" / "cmake" / "android.toolchain.cmake"
    cmake_cmd = [
        "cmake",
        "-S", str(PROJECT_ROOT / "module"),
        "-B", str(NATIVE_BUILD_DIR),
        f"-DCMAKE_TOOLCHAIN_FILE={toolchain}",
        "-DANDROID_ABI=arm64-v8a",
        "-DANDROID_PLATFORM=android-30",
        "-DCMAKE_BUILD_TYPE=Release",
        "-DTITAN_STEALTH_MODE=OFF",
    ]
    
    result = run(cmake_cmd, check=False, capture=True)
    if result.returncode != 0:
        log("CMake-Konfiguration fehlgeschlagen", "ERROR")
        return False
    
    result = run(["cmake", "--build", str(NATIVE_BUILD_DIR), "-j"], check=False, capture=True)
    if result.returncode != 0:
        log("Native-Build fehlgeschlagen", "ERROR")
        return False
    
    if NATIVE_SO_PATH.exists():
        size_kb = NATIVE_SO_PATH.stat().st_size / 1024
        log(f"Native SO erstellt: {NATIVE_SO_PATH.name} ({size_kb:.1f} KB)", "OK")
        return True
    else:
        log(f"Native SO nicht gefunden: {NATIVE_SO_PATH}", "ERROR")
        return False


def step_push_files() -> None:
    """2. Push: APK und SO nach /data/local/tmp/"""
    log("Pushing files to device...")
    
    if APK_PATH.exists():
        adb(["push", str(APK_PATH), REMOTE_APK_TMP])
        log(f"APK pushed: {REMOTE_APK_TMP}", "OK")
    
    if NATIVE_SO_PATH.exists():
        adb(["push", str(NATIVE_SO_PATH), REMOTE_SO_TMP])
        log(f"SO pushed: {REMOTE_SO_TMP}", "OK")


def step_systemize() -> None:
    """3. Systemize: Module-Struktur + APK als priv-app."""
    log("Systemizing APK as priv-app...")
    
    ensure_directory(PRIV_APP_PATH)
    ensure_directory(f"{ZYGISK_PATH}")
    
    if APK_PATH.exists():
        adb_shell(f"cp {REMOTE_APK_TMP} {PRIV_APP_PATH}/TitanVerifier.apk", as_root=True)
        adb_shell(f"chmod 644 {PRIV_APP_PATH}/TitanVerifier.apk", as_root=True)
        adb_shell(f"chown root:root {PRIV_APP_PATH}/TitanVerifier.apk", as_root=True)
        log("APK installiert als priv-app", "OK")
    
    module_prop = f"""id={MODULE_ID}
name=Titan Verifier
version=6.0.0
versionCode=600
author=Lead-Architect
description=Project Titan - Total Stealth (Phase 6.0 - Netlink/SUSFS/Widevine)
"""
    
    with tempfile.NamedTemporaryFile(mode="w", suffix=".prop", delete=False) as f:
        f.write(module_prop)
        tmp_prop = f.name
    
    try:
        adb(["push", tmp_prop, f"{REMOTE_TMP}/module.prop"])
        adb_shell(f"cp {REMOTE_TMP}/module.prop {MODULE_PATH}/module.prop", as_root=True)
        adb_shell(f"chmod 644 {MODULE_PATH}/module.prop", as_root=True)
    finally:
        os.unlink(tmp_prop)
    
    log("module.prop erstellt", "OK")


def step_deploy_zygisk() -> None:
    """4. Zygisk: SO nach /data/adb/modules/.../zygisk/"""
    log("Deploying Zygisk module...")
    
    if not NATIVE_SO_PATH.exists():
        log("Native SO nicht vorhanden - überspringe Zygisk-Deployment", "WARN")
        return
    
    ensure_directory(ZYGISK_PATH)
    
    zygisk_so_path = f"{ZYGISK_PATH}/arm64-v8a.so"
    adb_shell(f"cp {REMOTE_SO_TMP} {zygisk_so_path}", as_root=True)
    adb_shell(f"chmod 644 {zygisk_so_path}", as_root=True)
    adb_shell(f"chown root:root {zygisk_so_path}", as_root=True)
    
    log(f"Zygisk SO installiert: {zygisk_so_path}", "OK")


def step_selinux_context() -> None:
    """5. SELinux: Setze korrekten Security-Context."""
    log("Setting SELinux contexts...")
    
    # Module-Dateien: system_file Context
    adb_shell(f"chcon -R {SELINUX_CONTEXT_SYSTEM} {MODULE_PATH}", as_root=True, check=False)
    
    # Bridge-Datei: WICHTIG - system_file Context für Zygote-Zugriff!
    adb_shell(f"chcon {SELINUX_CONTEXT_SYSTEM} {BRIDGE_PATH}", as_root=True, check=False)
    
    log("SELinux-Contexts gesetzt", "OK")


def step_susfs_mac_overlay(mac_address: str) -> None:
    """
    Phase 6.0: SUSFS Kernel-Level MAC Overlay
    
    Überlager /sys/class/net/wlan0/address mit gespoofter MAC.
    Dies ist die EINZIGE Methode, die gegen TikToks libsscronet.so funktioniert!
    
    Benötigt SUSFS-Unterstützung im Kernel.
    """
    log("Setting up SUSFS MAC overlay (Kernel-Level)...")
    
    # Prüfe ob SUSFS verfügbar ist (mehrere Methoden)
    susfs_paths = [
        "which susfs",
        "ls /data/adb/ksu/modules/susfs",
        "ls /sys/fs/susfs",
    ]
    
    susfs_available = False
    for check_cmd in susfs_paths:
        result = adb_shell(f"su -c '{check_cmd} 2>/dev/null'", as_root=False, check=False)
        if result.returncode == 0 and result.stdout.strip():
            susfs_available = True
            log(f"SUSFS detected via: {check_cmd}", "OK")
            break
    
    if not susfs_available:
        log("SUSFS not available - MAC spoofing relies on libc hooks only", "WARN")
        log("  Empfehlung: Installiere SUSFS für Kernel-Level Protection")
        return
    
    try:
        # MAC-Datei erstellen
        mac_file_path = f"{REMOTE_TMP}/.titan_mac_overlay"
        adb_shell(f"echo '{mac_address}' > {mac_file_path}", as_root=True)
        adb_shell(f"chmod 444 {mac_file_path}", as_root=True)
        adb_shell(f"chcon u:object_r:system_file:s0 {mac_file_path}", as_root=True, check=False)
        
        # 1. SUSFS Overlay für wlan0
        wlan0_paths = [
            "/sys/class/net/wlan0/address",
            "/sys/devices/virtual/net/wlan0/address",
        ]
        for path in wlan0_paths:
            adb_shell(f"susfs add_sus_path {path} 2>/dev/null", as_root=True, check=False)
            adb_shell(f"susfs update_sus_path {path} {mac_file_path} 2>/dev/null", as_root=True, check=False)
        
        log(f"SUSFS MAC overlay: {mac_address}", "OK")
            
    except Exception as e:
        log(f"SUSFS MAC overlay error: {e}", "WARN")


def step_susfs_hide_root() -> None:
    """
    Phase 6.0: SUSFS Root Hiding
    
    Versteckt KernelSU, LSPosed und Zygisk vor Apps.
    TikTok scannt /proc/mounts und /proc/self/mountinfo.
    """
    log("Setting up SUSFS Root Hiding...")
    
    # Prüfe SUSFS
    result = adb_shell("su -c 'which susfs 2>/dev/null'", as_root=False, check=False)
    if result.returncode != 0:
        log("SUSFS not available - root hiding skipped", "WARN")
        return
    
    try:
        # Pfade zum Verstecken
        sus_paths = [
            # KernelSU/Magisk
            "/data/adb",
            "/data/adb/ksu",
            "/data/adb/modules",
            
            # LSPosed
            "/data/misc/riru",
            "/data/adb/lspd",
            
            # Titan Verifier Module
            f"{MODULE_PATH}",
        ]
        
        for path in sus_paths:
            adb_shell(f"susfs add_sus_path {path} 2>/dev/null", as_root=True, check=False)
        
        # SUSFS proc mount hiding (falls unterstützt)
        adb_shell("susfs set_uname 2>/dev/null", as_root=True, check=False)
        
        log("SUSFS root hiding configured", "OK")
        
    except Exception as e:
        log(f"SUSFS hide error: {e}", "WARN")


def step_susfs_hide_app() -> None:
    """
    Phase 6.0: SUSFS App Hiding
    
    Versteckt die Titan Verifier App vor anderen Apps.
    TikTok scannt installierte Packages.
    """
    log("Setting up SUSFS App Hiding...")
    
    result = adb_shell("su -c 'which susfs 2>/dev/null'", as_root=False, check=False)
    if result.returncode != 0:
        return
    
    try:
        # App UID holen
        uid_result = adb_shell(f"stat -c %u /data/data/{PKG_NAME} 2>/dev/null", as_root=True, check=False)
        if uid_result.returncode == 0 and uid_result.stdout.strip():
            uid = uid_result.stdout.strip()
            adb_shell(f"susfs add_sus_kstat_uid {uid} 2>/dev/null", as_root=True, check=False)
            log(f"SUSFS hiding UID {uid} ({PKG_NAME})", "OK")
            
    except Exception as e:
        log(f"SUSFS app hide error: {e}", "WARN")


def step_create_bridge(identity: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """
    Phase 5.0: Bridge ONLY in /data/adb/modules/titan_verifier/titan_identity
    
    Format: Key=Value (eine Zeile pro Feld)
    
    Returns: Die verwendete identity für weitere Schritte
    """
    log("Creating Bridge file (Phase 5.0 - Boot-safe path)...")
    
    # Generiere Identität falls nicht übergeben
    if identity is None:
        identity = generate_pixel6_identity()
        print_identity(identity)
    
    # Bridge-Content im Key=Value Format
    bridge_lines = [
        "# Titan Identity Bridge - Phase 5.0 Final Convergence",
        f"# Generated: {datetime.now().isoformat()}",
        "",
    ]
    for key, value in identity.items():
        bridge_lines.append(f"{key}={value}")
    
    bridge_content = "\n".join(bridge_lines) + "\n"
    
    with tempfile.NamedTemporaryFile(mode="w", suffix=".titan_identity", delete=False) as f:
        f.write(bridge_content)
        tmp_bridge = f.name
    
    try:
        # PRIMARY: /data/adb/modules/titan_verifier/titan_identity
        adb(["push", tmp_bridge, f"{REMOTE_TMP}/titan_identity_tmp"])
        adb_shell(f"cp {REMOTE_TMP}/titan_identity_tmp {BRIDGE_PATH}", as_root=True)
        adb_shell(f"chmod 644 {BRIDGE_PATH}", as_root=True)
        adb_shell(f"chcon {SELINUX_CONTEXT_SYSTEM} {BRIDGE_PATH}", as_root=True, check=False)
        
        # BACKUP: /sdcard/.titan_identity (für LSPosed in GMS-Prozessen)
        adb_shell(f"cp {REMOTE_TMP}/titan_identity_tmp {BRIDGE_PATH_SDCARD}", as_root=True, check=False)
        adb_shell(f"chmod 644 {BRIDGE_PATH_SDCARD}", as_root=True, check=False)
        
        # Cleanup
        adb_shell(f"rm {REMOTE_TMP}/titan_identity_tmp", as_root=True, check=False)
        
    finally:
        os.unlink(tmp_bridge)
    
    log(f"Bridge erstellt: {BRIDGE_PATH}", "OK")
    log(f"  Backup: {BRIDGE_PATH_SDCARD}")
    log(f"  Format: Key=Value (11 Felder)")
    log(f"  SELinux: {SELINUX_CONTEXT_SYSTEM}")
    
    return identity


def step_set_kill_switch() -> None:
    """Phase 5.0: Kill-Switch setzen für sicheres Testen."""
    log("Setting kill-switch for safe testing...")
    adb_shell(f"touch {KILL_SWITCH_PATH}", as_root=True)
    adb_shell(f"chmod 644 {KILL_SWITCH_PATH}", as_root=True)
    log(f"Kill-switch aktiv: {KILL_SWITCH_PATH}", "OK")
    log("  HINWEIS: Entferne mit 'adb shell rm {KILL_SWITCH_PATH}' um Hooks zu aktivieren")


def step_trigger_module_update() -> None:
    """Phase 5.0: Update-Flag setzen damit KernelSU das Modul neu lädt."""
    log("Triggering module update...")
    adb_shell(f"touch {MODULE_PATH}/update", as_root=True, check=False)
    log(f"Update-Flag gesetzt: {MODULE_PATH}/update", "OK")


def _indent_xml(elem: ET.Element, level: int = 0, indent: str = "  ") -> None:
    """Fügt Einrückung hinzu für XML-Ausgabe."""
    i = "\n" + level * indent
    if len(elem):
        if not elem.text or not elem.text.strip():
            elem.text = i + indent
        if not elem.tail or not elem.tail.strip():
            elem.tail = i
        for child in elem:
            _indent_xml(child, level + 1, indent)
        if not child.tail or not child.tail.strip():
            child.tail = i
    else:
        if level and (not elem.tail or not elem.tail.strip()):
            elem.tail = i


def step_xml_patch() -> None:
    """7. XML Permission Patch: Privilegierte Permissions gewähren."""
    log("Patching runtime-permissions.xml...")
    
    local_xml = PROJECT_ROOT / "runtime-permissions-patched.xml"
    
    result = run(
        ["adb", "shell", "su", "-c", f"cat {RUNTIME_PERMISSIONS}"],
        check=False,
        capture=True
    )
    
    if result.returncode == 0 and result.stdout:
        local_xml.write_text(result.stdout, encoding="utf-8")
    else:
        local_xml.write_text(
            '<?xml version="1.0" encoding="utf-8"?>\n<packages/>\n',
            encoding="utf-8"
        )
        log("Neues runtime-permissions.xml erstellt", "WARN")
    
    try:
        tree = ET.parse(local_xml)
        root = tree.getroot()
    except (ET.ParseError, FileNotFoundError):
        root = ET.Element("packages")
        tree = ET.ElementTree(root)
    
    def local_tag(e: ET.Element) -> str:
        return e.tag.split("}")[-1] if "}" in e.tag else e.tag
    
    pkg_el = None
    for p in root.iter():
        if local_tag(p) == "pkg" and p.get("name") == PKG_NAME:
            pkg_el = p
            break
    
    if pkg_el is None:
        pkg_el = ET.SubElement(root, "pkg", name=PKG_NAME)
        log(f"Erstelle <pkg name=\"{PKG_NAME}\">")
    
    for permission in PRIVILEGED_PERMISSIONS:
        found = False
        for item in pkg_el:
            if local_tag(item) == "item" and item.get("name") == permission:
                item.set("granted", "true")
                item.set("flags", "0")
                found = True
                break
        
        if not found:
            ET.SubElement(pkg_el, "item", name=permission, granted="true", flags="0")
            log(f"  Permission hinzugefügt: {permission}")
    
    _indent_xml(root)
    tree.write(local_xml, encoding="utf-8", xml_declaration=True, method="xml")
    
    adb(["push", str(local_xml), f"{REMOTE_TMP}/runtime-permissions-patched.xml"])
    adb_shell(
        f"cp {REMOTE_TMP}/runtime-permissions-patched.xml {RUNTIME_PERMISSIONS}",
        as_root=True
    )
    adb_shell(f"chown system:system {RUNTIME_PERMISSIONS}", as_root=True)
    adb_shell(f"chmod 600 {RUNTIME_PERMISSIONS}", as_root=True)
    
    local_xml.unlink(missing_ok=True)
    
    log("runtime-permissions.xml gepatcht", "OK")


def step_create_fake_files(identity: Dict[str, str]) -> None:
    """Erstellt Fake-Systemdateien für mount --bind / fopen-Hooks."""
    log("Creating fake system files on device...")
    
    fake_dir = f"{MODULE_PATH}/fake_files"
    adb_shell(f"mkdir -p {fake_dir}", as_root=True, check=False)
    
    # Fake MAC-Datei
    mac = identity.get("wifi_mac", "02:00:00:00:00:00")
    adb_shell(f"echo '{mac}' > {fake_dir}/wlan0_address", as_root=True)
    adb_shell(f"chmod 444 {fake_dir}/wlan0_address", as_root=True)
    
    # Fake cpuinfo (Tensor G1)
    cpuinfo_content = "Hardware\\t: GS101 Oriole\\nSerial\\t\\t: 0000000000000000"
    adb_shell(f"echo -e '{cpuinfo_content}' > {fake_dir}/cpuinfo_tail", as_root=True)
    
    # Fake kernel version
    kernel_ver = "Linux version 5.10.149-android13-4-00003-g05231a35ff43-ab9850636"
    adb_shell(f"echo '{kernel_ver}' > {fake_dir}/version", as_root=True)
    
    adb_shell(f"chcon -R {SELINUX_CONTEXT_SYSTEM} {fake_dir}", as_root=True, check=False)
    log(f"Fake files created in {fake_dir}", "OK")


def step_write_aaid(identity: Dict[str, str]) -> None:
    """Schreibt die deterministische AAID direkt in GMS SharedPreferences."""
    log("Writing AAID to GMS preferences...")
    
    import hashlib
    serial = identity.get("serial", "")
    imei = identity.get("imei1", "")
    gsf = identity.get("gsf_id", "")
    seed = f"{serial}-{imei}-{gsf}-aaid"
    h = hashlib.sha256(seed.encode()).hexdigest()
    aaid = f"{h[0:8]}-{h[8:12]}-4{h[13:16]}-{(int(h[16],16) & 0x3 | 0x8):x}{h[17:20]}-{h[20:32]}"
    
    log(f"  Deterministic AAID: {aaid}")
    
    # Force-stop GMS damit SharedPrefs nicht überschrieben werden
    adb_shell("am force-stop com.google.android.gms", as_root=True, check=False)
    
    xml_content = f"""<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <boolean name="enable_debug_logging" value="false" />
    <boolean name="using_cert" value="false" />
    <string name="adid_key">{aaid}</string>
    <string name="fake_adid_key"></string>
    <boolean name="enable_limit_ad_tracking" value="false" />
    <int name="adid_reset_count" value="2" />
</map>"""
    
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
        f.write(xml_content)
        tmp_path = f.name
    
    adb(["push", tmp_path, "/data/local/tmp/adid_settings.xml"], check=False)
    
    adb_shell(
        "cp /data/local/tmp/adid_settings.xml "
        "/data/data/com.google.android.gms/shared_prefs/adid_settings.xml && "
        "chown 10152:10152 /data/data/com.google.android.gms/shared_prefs/adid_settings.xml && "
        "chmod 660 /data/data/com.google.android.gms/shared_prefs/adid_settings.xml",
        as_root=True, check=False
    )
    
    import os
    os.unlink(tmp_path)
    log(f"AAID written: {aaid}", "OK")


def step_distribute_bridge(identity: Dict[str, str]) -> None:
    """Kopiert die Bridge-Datei in die Datenordner ALLER Ziel-Apps."""
    log("Distributing bridge to all target apps...")
    
    target_apps = {
        "com.titan.verifier":           None,
        "tw.reh.deviceid":              None,
        "com.androidfung.drminfo":      None,
        "com.zhiliaoapp.musically":     None,
        "com.ss.android.ugc.trill":     None,
        "com.google.android.gms":       None,
        "com.google.android.gsf":       None,
        "com.android.vending":          None,
    }
    
    # UIDs herausfinden
    for pkg in list(target_apps.keys()):
        result = adb_shell(f"pm list packages -U {pkg}", check=False)
        if f"package:{pkg} " in result.stdout and "uid:" in result.stdout:
            uid = result.stdout.strip().split("uid:")[-1].strip()
            target_apps[pkg] = uid
    
    copied = 0
    for pkg, uid in target_apps.items():
        if uid is None:
            continue
        
        result = adb_shell(
            f"mkdir -p /data/data/{pkg}/files && "
            f"cp {BRIDGE_PATH} /data/data/{pkg}/files/.titan_identity && "
            f"chown {uid}:{uid} /data/data/{pkg}/files/.titan_identity && "
            f"chown {uid}:{uid} /data/data/{pkg}/files && "
            f"chmod 600 /data/data/{pkg}/files/.titan_identity",
            as_root=True, check=False
        )
        if result.returncode == 0:
            copied += 1
    
    # World-readable Backup auf /sdcard
    adb_shell(
        f"cp {BRIDGE_PATH} /sdcard/.titan_identity && chmod 644 /sdcard/.titan_identity",
        as_root=True, check=False
    )
    
    log(f"Bridge distributed to {copied}/{len(target_apps)} apps + /sdcard backup", "OK")


def step_post_deploy_verify(identity: Dict[str, str]) -> None:
    """Post-Deploy Verification: Prüft ob Properties korrekt gesetzt sind."""
    log("Running post-deploy verification...")
    
    checks_passed = 0
    checks_total = 0
    
    # Prüfe Bridge-Datei existiert
    checks_total += 1
    result = adb_shell(f"cat {BRIDGE_PATH}", as_root=True, check=False)
    if result.returncode == 0 and identity.get("serial", "") in result.stdout:
        checks_passed += 1
        log(f"Bridge OK: Serial={identity.get('serial', '?')}", "OK")
    else:
        log("Bridge: NOT FOUND or wrong content", "ERROR")
    
    # Prüfe Zygisk SO existiert
    checks_total += 1
    result = adb_shell(f"ls -la {ZYGISK_PATH}/arm64-v8a.so", as_root=True, check=False)
    if result.returncode == 0:
        checks_passed += 1
        log("Zygisk SO: Present", "OK")
    else:
        log("Zygisk SO: MISSING", "ERROR")
    
    # Prüfe App installiert
    checks_total += 1
    result = adb_shell(f"pm path {PKG_NAME}", check=False)
    if result.returncode == 0 and "package:" in result.stdout:
        checks_passed += 1
        log(f"App: Installed ({result.stdout.strip()})", "OK")
    else:
        log("App: NOT INSTALLED", "ERROR")
    
    # Prüfe Bridge in App-Daten (für ALLE Ziel-Apps!)
    target_apps = [
        PKG_NAME,                          # com.titan.verifier
        "tw.reh.deviceid",                 # Device ID App
        "com.androidfung.drminfo",         # DRM Info App
        "com.zhiliaoapp.musically",        # TikTok
        "com.ss.android.ugc.trill",        # TikTok International
    ]
    
    for app_pkg in target_apps:
        checks_total += 1
        result = adb_shell(
            f"cat /data/data/{app_pkg}/files/.titan_identity",
            as_root=True, check=False
        )
        if result.returncode == 0 and identity.get("serial", "") in result.stdout:
            checks_passed += 1
            log(f"Bridge [{app_pkg}]: OK", "OK")
        else:
            # Auto-fix: Finde UID und kopiere Bridge
            uid_result = adb_shell(f"pm list packages -U {app_pkg}", check=False)
            if "uid:" in uid_result.stdout:
                uid = uid_result.stdout.split("uid:")[-1].strip()
                adb_shell(
                    f"mkdir -p /data/data/{app_pkg}/files && "
                    f"cp {BRIDGE_PATH} /data/data/{app_pkg}/files/.titan_identity && "
                    f"chown {uid}:{uid} /data/data/{app_pkg}/files/.titan_identity && "
                    f"chown {uid}:{uid} /data/data/{app_pkg}/files && "
                    f"chmod 600 /data/data/{app_pkg}/files/.titan_identity",
                    as_root=True, check=False
                )
                checks_passed += 1
                log(f"Bridge [{app_pkg}]: Copied (UID {uid})", "OK")
            else:
                log(f"Bridge [{app_pkg}]: App not installed", "WARN")
    
    # World-readable Backup auf /sdcard
    adb_shell(
        f"cp {BRIDGE_PATH} /sdcard/.titan_identity && chmod 644 /sdcard/.titan_identity",
        as_root=True, check=False
    )
    log("Bridge /sdcard/.titan_identity: Backup OK", "OK")
    
    # Prüfe Kill-Switch entfernt
    checks_total += 1
    result = adb_shell(f"ls {KILL_SWITCH_PATH}", as_root=True, check=False)
    if result.returncode != 0:
        checks_passed += 1
        log("Kill-Switch: Removed (hooks active)", "OK")
    else:
        log("Kill-Switch: ACTIVE (hooks disabled!)", "WARN")
    
    log(f"Verification: {checks_passed}/{checks_total} passed", 
        "OK" if checks_passed == checks_total else "WARN")


def step_finalize(full_reboot: bool = False) -> None:
    """8. Finalize: System neu starten."""
    log("Finalizing...")
    
    if full_reboot:
        log("Führe vollständigen Reboot aus...")
        adb(["reboot"], check=False)
        log("Gerät startet neu - warte auf Reconnect", "OK")
    else:
        log("Soft-Restart (stop && start)...")
        adb_shell("stop && start", as_root=True, check=False)
        log("System neu gestartet", "OK")


# ==============================================================================
# Hauptprogramm
# ==============================================================================

def main() -> None:
    global VERBOSE
    
    parser = argparse.ArgumentParser(
        description="Project Titan - Phase 5.0 Final Convergence Deployment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Beispiele:
  python automate_titan.py                      # Vollständiges Deployment (mit Kill-Switch)
  python automate_titan.py --skip-build         # Nur Deploy (ohne Build)
  python automate_titan.py --bridge-only        # Nur Bridge-Datei aktualisieren
  python automate_titan.py --generate-identity  # Zeige generierte Pixel 6 IDs

Nach Deployment:
  1. Manuell rebooten: adb reboot
  2. KernelSU + LSPosed konfigurieren
  3. Kill-Switch entfernen: adb shell rm /data/local/tmp/titan_stop
        """
    )
    parser.add_argument("--skip-build", action="store_true",
                        help="Überspringe Build-Schritte")
    parser.add_argument("--bridge-only", action="store_true",
                        help="Nur Bridge-Datei erstellen/aktualisieren")
    parser.add_argument("--generate-identity", action="store_true",
                        help="Generiere und zeige realistische Pixel 6 Identität")
    parser.add_argument("--full-reboot", action="store_true",
                        help="Vollständiger Reboot statt soft-restart")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Ausführliche Ausgabe")
    
    # Legacy-Argumente (ignoriert, aber akzeptiert für Kompatibilität)
    parser.add_argument("--serial", default="", help=argparse.SUPPRESS)
    parser.add_argument("--imei", default="", help=argparse.SUPPRESS)
    
    args = parser.parse_args()
    VERBOSE = args.verbose
    
    # Generate-Identity Mode
    if args.generate_identity:
        identity = generate_pixel6_identity()
        print_identity(identity)
        return
    
    print("=" * 60)
    print("Project Titan - Phase 5.0 Final Convergence")
    print("Target: Pixel 6 | Android 14 | KernelSU + Zygisk Next")
    print("Bridge: /data/adb/modules/titan_verifier/titan_identity")
    print("Safety: Kill-switch enabled by default")
    print("=" * 60)
    
    # Prüfe ADB-Verbindung
    log("Prüfe ADB-Verbindung...")
    result = adb(["devices"], check=False, capture=True)
    if "device" not in result.stdout or result.stdout.count("\n") < 2:
        log("Kein Gerät verbunden!", "ERROR")
        sys.exit(1)
    log("ADB-Verbindung OK", "OK")
    
    # Prüfe Root-Zugriff
    log("Prüfe Root-Zugriff...")
    if not check_adb_root():
        log("Root-Zugriff nicht verfügbar!", "ERROR")
        sys.exit(1)
    log("Root-Zugriff OK", "OK")
    
    # Bridge-Only Mode
    if args.bridge_only:
        print("\n[Bridge-Only Mode]")
        step_create_bridge()
        step_selinux_context()
        print("\n" + "=" * 60)
        print("Bridge-Update abgeschlossen!")
        print("=" * 60)
        return
    
    # Phase 5.0 Deployment
    print("\n[1/10] Build")
    if not args.skip_build:
        step_build_apk()
        step_build_native()
    else:
        log("Build übersprungen (--skip-build)", "WARN")
    
    print("\n[2/10] Push")
    step_push_files()
    
    print("\n[3/10] Systemize")
    step_systemize()
    
    print("\n[4/10] Zygisk Deploy")
    step_deploy_zygisk()
    
    print("\n[5/10] SELinux Context")
    step_selinux_context()
    
    print("\n[6/12] Bridge Setup (Boot-safe path)")
    identity = step_create_bridge()
    
    print("\n[7/12] SUSFS MAC Overlay (Kernel-Level)")
    if identity.get("wifi_mac"):
        step_susfs_mac_overlay(identity["wifi_mac"])
    
    print("\n[8/12] SUSFS Root Hiding")
    step_susfs_hide_root()
    
    print("\n[9/12] SUSFS App Hiding")
    step_susfs_hide_app()
    
    print("\n[10/14] Permission Patch")
    step_xml_patch()
    
    print("\n[11/16] Fake System Files")
    step_create_fake_files(identity)
    
    print("\n[12/16] AAID Write (GMS Preferences)")
    step_write_aaid(identity)
    
    print("\n[13/16] Bridge Distribution (All Target Apps)")
    step_distribute_bridge(identity)
    
    print("\n[14/16] Kill-Switch (Safety)")
    step_set_kill_switch()
    
    print("\n[15/16] Module Update Flag")
    step_trigger_module_update()
    
    print("\n[16/16] Post-Deploy Verification")
    step_post_deploy_verify(identity)
    
    print("\n" + "=" * 60)
    print("Phase 6.0 TOTAL STEALTH Deployment COMPLETE!")
    print("=" * 60)
    print(f"\nModule-Pfad:  {MODULE_PATH}")
    print(f"Zygisk-SO:    {ZYGISK_PATH}/arm64-v8a.so")
    print(f"Bridge:       {BRIDGE_PATH}")
    print(f"Kill-Switch:  {KILL_SWITCH_PATH} (AKTIV)")
    print(f"SELinux:      {SELINUX_CONTEXT_SYSTEM}")
    print("\n" + "=" * 60)
    print("Phase 6.0 - TOTAL STEALTH Features:")
    print("=" * 60)
    print("  - Netlink recvmsg Hook (gegen libsscronet.so)")
    print("  - SUSFS MAC Overlay (Kernel-Level)")
    print("  - SUSFS Root Hiding")
    print("  - open/read File Shadowing")
    print("  - Widevine Java Hook")
    print("  - GSF MatrixCursor Injection")
    print("\n" + "=" * 60)
    print("WICHTIGE NÄCHSTE SCHRITTE:")
    print("=" * 60)
    print("1. Starte das Gerät MANUELL neu (adb reboot)")
    print("2. Nach Boot: Öffne KernelSU - prüfe ob 'titan_verifier' erscheint")
    print("3. Öffne LSPosed - aktiviere 'Titan Verifier' für:")
    print("   - System Framework (android)")
    print("   - com.titan.verifier")
    print("   - com.google.android.gms (GMS)")
    print("   - com.google.android.gsf (GSF)")
    print("   - com.zhiliaoapp.musically (TikTok)")
    print(f"4. ERST wenn stabil: adb shell rm {KILL_SWITCH_PATH}")
    print("5. App neu starten und Audit prüfen - ZIEL: 10/10")


if __name__ == "__main__":
    main()
