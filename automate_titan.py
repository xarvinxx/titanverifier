#!/usr/bin/env python3
"""
Project Titan – Phase 5.0 Final Convergence Automator

STABILE Deployment-Lösung für Pixel 6 (Android 14 + KernelSU):
1. Build: APK + Native SO (optimiert)
2. Zygisk: SO nach /data/adb/modules/.../zygisk/
3. Bridge: NUR /data/adb/modules/.../titan_identity (Boot-sicher!)
4. SELinux: Korrekter Security-Context
5. Kill-Switch: Sicherheitsschalter setzen
6. Update-Flag: Modul neu laden

WICHTIG: Keine Zugriffe auf /sdcard oder /data/local/tmp während Boot!

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


def generate_pixel6_identity() -> Dict[str, str]:
    """
    Generiert eine vollständige, realistische Pixel 6 Identität.
    Alle IMEIs sind Luhn-konform, alle IDs im korrekten Format.
    """
    serial = generate_serial()
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
        "operator_name": generate_operator_name(),
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
version=4.2.0
versionCode=420
author=Lead-Architect
description=Project Titan - Full Identity Spoofing (Phase 4.2 Singularity)
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
    5b. SUSFS MAC Overlay: Überlager /sys/class/net/wlan0/address mit gespoofter MAC.
    Dies ist eine zusätzliche Schutzschicht für Apps, die direkt /sys lesen.
    
    Benötigt SUSFS-Unterstützung im Kernel.
    """
    log("Setting up SUSFS MAC overlay...")
    
    # Prüfe ob SUSFS verfügbar ist
    susfs_check = adb_shell("su -c 'which susfs 2>/dev/null || echo NOT_FOUND'", as_root=False, check=False)
    
    if "NOT_FOUND" in susfs_check.stdout or susfs_check.returncode != 0:
        log("SUSFS not available - skipping MAC overlay", "WARN")
        return
    
    try:
        # Erstelle temporäre Datei mit MAC-Adresse
        mac_file_path = f"{REMOTE_TMP}/.titan_mac_overlay"
        adb_shell(f"echo '{mac_address}' > {mac_file_path}", as_root=True)
        adb_shell(f"chmod 444 {mac_file_path}", as_root=True)
        
        # SUSFS Overlay erstellen (falls unterstützt)
        # susfs add_sus_path /sys/class/net/wlan0/address
        # susfs update_sus_path /sys/class/net/wlan0/address {mac_file_path}
        result = adb_shell(
            f"susfs add_sus_path /sys/class/net/wlan0/address 2>/dev/null",
            as_root=True, check=False
        )
        
        if result.returncode == 0:
            adb_shell(
                f"susfs update_sus_path /sys/class/net/wlan0/address {mac_file_path}",
                as_root=True, check=False
            )
            log(f"SUSFS MAC overlay created: {mac_address}", "OK")
        else:
            log("SUSFS overlay failed (kernel might not support)", "WARN")
            
    except Exception as e:
        log(f"SUSFS MAC overlay error: {e}", "WARN")


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
    
    print("\n[6/10] Bridge Setup (Boot-safe path)")
    identity = step_create_bridge()
    
    print("\n[7/10] SUSFS MAC Overlay (Optional)")
    if identity.get("wifi_mac"):
        step_susfs_mac_overlay(identity["wifi_mac"])
    
    print("\n[8/10] Permission Patch")
    step_xml_patch()
    
    print("\n[9/10] Kill-Switch (Safety)")
    step_set_kill_switch()
    
    print("\n[10/10] Module Update Flag")
    step_trigger_module_update()
    
    print("\n" + "=" * 60)
    print("Phase 5.0 Deployment COMPLETE!")
    print("=" * 60)
    print(f"\nModule-Pfad:  {MODULE_PATH}")
    print(f"Zygisk-SO:    {ZYGISK_PATH}/arm64-v8a.so")
    print(f"Bridge:       {BRIDGE_PATH}")
    print(f"Kill-Switch:  {KILL_SWITCH_PATH} (AKTIV)")
    print(f"SELinux:      {SELINUX_CONTEXT_SYSTEM}")
    print("\n" + "=" * 60)
    print("WICHTIGE NÄCHSTE SCHRITTE:")
    print("=" * 60)
    print("1. Starte das Gerät MANUELL neu (adb reboot)")
    print("2. Nach Boot: Öffne KernelSU - prüfe ob 'titan_verifier' erscheint")
    print("3. Öffne LSPosed - aktiviere 'Titan Verifier' für:")
    print("   - System Framework")
    print("   - com.titan.verifier")
    print("   - com.zhiliaoapp.musically (TikTok)")
    print(f"4. ERST wenn stabil: adb shell rm {KILL_SWITCH_PATH}")
    print("5. App neu starten und Audit prüfen")


if __name__ == "__main__":
    main()
