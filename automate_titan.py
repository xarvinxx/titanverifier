#!/usr/bin/env python3
"""
Project Titan – Phase 3.3 Convergence Master Automator

Vollautomatisches Deployment für Pixel 6 (Android 14 + KernelSU):
1. Build: APK + Native SO
2. Push: APK nach /system/priv-app/
3. Zygisk: SO nach /data/adb/modules/.../zygisk/
4. Bridge: Erstelle /data/local/tmp/.titan_state
5. SELinux: Setze korrekten Security-Context
6. Permissions: XML-Patch für privilegierte Permissions
7. Finalize: System-Neustart

Anforderungen:
- ADB mit Root-Zugriff (KernelSU oder Magisk)
- Android NDK im PATH oder ANDROID_NDK_HOME gesetzt
- Gradle Wrapper im Projektverzeichnis

Verwendung:
    python automate_titan.py [--skip-build] [--bridge-only] [--verbose]
"""

import os
import subprocess
import sys
import argparse
import tempfile
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional
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

# Bridge-Konfiguration
BRIDGE_PATH = f"{REMOTE_TMP}/.titan_state"

# Permission-Konfiguration
RUNTIME_PERMISSIONS = "/data/system/users/0/runtime-permissions.xml"
PKG_NAME = "com.titan.verifier"
PRIVILEGED_PERMISSIONS = [
    "android.permission.READ_PRIVILEGED_PHONE_STATE",
    "android.permission.READ_PRECISE_PHONE_STATE",
]

# SELinux Contexts
SELINUX_CONTEXT_SYSTEM = "u:object_r:system_file:s0"
SELINUX_CONTEXT_DATA = "u:object_r:shell_data_file:s0"

# Verbose-Flag
VERBOSE = False


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
        # Für KernelSU/Magisk: su -c "command"
        # Escaping für verschachtelte Quotes
        escaped_cmd = cmd.replace('"', '\\"')
        cmd = f'su -c "{escaped_cmd}"'
    return adb(["shell", cmd], check=check, capture=True)


def check_adb_root() -> bool:
    """Prüft ob Root-Zugriff via ADB verfügbar ist."""
    result = adb_shell("id", as_root=True, check=False)
    if result.returncode == 0 and "uid=0" in result.stdout:
        return True
    # Fallback: adb root
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
    
    # Prüfe NDK
    ndk_home = os.environ.get("ANDROID_NDK_HOME") or os.environ.get("ANDROID_NDK")
    if not ndk_home:
        # Versuche Standard-Pfade
        possible_paths = [
            Path.home() / "Android" / "Sdk" / "ndk",
            Path("/opt/android-ndk"),
        ]
        for p in possible_paths:
            if p.exists():
                # Nimm neueste Version
                versions = sorted(p.iterdir(), reverse=True)
                if versions:
                    ndk_home = str(versions[0])
                    break
    
    if not ndk_home or not Path(ndk_home).exists():
        log("Android NDK nicht gefunden", "ERROR")
        log("Setze ANDROID_NDK_HOME oder installiere NDK via Android Studio", "ERROR")
        return False
    
    log(f"NDK: {ndk_home}")
    
    # Erstelle Build-Verzeichnis
    NATIVE_BUILD_DIR.mkdir(parents=True, exist_ok=True)
    
    # CMake konfigurieren
    toolchain = Path(ndk_home) / "build" / "cmake" / "android.toolchain.cmake"
    cmake_cmd = [
        "cmake",
        "-S", str(PROJECT_ROOT / "module"),
        "-B", str(NATIVE_BUILD_DIR),
        f"-DCMAKE_TOOLCHAIN_FILE={toolchain}",
        "-DANDROID_ABI=arm64-v8a",
        "-DANDROID_PLATFORM=android-30",
        "-DCMAKE_BUILD_TYPE=Release",
    ]
    
    result = run(cmake_cmd, check=False, capture=True)
    if result.returncode != 0:
        log("CMake-Konfiguration fehlgeschlagen", "ERROR")
        if VERBOSE and result.stderr:
            print(result.stderr)
        return False
    
    # Build
    result = run(
        ["cmake", "--build", str(NATIVE_BUILD_DIR), "-j"],
        check=False,
        capture=True
    )
    
    if result.returncode != 0:
        log("Native-Build fehlgeschlagen", "ERROR")
        if VERBOSE and result.stderr:
            print(result.stderr)
        return False
    
    # Prüfe Output
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
    
    # Erstelle Module-Struktur
    ensure_directory(PRIV_APP_PATH)
    ensure_directory(f"{ZYGISK_PATH}/arm64-v8a")
    
    # Kopiere APK
    if APK_PATH.exists():
        adb_shell(f"cp {REMOTE_APK_TMP} {PRIV_APP_PATH}/TitanVerifier.apk", as_root=True)
        adb_shell(f"chmod 644 {PRIV_APP_PATH}/TitanVerifier.apk", as_root=True)
        adb_shell(f"chown root:root {PRIV_APP_PATH}/TitanVerifier.apk", as_root=True)
        log("APK installiert als priv-app", "OK")
    
    # module.prop erstellen
    module_prop = f"""id={MODULE_ID}
name=Titan Verifier
version=1.0.0
versionCode=1
author=Lead-Architect
description=Project Titan - Hardware Identity Spoofing (Phase 3.3)
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
    """4. Zygisk: SO nach /data/adb/modules/.../zygisk/arm64-v8a/"""
    log("Deploying Zygisk module...")
    
    if not NATIVE_SO_PATH.exists():
        log("Native SO nicht vorhanden - überspringe Zygisk-Deployment", "WARN")
        return
    
    # Erstelle Zygisk-Verzeichnis
    ensure_directory(f"{ZYGISK_PATH}/arm64-v8a")
    
    # Kopiere SO
    # WICHTIG: Für Zygisk muss die Datei arm64-v8a.so heißen (nicht libtitan_zygisk.so)
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
    
    # Bridge-Datei: shell_data_file Context (lesbar für alle Prozesse)
    adb_shell(f"chcon {SELINUX_CONTEXT_DATA} {BRIDGE_PATH}", as_root=True, check=False)
    
    log("SELinux-Contexts gesetzt", "OK")


def step_create_bridge(serial: str = "", imei: str = "", boot_serial: str = "",
                       gsfid: str = "") -> None:
    """6. Bridge: Erstelle /data/local/tmp/.titan_state"""
    log("Creating Bridge file...")
    
    # Wenn keine Werte übergeben, verwende Platzhalter
    if not serial:
        serial = "TITAN_SERIAL_001"
    if not imei:
        imei = "123456789012345"
    if not boot_serial:
        boot_serial = serial
    if not gsfid:
        gsfid = "1234567890123456"
    
    # Bridge-Format: serial\nimei\nboot_serial\ngsfid
    bridge_content = f"{serial}\n{imei}\n{boot_serial}\n{gsfid}\n"
    
    with tempfile.NamedTemporaryFile(mode="w", suffix=".titan_state", delete=False) as f:
        f.write(bridge_content)
        tmp_bridge = f.name
    
    try:
        adb(["push", tmp_bridge, BRIDGE_PATH])
        # WICHTIG: chmod 666 damit Zygisk-Module lesen können
        adb_shell(f"chmod 666 {BRIDGE_PATH}", as_root=True)
        # SELinux-Context für Lesbarkeit
        adb_shell(f"chcon {SELINUX_CONTEXT_DATA} {BRIDGE_PATH}", as_root=True, check=False)
    finally:
        os.unlink(tmp_bridge)
    
    log(f"Bridge erstellt: {BRIDGE_PATH}", "OK")
    log(f"  Serial: {serial}")
    log(f"  IMEI: {imei}")


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
    
    # Pull aktuelle runtime-permissions.xml
    result = run(
        ["adb", "shell", "su", "-c", f"cat {RUNTIME_PERMISSIONS}"],
        check=False,
        capture=True
    )
    
    if result.returncode == 0 and result.stdout:
        local_xml.write_text(result.stdout, encoding="utf-8")
    else:
        # Fallback: Neues XML erstellen
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
    
    # Finde oder erstelle pkg-Element
    pkg_el = None
    for p in root.iter():
        if local_tag(p) == "pkg" and p.get("name") == PKG_NAME:
            pkg_el = p
            break
    
    if pkg_el is None:
        pkg_el = ET.SubElement(root, "pkg", name=PKG_NAME)
        log(f"Erstelle <pkg name=\"{PKG_NAME}\">")
    
    # Füge alle privilegierten Permissions hinzu
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
    
    # Push zurück aufs Gerät
    adb(["push", str(local_xml), f"{REMOTE_TMP}/runtime-permissions-patched.xml"])
    adb_shell(
        f"cp {REMOTE_TMP}/runtime-permissions-patched.xml {RUNTIME_PERMISSIONS}",
        as_root=True
    )
    adb_shell(f"chown system:system {RUNTIME_PERMISSIONS}", as_root=True)
    adb_shell(f"chmod 600 {RUNTIME_PERMISSIONS}", as_root=True)
    
    # Cleanup
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
        # Soft-Restart: stop && start
        log("Soft-Restart (stop && start)...")
        adb_shell("stop && start", as_root=True, check=False)
        log("System neu gestartet", "OK")


# ==============================================================================
# Hauptprogramm
# ==============================================================================

def main() -> None:
    global VERBOSE
    
    parser = argparse.ArgumentParser(
        description="Project Titan - Automated Deployment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Beispiele:
  python automate_titan.py                  # Vollständiges Deployment
  python automate_titan.py --skip-build     # Nur Deploy (ohne Build)
  python automate_titan.py --bridge-only    # Nur Bridge-Datei aktualisieren
  python automate_titan.py --full-reboot    # Mit vollständigem Reboot
        """
    )
    parser.add_argument("--skip-build", action="store_true",
                        help="Überspringe Build-Schritte")
    parser.add_argument("--bridge-only", action="store_true",
                        help="Nur Bridge-Datei erstellen/aktualisieren")
    parser.add_argument("--full-reboot", action="store_true",
                        help="Vollständiger Reboot statt soft-restart")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Ausführliche Ausgabe")
    parser.add_argument("--serial", default="",
                        help="Spoofed Serial Number für Bridge")
    parser.add_argument("--imei", default="",
                        help="Spoofed IMEI für Bridge")
    
    args = parser.parse_args()
    VERBOSE = args.verbose
    
    print("=" * 60)
    print("Project Titan - Phase 3.3 Convergence Deployment")
    print("Target: Pixel 6 | Android 14 | KernelSU + Zygisk Next")
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
        log("Stelle sicher, dass KernelSU/Magisk Shell-Root erlaubt", "ERROR")
        sys.exit(1)
    log("Root-Zugriff OK", "OK")
    
    # Bridge-Only Mode
    if args.bridge_only:
        print("\n[Bridge-Only Mode]")
        step_create_bridge(serial=args.serial, imei=args.imei)
        print("\n" + "=" * 60)
        print("Bridge-Update abgeschlossen!")
        print("=" * 60)
        return
    
    # Vollständiges Deployment
    print("\n[1/8] Build")
    if not args.skip_build:
        step_build_apk()
        step_build_native()
    else:
        log("Build übersprungen (--skip-build)", "WARN")
    
    print("\n[2/8] Push")
    step_push_files()
    
    print("\n[3/8] Systemize")
    step_systemize()
    
    print("\n[4/8] Zygisk Deploy")
    step_deploy_zygisk()
    
    print("\n[5/8] SELinux Context")
    step_selinux_context()
    
    print("\n[6/8] Bridge Setup")
    step_create_bridge(serial=args.serial, imei=args.imei)
    
    print("\n[7/8] Permission Patch")
    step_xml_patch()
    
    print("\n[8/8] Finalize")
    step_finalize(full_reboot=args.full_reboot)
    
    print("\n" + "=" * 60)
    print("Deployment abgeschlossen!")
    print("=" * 60)
    print(f"\nModule-Pfad: {MODULE_PATH}")
    print(f"Zygisk-SO:   {ZYGISK_PATH}/arm64-v8a.so")
    print(f"Bridge:      {BRIDGE_PATH}")
    print("\nNächste Schritte:")
    print("  1. Warte auf System-Neustart")
    print("  2. Öffne Titan Verifier App")
    print("  3. Prüfe ob Serial/IMEI gespooft werden")


if __name__ == "__main__":
    main()
