#!/usr/bin/env python3
"""
Phase 2.2 - Full Automated System Integration & Permission Injection
Deployment-Workflow für Pixel 6: Build -> Push -> Systemize -> XML Permission Patch -> Reboot
"""

import os
import subprocess
import sys
import xml.etree.ElementTree as ET
import tempfile
from pathlib import Path

# Konfiguration
PROJECT_ROOT = Path(__file__).resolve().parent
APK_PATH = PROJECT_ROOT / "app" / "build" / "outputs" / "apk" / "debug" / "app-debug.apk"
REMOTE_TMP = "/data/local/tmp/titan_verifier.apk"
MODULE_ID = "titan_verifier"
MODULE_PATH = f"/data/adb/modules/{MODULE_ID}"
PRIV_APP_PATH = f"{MODULE_PATH}/system/priv-app/TitanVerifier"
RUNTIME_PERMISSIONS = "/data/system/users/0/runtime-permissions.xml"
PKG_NAME = "com.titan.verifier"
PERMISSION = "android.permission.READ_PRIVILEGED_PHONE_STATE"


def run(cmd: list[str], check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    """Führt einen Befehl aus."""
    print(f"  $ {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=capture, text=True, check=False)
    if check and result.returncode != 0:
        print(f"  FEHLER: exit code {result.returncode}")
        if capture and result.stderr:
            print(f"  stderr: {result.stderr[:500]}")
        sys.exit(1)
    return result


def adb(args: list[str], check: bool = True, shell: bool = False) -> subprocess.CompletedProcess:
    """Führt adb [args] aus."""
    cmd = ["adb"] + args
    return run(cmd, check=check, capture=shell)


def adb_shell(cmd: str, as_root: bool = False, check: bool = True) -> subprocess.CompletedProcess:
    """Führt adb shell [cmd] aus."""
    if as_root:
        cmd = f'su -c "{cmd.replace(chr(34), chr(39))}"'
    return adb(["shell", cmd], check=check, shell=True)


def step_build() -> None:
    """1. Build: ./gradlew assembleDebug"""
    print("\n[1/5] Build")
    os.chdir(PROJECT_ROOT)
    run(["./gradlew", "assembleDebug"])
    if not APK_PATH.exists():
        print(f"  FEHLER: APK nicht gefunden: {APK_PATH}")
        sys.exit(1)
    print(f"  OK: {APK_PATH}")


def step_push() -> None:
    """2. Push APK nach /data/local/tmp"""
    print("\n[2/5] Push")
    adb(["push", str(APK_PATH), REMOTE_TMP])
    print(f"  OK: {REMOTE_TMP}")


def step_systemize() -> None:
    """3. Systemize: Module-Struktur + APK + module.prop"""
    print("\n[3/5] Systemize")
    adb_shell(f"mkdir -p {PRIV_APP_PATH}", as_root=True)
    adb_shell(f"cp {REMOTE_TMP} {PRIV_APP_PATH}/TitanVerifier.apk", as_root=True)
    adb_shell(f"chmod 644 {PRIV_APP_PATH}/TitanVerifier.apk", as_root=True)
    adb_shell(f"chown root:root {PRIV_APP_PATH}/TitanVerifier.apk", as_root=True)

    module_prop = f"""id={MODULE_ID}
name=Titan Verifier
version=1.0.0
versionCode=1
author=Lead-Architect
description=Ground Truth Audit / System Integration (Project Titan)
"""
    # module.prop via temporäre Datei
    with tempfile.NamedTemporaryFile(mode="w", suffix=".prop", delete=False) as f:
        f.write(module_prop)
        tmp = f.name
    try:
        adb(["push", tmp, f"/data/local/tmp/module.prop"])
        adb_shell(f"cp /data/local/tmp/module.prop {MODULE_PATH}/module.prop", as_root=True)
        adb_shell(f"chmod 644 {MODULE_PATH}/module.prop", as_root=True)
    finally:
        os.unlink(tmp)
    print(f"  OK: {PRIV_APP_PATH}")


def _indent_xml(elem: ET.Element, level: int = 0, indent: str = "  ") -> None:
    """Fügt Einrückung hinzu (Python < 3.9 Kompatibilität)."""
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
    """4. XML Permission Patch (Titan-Bypass)"""
    print("\n[4/5] XML Permission Patch")
    local_xml = PROJECT_ROOT / "runtime-permissions-patched.xml"

    # Pull runtime-permissions.xml (via su + cat, da /data/system root-only)
    r = run(
        ["adb", "shell", "su", "-c", f"cat {RUNTIME_PERMISSIONS}"],
        check=False,
        capture=True,
    )
    if r.returncode == 0 and r.stdout:
        local_xml.write_text(r.stdout, encoding="utf-8")
    else:
        # Fallback: adb pull (funktioniert wenn adb root)
        r2 = adb(["pull", RUNTIME_PERMISSIONS, str(local_xml)], check=False)
        if r2.returncode != 0 or not local_xml.exists():
            # Neues XML erstellen
            local_xml.write_text(
                '<?xml version="1.0" encoding="utf-8"?>\n<packages/>\n',
                encoding="utf-8",
            )
            print("  Neues runtime-permissions.xml (leer)")

    try:
        tree = ET.parse(local_xml)
        root = tree.getroot()
    except (ET.ParseError, FileNotFoundError):
        root = ET.Element("packages")
        tree = ET.ElementTree(root)

    # Entferne Namespace für einfachere Suche (tag kann {uri}localname sein)
    def local_tag(e: ET.Element) -> str:
        return e.tag.split("}")[-1] if "}" in e.tag else e.tag

    pkg_el = None
    for p in root.iter():
        if local_tag(p) == "pkg" and p.get("name") == PKG_NAME:
            pkg_el = p
            break

    if pkg_el is None:
        pkg_el = ET.SubElement(root, "pkg", name=PKG_NAME)
        print(f"  Erstelle <pkg name=\"{PKG_NAME}\">")

    found = False
    for item in pkg_el:
        if local_tag(item) == "item" and item.get("name") == PERMISSION:
            item.set("granted", "true")
            item.set("flags", "0")
            found = True
            break
    if not found:
        ET.SubElement(pkg_el, "item", name=PERMISSION, granted="true", flags="0")
        print(f"  Inseriere {PERMISSION}")

    _indent_xml(root)
    tree.write(local_xml, encoding="utf-8", xml_declaration=True, method="xml")

    adb(["push", str(local_xml), "/data/local/tmp/runtime-permissions-patched.xml"])
    adb_shell(
        "cp /data/local/tmp/runtime-permissions-patched.xml " + RUNTIME_PERMISSIONS,
        as_root=True,
    )
    adb_shell(f"chown system:system {RUNTIME_PERMISSIONS}", as_root=True)
    adb_shell(f"chmod 600 {RUNTIME_PERMISSIONS}", as_root=True)
    local_xml.unlink(missing_ok=True)
    print("  OK: runtime-permissions.xml gepatcht")


def step_finalize() -> None:
    """5. Finalize: stop && start"""
    print("\n[5/5] Finalize")
    adb_shell("stop && start", as_root=True)
    print("  OK: System neu gestartet")


def main() -> None:
    print("=== Titan Verifier - Automated System Integration ===")
    print("Target: Pixel 6 | KernelSU / Magisk Module")
    step_build()
    step_push()
    step_systemize()
    step_xml_patch()
    step_finalize()
    print("\n=== Deployment abgeschlossen ===")


if __name__ == "__main__":
    main()
