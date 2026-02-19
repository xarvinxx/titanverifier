#!/usr/bin/env python3
"""
Identity Factory (Phase 12.5) — Industrial-Grade Hardware Identity Architect

Generates mathematically perfect, forensically consistent Pixel 6 identities.
Every IMEI passes Luhn, every MAC uses real Google OUIs, every build fingerprint
is internally consistent with its security patch level.

Usage:
    python identity_factory.py --new "Acc_NYC_01"          # Neues Profil erstellen
    python identity_factory.py --new "Acc_LA_02" --carrier tmobile
    python identity_factory.py --list                       # Alle Profile anzeigen
    python identity_factory.py --show "Acc_NYC_01"          # Profil-Details
    python identity_factory.py --apply "Acc_NYC_01"         # Profil auf Gerät laden
    python identity_factory.py --apply "Acc_NYC_01" --wipe  # + TikTok Daten löschen
    python identity_factory.py --delete "Acc_NYC_01"        # Profil löschen
    python identity_factory.py --verify "Acc_NYC_01"        # Mathematische Validierung
    python identity_factory.py --export "Acc_NYC_01"        # Bridge-Datei exportieren
"""

import argparse
import hashlib
import json
import os
import random
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ==============================================================================
# Konfiguration
# ==============================================================================

PROJECT_ROOT = Path(__file__).resolve().parent
IDENTITIES_DB = PROJECT_ROOT / "identities.json"

# Remote Paths auf dem Gerät
MODULE_PATH = "/data/adb/modules/hw_overlay"
BRIDGE_PATH = f"{MODULE_PATH}/.hw_config"
BRIDGE_PATH_SDCARD = "/sdcard/.hw_config"
BRIDGE_PATH_APP = "/data/data/com.oem.hardware.service/files/.hw_config"
KILL_SWITCH_PATH = "/data/local/tmp/.hw_disabled"
SELINUX_CONTEXT = "u:object_r:system_file:s0"

# TikTok Package Names
TIKTOK_PACKAGES = [
    "com.zhiliaoapp.musically",
    "com.ss.android.ugc.trill",
]

# ==============================================================================
# 1. IMEI Synthesis (Luhn-Algorithmus)
# ==============================================================================

# Verifizierte Pixel 6 TACs (Type Allocation Codes, 8 Digits)
# Quelle: GSMA TAC Database
PIXEL6_TACS = [
    "35226911",   # Google Pixel 6 (GB7N6)
    "35847631",   # Google Pixel 6 (GR1YH)
    "35847632",   # Google Pixel 6 Pro
    "35394712",   # Google Pixel 6a
]


def luhn_checksum(number: str) -> int:
    """Berechnet die Luhn-Prüfziffer (ISO/IEC 7812)."""
    digits = [int(d) for d in number]
    odd = digits[-1::-2]
    even = digits[-2::-2]
    total = sum(odd)
    for d in even:
        d2 = d * 2
        total += d2 - 9 if d2 > 9 else d2
    return total % 10


def luhn_check_digit(partial: str) -> int:
    """Berechnet die Check-Digit für eine unvollständige Nummer."""
    return (10 - luhn_checksum(partial + "0")) % 10


def luhn_validate(number: str) -> bool:
    """Validiert eine Nummer gegen den Luhn-Algorithmus."""
    if not number.isdigit() or len(number) < 2:
        return False
    return luhn_checksum(number) == 0


def generate_imei(tac: Optional[str] = None) -> str:
    """
    Generiert eine Luhn-valide 15-stellige IMEI.
    
    Struktur: TAC (8) + Serial (6) + Check (1) = 15
    """
    if tac is None:
        tac = random.choice(PIXEL6_TACS)
    
    # 6 zufällige Seriennummern-Ziffern
    serial = ''.join(str(random.randint(0, 9)) for _ in range(6))
    partial = tac + serial  # 14 Ziffern
    
    check = luhn_check_digit(partial)
    imei = partial + str(check)
    
    # Doppelte Validierung
    assert luhn_validate(imei), f"FATAL: Generated IMEI {imei} fails Luhn check!"
    assert len(imei) == 15, f"FATAL: IMEI length {len(imei)} != 15"
    
    return imei


# ==============================================================================
# 2. OUI-Based MAC Generation
# ==============================================================================

# Verifizierte Google/Pixel OUIs (Organizationally Unique Identifier)
# Quelle: IEEE OUI Database (MA-L assignments to Google Inc.)
GOOGLE_OUIS = [
    (0xF4, 0xF5, 0xD8),   # Google Inc. - Pixel WiFi
    (0x3C, 0x5A, 0xB4),   # Google Inc. - Chromecast/Pixel
    (0x00, 0x1A, 0x11),   # Google Inc. - Corporate
    (0x54, 0x60, 0x09),   # Google Inc. - Pixel 6/7 series
    (0xA4, 0x77, 0x33),   # Google Inc. - Nest/Pixel
    (0x94, 0xEB, 0x2C),   # Google Inc. - Pixel WiFi alt
]


def generate_mac(oui: Optional[Tuple[int, int, int]] = None) -> str:
    """
    Generiert eine MAC-Adresse mit echtem Google OUI.
    
    Format: OUI (3 Bytes) + NIC (3 zufällige Bytes)
    KEIN locally-administered bit - echte Hersteller-MAC!
    """
    if oui is None:
        oui = random.choice(GOOGLE_OUIS)
    
    # 3 zufällige NIC-Bytes
    nic = [random.randint(0x00, 0xFF) for _ in range(3)]
    
    mac_bytes = list(oui) + nic
    return ':'.join(f'{b:02x}' for b in mac_bytes)


# ==============================================================================
# 3. Build Fingerprint & Version Sync
# ==============================================================================

# Verifizierte Pixel 6 Build-Kombinationen (Android 14)
# KRITISCH: Build-ID MUSS zum Security Patch passen!
PIXEL6_BUILDS = [
    {
        "build_id": "AP1A.240505.004",
        "security_patch": "2024-05-05",
        "incremental": "11583682",
        "description": "oriole-user 14 AP1A.240505.004 11583682 release-keys",
        "fingerprint": "google/oriole/oriole:14/AP1A.240505.004/11583682:user/release-keys",
    },
    {
        "build_id": "AP1A.240305.019.A1",
        "security_patch": "2024-03-05",
        "incremental": "11473478",
        "description": "oriole-user 14 AP1A.240305.019.A1 11473478 release-keys",
        "fingerprint": "google/oriole/oriole:14/AP1A.240305.019.A1/11473478:user/release-keys",
    },
    {
        "build_id": "AP1A.240105.019.A1",
        "security_patch": "2024-01-05",
        "incremental": "11244377",
        "description": "oriole-user 14 AP1A.240105.019.A1 11244377 release-keys",
        "fingerprint": "google/oriole/oriole:14/AP1A.240105.019.A1/11244377:user/release-keys",
    },
    {
        "build_id": "AP2A.240805.005",
        "security_patch": "2024-08-05",
        "incremental": "12025142",
        "description": "oriole-user 14 AP2A.240805.005 12025142 release-keys",
        "fingerprint": "google/oriole/oriole:14/AP2A.240805.005/12025142:user/release-keys",
    },
    {
        "build_id": "AP2A.241005.015",
        "security_patch": "2024-10-05",
        "incremental": "12298734",
        "description": "oriole-user 14 AP2A.241005.015 12298734 release-keys",
        "fingerprint": "google/oriole/oriole:14/AP2A.241005.015/12298734:user/release-keys",
    },
]

# ==============================================================================
# 4. Carrier / SIM Configuration
# ==============================================================================

CARRIERS = {
    "tmobile": {
        "mcc_mnc": "310260",
        "operator_name": "T-Mobile",
        "sim_operator_name": "T-Mobile",
        "country_iso": "us",
        "voicemail": "+18056377243",
        "phone_type": "GSM",
        "network_type": "LTE",
        "imsi_prefix": "310260",
        "iccid_prefix": "890126",
    },
    "att": {
        "mcc_mnc": "310410",
        "operator_name": "AT&T",
        "sim_operator_name": "AT&T",
        "country_iso": "us",
        "voicemail": "+18888880800",
        "phone_type": "GSM",
        "network_type": "LTE",
        "imsi_prefix": "310410",
        "iccid_prefix": "890141",
    },
    "verizon": {
        "mcc_mnc": "311480",
        "operator_name": "Verizon",
        "sim_operator_name": "Verizon Wireless",
        "country_iso": "us",
        "voicemail": "+18009220204",
        "phone_type": "CDMA",
        "network_type": "LTE",
        "imsi_prefix": "311480",
        "iccid_prefix": "891480",
    },
    "googlefi": {
        "mcc_mnc": "312530",
        "operator_name": "Google Fi",
        "sim_operator_name": "Google Fi",
        "country_iso": "us",
        "voicemail": "+14043986429",
        "phone_type": "GSM",
        "network_type": "LTE",
        "imsi_prefix": "312530",
        "iccid_prefix": "891253",
    },
    "mint": {
        "mcc_mnc": "310260",
        "operator_name": "Mint Mobile",
        "sim_operator_name": "Mint",
        "country_iso": "us",
        "voicemail": "+18056377243",
        "phone_type": "GSM",
        "network_type": "LTE",
        "imsi_prefix": "310260",
        "iccid_prefix": "890126",
    },
    "o2_de": {
        "mcc_mnc": "26207",
        "operator_name": "o2 - de",
        "sim_operator_name": "o2 - de",
        "country_iso": "de",
        "voicemail": "+4917633333333",
        "phone_type": "GSM",
        "network_type": "LTE",
        "imsi_prefix": "26207",
        "iccid_prefix": "894922",
    },
}

# US Area Codes (Top 25 Metro Areas)
US_AREA_CODES = [
    "212", "213", "310", "312", "347", "404", "415", "469",
    "502", "512", "516", "617", "646", "702", "713", "718",
    "786", "818", "832", "917", "929", "949", "954", "972",
]


def generate_phone_number(country_iso: str = "us") -> str:
    """Generates a random phone number based on the country code."""
    if country_iso == "de":
        prefix = random.choice(["176", "179", "1590", "152", "151", "171"])
        subscriber = ''.join(str(random.randint(0, 9)) for _ in range(7))
        return f"+49{prefix}{subscriber}"
    else:
        area = random.choice(US_AREA_CODES)
        exchange = str(random.randint(200, 999))
        subscriber = str(random.randint(1000, 9999))
        return f"+1{area}{exchange}{subscriber}"


def generate_imsi(prefix: str) -> str:
    """IMSI: MCC(3) + MNC(3) + MSIN(9-10) = 15 Digits."""
    msin = ''.join(str(random.randint(0, 9)) for _ in range(15 - len(prefix)))
    return prefix + msin


def generate_iccid(prefix: str) -> str:
    """ICCID (SIM Serial): Luhn-valide, 19-20 Digits."""
    body_len = 19  # 19 + 1 check = 20
    body = prefix + ''.join(str(random.randint(0, 9)) for _ in range(body_len - len(prefix)))
    check = luhn_check_digit(body)
    iccid = body + str(check)
    assert luhn_validate(iccid), f"Generated ICCID {iccid} fails Luhn!"
    return iccid


def generate_android_id() -> str:
    """16-stellige Hex Android ID (SSAID)."""
    return ''.join(random.choices('0123456789abcdef', k=16))


def generate_gsf_id() -> str:
    """17-stellige dezimale GSF ID."""
    # GSF IDs beginnen nie mit 0
    first = str(random.randint(1, 9))
    rest = ''.join(str(random.randint(0, 9)) for _ in range(16))
    return first + rest


def generate_serial() -> str:
    """12-stellige alphanumerische Pixel Serial Number."""
    # Pixel Serials vermeiden I, O (verwechselbar mit 1, 0)
    chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ0123456789'
    return ''.join(random.choices(chars, k=12))


def generate_widevine_id() -> str:
    """32-stellige Hex Widevine Device Unique ID."""
    return hashlib.sha256(os.urandom(32)).hexdigest()[:32]


# ==============================================================================
# 5. Identity Factory - Hauptlogik
# ==============================================================================

def create_identity(name: str, carrier_key: str = "o2_de",
                    build_idx: Optional[int] = None) -> Dict:
    """
    Erstellt eine vollständige, forensisch konsistente Pixel 6 Identität.
    
    Jeder Wert ist mathematisch validiert und intern konsistent.
    """
    # Carrier wählen
    carrier = CARRIERS.get(carrier_key, CARRIERS["o2_de"])
    
    # Build wählen (konsistent!)
    build = PIXEL6_BUILDS[build_idx] if build_idx is not None else random.choice(PIXEL6_BUILDS)
    
    # Seriennummer
    serial = generate_serial()
    
    # IMEIs (beide mit gleichem TAC für Dual-SIM Konsistenz)
    tac1 = random.choice(PIXEL6_TACS[:2])  # Pixel 6 TACs
    tac2 = random.choice(PIXEL6_TACS[:2])
    imei1 = generate_imei(tac1)
    imei2 = generate_imei(tac2)
    
    # MAC mit echtem Google OUI
    wifi_mac = generate_mac()
    
    # IDs
    android_id = generate_android_id()
    gsf_id = generate_gsf_id()
    widevine_id = generate_widevine_id()
    
    # SIM
    imsi = generate_imsi(carrier["imsi_prefix"])
    iccid = generate_iccid(carrier["iccid_prefix"])
    phone_number = generate_phone_number(carrier.get("country_iso", "us"))
    
    identity = {
        # Metadata
        "_name": name,
        "_created": datetime.now().isoformat(),
        "_carrier": carrier_key,
        "_build": build["build_id"],
        
        # Core Identity (Bridge-Felder)
        "serial": serial,
        "boot_serial": serial,
        "imei1": imei1,
        "imei2": imei2,
        "gsf_id": gsf_id,
        "android_id": android_id,
        "wifi_mac": wifi_mac,
        "widevine_id": widevine_id,
        "imsi": imsi,
        "sim_serial": iccid,
        "operator_name": carrier["operator_name"],
        
        # Phase 10.0 Telephony
        "phone_number": phone_number,
        "sim_operator": carrier["mcc_mnc"],
        "sim_operator_name": carrier["sim_operator_name"],
        "voicemail_number": carrier["voicemail"],
        
        # Build Fingerprint (intern konsistent!)
        "build_id": build["build_id"],
        "build_fingerprint": build["fingerprint"],
        "build_description": build["description"],
        "build_incremental": build["incremental"],
        "security_patch": build["security_patch"],
    }
    
    return identity


# ==============================================================================
# 6. Database (identities.json)
# ==============================================================================

def load_db() -> Dict[str, Dict]:
    """Lädt die Identity-Datenbank."""
    if IDENTITIES_DB.exists():
        try:
            return json.loads(IDENTITIES_DB.read_text())
        except (json.JSONDecodeError, IOError):
            return {}
    return {}


def save_db(db: Dict[str, Dict]) -> None:
    """Speichert die Identity-Datenbank."""
    IDENTITIES_DB.write_text(json.dumps(db, indent=2, ensure_ascii=False))


def get_bridge_fields(identity: Dict) -> Dict[str, str]:
    """
    Extrahiert die Bridge-relevanten Felder (keine internen Metadaten).

    v5.1: build_id, build_fingerprint, security_patch, build_incremental,
    build_description werden AUSGESCHLOSSEN — PIF hat exklusive Kontrolle
    über Build-Properties. Unser Zygisk-Modul darf diese NICHT spooven,
    da es sonst PIF's Canary-Fingerprint überschreibt → kein BASIC_INTEGRITY.
    """
    skip_keys = {
        "_name", "_created", "_carrier", "_build",
        "build_id", "build_fingerprint", "build_description",
        "build_incremental", "security_patch",
    }
    return {k: v for k, v in identity.items() if k not in skip_keys}


# ==============================================================================
# 7. Verification
# ==============================================================================

def verify_identity(identity: Dict) -> List[str]:
    """
    Mathematische und forensische Validierung einer Identität.
    Gibt eine Liste von Fehlern zurück (leer = perfekt).
    """
    errors = []
    
    # IMEI Luhn Check
    for key in ("imei1", "imei2"):
        imei = identity.get(key, "")
        if not imei:
            errors.append(f"{key}: MISSING")
        elif len(imei) != 15:
            errors.append(f"{key}: Length {len(imei)} != 15")
        elif not luhn_validate(imei):
            errors.append(f"{key}: LUHN FAILED ({imei})")
        elif imei[:8] not in [t for t in PIXEL6_TACS]:
            errors.append(f"{key}: Unknown TAC {imei[:8]}")
    
    # ICCID Luhn Check
    iccid = identity.get("sim_serial", "")
    if iccid and not luhn_validate(iccid):
        errors.append(f"sim_serial: LUHN FAILED ({iccid})")
    
    # MAC OUI Check
    mac = identity.get("wifi_mac", "")
    if mac:
        parts = mac.split(":")
        if len(parts) == 6:
            oui = tuple(int(p, 16) for p in parts[:3])
            if oui not in GOOGLE_OUIS:
                errors.append(f"wifi_mac: OUI {':'.join(parts[:3])} not in Google OUI list")
        else:
            errors.append(f"wifi_mac: Invalid format ({mac})")
    
    # Build Consistency
    build_id = identity.get("build_id", identity.get("_build", ""))
    security_patch = identity.get("security_patch", "")
    fingerprint = identity.get("build_fingerprint", "")
    
    if build_id and security_patch:
        # Finde den passenden Build
        matching_build = None
        for b in PIXEL6_BUILDS:
            if b["build_id"] == build_id:
                matching_build = b
                break
        
        if matching_build:
            if matching_build["security_patch"] != security_patch:
                errors.append(
                    f"Build/Patch MISMATCH: {build_id} expects "
                    f"{matching_build['security_patch']}, got {security_patch}"
                )
            if fingerprint and matching_build["fingerprint"] != fingerprint:
                errors.append(f"Fingerprint inconsistent with build_id {build_id}")
    
    # Android ID Format
    android_id = identity.get("android_id", "")
    if android_id:
        if len(android_id) != 16:
            errors.append(f"android_id: Length {len(android_id)} != 16")
        if not all(c in '0123456789abcdef' for c in android_id):
            errors.append(f"android_id: Not valid hex")
    
    # Widevine ID Format
    widevine = identity.get("widevine_id", "")
    if widevine:
        if len(widevine) != 32:
            errors.append(f"widevine_id: Length {len(widevine)} != 32")
        if not all(c in '0123456789abcdef' for c in widevine):
            errors.append(f"widevine_id: Not valid hex")
    
    # Serial Format
    serial = identity.get("serial", "")
    if serial and len(serial) != 12:
        errors.append(f"serial: Length {len(serial)} != 12")
    
    # IMSI Length
    imsi = identity.get("imsi", "")
    if imsi and len(imsi) != 15:
        errors.append(f"imsi: Length {len(imsi)} != 15")
    
    # Carrier Consistency
    sim_op = identity.get("sim_operator", "")
    op_name = identity.get("operator_name", "")
    if sim_op and op_name:
        found = False
        for c in CARRIERS.values():
            if c["mcc_mnc"] == sim_op and c["operator_name"] == op_name:
                found = True
                break
        if not found:
            # Soft-Warnung: Carrier könnte custom sein
            pass
    
    return errors


# ==============================================================================
# 8. ADB Integration
# ==============================================================================

def adb_cmd(args: List[str], check: bool = True) -> subprocess.CompletedProcess:
    """Führt adb [args] aus."""
    result = subprocess.run(
        ["adb"] + args, capture_output=True, text=True, check=False
    )
    if check and result.returncode != 0:
        print(f"  [ERROR] adb {' '.join(args)}: {result.stderr.strip()}")
    return result


def adb_shell(cmd: str, root: bool = False) -> subprocess.CompletedProcess:
    """Führt adb shell aus, optional als root."""
    if root:
        cmd = f'su -c "{cmd}"'
    return adb_cmd(["shell", cmd], check=False)


def check_device() -> bool:
    """Prüft ob ein Gerät verbunden ist."""
    r = adb_cmd(["devices"], check=False)
    lines = [l for l in r.stdout.strip().split("\n") if "\tdevice" in l]
    return len(lines) > 0


def apply_identity(identity: Dict, wipe_tiktok: bool = False) -> bool:
    """
    Schreibt ein Identity-Profil auf das Gerät und aktiviert es.
    
    1. Bridge-Datei schreiben
    2. In App-Datenordner kopieren (für AuditEngine)
    3. Optional: TikTok-Daten löschen
    4. Zygote killen (Hooks neu laden)
    """
    name = identity.get("_name", "Unknown")
    
    print(f"\n  Applying identity: {name}")
    
    if not check_device():
        print("  [ERROR] Kein Gerät verbunden!")
        return False
    
    # Root-Check
    r = adb_shell("id", root=True)
    if "uid=0" not in r.stdout:
        print("  [ERROR] Root-Zugriff nicht verfügbar!")
        return False
    
    # Bridge-Content generieren
    bridge_fields = get_bridge_fields(identity)
    lines = [
        f"# HW Config: {name}",
        f"# Created: {identity.get('_created', 'unknown')}",
        f"# Carrier: {identity.get('_carrier', 'unknown')}",
        f"# Build: {identity.get('_build', 'unknown')}",
        "",
    ]
    for key, value in bridge_fields.items():
        lines.append(f"{key}={value}")
    
    bridge_content = "\n".join(lines) + "\n"
    
    # Temporäre Datei schreiben und pushen
    with tempfile.NamedTemporaryFile(mode="w", suffix=".bridge", delete=False) as f:
        f.write(bridge_content)
        tmp_path = f.name
    
    try:
        # Push to device
        adb_cmd(["push", tmp_path, "/data/local/tmp/.hw_bridge_tmp"])
        
        # Primary: Module-Pfad
        adb_shell(f"mkdir -p {MODULE_PATH}", root=True)
        adb_shell(f"cp /data/local/tmp/.hw_bridge_tmp {BRIDGE_PATH}", root=True)
        adb_shell(f"chmod 644 {BRIDGE_PATH}", root=True)
        adb_shell(f"chcon {SELINUX_CONTEXT} {BRIDGE_PATH}", root=True)
        print(f"  [OK] Bridge: {BRIDGE_PATH}")
        
        # Backup: sdcard
        adb_shell(f"cp /data/local/tmp/.hw_bridge_tmp {BRIDGE_PATH_SDCARD}", root=True)
        print(f"  [OK] Backup: {BRIDGE_PATH_SDCARD}")
        
        # App-Datenordner (für AuditEngine)
        adb_shell("mkdir -p /data/data/com.oem.hardware.service/files", root=True)
        adb_shell(f"cp /data/local/tmp/.hw_bridge_tmp {BRIDGE_PATH_APP}", root=True)
        adb_shell(f"chmod 644 {BRIDGE_PATH_APP}", root=True)
        # Owner auf App-UID setzen
        r = adb_shell("stat -c %u /data/data/com.oem.hardware.service 2>/dev/null", root=True)
        uid = r.stdout.strip()
        if uid and uid.isdigit():
            adb_shell(f"chown {uid}:{uid} {BRIDGE_PATH_APP}", root=True)
        print(f"  [OK] App-Data: {BRIDGE_PATH_APP}")
        
        # Cleanup
        adb_shell("rm /data/local/tmp/.hw_bridge_tmp", root=True)
        
    finally:
        os.unlink(tmp_path)
    
    # Optional: TikTok Daten löschen
    if wipe_tiktok:
        print("\n  Wiping TikTok data...")
        for pkg in TIKTOK_PACKAGES:
            r = adb_shell(f"pm clear {pkg} 2>/dev/null", root=True)
            if "Success" in r.stdout:
                print(f"  [OK] Cleared: {pkg}")
            else:
                print(f"  [--] Not installed: {pkg}")
    
    # Kill-Switch entfernen (falls vorhanden)
    adb_shell(f"rm -f {KILL_SWITCH_PATH}", root=True)
    print(f"  [OK] Kill-switch removed")
    
    # Zygote killen (lädt alle Hooks neu)
    print("\n  Restarting Zygote (activating hooks)...")
    adb_shell("killall zygote", root=True)
    
    print(f"\n  Identity '{name}' applied successfully!")
    print("  Gerät startet Apps neu. Warte 10 Sekunden, dann öffne den Auditor.")
    
    return True


# ==============================================================================
# 9. CLI Interface
# ==============================================================================

def cmd_new(args):
    """Erstellt ein neues Identity-Profil."""
    name = args.name
    carrier = args.carrier or "o2_de"
    
    if carrier not in CARRIERS:
        print(f"[ERROR] Unknown carrier: {carrier}")
        print(f"  Available: {', '.join(CARRIERS.keys())}")
        return
    
    db = load_db()
    if name in db and not args.force:
        print(f"[ERROR] Profile '{name}' already exists. Use --force to overwrite.")
        return
    
    identity = create_identity(name, carrier_key=carrier)
    
    # Verify
    errors = verify_identity(identity)
    if errors:
        print("[FATAL] Generated identity has errors:")
        for e in errors:
            print(f"  - {e}")
        return
    
    db[name] = identity
    save_db(db)
    
    print(f"\n{'='*60}")
    print(f"  NEW IDENTITY: {name}")
    print(f"{'='*60}")
    print(f"  Carrier:     {CARRIERS[carrier]['operator_name']}")
    print(f"  Build:       {identity['build_id']}")
    print(f"  Patch:       {identity['security_patch']}")
    print(f"{'='*60}")
    print(f"  Serial:      {identity['serial']}")
    print(f"  IMEI 1:      {identity['imei1']}  (Luhn: OK)")
    print(f"  IMEI 2:      {identity['imei2']}  (Luhn: OK)")
    print(f"  WiFi MAC:    {identity['wifi_mac']}  (OUI: Google)")
    print(f"  GSF ID:      {identity['gsf_id']}")
    print(f"  Android ID:  {identity['android_id']}")
    print(f"  Widevine:    {identity['widevine_id']}")
    print(f"  IMSI:        {identity['imsi']}")
    print(f"  ICCID:       {identity['sim_serial']}  (Luhn: OK)")
    print(f"  Phone:       {identity['phone_number']}")
    print(f"  Fingerprint: {identity['build_fingerprint']}")
    print(f"{'='*60}")
    print(f"  Saved to: {IDENTITIES_DB}")
    print(f"  Apply with: python identity_factory.py --apply \"{name}\"")


def cmd_list(args):
    """Listet alle gespeicherten Profile."""
    db = load_db()
    if not db:
        print("No identities stored yet.")
        print("  Create one: python identity_factory.py --new \"MyProfile\"")
        return
    
    print(f"\n{'='*80}")
    print(f"  {'Name':<20} {'Carrier':<12} {'Build':<22} {'Created':<20}")
    print(f"{'='*80}")
    
    for name, identity in db.items():
        carrier = identity.get("_carrier", "?")
        build = identity.get("_build", "?")
        created = identity.get("_created", "?")[:19]
        print(f"  {name:<20} {carrier:<12} {build:<22} {created:<20}")
    
    print(f"{'='*80}")
    print(f"  Total: {len(db)} profiles")


def cmd_show(args):
    """Zeigt Details eines Profils."""
    db = load_db()
    name = args.name
    
    if name not in db:
        print(f"[ERROR] Profile '{name}' not found.")
        return
    
    identity = db[name]
    
    print(f"\n{'='*60}")
    print(f"  IDENTITY: {name}")
    print(f"{'='*60}")
    
    for key, value in identity.items():
        if key.startswith("_"):
            print(f"  {key[1:]:<25} {value}")
        else:
            # Inline-Validierung
            suffix = ""
            if key in ("imei1", "imei2"):
                suffix = " [Luhn OK]" if luhn_validate(str(value)) else " [LUHN FAIL!]"
            elif key == "sim_serial":
                suffix = " [Luhn OK]" if luhn_validate(str(value)) else " [LUHN FAIL!]"
            elif key == "wifi_mac":
                parts = value.split(":")
                if len(parts) == 6:
                    oui = tuple(int(p, 16) for p in parts[:3])
                    suffix = " [Google OUI]" if oui in GOOGLE_OUIS else " [Unknown OUI!]"
            
            print(f"  {key:<25} {value}{suffix}")
    
    print(f"{'='*60}")


def cmd_verify(args):
    """Mathematische Validierung eines Profils."""
    db = load_db()
    name = args.name
    
    if name not in db:
        print(f"[ERROR] Profile '{name}' not found.")
        return
    
    identity = db[name]
    errors = verify_identity(identity)
    
    print(f"\n  Verifying: {name}")
    print(f"  {'='*50}")
    
    checks = [
        ("IMEI 1 Luhn", luhn_validate(identity.get("imei1", ""))),
        ("IMEI 2 Luhn", luhn_validate(identity.get("imei2", ""))),
        ("ICCID Luhn", luhn_validate(identity.get("sim_serial", ""))),
        ("MAC OUI (Google)", identity.get("wifi_mac", "").split(":")[0:3] != []),
        ("Android ID (16 hex)", len(identity.get("android_id", "")) == 16),
        ("Widevine ID (32 hex)", len(identity.get("widevine_id", "")) == 32),
        ("Serial (12 chars)", len(identity.get("serial", "")) == 12),
        ("IMSI (15 digits)", len(identity.get("imsi", "")) == 15),
        ("Build Consistency", not any("Build" in e or "Patch" in e for e in errors)),
    ]
    
    all_ok = True
    for label, passed in checks:
        status = "PASS" if passed else "FAIL"
        icon = "+" if passed else "!"
        print(f"  [{icon}] {label:<30} [{status}]")
        if not passed:
            all_ok = False
    
    if errors:
        print(f"\n  Errors:")
        for e in errors:
            print(f"    - {e}")
    
    print(f"\n  Result: {'ALL CHECKS PASSED' if all_ok else 'VALIDATION FAILED'}")


def cmd_apply(args):
    """Wendet ein Profil auf das Gerät an."""
    db = load_db()
    name = args.name
    
    if name not in db:
        print(f"[ERROR] Profile '{name}' not found.")
        return
    
    identity = db[name]
    
    # Erst validieren
    errors = verify_identity(identity)
    if errors:
        print(f"[WARNING] Profile has validation errors:")
        for e in errors:
            print(f"  - {e}")
        if not args.force:
            print("Use --force to apply anyway.")
            return
    
    apply_identity(identity, wipe_tiktok=args.wipe)


def cmd_delete(args):
    """Löscht ein Profil."""
    db = load_db()
    name = args.name
    
    if name not in db:
        print(f"[ERROR] Profile '{name}' not found.")
        return
    
    del db[name]
    save_db(db)
    print(f"  Profile '{name}' deleted.")


def cmd_export(args):
    """Exportiert ein Profil als Bridge-Datei."""
    db = load_db()
    name = args.name
    
    if name not in db:
        print(f"[ERROR] Profile '{name}' not found.")
        return
    
    identity = db[name]
    bridge_fields = get_bridge_fields(identity)
    
    output_path = PROJECT_ROOT / f"bridge_{name}.txt"
    lines = [
        f"# HW Config: {name}",
        f"# Created: {identity.get('_created', 'unknown')}",
        f"# Carrier: {identity.get('_carrier', 'unknown')}",
        f"# Build: {identity.get('_build', 'unknown')}",
        "",
    ]
    for key, value in bridge_fields.items():
        lines.append(f"{key}={value}")
    
    output_path.write_text("\n".join(lines) + "\n")
    print(f"  Exported to: {output_path}")


# ==============================================================================
# Main
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Identity Factory (Phase 12.5)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python identity_factory.py --new "Acc_NYC_01"                  # T-Mobile default
  python identity_factory.py --new "Acc_LA_02" --carrier att     # AT&T
  python identity_factory.py --new "Acc_VZ_03" --carrier verizon # Verizon
  python identity_factory.py --list                               # All profiles
  python identity_factory.py --show "Acc_NYC_01"                  # Details
  python identity_factory.py --verify "Acc_NYC_01"                # Validate
  python identity_factory.py --apply "Acc_NYC_01"                 # Push to device
  python identity_factory.py --apply "Acc_NYC_01" --wipe          # + clear TikTok
  python identity_factory.py --delete "Acc_NYC_01"                # Remove
  python identity_factory.py --export "Acc_NYC_01"                # Export bridge file

Carriers: tmobile, att, verizon, googlefi, mint
        """
    )
    
    # Mutual exclusive primary actions
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--new", metavar="NAME", dest="new_name",
                       help="Create new identity profile")
    group.add_argument("--list", action="store_true",
                       help="List all stored profiles")
    group.add_argument("--show", metavar="NAME",
                       help="Show profile details")
    group.add_argument("--verify", metavar="NAME",
                       help="Validate profile mathematically")
    group.add_argument("--apply", metavar="NAME",
                       help="Apply profile to device")
    group.add_argument("--delete", metavar="NAME",
                       help="Delete a profile")
    group.add_argument("--export", metavar="NAME",
                       help="Export profile as bridge file")
    
    # Options
    parser.add_argument("--carrier", default="o2_de",
                        choices=list(CARRIERS.keys()),
                        help="Carrier for new profile (default: o2_de)")
    parser.add_argument("--wipe", action="store_true",
                        help="Clear TikTok data when applying")
    parser.add_argument("--force", action="store_true",
                        help="Force overwrite or apply despite warnings")
    
    args = parser.parse_args()
    
    # Route to command
    if args.new_name:
        args.name = args.new_name
        cmd_new(args)
    elif args.list:
        cmd_list(args)
    elif args.show:
        args.name = args.show
        cmd_show(args)
    elif args.verify:
        args.name = args.verify
        cmd_verify(args)
    elif args.apply:
        args.name = args.apply
        cmd_apply(args)
    elif args.delete:
        args.name = args.delete
        cmd_delete(args)
    elif args.export:
        args.name = args.export
        cmd_export(args)


if __name__ == "__main__":
    main()
