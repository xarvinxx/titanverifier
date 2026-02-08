"""
Project Titan — Host-Side Orchestrator: Zentrale Konfiguration
==============================================================

Single Source of Truth für alle Konstanten, Pfade und Carrier-Regeln.
Abgeleitet aus TITAN_CONTEXT.md (Abschnitt 3A: Identity Engine).

KEINE Zufallswerte hier — nur deterministische Regeln und Constraints.
"""

from pathlib import Path

# =============================================================================
# 1. Projekt-Pfade (Host-Seite)
# =============================================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent          # titanverifier/
HOST_ROOT = Path(__file__).resolve().parent                    # titanverifier/host/

# SQLite Datenbank — liegt im Projekt-Root, nicht im host/ Ordner
DATABASE_PATH = PROJECT_ROOT / "titan.db"
DATABASE_URL = f"sqlite+aiosqlite:///{DATABASE_PATH}"

# Backup-Verzeichnis für tar-Streams (App-Data)
BACKUP_DIR = PROJECT_ROOT / "backups"

# Unterverzeichnisse für Full-State-Backups
BACKUP_TIKTOK_SUBDIR = "tiktok"            # TikTok App-Daten
BACKUP_GMS_SUBDIR = "gms"                  # GMS/GSF/Vending App-Daten
BACKUP_ACCOUNTS_SUBDIR = "accounts"        # System Account-Datenbanken

# =============================================================================
# 2. Device Bridge Pfade (Android-Seite, via ADB)
# =============================================================================

# Primärer Bridge-Pfad (Boot-sicher, von Zygisk gelesen)
# Quelle: module/zygisk_module.cpp Zeile 63, automate_titan.py Zeile 54
BRIDGE_MODULE_PATH = "/data/adb/modules/titan_verifier"
BRIDGE_FILE_PATH = f"{BRIDGE_MODULE_PATH}/titan_identity"

# Fallback-Pfade (für LSPosed/App-interne Reader)
BRIDGE_SDCARD_PATH = "/sdcard/.titan_identity"
BRIDGE_APP_TEMPLATE = "/data/data/{package}/files/.titan_identity"

# Kill-Switch (deaktiviert Hooks wenn vorhanden)
KILL_SWITCH_PATH = "/data/local/tmp/titan_stop"

# SELinux Context für Bridge-Dateien (Zygote-Zugriff!)
SELINUX_CONTEXT = "u:object_r:system_file:s0"

# =============================================================================
# 3. Target Hardware: Google Pixel 6 (Oriole)
# =============================================================================

DEVICE_MODEL = "Pixel 6"
DEVICE_CODENAME = "oriole"
DEVICE_SOC = "Tensor G1 (GS101)"
ANDROID_VERSION = 14
API_LEVEL = 34

# =============================================================================
# 4. O2 Germany Carrier Spezifikation
#    Quelle: TITAN_CONTEXT.md Abschnitt 3A (Telephony)
# =============================================================================

class O2_DE:
    """
    O2 Germany (Telefónica Deutschland) — Carrier-Konstanten.
    
    MCC 262 = Deutschland
    MNC 07  = O2 / Telefónica
    """
    # --- Netzwerk-IDs ---
    MCC = "262"
    MNC = "07"
    MCC_MNC = "26207"                   # SIM_OPERATOR Feld
    OPERATOR_NAME = "o2-de"             # operator_name Feld
    SIM_OPERATOR_NAME = "o2 - de"       # sim_operator_name Feld (wie auf echten Geräten)
    COUNTRY_ISO = "de"
    NETWORK_TYPE = "LTE"
    PHONE_TYPE = "GSM"

    # --- IMSI Regeln ---
    # IMSI = MCC(3) + MNC(2) + MSIN(10) = 15 Ziffern
    IMSI_PREFIX = "26207"               # Muss mit 26207 beginnen
    IMSI_LENGTH = 15

    # --- ICCID (SIM Serial) Regeln ---
    # ICCID = 89 (Telecom) + 49 (Deutschland) + 22 (O2 Issuer) + ...
    ICCID_PREFIX = "894922"             # O2 DE Prefix
    ICCID_LENGTH = 20                   # 19 Body + 1 Luhn Check

    # --- Telefonnummer ---
    PHONE_PREFIX = "+49176"             # O2 Mobilfunk-Gasse
    PHONE_LENGTH = 13                   # +49176XXXXXXX (13 Zeichen total)

    # --- Voicemail ---
    VOICEMAIL_NUMBER = "+4917610"       # O2 Mailbox

    # --- Locale & Timezone ---
    LOCALE = "de-DE"
    TIMEZONE = "Europe/Berlin"


# =============================================================================
# 5. Pixel 6 IMEI/TAC Spezifikation
#    Quelle: TITAN_CONTEXT.md Abschnitt 3A (Hardware Identifiers)
# =============================================================================

class PIXEL6_TAC:
    """
    Type Allocation Codes für Google Pixel 6 (Oriole).
    
    TAC = erste 8 Ziffern der IMEI.
    TITAN_CONTEXT.md: "TAC: Must begin with 355543"
    
    Verifizierte 8-stellige TACs die mit 355543 beginnen:
    """
    PREFIX = "355543"                   # 6-stelliger Pflicht-Prefix

    # Vollständige 8-stellige TACs (Pixel 6 Varianten)
    TACS = [
        "35554310",                     # Pixel 6 (GB7N6) — Global
        "35554311",                     # Pixel 6 (GR1YH) — US
        "35554312",                     # Pixel 6 (G9S9B) — EU/DE
    ]

    IMEI_LENGTH = 15                    # 15 Ziffern (inkl. Luhn Check)


# =============================================================================
# 6. Widevine & DRM
# =============================================================================

WIDEVINE_ID_LENGTH = 32                 # 32 Hex-Zeichen
ANDROID_ID_LENGTH = 16                  # 16 Hex-Zeichen (SSAID)
GSF_ID_LENGTH = 17                      # 17 Dezimalziffern
SERIAL_LENGTH = 12                      # 12 alphanumerische Zeichen


# =============================================================================
# 7. Pixel 6 Build Fingerprints (Android 14)
#    Build-ID MUSS zum Security Patch passen — keine Mischung!
# =============================================================================

PIXEL6_BUILDS = [
    {
        "build_id": "AP2A.241005.015",
        "security_patch": "2024-10-05",
        "incremental": "12298734",
        "fingerprint": "google/oriole/oriole:14/AP2A.241005.015/12298734:user/release-keys",
        "description": "oriole-user 14 AP2A.241005.015 12298734 release-keys",
    },
    {
        "build_id": "AP2A.240805.005",
        "security_patch": "2024-08-05",
        "incremental": "12025142",
        "fingerprint": "google/oriole/oriole:14/AP2A.240805.005/12025142:user/release-keys",
        "description": "oriole-user 14 AP2A.240805.005 12025142 release-keys",
    },
    {
        "build_id": "AP1A.240505.004",
        "security_patch": "2024-05-05",
        "incremental": "11583682",
        "fingerprint": "google/oriole/oriole:14/AP1A.240505.004/11583682:user/release-keys",
        "description": "oriole-user 14 AP1A.240505.004 11583682 release-keys",
    },
    {
        "build_id": "AP1A.240305.019.A1",
        "security_patch": "2024-03-05",
        "incremental": "11473478",
        "fingerprint": "google/oriole/oriole:14/AP1A.240305.019.A1/11473478:user/release-keys",
        "description": "oriole-user 14 AP1A.240305.019.A1 11473478 release-keys",
    },
]


# =============================================================================
# 8. Google OUIs für WiFi MAC-Adressen
#    Quelle: IEEE OUI Database (MA-L assignments to Google Inc.)
# =============================================================================

GOOGLE_OUIS: list[tuple[int, int, int]] = [
    (0xF4, 0xF5, 0xD8),                # Google Inc. — Pixel WiFi
    (0x3C, 0x5A, 0xB4),                # Google Inc. — Chromecast/Pixel
    (0x54, 0x60, 0x09),                # Google Inc. — Pixel 6/7 series
    (0xA4, 0x77, 0x33),                # Google Inc. — Nest/Pixel
    (0x94, 0xEB, 0x2C),                # Google Inc. — Pixel WiFi alt
    (0x00, 0x1A, 0x11),                # Google Inc. — Corporate
]


# =============================================================================
# 9. Target Apps (für Bridge-Distribution & pm clear)
# =============================================================================

TIKTOK_PACKAGES = [
    "com.zhiliaoapp.musically",         # TikTok (International)
    "com.ss.android.ugc.trill",         # TikTok (Alternate)
]

GMS_PACKAGES = [
    "com.google.android.gms",           # Google Play Services
    "com.google.android.gsf",           # Google Services Framework
    "com.android.vending",              # Play Store
]

BRIDGE_TARGET_APPS = [
    *TIKTOK_PACKAGES,
    *GMS_PACKAGES,
    "com.titan.verifier",               # Unsere eigene App (Audit)
    "tw.reh.deviceid",                  # Device ID Checker
    "com.androidfung.drminfo",          # DRM Info Checker
]


# =============================================================================
# 9b. Full-State Backup: GMS App-Pakete + System Account-DBs
#     Für Google-Login-Erhalt beim Identity-Switch
# =============================================================================

# GMS-Pakete deren App-Daten pro Profil gesichert werden
GMS_BACKUP_PACKAGES = [
    "com.google.android.gms",           # Play Services (Auth-Tokens, Checkin)
    "com.google.android.gsf",           # Services Framework (GSF ID)
    "com.android.vending",              # Play Store (Session)
]

# System Account-Datenbanken (User 0 = primärer User)
# Diese speichern die Konto-Registry: WELCHE Accounts existieren
SYSTEM_ACCOUNT_DBS = [
    "/data/system_ce/0/accounts_ce.db",
    "/data/system_ce/0/accounts_ce.db-journal",
    "/data/system_ce/0/accounts_ce.db-wal",
    "/data/system_ce/0/accounts_ce.db-shm",
]

# SELinux-Context für Account-Datenbanken (KRITISCH!)
ACCOUNTS_DB_SELINUX = "u:object_r:accounts_data_file:s0"

# Permissions für Account-Datenbanken
ACCOUNTS_DB_OWNER = "1000"               # system UID
ACCOUNTS_DB_GROUP = "1000"               # system GID
ACCOUNTS_DB_MODE = "660"                 # rw-rw---- (system:system)


# =============================================================================
# 10. Flow-Timing Konstanten (aus TITAN_CONTEXT.md Abschnitt 3C)
# =============================================================================

class TIMING:
    """Wartezeiten für die Orchestrator-Flows."""
    AIRPLANE_MODE_LEASE_SECONDS = 12    # "Airplane Mode ON (12s wait for Lease)"
    BOOT_WAIT_SECONDS = 0              # 0 = unbegrenzt warten bis Gerät bootet
    BOOT_POLL_INTERVAL = 3              # Polling-Intervall beim Boot-Wait
    POST_BOOT_SETTLE_SECONDS = 5        # Nach Boot warten bevor Unlock
    ZYGOTE_RESTART_WAIT = 5             # Wartezeit nach killall zygote
    ADB_COMMAND_TIMEOUT = 30            # Timeout für einzelne ADB-Befehle
    IP_AUDIT_WAIT_SECONDS = 15          # Wartezeit nach Flugmodus-AUS bevor IP-Check


# =============================================================================
# 11. FastAPI Server
# =============================================================================

API_HOST = "0.0.0.0"
API_PORT = 8000
API_TITLE = "Project Titan — Command Center"
API_VERSION = "1.0.0"
