"""
Project Titan — Host-Side Orchestrator: Zentrale Konfiguration
==============================================================

Single Source of Truth für alle Konstanten, Pfade und Carrier-Regeln.
Abgeleitet aus TITAN_CONTEXT.md (Abschnitt 3A: Identity Engine).

KEINE Zufallswerte hier — nur deterministische Regeln und Constraints.
"""

import logging
from datetime import date, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

# =============================================================================
# 0. Zeitzone (Europe/Berlin — CET/CEST)
# =============================================================================

LOCAL_TZ = ZoneInfo("Europe/Berlin")

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
BACKUP_TIKTOK_SUBDIR = "tiktok"            # TikTok App-Daten (/data/data/<pkg>/)
BACKUP_SANDBOX_SUBDIR = "sandbox"          # TikTok Sandbox (/sdcard/Android/data/<pkg>/)
BACKUP_GMS_SUBDIR = "gms"                  # GMS/GSF/Vending App-Daten
BACKUP_ACCOUNTS_SUBDIR = "accounts"        # System Account-Datenbanken

# TikTok Sandbox-Pfade (Scoped Storage — enthält SDK-Fingerprints, Cache, Medien)
TIKTOK_SANDBOX_PATHS = [
    "/storage/emulated/0/Android/data/com.zhiliaoapp.musically",
    "/storage/emulated/0/Android/data/com.ss.android.ugc.trill",
]

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
# 7b. PIF (Play Integrity Fix) Fingerprint Spoof-Pool
#     Für /data/adb/pif.json — Software-Integrität (MEETS_BASIC_INTEGRITY)
#
#     TrickyStore liefert MEETS_DEVICE_INTEGRITY (Hardware-Ebene),
#     aber MEETS_BASIC_INTEGRITY erfordert einen gültigen Software-Fingerprint.
#     Ohne pif.json auf Android 14 = BASIC_INTEGRITY schlägt IMMER fehl.
#
#     SAFETY CONSTRAINT (v3.2):
#       Die pif.json darf NIEMALS die echten Pixel 6 (oriole) Daten enthalten!
#       Stattdessen simulieren wir ein ÄLTERES Pixel-Modell (Pixel 5, 5a, 4a 5G).
#       Grund: Wenn Hardware-Attestation (Tensor G1) und Software-Fingerprint
#       dasselbe Gerät beschreiben, kann Google die Diskrepanz zwischen echtem
#       TEE-Zertifikat und gespooftem Build erkennen → FAIL.
#       Mit einem älteren Modell ist die Software-Ebene plausibel entkoppelt.
#
#     Format: Exakt wie von Google signierte Build-Fingerprints.
#     Jeder Eintrag muss intern konsistent sein (build_id ↔ patch ↔ fingerprint).
# =============================================================================

# v4.1: PlayIntegrityFix nutzt custom.pif.prop (Key=Value), NICHT pif.json (JSON)!
# Der Pfad liegt im Modul-Ordner des PIF-Moduls.
PIF_PROP_PATH = "/data/adb/modules/playintegrityfix/custom.pif.prop"
# Legacy-Alias (wird noch in inject_pif_fingerprint referenziert)
PIF_JSON_PATH = PIF_PROP_PATH

PIF_SPOOF_POOL: list[dict[str, str]] = [
    # -----------------------------------------------------------------
    # Pixel 5 (redfin) — Android 14, letzte Updates Okt 2024
    # DEVICE_INITIAL_SDK_INT=30 (Android 11 ab Werk)
    # -----------------------------------------------------------------
    {
        "MANUFACTURER": "Google",
        "MODEL": "Pixel 5",
        "DEVICE": "redfin",
        "PRODUCT": "redfin",
        "BRAND": "google",
        "FINGERPRINT": "google/redfin/redfin:14/AP2A.241005.015/12298734:user/release-keys",
        "SECURITY_PATCH": "2024-10-05",
        "DEVICE_INITIAL_SDK_INT": "30",
        "BUILD_ID": "AP2A.241005.015",
        "INCREMENTAL": "12298734",
        "TYPE": "user",
        "TAGS": "release-keys",
    },
    {
        "MANUFACTURER": "Google",
        "MODEL": "Pixel 5",
        "DEVICE": "redfin",
        "PRODUCT": "redfin",
        "BRAND": "google",
        "FINGERPRINT": "google/redfin/redfin:14/AP2A.240805.005/12025142:user/release-keys",
        "SECURITY_PATCH": "2024-08-05",
        "DEVICE_INITIAL_SDK_INT": "30",
        "BUILD_ID": "AP2A.240805.005",
        "INCREMENTAL": "12025142",
        "TYPE": "user",
        "TAGS": "release-keys",
    },
    # -----------------------------------------------------------------
    # Pixel 5a (barbet) — Android 14, letzte Updates Aug 2024
    # DEVICE_INITIAL_SDK_INT=30 (Android 11 ab Werk)
    # -----------------------------------------------------------------
    {
        "MANUFACTURER": "Google",
        "MODEL": "Pixel 5a",
        "DEVICE": "barbet",
        "PRODUCT": "barbet",
        "BRAND": "google",
        "FINGERPRINT": "google/barbet/barbet:14/AP2A.240805.005/12025142:user/release-keys",
        "SECURITY_PATCH": "2024-08-05",
        "DEVICE_INITIAL_SDK_INT": "30",
        "BUILD_ID": "AP2A.240805.005",
        "INCREMENTAL": "12025142",
        "TYPE": "user",
        "TAGS": "release-keys",
    },
    {
        "MANUFACTURER": "Google",
        "MODEL": "Pixel 5a",
        "DEVICE": "barbet",
        "PRODUCT": "barbet",
        "BRAND": "google",
        "FINGERPRINT": "google/barbet/barbet:14/AP1A.240505.004/11583682:user/release-keys",
        "SECURITY_PATCH": "2024-05-05",
        "DEVICE_INITIAL_SDK_INT": "30",
        "BUILD_ID": "AP1A.240505.004",
        "INCREMENTAL": "11583682",
        "TYPE": "user",
        "TAGS": "release-keys",
    },
    # -----------------------------------------------------------------
    # Pixel 4a 5G (bramble) — Android 14, EoL Aug 2024
    # DEVICE_INITIAL_SDK_INT=30 (Android 11 ab Werk)
    # -----------------------------------------------------------------
    {
        "MANUFACTURER": "Google",
        "MODEL": "Pixel 4a (5G)",
        "DEVICE": "bramble",
        "PRODUCT": "bramble",
        "BRAND": "google",
        "FINGERPRINT": "google/bramble/bramble:14/AP1A.240305.019.A1/11473478:user/release-keys",
        "SECURITY_PATCH": "2024-03-05",
        "DEVICE_INITIAL_SDK_INT": "30",
        "BUILD_ID": "AP1A.240305.019.A1",
        "INCREMENTAL": "11473478",
        "TYPE": "user",
        "TAGS": "release-keys",
    },
]

# Legacy-Alias für Abwärtskompatibilität (wird in v4.0 entfernt)
PIXEL6_PIF_POOL = PIF_SPOOF_POOL


# =============================================================================
# 7c. Time-Travel Prevention — PIF Pool Integrity Validator
#
#     Verhindert logisch unmögliche Fingerprint-Konstellationen:
#       - SECURITY_PATCH in der Zukunft → technisch unmöglich (Instant-Fail)
#       - SECURITY_PATCH > 2 Jahre alt  → verdächtig, heuristisches Flag
#
#     Wird beim Import und explizit vom Injector aufgerufen.
#     Gibt die Liste der validen Einträge zurück.
# =============================================================================

_config_logger = logging.getLogger("titan.config")

# Pflichtfelder für einen gültigen PIF-Eintrag
PIF_REQUIRED_KEYS = frozenset({
    "DEVICE", "MODEL", "FINGERPRINT", "BUILD_ID", "SECURITY_PATCH",
})

# Maximales Alter eines PIF-Patch-Datums relativ zum heutigen Tag
PIF_MAX_AGE_DAYS = 730  # ~2 Jahre


def validate_pif_pool_integrity(
    pool: list[dict[str, str]] | None = None,
    *,
    reference_date: date | None = None,
    max_age_days: int = PIF_MAX_AGE_DAYS,
) -> list[dict[str, str]]:
    """
    Validiert den PIF_SPOOF_POOL auf zeitliche Konsistenz.

    Prüfungen pro Eintrag:
      1. Alle Pflichtfelder vorhanden und nicht leer
      2. SECURITY_PATCH ist ein gültiges ISO-Datum (YYYY-MM-DD)
      3. SECURITY_PATCH liegt NICHT in der Zukunft (Time-Travel)
      4. SECURITY_PATCH ist nicht älter als ``max_age_days``

    Args:
        pool:           Pool zum Validieren (Default: PIF_SPOOF_POOL)
        reference_date: Referenz-Datum (Default: heute). Nützlich für Tests.
        max_age_days:   Maximales Alter in Tagen (Default: 730 = ~2 Jahre)

    Returns:
        Liste der validen Pool-Einträge (kann leer sein!).
        Ungültige Einträge werden geloggt und übersprungen.
    """
    if pool is None:
        pool = PIF_SPOOF_POOL

    if reference_date is None:
        reference_date = date.today()

    oldest_allowed = reference_date - timedelta(days=max_age_days)
    valid: list[dict[str, str]] = []

    for idx, entry in enumerate(pool):
        model = entry.get("MODEL", "?")
        device = entry.get("DEVICE", "?")
        label = f"Pool[{idx}] {model}/{device}"

        # --- Pflichtfelder-Check ---
        missing = PIF_REQUIRED_KEYS - {
            k for k, v in entry.items() if v and v.strip()
        }
        if missing:
            _config_logger.error(
                "PIF INVALID: %s — Fehlende Felder: %s", label, missing,
            )
            continue

        # --- Datum parsen ---
        patch_str = entry["SECURITY_PATCH"].strip()
        try:
            patch_date = date.fromisoformat(patch_str)
        except ValueError:
            _config_logger.error(
                "PIF INVALID: %s — SECURITY_PATCH '%s' ist kein gültiges "
                "ISO-Datum (YYYY-MM-DD)", label, patch_str,
            )
            continue

        # --- Zukunfts-Check (Time-Travel) ---
        if patch_date > reference_date:
            _config_logger.error(
                "PIF TIME-TRAVEL: %s — SECURITY_PATCH %s liegt IN DER ZUKUNFT "
                "(heute: %s)! Eintrag wird ignoriert.",
                label, patch_str, reference_date.isoformat(),
            )
            continue

        # --- Alters-Check ---
        if patch_date < oldest_allowed:
            _config_logger.warning(
                "PIF STALE: %s — SECURITY_PATCH %s ist älter als %d Tage "
                "(Grenze: %s). Eintrag wird als verdächtig markiert, "
                "aber NICHT entfernt.",
                label, patch_str, max_age_days, oldest_allowed.isoformat(),
            )
            # Stale Einträge werden NICHT gefiltert — nur gewarnt.
            # Ein 2 Jahre alter Patch ist ungewöhnlich, aber nicht unmöglich.
            # Der Injector kann sie bei Bedarf weiter filtern.

        valid.append(entry)

    _config_logger.info(
        "PIF Pool Integrity: %d/%d Einträge valide (Ref: %s, MaxAge: %dd)",
        len(valid), len(pool), reference_date.isoformat(), max_age_days,
    )
    return valid


# GMS-Datenbank-Pfade (für Namespace-Nuke + SQL-Cleanup)
GMS_AUTH_DB = "/data/data/com.google.android.gms/databases/auth.db"
GMS_DG_CACHE = "/data/data/com.google.android.gms/app_dg_cache"
GSF_GSERVICES_DB = "/data/data/com.google.android.gsf/databases/gservices.db"


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

# FIX-19: Instagram + Snapchat hinzugefügt (Multi-App Vorbereitung)
# Die Zygisk-Hooks targetieren diese Apps bereits — ohne Bridge-Datei
# in ihrem App-Ordner deaktivieren sich die Hooks (FIX-20).
# Mit Bridge-Distribution erhalten sie die korrekt gespooften IDs.
SOCIAL_MEDIA_PACKAGES = [
    *TIKTOK_PACKAGES,
    "com.instagram.android",            # Instagram
    "com.snapchat.android",             # Snapchat
]

BRIDGE_TARGET_APPS = [
    *SOCIAL_MEDIA_PACKAGES,
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

    # --- GMS Smart Wait (Passive GSF Polling) ---
    GSF_READY_TIMEOUT_SECONDS = 600     # Max 10 Min auf GSF-ID warten (v3.0: von 300 auf 600)
    GSF_POLL_INTERVAL_SECONDS = 5       # Alle 5s Content Provider prüfen
    GMS_KICKSTART_SETTLE_SECONDS = 3    # Nach Kickstart kurz warten bevor Polling
    GSF_RETRY_KICKSTART_SECONDS = 180   # v3.0: Nach 180s ohne GSF-ID → zweiter Kickstart
    NETWORK_CONNECTIVITY_WAIT = 30      # v3.0: Wartezeit bei fehlender Konnektivität


# =============================================================================
# 11. FastAPI Server
# =============================================================================

API_HOST = "0.0.0.0"
API_PORT = 8000
API_TITLE = "Project Titan — Command Center"
API_VERSION = "1.0.0"
