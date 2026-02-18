"""
Identity Models
================

Pydantic-Modelle für Hardware-Identitäten (O2 Germany / Pixel 6).

Drei Schichten:
  1. IdentityCreate  — Input-Validierung beim Erstellen neuer Identitäten
  2. IdentityRead    — Vollständiges DB-Modell mit Metadaten (id, created_at, ...)
  3. IdentityBridge  — Nur die Felder, die in die Bridge-Datei geschrieben werden

SQL-Schema: Siehe database.py → CREATE TABLE identities
"""

from __future__ import annotations

import re
from datetime import datetime

from host.config import LOCAL_TZ
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator

from host.config import (
    ANDROID_ID_LENGTH,
    GSF_ID_LENGTH,
    O2_DE,
    PIXEL6_DEVICE_PROPS,
    PIXEL6_TAC,
    SERIAL_LENGTH,
    WIDEVINE_ID_LENGTH,
)


# =============================================================================
# Enums
# =============================================================================

class IdentityStatus(str, Enum):
    """Lifecycle-Status einer Identität."""
    READY = "ready"             # Generiert, validiert, einsatzbereit
    ACTIVE = "active"           # Aktuell auf dem Gerät geladen
    RETIRED = "retired"         # Nicht mehr in Verwendung
    CORRUPTED = "corrupted"     # tar-Stream abgebrochen / Daten inkonsistent


# =============================================================================
# Bridge Model — Exakt die Felder für die Bridge-Datei (.hw_config)
# =============================================================================

class IdentityBridge(BaseModel):
    """
    Die Felder, die 1:1 in die Bridge-Datei geschrieben werden.

    Format auf dem Gerät (Key=Value):
        serial=ABC123DEF456
        boot_serial=ABC123DEF456
        imei1=355543100123456
        ...

    Muss kompatibel sein mit:
      - Native C++ Parser (Hardware-Bridge)
      - Kotlin Bridge-Reader
      - Zygisk-Modul (zygisk_module.cpp)
    """

    # --- Core Hardware ---
    serial: str = Field(..., min_length=SERIAL_LENGTH, max_length=SERIAL_LENGTH,
                        description="12-stellige Pixel Serial Number")
    boot_serial: str = Field(..., min_length=SERIAL_LENGTH, max_length=SERIAL_LENGTH,
                             description="Boot Serial (identisch mit serial)")

    # --- IMEI (Dual-SIM) ---
    imei1: str = Field(..., min_length=15, max_length=15,
                       description="Primäre IMEI (Luhn-valide, TAC 355543xx)")
    imei2: str = Field(..., min_length=15, max_length=15,
                       description="Sekundäre IMEI (Luhn-valide, TAC 355543xx)")

    # --- Identifiers ---
    gsf_id: str = Field(..., min_length=GSF_ID_LENGTH, max_length=GSF_ID_LENGTH,
                        description="Google Services Framework ID (17 Dezimalziffern)")
    android_id: str = Field(..., min_length=ANDROID_ID_LENGTH, max_length=ANDROID_ID_LENGTH,
                            description="Android SSAID (16 Hex-Zeichen)")
    wifi_mac: str = Field(..., pattern=r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$",
                          description="WiFi MAC mit Google OUI (xx:xx:xx:xx:xx:xx)")
    widevine_id: str = Field(..., min_length=WIDEVINE_ID_LENGTH, max_length=WIDEVINE_ID_LENGTH,
                             description="Widevine Device ID (32 Hex-Zeichen)")

    # --- Advertising & Bluetooth ---
    advertising_id: Optional[str] = Field(default=None,
                                          pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
                                          description="Google Advertising ID (UUID v4)")
    bluetooth_mac: Optional[str] = Field(default=None,
                                         pattern=r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$",
                                         description="Bluetooth MAC (abgeleitet von WiFi MAC)")

    # --- SIM / Telephony ---
    imsi: str = Field(..., min_length=O2_DE.IMSI_LENGTH, max_length=O2_DE.IMSI_LENGTH,
                      description="IMSI (26207 + 10 Ziffern)")
    sim_serial: str = Field(..., min_length=19, max_length=O2_DE.ICCID_LENGTH,
                            description="ICCID / SIM Serial (894922..., Luhn-valide)")
    operator_name: str = Field(default=O2_DE.OPERATOR_NAME,
                               description="Carrier Display Name")
    phone_number: str = Field(..., description="Telefonnummer (+49176XXXXXXX)")
    sim_operator: str = Field(default=O2_DE.MCC_MNC,
                              description="MCC+MNC (26207)")
    sim_operator_name: str = Field(default=O2_DE.SIM_OPERATOR_NAME,
                                   description="SIM Operator Display Name")
    voicemail_number: str = Field(default=O2_DE.VOICEMAIL_NUMBER,
                                  description="Voicemail-Nummer")

    # -------------------------------------------------------------------------
    # Validatoren
    # -------------------------------------------------------------------------

    @field_validator("imei1", "imei2")
    @classmethod
    def validate_imei(cls, v: str) -> str:
        """IMEI muss 15 Ziffern sein, Luhn-valide, TAC beginnt mit 355543."""
        if not v.isdigit():
            raise ValueError(f"IMEI muss nur Ziffern enthalten, bekam: {v!r}")
        if len(v) != PIXEL6_TAC.IMEI_LENGTH:
            raise ValueError(f"IMEI muss {PIXEL6_TAC.IMEI_LENGTH} Ziffern haben, bekam {len(v)}")
        if not v.startswith(PIXEL6_TAC.PREFIX):
            raise ValueError(
                f"IMEI-TAC muss mit {PIXEL6_TAC.PREFIX} beginnen "
                f"(Pixel 6), bekam: {v[:8]}"
            )
        if not _luhn_valid(v):
            raise ValueError(f"IMEI {v} besteht Luhn-Check nicht")
        return v

    @field_validator("imsi")
    @classmethod
    def validate_imsi(cls, v: str) -> str:
        """IMSI muss mit 26207 beginnen und 15 Ziffern haben."""
        if not v.isdigit():
            raise ValueError("IMSI muss nur Ziffern enthalten")
        if not v.startswith(O2_DE.IMSI_PREFIX):
            raise ValueError(f"IMSI muss mit {O2_DE.IMSI_PREFIX} beginnen (O2 DE)")
        if len(v) != O2_DE.IMSI_LENGTH:
            raise ValueError(f"IMSI muss {O2_DE.IMSI_LENGTH} Ziffern haben")
        return v

    @field_validator("sim_serial")
    @classmethod
    def validate_iccid(cls, v: str) -> str:
        """ICCID muss mit 894922 beginnen und Luhn-valide sein."""
        if not v.isdigit():
            raise ValueError("ICCID muss nur Ziffern enthalten")
        if not v.startswith(O2_DE.ICCID_PREFIX):
            raise ValueError(f"ICCID muss mit {O2_DE.ICCID_PREFIX} beginnen (O2 DE)")
        if not _luhn_valid(v):
            raise ValueError(f"ICCID {v} besteht Luhn-Check nicht")
        return v

    @field_validator("phone_number")
    @classmethod
    def validate_phone(cls, v: str) -> str:
        """Telefonnummer muss +49176 Format haben."""
        if not v.startswith(O2_DE.PHONE_PREFIX):
            raise ValueError(f"Telefonnummer muss mit {O2_DE.PHONE_PREFIX} beginnen")
        if len(v) != O2_DE.PHONE_LENGTH:
            raise ValueError(
                f"Telefonnummer muss {O2_DE.PHONE_LENGTH} Zeichen haben "
                f"({O2_DE.PHONE_PREFIX}XXXXXXX), bekam {len(v)}"
            )
        return v

    @field_validator("android_id")
    @classmethod
    def validate_android_id(cls, v: str) -> str:
        """Android ID muss 16 Hex-Zeichen sein (lowercase)."""
        v = v.lower()
        if not re.fullmatch(r"[0-9a-f]{16}", v):
            raise ValueError("Android ID muss 16 lowercase Hex-Zeichen sein")
        return v

    @field_validator("widevine_id")
    @classmethod
    def validate_widevine(cls, v: str) -> str:
        """Widevine ID muss 32 Hex-Zeichen sein (lowercase)."""
        v = v.lower()
        if not re.fullmatch(r"[0-9a-f]{32}", v):
            raise ValueError("Widevine ID muss 32 lowercase Hex-Zeichen sein")
        return v

    @field_validator("gsf_id")
    @classmethod
    def validate_gsf_id(cls, v: str) -> str:
        """GSF ID muss 17 Dezimalziffern sein, darf nicht mit 0 beginnen."""
        if not v.isdigit():
            raise ValueError("GSF ID muss nur Ziffern enthalten")
        if v.startswith("0"):
            raise ValueError("GSF ID darf nicht mit 0 beginnen")
        return v

    # -------------------------------------------------------------------------
    # Serialisierung → Bridge-Datei
    # -------------------------------------------------------------------------

    # Felder die NICHT in die Bridge-Datei geschrieben werden dürfen.
    # Diese existieren nur in IdentityRead (DB-Metadaten) und würden
    # die C++/Kotlin Parser verwirren.
    _BRIDGE_EXCLUDE_FIELDS: set[str] = {
        "id", "name", "status", "notes",
        "last_public_ip", "last_ip_service", "last_ip_at",
        "last_audit_score", "last_audit_at", "last_audit_detail",
        "total_audits",
        "created_at", "updated_at", "last_used_at", "usage_count",
        # v5.1: Build-Properties NICHT in Bridge schreiben!
        # PIF hat exklusive Kontrolle — unser Zygisk-Modul darf
        # ro.build.fingerprint etc. NICHT spooven (blockiert PIF → kein BASIC)
        "build_id", "build_fingerprint", "build_description",
        "build_incremental", "security_patch",
    }

    def to_bridge_string(self, label: str = "") -> str:
        """
        Erzeugt den Inhalt der Bridge-Datei im Key=Value Format.

        Kompatibel mit Bridge-Parser:
            - Kommentarzeilen beginnen mit #
            - Leerzeilen werden ignoriert
            - Format: key=value (kein Whitespace um =)

        v6.0: Zwei Sektionen:
          1. Hardware-Identitäts-Felder (serial, imei, mac, etc.)
          2. Device Properties (ro.product.*, ro.build.type, etc.)
             → werden vom Zygisk-Modul als System-Property Overrides gelesen

        Build-Fingerprints (ro.build.fingerprint, ro.build.id, etc.)
        werden NICHT geschrieben — PIF hat exklusive Kontrolle.
        """
        lines = [
            f"# Identity Bridge — {label or self.serial}",
            f"# Generated: {datetime.now(LOCAL_TZ).isoformat()}",
            f"# Carrier: O2-DE ({O2_DE.MCC_MNC})",
            "",
        ]

        # --- Sektion 1: Hardware-Identitäts-Felder ---
        for key, value in self.model_dump().items():
            if key in self._BRIDGE_EXCLUDE_FIELDS:
                continue
            if value is None:
                continue
            if hasattr(value, "value"):
                value = value.value
            lines.append(f"{key}={value}")

        # --- Sektion 2: Device Properties (ro.*) ---
        # v6.0: Das Zygisk-Modul liest diese dynamisch statt sie
        # statisch im C++ Binary zu haben → keine Bans durch
        # einkompilierte Fingerprints.
        lines.append("")
        lines.append("# Device Properties (Zygisk dynamic override)")
        for prop_name, prop_value in PIXEL6_DEVICE_PROPS.items():
            lines.append(f"{prop_name}={prop_value}")

        return "\n".join(lines) + "\n"


# =============================================================================
# Create Model — Input für die Identity Engine
# =============================================================================

class IdentityCreate(BaseModel):
    """
    Minimaler Input zum Erstellen einer neuen Identität.
    Alle Hardware-Werte werden vom Identity Engine generiert.
    """
    name: str = Field(..., min_length=1, max_length=64,
                      description="Anzeigename für das Profil (z.B. 'DE_Berlin_001')")
    notes: Optional[str] = Field(default=None, max_length=500,
                                 description="Optionale Notizen")


# =============================================================================
# Read Model — Vollständiges DB-Modell (Response)
# =============================================================================

class IdentityRead(IdentityBridge):
    """
    Vollständige Identität inkl. DB-Metadaten.
    Extends IdentityBridge um id, name, status, timestamps,
    Netzwerk-Tracking, Audit-Tracking und Usage-Counter.
    """
    id: int = Field(..., description="Auto-increment DB Primary Key")
    name: str = Field(..., description="Anzeigename")
    status: IdentityStatus = Field(default=IdentityStatus.READY)
    notes: Optional[str] = Field(default=None)

    # Build-Fingerprint (intern konsistent — FIX-30: pro Identität variabel)
    build_id: Optional[str] = Field(default=None,
                                    description="z.B. AP2A.241005.015")
    build_fingerprint: Optional[str] = Field(default=None,
                                             description="Vollständiger Build-Fingerprint")
    security_patch: Optional[str] = Field(default=None,
                                          description="z.B. 2024-10-05")
    build_incremental: Optional[str] = Field(default=None,
                                             description="Build Incremental Number z.B. 12298734")
    build_description: Optional[str] = Field(default=None,
                                             description="Build Description String")

    # --- Netzwerk-Tracking ---
    last_public_ip: Optional[str] = Field(default=None,
                                          description="Letzte erkannte öffentliche IP")
    last_ip_service: Optional[str] = Field(default=None,
                                           description="IP-Service der letzten Erkennung")
    last_ip_at: Optional[str] = Field(default=None,
                                      description="Zeitpunkt der letzten IP-Erkennung")

    # --- Audit-Tracking ---
    last_audit_score: Optional[int] = Field(default=None,
                                            description="Letzter Audit-Score (0-100%)")
    last_audit_at: Optional[str] = Field(default=None,
                                         description="Zeitpunkt des letzten Audits")
    last_audit_detail: Optional[str] = Field(default=None,
                                             description="JSON-Detail des letzten Audits")
    total_audits: int = Field(default=0,
                              description="Gesamtanzahl durchgeführter Audits")

    # --- Timestamps & Counters ---
    created_at: datetime = Field(default_factory=lambda: datetime.now(LOCAL_TZ))
    updated_at: Optional[datetime] = Field(default=None)
    last_used_at: Optional[datetime] = Field(default=None)
    usage_count: int = Field(default=0,
                             description="Wie oft diese Identität geladen wurde")

    model_config = {"from_attributes": True}


# =============================================================================
# Hilfsfunktionen (Luhn)
# =============================================================================

def _luhn_valid(number: str) -> bool:
    """
    Validiert eine Nummer gegen den Luhn-Algorithmus (ISO/IEC 7812).
    Wird von den IMEI- und ICCID-Validatoren verwendet.
    """
    if not number.isdigit() or len(number) < 2:
        return False
    digits = [int(d) for d in number]
    odd = digits[-1::-2]
    even = digits[-2::-2]
    total = sum(odd)
    for d in even:
        d2 = d * 2
        total += d2 - 9 if d2 > 9 else d2
    return total % 10 == 0
