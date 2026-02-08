"""
Project Titan — Identity Models
================================

Pydantic-Modelle für Hardware-Identitäten (O2 Germany / Pixel 6).

Drei Schichten:
  1. IdentityCreate  — Input-Validierung beim Erstellen neuer Identitäten
  2. IdentityRead    — Vollständiges DB-Modell mit Metadaten (id, created_at, ...)
  3. IdentityBridge  — Nur die Felder, die in die Bridge-Datei geschrieben werden

SQL-Schema: Siehe database.py → CREATE TABLE identities
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator

from host.config import (
    ANDROID_ID_LENGTH,
    GSF_ID_LENGTH,
    O2_DE,
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
# Bridge Model — Exakt die Felder für /data/adb/.../titan_identity
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
      - common/titan_hardware.h  (C++ Parser)
      - TitanBridgeReader.kt     (Kotlin Parser)
      - module/zygisk_module.cpp  (Zygisk Reader)
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

    def to_bridge_string(self, label: str = "") -> str:
        """
        Erzeugt den Inhalt der Bridge-Datei im Key=Value Format.

        Kompatibel mit titan_hardware.h Parser:
            - Kommentarzeilen beginnen mit #
            - Leerzeilen werden ignoriert
            - Format: key=value (kein Whitespace um =)
        """
        lines = [
            f"# Titan Identity Bridge — {label or self.serial}",
            f"# Generated: {datetime.now(timezone.utc).isoformat()}",
            f"# Carrier: O2-DE ({O2_DE.MCC_MNC})",
            "",
        ]
        for key, value in self.model_dump().items():
            lines.append(f"{key}={value}")
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
    Extends IdentityBridge um id, name, status, timestamps.
    """
    id: int = Field(..., description="Auto-increment DB Primary Key")
    name: str = Field(..., description="Anzeigename")
    status: IdentityStatus = Field(default=IdentityStatus.READY)
    notes: Optional[str] = Field(default=None)

    # Build-Fingerprint (intern konsistent)
    build_id: Optional[str] = Field(default=None)
    build_fingerprint: Optional[str] = Field(default=None)
    security_patch: Optional[str] = Field(default=None)

    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: Optional[datetime] = Field(default=None)
    last_used_at: Optional[datetime] = Field(default=None)

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
