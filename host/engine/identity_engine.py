"""
Identity Engine
================

Herzstück der Hardware-Identitäts-Generierung.

Generiert forensisch konsistente, O2-Germany-konforme Pixel 6 Identitäten.
Jeder Wert wird mathematisch validiert bevor er zurückgegeben wird.

Hard Constraints:
  - IMEI:  TAC beginnt mit 355543, Luhn-valide
  - IMSI:  beginnt mit 26207, exakt 15 Ziffern
  - ICCID: beginnt mit 894922, Luhn-valide, 20 Ziffern
  - Phone: +49176XXXXXXX (13 Zeichen)
  - MAC:   echte Google OUI (kein locally-administered bit)

Separation of Concerns:
  - Diese Klasse generiert NUR Pydantic-Objekte.
  - Sie speichert NICHTS in der Datenbank.
  - Die DB-Persistierung erfolgt im API/Service-Layer.
"""

from __future__ import annotations

import hashlib
import logging
import os
import random
import secrets
from datetime import datetime

from host.config import LOCAL_TZ
from typing import Optional

from host.config import (
    ANDROID_ID_LENGTH,
    GOOGLE_OUIS,
    GSF_ID_LENGTH,
    O2_DE,
    PIXEL6_BUILDS,
    PIXEL6_TAC,
    SERIAL_LENGTH,
    WIDEVINE_ID_LENGTH,
)
from host.models.identity import IdentityBridge, IdentityRead, IdentityStatus

logger = logging.getLogger("host.identity")


class IdentityGenerator:
    """
    Generiert vollständige, O2-DE-konforme Pixel 6 Hardware-Identitäten.

    Jede generierte Identität durchläuft automatisch die Pydantic-Validierung
    in IdentityBridge (Luhn-Check, Prefix-Check, Format-Check).

    Usage:
        gen = IdentityGenerator()
        identity = gen.generate_new("DE_Berlin_001")
        # identity.id == 0  (nicht persistiert)
        # identity.imei1 beginnt mit 355543, ist Luhn-valide
        # identity.imsi beginnt mit 26207
    """

    # =========================================================================
    # Public API
    # =========================================================================

    def generate_new(
        self,
        name: str,
        notes: Optional[str] = None,
    ) -> IdentityRead:
        """
        Erstellt eine komplette, valide O2-DE Pixel 6 Identität.

        Ablauf:
          1. Einen konsistenten Build-Fingerprint wählen
          2. Alle Hardware-Werte generieren (IMEI, MAC, IDs, SIM, ...)
          3. IdentityBridge konstruieren (löst Pydantic-Validierung aus)
          4. In IdentityRead wrappen (mit Metadaten, id=0 = nicht persistiert)

        Args:
            name:  Anzeigename für das Profil (z.B. 'DE_Berlin_001')
            notes: Optionale Notizen

        Returns:
            IdentityRead mit id=0 (muss vom Caller in die DB geschrieben werden)

        Raises:
            ValueError: Falls die generierte Identität die Validierung nicht besteht
                        (sollte nie passieren — wäre ein Bug im Generator)
        """
        # 1. Build wählen (alle Felder intern konsistent)
        build = random.choice(PIXEL6_BUILDS)

        # 2. Serial (identisch für serial + boot_serial)
        serial = self._generate_serial()

        # 3. Beide IMEIs mit TACs aus dem Pool
        tac1 = random.choice(PIXEL6_TAC.TACS)
        tac2 = random.choice(PIXEL6_TAC.TACS)
        imei1 = self._generate_imei(tac1)
        imei2 = self._generate_imei(tac2)

        # 4. Identifier
        gsf_id = self._generate_gsf_id()
        android_id = self._generate_android_id()
        wifi_mac = self._generate_mac()
        widevine_id = self._generate_widevine()

        # 5. SIM / Telephony (O2 DE)
        imsi = self._generate_imsi()
        sim_serial = self._generate_iccid()
        phone_number = self._generate_phone_number()

        # 6. Bridge-Objekt bauen (Pydantic-Validierung greift hier!)
        bridge = IdentityBridge(
            serial=serial,
            boot_serial=serial,
            imei1=imei1,
            imei2=imei2,
            gsf_id=gsf_id,
            android_id=android_id,
            wifi_mac=wifi_mac,
            widevine_id=widevine_id,
            imsi=imsi,
            sim_serial=sim_serial,
            operator_name=O2_DE.OPERATOR_NAME,
            phone_number=phone_number,
            sim_operator=O2_DE.MCC_MNC,
            sim_operator_name=O2_DE.SIM_OPERATOR_NAME,
            voicemail_number=O2_DE.VOICEMAIL_NUMBER,
        )

        # 7. In IdentityRead wrappen (id=0 → noch nicht persistiert)
        now = datetime.now(LOCAL_TZ)
        identity = IdentityRead(
            id=0,
            name=name,
            status=IdentityStatus.READY,
            notes=notes,
            # Bridge-Felder durchreichen
            **bridge.model_dump(),
            # Build-Fingerprint (FIX-30: pro Identität variabel → Bridge → Zygisk)
            build_id=build["build_id"],
            build_fingerprint=build["fingerprint"],
            security_patch=build["security_patch"],
            build_incremental=build["incremental"],
            build_description=build["description"],
            # Timestamps
            created_at=now,
            updated_at=None,
            last_used_at=None,
        )

        logger.info(
            "Identität generiert: name=%s serial=%s imei1=%s…%s carrier=O2-DE",
            name, serial, imei1[:6], imei1[-4:],
        )

        return identity

    # =========================================================================
    # IMEI Generation (Luhn-Algorithmus)
    # =========================================================================

    def _generate_imei(self, tac: str) -> str:
        """
        Generiert eine 15-stellige, Luhn-valide IMEI.

        Struktur: TAC(8) + Serial(6) + Check(1) = 15
        Constraint: TAC muss mit 355543 beginnen (Pixel 6).

        Args:
            tac: 8-stelliger Type Allocation Code (z.B. '35554312')

        Returns:
            15-stellige IMEI als String
        """
        assert tac.startswith(PIXEL6_TAC.PREFIX), \
            f"TAC {tac} beginnt nicht mit {PIXEL6_TAC.PREFIX}"
        assert len(tac) == 8, f"TAC muss 8 Ziffern haben, bekam {len(tac)}"

        # 6 zufällige Serial-Ziffern
        serial_part = "".join(str(secrets.randbelow(10)) for _ in range(6))
        partial = tac + serial_part  # 14 Ziffern

        check = self._luhn_check_digit(partial)
        imei = partial + str(check)

        # Paranoia-Check
        assert len(imei) == 15
        assert self._luhn_valid(imei), f"BUG: Generierte IMEI {imei} ist nicht Luhn-valide!"

        return imei

    # =========================================================================
    # MAC Address (Google OUI)
    # =========================================================================

    def _generate_mac(self) -> str:
        """
        Generiert eine MAC-Adresse mit echtem Google OUI.

        Format: OUI(3 Bytes) + NIC(3 zufällige Bytes) = 6 Bytes
        KEIN locally-administered bit — echte Hersteller-MAC!

        OUI-Pool: config.GOOGLE_OUIS (IEEE MA-L Assignments)

        Returns:
            MAC im Format 'xx:xx:xx:xx:xx:xx' (lowercase)
        """
        oui = random.choice(GOOGLE_OUIS)

        # 3 zufällige NIC-Bytes (kryptographisch sicher)
        nic = [secrets.randbelow(256) for _ in range(3)]

        mac_bytes = list(oui) + nic
        return ":".join(f"{b:02x}" for b in mac_bytes)

    # =========================================================================
    # Widevine Device ID
    # =========================================================================

    def _generate_widevine(self) -> str:
        """
        Generiert eine 32-stellige Widevine Device Unique ID.

        Methode: SHA-256 über 32 Bytes OS-Entropy, gekürzt auf 32 Hex-Zeichen.
        Damit ist Kollisionswahrscheinlichkeit bei 2^128 — praktisch null.

        Returns:
            32 lowercase Hex-Zeichen
        """
        return hashlib.sha256(os.urandom(32)).hexdigest()[:WIDEVINE_ID_LENGTH]

    # =========================================================================
    # Serial Number
    # =========================================================================

    def _generate_serial(self) -> str:
        """
        Generiert eine 12-stellige Pixel Serial Number.

        Zeichenpool: A-Z (ohne I, O — verwechselbar mit 1, 0) + 0-9
        Format wie echte Pixel Serials: z.B. 'A4B2C7D9E1F3'

        Returns:
            12 alphanumerische Zeichen (uppercase)
        """
        # Pixel Serials vermeiden I und O
        chars = "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789"
        return "".join(secrets.choice(chars) for _ in range(SERIAL_LENGTH))

    # =========================================================================
    # Android ID (SSAID)
    # =========================================================================

    def _generate_android_id(self) -> str:
        """
        Generiert eine 16-stellige Hex Android ID (Settings.Secure.ANDROID_ID).

        Returns:
            16 lowercase Hex-Zeichen
        """
        return secrets.token_hex(ANDROID_ID_LENGTH // 2)

    # =========================================================================
    # GSF ID (Google Services Framework)
    # =========================================================================

    def _generate_gsf_id(self) -> str:
        """
        Generiert eine 17-stellige dezimale GSF ID.

        Constraint: Darf nicht mit 0 beginnen.

        Returns:
            17 Dezimalziffern als String
        """
        first = str(secrets.randbelow(9) + 1)  # 1-9
        rest = "".join(str(secrets.randbelow(10)) for _ in range(GSF_ID_LENGTH - 1))
        return first + rest

    # =========================================================================
    # IMSI (O2 Germany)
    # =========================================================================

    def _generate_imsi(self) -> str:
        """
        Generiert eine 15-stellige IMSI für O2 Germany.

        Struktur: MCC(3) + MNC(2) + MSIN(10) = 15
        Prefix: 26207 (O2 DE)

        Returns:
            15 Dezimalziffern, beginnt mit '26207'
        """
        prefix = O2_DE.IMSI_PREFIX
        msin_len = O2_DE.IMSI_LENGTH - len(prefix)
        msin = "".join(str(secrets.randbelow(10)) for _ in range(msin_len))
        return prefix + msin

    # =========================================================================
    # ICCID / SIM Serial (O2 Germany, Luhn-valide)
    # =========================================================================

    def _generate_iccid(self) -> str:
        """
        Generiert eine 20-stellige ICCID für O2 Germany.

        Struktur: 89(Telecom) + 49(DE) + 22(O2) + Body + Luhn-Check = 20
        Prefix: 894922

        Returns:
            20 Dezimalziffern, Luhn-valide, beginnt mit '894922'
        """
        prefix = O2_DE.ICCID_PREFIX
        # Body: Prefix + Zufallsziffern bis 19 Stellen (Platz für 1 Check-Digit)
        body_len = O2_DE.ICCID_LENGTH - 1  # 19
        fill_len = body_len - len(prefix)
        fill = "".join(str(secrets.randbelow(10)) for _ in range(fill_len))
        body = prefix + fill  # 19 Ziffern

        check = self._luhn_check_digit(body)
        iccid = body + str(check)

        assert len(iccid) == O2_DE.ICCID_LENGTH
        assert self._luhn_valid(iccid), f"BUG: Generierte ICCID {iccid} ist nicht Luhn-valide!"

        return iccid

    # =========================================================================
    # Telefonnummer (O2 Germany)
    # =========================================================================

    def _generate_phone_number(self) -> str:
        """
        Generiert eine Telefonnummer im O2-DE Format.

        Format: +49176XXXXXXX (13 Zeichen total)
        Prefix: +49176 (O2 Mobilfunk-Gasse)

        Returns:
            Telefonnummer als String, z.B. '+491761234567'
        """
        prefix = O2_DE.PHONE_PREFIX
        suffix_len = O2_DE.PHONE_LENGTH - len(prefix)
        suffix = "".join(str(secrets.randbelow(10)) for _ in range(suffix_len))
        return prefix + suffix

    # =========================================================================
    # Luhn-Algorithmus (intern)
    # =========================================================================

    @staticmethod
    def _luhn_check_digit(partial: str) -> int:
        """
        Berechnet die Luhn-Check-Digit für eine unvollständige Nummer.

        Algorithmus (ISO/IEC 7812):
          1. Füge '0' als Platzhalter an
          2. Berechne Luhn-Checksumme
          3. Check-Digit = (10 - Checksumme) % 10

        Args:
            partial: Unvollständige Nummer (ohne Check-Digit)

        Returns:
            Einzelne Ziffer (0-9)
        """
        digits = [int(d) for d in partial + "0"]
        odd = digits[-1::-2]
        even = digits[-2::-2]
        total = sum(odd)
        for d in even:
            d2 = d * 2
            total += d2 - 9 if d2 > 9 else d2
        return (10 - (total % 10)) % 10

    @staticmethod
    def _luhn_valid(number: str) -> bool:
        """
        Validiert eine Nummer gegen den Luhn-Algorithmus.

        Args:
            number: Vollständige Nummer inkl. Check-Digit

        Returns:
            True wenn valide
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
