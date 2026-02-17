"""
Unit Tests: Identity Engine
============================

Stress-Test: Generiert 100 Identitäten und prüft ALLE Hard Constraints
aus dem Kontext-Dokument §3A.

Prüfungen:
  - IMEI:    Luhn-valide, TAC beginnt mit 355543, 15 Ziffern
  - IMSI:    beginnt mit 26207, exakt 15 Ziffern
  - ICCID:   beginnt mit 894922, Luhn-valide, 20 Ziffern
  - Phone:   +49176XXXXXXX Format, 13 Zeichen
  - MAC:     Google OUI, lowercase, xx:xx:xx:xx:xx:xx Format
  - Widevine: 32 Hex-Zeichen, lowercase
  - Serial:  12 Zeichen, kein I oder O
  - GSF ID:  17 Ziffern, beginnt nicht mit 0
  - Android ID: 16 Hex-Zeichen
  - Build:   build_id passt zu security_patch
  - Duplikate: Keine doppelten IMEI1, IMEI2, Widevine, Serial, Android ID
"""

import re

import pytest

from host.config import GOOGLE_OUIS, O2_DE, PIXEL6_BUILDS, PIXEL6_TAC
from host.engine.identity_engine import IdentityGenerator
from host.models.identity import IdentityRead, IdentityStatus

# =============================================================================
# Fixtures
# =============================================================================

SAMPLE_SIZE = 100


@pytest.fixture(scope="module")
def generator() -> IdentityGenerator:
    """Singleton Generator für alle Tests im Modul."""
    return IdentityGenerator()


@pytest.fixture(scope="module")
def identities(generator: IdentityGenerator) -> list[IdentityRead]:
    """Generiert 100 Identitäten einmalig für alle Tests."""
    return [generator.generate_new(f"Test_{i:03d}") for i in range(SAMPLE_SIZE)]


# =============================================================================
# Hilfsfunktionen
# =============================================================================

def luhn_valid(number: str) -> bool:
    """Unabhängige Luhn-Validierung (nicht aus der Engine importiert)."""
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


def parse_mac_oui(mac: str) -> tuple[int, int, int]:
    """Extrahiert das OUI (erste 3 Bytes) aus einer MAC-Adresse."""
    parts = mac.split(":")
    return (int(parts[0], 16), int(parts[1], 16), int(parts[2], 16))


# =============================================================================
# Test: Grundstruktur
# =============================================================================

class TestGeneratorBasics:
    """Grundlegende Struktur- und Typ-Checks."""

    def test_returns_identity_read(self, generator: IdentityGenerator):
        """generate_new() muss IdentityRead zurückgeben."""
        result = generator.generate_new("Smoke_Test")
        assert isinstance(result, IdentityRead)

    def test_id_is_zero(self, generator: IdentityGenerator):
        """id muss 0 sein (nicht persistiert)."""
        result = generator.generate_new("ID_Zero_Test")
        assert result.id == 0

    def test_status_is_ready(self, generator: IdentityGenerator):
        """Status muss 'ready' sein."""
        result = generator.generate_new("Status_Test")
        assert result.status == IdentityStatus.READY

    def test_name_preserved(self, generator: IdentityGenerator):
        """Name muss unverändert durchgereicht werden."""
        result = generator.generate_new("Mein_Profil_123", notes="Testnotiz")
        assert result.name == "Mein_Profil_123"
        assert result.notes == "Testnotiz"

    def test_serial_equals_boot_serial(self, identities: list[IdentityRead]):
        """serial und boot_serial müssen identisch sein."""
        for ident in identities:
            assert ident.serial == ident.boot_serial, (
                f"serial={ident.serial} != boot_serial={ident.boot_serial}"
            )


# =============================================================================
# Test: IMEI (Luhn + TAC)
# =============================================================================

class TestIMEI:
    """Alle IMEI-Constraints aus dem Kontext-Dokument."""

    def test_imei1_length(self, identities: list[IdentityRead]):
        """Alle IMEI1 müssen exakt 15 Ziffern haben."""
        for ident in identities:
            assert len(ident.imei1) == 15, f"IMEI1 Länge: {len(ident.imei1)}"
            assert ident.imei1.isdigit(), f"IMEI1 nicht numerisch: {ident.imei1}"

    def test_imei2_length(self, identities: list[IdentityRead]):
        """Alle IMEI2 müssen exakt 15 Ziffern haben."""
        for ident in identities:
            assert len(ident.imei2) == 15, f"IMEI2 Länge: {len(ident.imei2)}"
            assert ident.imei2.isdigit(), f"IMEI2 nicht numerisch: {ident.imei2}"

    def test_imei1_tac_prefix(self, identities: list[IdentityRead]):
        """Alle IMEI1 TACs müssen mit 355543 beginnen."""
        for ident in identities:
            assert ident.imei1.startswith(PIXEL6_TAC.PREFIX), (
                f"IMEI1 TAC beginnt nicht mit {PIXEL6_TAC.PREFIX}: {ident.imei1[:8]}"
            )

    def test_imei2_tac_prefix(self, identities: list[IdentityRead]):
        """Alle IMEI2 TACs müssen mit 355543 beginnen."""
        for ident in identities:
            assert ident.imei2.startswith(PIXEL6_TAC.PREFIX), (
                f"IMEI2 TAC beginnt nicht mit {PIXEL6_TAC.PREFIX}: {ident.imei2[:8]}"
            )

    def test_imei1_tac_valid(self, identities: list[IdentityRead]):
        """Alle IMEI1 TACs müssen aus dem PIXEL6_TAC.TACS Pool stammen."""
        for ident in identities:
            assert ident.imei1[:8] in PIXEL6_TAC.TACS, (
                f"IMEI1 TAC {ident.imei1[:8]} nicht im Pool: {PIXEL6_TAC.TACS}"
            )

    def test_imei1_luhn(self, identities: list[IdentityRead]):
        """Alle IMEI1 müssen den Luhn-Check bestehen."""
        for ident in identities:
            assert luhn_valid(ident.imei1), f"IMEI1 Luhn-FAIL: {ident.imei1}"

    def test_imei2_luhn(self, identities: list[IdentityRead]):
        """Alle IMEI2 müssen den Luhn-Check bestehen."""
        for ident in identities:
            assert luhn_valid(ident.imei2), f"IMEI2 Luhn-FAIL: {ident.imei2}"


# =============================================================================
# Test: SIM / Telephony (O2 Germany)
# =============================================================================

class TestO2Telephony:
    """O2-Germany Hard Constraints."""

    def test_imsi_prefix(self, identities: list[IdentityRead]):
        """Alle IMSI müssen mit 26207 beginnen."""
        for ident in identities:
            assert ident.imsi.startswith(O2_DE.IMSI_PREFIX), (
                f"IMSI beginnt nicht mit {O2_DE.IMSI_PREFIX}: {ident.imsi}"
            )

    def test_imsi_length(self, identities: list[IdentityRead]):
        """Alle IMSI müssen exakt 15 Ziffern haben."""
        for ident in identities:
            assert len(ident.imsi) == O2_DE.IMSI_LENGTH, (
                f"IMSI Länge: {len(ident.imsi)}, erwartet {O2_DE.IMSI_LENGTH}"
            )
            assert ident.imsi.isdigit(), f"IMSI nicht numerisch: {ident.imsi}"

    def test_iccid_prefix(self, identities: list[IdentityRead]):
        """Alle ICCID müssen mit 894922 beginnen."""
        for ident in identities:
            assert ident.sim_serial.startswith(O2_DE.ICCID_PREFIX), (
                f"ICCID beginnt nicht mit {O2_DE.ICCID_PREFIX}: {ident.sim_serial}"
            )

    def test_iccid_length(self, identities: list[IdentityRead]):
        """Alle ICCID müssen exakt 20 Ziffern haben."""
        for ident in identities:
            assert len(ident.sim_serial) == O2_DE.ICCID_LENGTH, (
                f"ICCID Länge: {len(ident.sim_serial)}, erwartet {O2_DE.ICCID_LENGTH}"
            )

    def test_iccid_luhn(self, identities: list[IdentityRead]):
        """Alle ICCID müssen den Luhn-Check bestehen."""
        for ident in identities:
            assert luhn_valid(ident.sim_serial), (
                f"ICCID Luhn-FAIL: {ident.sim_serial}"
            )

    def test_phone_prefix(self, identities: list[IdentityRead]):
        """Alle Telefonnummern müssen mit +49176 beginnen."""
        for ident in identities:
            assert ident.phone_number.startswith(O2_DE.PHONE_PREFIX), (
                f"Phone beginnt nicht mit {O2_DE.PHONE_PREFIX}: {ident.phone_number}"
            )

    def test_phone_length(self, identities: list[IdentityRead]):
        """Alle Telefonnummern müssen 13 Zeichen haben."""
        for ident in identities:
            assert len(ident.phone_number) == O2_DE.PHONE_LENGTH, (
                f"Phone Länge: {len(ident.phone_number)}, erwartet {O2_DE.PHONE_LENGTH}"
            )

    def test_sim_operator(self, identities: list[IdentityRead]):
        """sim_operator muss 26207 sein."""
        for ident in identities:
            assert ident.sim_operator == O2_DE.MCC_MNC

    def test_operator_name(self, identities: list[IdentityRead]):
        """operator_name muss 'o2-de' sein."""
        for ident in identities:
            assert ident.operator_name == O2_DE.OPERATOR_NAME


# =============================================================================
# Test: MAC Address (Google OUI)
# =============================================================================

class TestMAC:
    """WiFi MAC mit echtem Google OUI."""

    def test_mac_format(self, identities: list[IdentityRead]):
        """MAC muss im Format xx:xx:xx:xx:xx:xx sein (lowercase)."""
        pattern = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
        for ident in identities:
            assert pattern.match(ident.wifi_mac), (
                f"MAC Format falsch: {ident.wifi_mac}"
            )

    def test_mac_google_oui(self, identities: list[IdentityRead]):
        """Das OUI (erste 3 Bytes) muss ein Google OUI sein."""
        for ident in identities:
            oui = parse_mac_oui(ident.wifi_mac)
            assert oui in GOOGLE_OUIS, (
                f"OUI {oui} nicht in GOOGLE_OUIS: {ident.wifi_mac}"
            )

    def test_mac_not_locally_administered(self, identities: list[IdentityRead]):
        """Bit 1 des ersten Bytes darf NICHT gesetzt sein (keine LA-MAC)."""
        for ident in identities:
            first_byte = int(ident.wifi_mac.split(":")[0], 16)
            assert (first_byte & 0x02) == 0, (
                f"MAC hat locally-administered bit gesetzt: {ident.wifi_mac}"
            )


# =============================================================================
# Test: Identifiers (Widevine, Android ID, GSF ID, Serial)
# =============================================================================

class TestIdentifiers:
    """Format-Checks für alle ID-Felder."""

    def test_widevine_format(self, identities: list[IdentityRead]):
        """Widevine ID: 32 lowercase Hex-Zeichen."""
        for ident in identities:
            assert re.fullmatch(r"[0-9a-f]{32}", ident.widevine_id), (
                f"Widevine Format falsch: {ident.widevine_id}"
            )

    def test_android_id_format(self, identities: list[IdentityRead]):
        """Android ID: 16 lowercase Hex-Zeichen."""
        for ident in identities:
            assert re.fullmatch(r"[0-9a-f]{16}", ident.android_id), (
                f"Android ID Format falsch: {ident.android_id}"
            )

    def test_gsf_id_format(self, identities: list[IdentityRead]):
        """GSF ID: 17 Dezimalziffern, beginnt nicht mit 0."""
        for ident in identities:
            assert len(ident.gsf_id) == 17, f"GSF ID Länge: {len(ident.gsf_id)}"
            assert ident.gsf_id.isdigit(), f"GSF ID nicht numerisch: {ident.gsf_id}"
            assert not ident.gsf_id.startswith("0"), (
                f"GSF ID beginnt mit 0: {ident.gsf_id}"
            )

    def test_serial_format(self, identities: list[IdentityRead]):
        """Serial: 12 Zeichen, kein I oder O."""
        for ident in identities:
            assert len(ident.serial) == 12, f"Serial Länge: {len(ident.serial)}"
            assert "I" not in ident.serial, f"Serial enthält 'I': {ident.serial}"
            assert "O" not in ident.serial, f"Serial enthält 'O': {ident.serial}"
            assert ident.serial.isalnum(), f"Serial nicht alphanumerisch: {ident.serial}"


# =============================================================================
# Test: Build-Fingerprint Konsistenz
# =============================================================================

class TestBuildConsistency:
    """Build-ID muss zum Security-Patch passen."""

    def test_build_id_in_pool(self, identities: list[IdentityRead]):
        """build_id muss aus PIXEL6_BUILDS stammen."""
        valid_ids = {b["build_id"] for b in PIXEL6_BUILDS}
        for ident in identities:
            assert ident.build_id in valid_ids, (
                f"build_id {ident.build_id} nicht im Pool"
            )

    def test_build_patch_consistency(self, identities: list[IdentityRead]):
        """security_patch muss zum build_id passen."""
        build_map = {b["build_id"]: b["security_patch"] for b in PIXEL6_BUILDS}
        for ident in identities:
            expected_patch = build_map[ident.build_id]
            assert ident.security_patch == expected_patch, (
                f"Build {ident.build_id}: Patch {ident.security_patch} "
                f"!= erwartet {expected_patch}"
            )

    def test_fingerprint_consistency(self, identities: list[IdentityRead]):
        """build_fingerprint muss zum build_id passen."""
        fp_map = {b["build_id"]: b["fingerprint"] for b in PIXEL6_BUILDS}
        for ident in identities:
            expected_fp = fp_map[ident.build_id]
            assert ident.build_fingerprint == expected_fp, (
                f"Fingerprint Mismatch für {ident.build_id}"
            )


# =============================================================================
# Test: Duplikate (Uniqueness über 100 Identitäten)
# =============================================================================

class TestUniqueness:
    """Keine Duplikate bei kritischen Feldern."""

    def test_no_duplicate_imei1(self, identities: list[IdentityRead]):
        """Alle IMEI1 müssen einzigartig sein."""
        imei1s = [i.imei1 for i in identities]
        assert len(imei1s) == len(set(imei1s)), (
            f"Duplikate bei IMEI1! {len(imei1s)} total, {len(set(imei1s))} unique"
        )

    def test_no_duplicate_imei2(self, identities: list[IdentityRead]):
        """Alle IMEI2 müssen einzigartig sein."""
        imei2s = [i.imei2 for i in identities]
        assert len(imei2s) == len(set(imei2s)), (
            f"Duplikate bei IMEI2! {len(imei2s)} total, {len(set(imei2s))} unique"
        )

    def test_no_duplicate_widevine(self, identities: list[IdentityRead]):
        """Alle Widevine IDs müssen einzigartig sein."""
        wids = [i.widevine_id for i in identities]
        assert len(wids) == len(set(wids)), (
            f"Duplikate bei Widevine! {len(wids)} total, {len(set(wids))} unique"
        )

    def test_no_duplicate_serial(self, identities: list[IdentityRead]):
        """Alle Serials müssen einzigartig sein."""
        serials = [i.serial for i in identities]
        assert len(serials) == len(set(serials)), (
            f"Duplikate bei Serial! {len(serials)} total, {len(set(serials))} unique"
        )

    def test_no_duplicate_android_id(self, identities: list[IdentityRead]):
        """Alle Android IDs müssen einzigartig sein."""
        aids = [i.android_id for i in identities]
        assert len(aids) == len(set(aids)), (
            f"Duplikate bei Android ID! {len(aids)} total, {len(set(aids))} unique"
        )

    def test_no_duplicate_iccid(self, identities: list[IdentityRead]):
        """Alle ICCIDs müssen einzigartig sein."""
        iccids = [i.sim_serial for i in identities]
        assert len(iccids) == len(set(iccids)), (
            f"Duplikate bei ICCID! {len(iccids)} total, {len(set(iccids))} unique"
        )

    def test_imei1_imei2_different(self, identities: list[IdentityRead]):
        """IMEI1 und IMEI2 desselben Profils sollten verschieden sein."""
        for ident in identities:
            assert ident.imei1 != ident.imei2, (
                f"IMEI1 == IMEI2: {ident.imei1} (Profil {ident.name})"
            )


# =============================================================================
# Test: Bridge-Serialisierung
# =============================================================================

class TestBridgeSerialization:
    """Bridge-Datei Output."""

    def test_bridge_string_format(self, generator: IdentityGenerator):
        """to_bridge_string() muss Key=Value Format erzeugen."""
        ident = generator.generate_new("Bridge_Test")
        bridge_str = ident.to_bridge_string("Bridge_Test")

        # Muss Kommentarzeilen enthalten
        assert bridge_str.startswith("#")

        # Jede Nicht-Kommentar/Leerzeile muss Key=Value sein
        for line in bridge_str.strip().split("\n"):
            if line.startswith("#") or line == "":
                continue
            assert "=" in line, f"Zeile ohne '=': {line}"
            key, _, value = line.partition("=")
            assert key.strip() == key, f"Key hat Whitespace: {key!r}"
            assert value.strip() == value, f"Value hat Whitespace: {value!r}"

    def test_bridge_contains_all_fields(self, generator: IdentityGenerator):
        """Bridge-String muss alle 15 Pflichtfelder enthalten."""
        ident = generator.generate_new("Field_Check")
        bridge_str = ident.to_bridge_string()

        required_keys = {
            "serial", "boot_serial", "imei1", "imei2",
            "gsf_id", "android_id", "wifi_mac", "widevine_id",
            "imsi", "sim_serial", "operator_name",
            "phone_number", "sim_operator", "sim_operator_name",
            "voicemail_number",
        }

        found_keys = set()
        for line in bridge_str.strip().split("\n"):
            if line.startswith("#") or line == "":
                continue
            key, _, _ = line.partition("=")
            found_keys.add(key)

        missing = required_keys - found_keys
        assert not missing, f"Fehlende Bridge-Felder: {missing}"
