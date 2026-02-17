# Operation Tarnkappe — Stealth-Hardening Plan

## Ziel
Alle identifizierbaren Strings, Namen, Pfade und Log-Tags aus dem gesamten Projekt entfernen.
Nach Abschluss darf `grep -ri "titan" .` (exkl. Docs/Git) **null Treffer** liefern.

---

## Neue Identität (Namens-Mapping)

| Kategorie | Alt (auffällig) | Neu (getarnt) | Begründung |
|-----------|-----------------|---------------|------------|
| **Package-Name** | `com.titan.verifier` | `com.oem.hardware.service` | Sieht aus wie OEM Hardware-Service |
| **Modul-ID** | `titan_verifier` | `hw_overlay` | Sieht aus wie Hardware-Overlay |
| **Bridge-Datei** | `.titan_identity` / `titan_identity` | `.hw_config` | Sieht aus wie Hardware-Config |
| **Kill-Switch** | `titan_stop` | `.hw_disabled` | Generischer Service-Flag |
| **SO-Datei** | `libtitan_zygisk.so` | `libhw_overlay.so` | Passt zum Modul-ID |
| **App-Label** | `Titan Verifier` | `Hardware Service` | Langweilig = unauffällig |
| **Log-Tag (C++)** | `TitanZygisk` | — (DEAKTIVIERT) | Keine Logs im Release |
| **Log-Tag (Kotlin)** | `TitanBridge` | — (DEAKTIVIERT) | Keine Logs im Release |
| **Modul-Pfad** | `/data/adb/modules/titan_verifier/` | `/data/adb/modules/hw_overlay/` | |
| **Bridge-Pfad primär** | `.../titan_verifier/titan_identity` | `.../hw_overlay/.hw_config` | |
| **Bridge-Pfad SDCard** | `/sdcard/.titan_identity` | `/sdcard/.hw_config` | |
| **Bridge-Pfad App** | `/data/data/com.titan.verifier/files/.titan_identity` | `/data/data/com.oem.hardware.service/files/.hw_config` | |
| **C++ Klasse** | `TitanModule` | `CompatModule` | |
| **C++ Klasse** | `TitanHardware` | `HwCompat` | |
| **C++ Header** | `titan_hardware.h` | `hw_compat.h` | |
| **C++ Source** | `titan_hardware.cpp` | `hw_compat.cpp` | |
| **C++ Konstanten** | `TITAN_*` | `HW_*` | |
| **Kotlin Klasse** | `TitanXposedModule` | `TelephonyServiceModule` | |
| **Kotlin Klasse** | `TitanBridgeReader` | `ServiceConfigReader` | |
| **Python Klasse** | `TitanShifter` | `AppShifter` | |
| **Python Klasse** | `TitanAuditor` | `DeviceAuditor` | |
| **Python Klasse** | `TitanInjector` | `BridgeInjector` | |
| **Python Logger** | `titan.*` | `host.*` | |
| **Theme** | `Theme.TitanVerifier` | `Theme.HwService` | |
| **Xposed Description** | `Project Titan - Hardware Identity Spoofing` | `Telephony compatibility layer` | |
| **module.prop name** | `Titan Verifier` | `HW Overlay` | |
| **API Titel** | `Project Titan — Command Center` | `Device Manager` | |

---

## Phasen — ALLE ABGESCHLOSSEN ✓

### Phase A: Zygisk-Modul (C++) — `module/zygisk_module.cpp` ✓
- [x] `#define STEALTH_MODE` → aktiviert (alle LOGI/LOGW/LOGE werden zu no-ops)
- [x] Alle `[TITAN]` → `[HW]`, `[TITAN-MEM]` → `[MEM]`
- [x] Klasse `TitanModule` → `CompatModule`
- [x] `TITAN_XOR_KEY` → `_XK`
- [x] `TITAN_DEC` → `DEC_STR`, `_titan_xor_decode` → `_xdec`
- [x] `TITAN_KILL_SWITCH*` → `KILL_SWITCH_PATH`
- [x] `TITAN_BRIDGE_PATH*` → `BRIDGE_FILE_PATH`
- [x] Alle Kommentare mit "Titan" neutralisiert
- [x] XOR-encoded Pfade aktualisiert für neue Dateinamen
- [x] Log-Tag komplett entfernt (STEALTH_MODE aktiv)
- [x] `TitanHardware` → `HwCompat`, `TitanDrmByteArray` → `DrmByteArray`
- [x] Alle `titan_hooked_*` Funktionen → `_hooked_*`
- [x] Verifier-Package XOR-Bytes aktualisiert (com.oem.hardware.service)

### Phase B: Host Config — `host/config.py` + Python-Klassen ✓
- [x] Alle Bridge-Pfade aktualisiert (hw_overlay, .hw_config, .hw_disabled)
- [x] `BRIDGE_TARGET_APPS` → `com.oem.hardware.service`
- [x] `API_TITLE` → `Device Manager`
- [x] Alle Logger `titan.*` → `host.*` (15+ Dateien)
- [x] Klassen: `TitanShifter` → `AppShifter`
- [x] Klassen: `TitanAuditor` → `DeviceAuditor`
- [x] Klassen: `TitanInjector` → `BridgeInjector`
- [x] Klassen: `TitanDatabase` → `HostDatabase`
- [x] Alle Imports angepasst
- [x] Docstrings/Kommentare neutralisiert
- [x] `titan.db` → `device_manager.db`
- [x] `titan.log` → `host.log`

### Phase C: Android App ✓
- [x] `build.gradle.kts`: namespace + applicationId → `com.oem.hardware.service`
- [x] Komplette Verzeichnisstruktur migriert
- [x] Alle Package-Deklarationen aktualisiert
- [x] `TitanXposedModule` → `TelephonyServiceModule`
- [x] `TitanBridgeReader` → `ServiceConfigReader`
- [x] `xposed_init` → `com.oem.hardware.service.xposed.TelephonyServiceModule`
- [x] AndroidManifest, strings.xml, themes.xml, arrays.xml aktualisiert
- [x] JNI-Funktionsnamen aktualisiert (`Java_com_oem_hardware_service_*`)
- [x] Alte Kotlin-Dateien unter com/titan/ gelöscht
- [x] Bridge-Pfade in Kotlin aktualisiert (.hw_config)
- [x] `settings.gradle.kts`: rootProject.name → `HwService`

### Phase D: Scripts ✓
- [x] `automate_titan.py`: MODULE_ID, Pfade, PKG_NAME, SO-Name, module.prop
- [x] `identity_factory.py`: Alle Pfade und Package-Referenzen
- [x] `verify_hooks.py`: Bridge-Pfad, Log-Tag-Filter

### Phase E: Native C++ Shared Code ✓
- [x] `titan_hardware.cpp` → `hw_compat.cpp` (neu erstellt)
- [x] `titan_hardware.h` → `hw_compat.h` (neu erstellt)
- [x] Alte Dateien gelöscht
- [x] Klasse `TitanHardware` → `HwCompat`
- [x] Alle `TITAN_*` Konstanten → `HW_*`
- [x] XOR-encoded Pfade korrekt berechnet und aktualisiert
- [x] `titan_ids.h` → `hw_ids.h`
- [x] `module/CMakeLists.txt` komplett refactored
- [x] `module/main.cpp` refactored

### Phase F: Abschluss-Verifikation ✓
- [x] Grep über alle Code-Dateien: **0 Treffer** (nur Build-Cache in .cxx/)
- [x] HTML-Templates: "Project Titan" → "Device Manager", Farb-Token titan- → accent-
- [x] requirements.txt, runtime-permissions-patched.xml neutralisiert

---

## Sicherheitsregeln

1. **Bridge-FORMAT bleibt gleich** — `serial=`, `imei1=` etc. ändern sich NICHT
2. **Pfade müssen überall synchron sein** — C++, Kotlin, Python, Scripts
3. **XOR-Encoding muss neu berechnet werden** für neue Pfadnamen
4. **JNI-Funktionsnamen folgen dem Package** — `Java_com_oem_hardware_service_*`
5. **Altes Package deinstallieren VOR neuem Install** auf dem Gerät
6. **host/config.py zuerst ändern, dann testen** — Rest ist Schicht 2
