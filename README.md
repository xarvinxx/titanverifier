# Project Titan - Vollständige Dokumentation

> **Kernel-Level Identity Spoofing System für Google Pixel 6**
> Android 14 | KernelSU | Zygisk Next | LSPosed | Dobby

---

## Inhaltsverzeichnis

1. [Was ist Project Titan?](#1-was-ist-project-titan)
2. [Architektur-Übersicht](#2-architektur-übersicht)
3. [Verzeichnisstruktur](#3-verzeichnisstruktur)
4. [Voraussetzungen (Hardware & Software)](#4-voraussetzungen)
5. [Erstinstallation (Schritt für Schritt)](#5-erstinstallation)
6. [Identität erstellen & anwenden](#6-identität-erstellen--anwenden)
7. [Automatisiertes Deployment](#7-automatisiertes-deployment)
8. [Reinstallation / Update](#8-reinstallation--update)
9. [Identitätswechsel (Account-Rotation)](#9-identitätswechsel)
10. [Hook-Referenz (alle 55+ Werte)](#10-hook-referenz)
11. [Verifikation & Debugging](#11-verifikation--debugging)
12. [Sicherheitsmechanismen](#12-sicherheitsmechanismen)
13. [Fehlerbehebung (Troubleshooting)](#13-fehlerbehebung)
14. [Bridge-Datei Format](#14-bridge-datei-format)
15. [Build from Source](#15-build-from-source)

---

## 1. Was ist Project Titan?

Project Titan ist ein 3-Schichten Identity-Spoofing-System, das auf einem gerooteten Google Pixel 6 eine **vollständig synthetische Geräteidentität** erzeugt. Das Ziel: Jede App auf dem Gerät — einschließlich TikTok, Google Play Services und Drittanbieter-Diagnose-Apps — sieht identische, konsistente Fake-Werte auf **allen API-Ebenen** (Java, Native, Kernel).

**Warum 3 Schichten?**

Apps wie TikTok fragen die Geräteidentität nicht nur über eine API ab. Sie nutzen:
- **Java APIs** (`Build.MODEL`, `TelephonyManager.getImei()`)
- **Native APIs** (`__system_property_get`, `ioctl`, `getifaddrs`)
- **Dateisystem** (`/proc/cpuinfo`, `/sys/class/net/wlan0/address`)
- **IPC/Binder** (Netlink-Sockets für MAC, ContentResolver für GSF)

Wenn auch nur **ein** Wert auf einer Ebene abweicht, erkennt Anti-Fingerprinting die Inkonsistenz. Titan schließt **alle** diese Kanäle.

---

## 2. Architektur-Übersicht

```
┌─────────────────────────────────────────────────────┐
│                    Ziel-App (z.B. TikTok)           │
│                                                     │
│  Java API Call                 Native API Call       │
│  Build.MODEL ──┐              __system_property_get ─┐
│  getImei() ────┤              getifaddrs() ──────────┤
│  getAndroidId()┤              ioctl(SIOCGIFHWADDR) ──┤
│  query(gsf) ───┤              open("/proc/cpuinfo") ─┤
│                │              recvmsg(RTM_NEWLINK) ───┤
├────────────────┼──────────────────────────────────────┤
│                │                                      │
│  ┌─────────────▼──────────┐  ┌───────────────────────▼┐
│  │  SCHICHT 3: LSPosed    │  │  SCHICHT 2: Dobby      │
│  │  (Java Framework Hooks)│  │  (Inline Native Hooks)  │
│  │                        │  │                          │
│  │  19 Java-Methoden:     │  │  17 libc-Funktionen:     │
│  │  • Build.* Fields      │  │  • __system_property_get │
│  │  • TelephonyManager    │  │  • __system_property_read│
│  │  • Settings.Secure     │  │  • getifaddrs            │
│  │  • ContentResolver     │  │  • ioctl                 │
│  │  • WifiInfo            │  │  • recvmsg / sendmsg     │
│  │  • MediaDrm            │  │  • open / read           │
│  │  • Display/Sensor/Bat  │  │  • fopen / fgets         │
│  │  • AdvertisingId       │  │  • opendir/readdir       │
│  │  • InputManager        │  │  • AMediaDrm_*           │
│  └────────────┬───────────┘  └──────────────┬──────────┘
│               │                              │
│  ┌────────────▼──────────────────────────────▼──────┐
│  │          SCHICHT 1: Memory Patching              │
│  │          (MAP_PRIVATE Property Regions)           │
│  │                                                   │
│  │  54 Regions privatisiert (MAP_SHARED → PRIVATE)   │
│  │  46 Properties direkt im RAM überschrieben        │
│  │  Kein Hook nötig — Daten sind im Speicher geändert│
│  └───────────────────────┬───────────────────────────┘
│                          │
├──────────────────────────┼───────────────────────────┤
│                          ▼                           │
│  ┌───────────────────────────────────────────────┐   │
│  │        Bridge-Datei (titan_identity)          │   │
│  │        key=value Format, 15 Felder            │   │
│  │        Wird von beiden Schichten gelesen       │   │
│  └───────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

### Die 3 Schichten im Detail

| Schicht | Technik | Wo | Was |
|---------|---------|-----|-----|
| **1 — Memory Patch** | `mmap(MAP_PRIVATE)` + `mprotect` | Zygisk `postAppSpecialize` | System-Property-Speicher wird privatisiert und überschrieben. Jede App hat ihre eigene Kopie mit Fake-Werten. |
| **2 — Native Hooks** | Dobby Inline Hooking | `libc.so`, `libmediandk.so` | 17 Funktionen werden on-the-fly umgeleitet. Jeder Aufruf von z.B. `__system_property_get("ro.serialno")` liefert den Fake-Wert. |
| **3 — Java Hooks** | LSPosed / Xposed API | Android Framework | 19 Java-Methoden werden gehookt. `Build.MODEL` gibt "Pixel 6" zurück, `TelephonyManager.getImei()` die Fake-IMEI usw. |

---

## 3. Verzeichnisstruktur

```
Custom Hook Module/
│
├── module/                         # Zygisk Native Module (C++)
│   ├── zygisk_module.cpp           # Haupt-Modul: 17 Dobby-Hooks + Memory Patching
│   ├── CMakeLists.txt              # Build-Config mit Stealth-Flags
│   └── main.cpp                    # Legacy (nicht verwendet)
│
├── common/                         # Shared Code (C++ Header & Impl.)
│   ├── titan_hardware.h            # TitanHardware Singleton (Thread-safe)
│   ├── titan_hardware.cpp          # Bridge-Parser, Buffer-Management
│   └── titan_ids.h                 # Shared Constants
│
├── include/                        # Externe Header
│   ├── zygisk.hpp                  # Zygisk API v4
│   └── dobby.h                     # Dobby Inline-Hooking API
│
├── libs/dobby/                     # Prebuilt Dobby Library
│   └── arm64-v8a/libdobby.a        # ARM64 Static Library
│
├── app/                            # Android App (Kotlin + Compose)
│   └── src/main/
│       ├── kotlin/com/titan/verifier/
│       │   ├── MainActivity.kt             # Jetpack Compose Entry Point
│       │   ├── AuditEngine.kt              # 3-Layer Audit (Java/Native/Root)
│       │   ├── SecurityAuditScreen.kt      # Hauptbildschirm UI
│       │   ├── AuditExporter.kt            # Export als Textdatei
│       │   ├── NativeEngine.kt             # JNI Bridge zu audit_engine.cpp
│       │   ├── RootShell.kt                # su-Kommando Executor
│       │   └── xposed/
│       │       ├── TitanXposedModule.kt    # LSPosed Hooks (19 Methoden)
│       │       └── TitanBridgeReader.kt    # Bridge-Datei Parser (Kotlin)
│       ├── cpp/
│       │   ├── audit_engine.cpp            # Native Audit (JNI)
│       │   └── native-lib.cpp              # JNI Loader
│       └── assets/
│           └── xposed_init                 # LSPosed Registrierung
│
├── automate_titan.py               # Deployment-Automatisierung (16 Steps)
├── identity_factory.py             # Identitäts-Generator (Luhn, OUI, etc.)
├── verify_hooks.py                 # Unabhängiges Hook-Verifikationstool
├── identities.json                 # Identitäts-Datenbank (Profile)
│
├── build.gradle.kts                # Root Gradle Config
├── settings.gradle.kts             # Gradle Settings + Xposed Maven
└── gradle/                         # Gradle Wrapper
```

---

## 4. Voraussetzungen

### Hardware
- **Google Pixel 6** (Oriole) mit **Tensor G1** SoC
- USB-Kabel für ADB-Verbindung

### Software auf dem Pixel 6
| Komponente | Version | Warum |
|------------|---------|-------|
| **Android** | 14 (API 34) | Target-Version |
| **KernelSU** | Aktuell | Root-Zugriff ohne Magisk-Erkennung |
| **Zygisk Next** | Kompatibel mit KernelSU | Zygisk-API für Native-Module |
| **LSPosed** (Zygisk-Variante) | Aktuell | Java Framework Hooking |
| **SUSFS** (Optional) | Kernel-Modul | Kernel-Level Dateisystem-Masking |

### Software auf dem PC (Host)
| Tool | Version | Installation |
|------|---------|-------------|
| **Python** | 3.10+ | `brew install python` (macOS) |
| **ADB** | Aktuell | `brew install android-platform-tools` |
| **Android SDK / NDK** | NDK r26+ | Android Studio oder standalone |
| **Gradle** | 8.x | Via Gradle Wrapper (`./gradlew`) |
| **CMake** | 3.22+ | `brew install cmake` |

### Umgebungsvariablen
```bash
export ANDROID_HOME=$HOME/Library/Android/sdk
export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/26.1.10909125  # Anpassen!
export PATH=$PATH:$ANDROID_HOME/platform-tools
```

---

## 5. Erstinstallation

### Schritt 1: Pixel 6 vorbereiten

```bash
# 1. Bootloader entsperren (einmalig, löscht alle Daten!)
adb reboot bootloader
fastboot flashing unlock

# 2. KernelSU flashen
#    → Download: https://github.com/tiann/KernelSU
#    → Die passende boot.img für Pixel 6 (oriole) Android 14 wählen
fastboot flash boot kernelsu_boot.img
fastboot reboot

# 3. Zygisk Next installieren
#    → Download: https://github.com/nickcao/ZygiskNext/releases
#    → ZIP über KernelSU Manager installieren

# 4. LSPosed installieren
#    → Download: https://github.com/LSPosed/LSPosed/releases
#    → Die Zygisk-Variante wählen
#    → ZIP über KernelSU Manager installieren
#    → Neustart
```

### Schritt 2: Projekt klonen & konfigurieren

```bash
git clone <repo-url> "Custom Hook Module"
cd "Custom Hook Module"

# Python-Abhängigkeiten (nur Standardbibliothek, keine externen Pakete nötig)
python3 --version  # Muss 3.10+ sein

# ADB-Verbindung prüfen
adb devices  # Gerät muss als "device" erscheinen
```

### Schritt 3: Erste Identität generieren

```bash
python3 identity_factory.py --new "MeinErstesKonto" --carrier att

# Ausgabe:
# ✓ Identity 'MeinErstesKonto' created
# ✓ IMEI1: 352269118960363 (Luhn ✓)
# ✓ IMEI2: 352269112786780 (Luhn ✓)
# ✓ MAC: 6e:24:b5:87:e8:ba (Google OUI ✓)
# ✓ Serial: 7P7QWXNTY2WG
# ✓ GSF ID: 32828001283587705
# ✓ Android ID: 5907d4064b07b1d4
# ...
```

### Schritt 4: Automatisiertes Deployment

```bash
python3 automate_titan.py

# Das Script durchläuft 16 Schritte:
# [1/16]  Identity Generation / Load
# [2/16]  APK Build (Gradle)
# [3/16]  Native SO Build (CMake + NDK)
# [4/16]  Module Directory Structure
# [5/16]  APK Install (Privileged System App)
# [6/16]  Zygisk SO Deploy (arm64-v8a)
# [7/16]  Bridge File Write (titan_identity)
# [8/16]  SELinux Context Fix
# [9/16]  SUSFS Integration (optional)
# [10/16] Permission Patch (Privileged Perms)
# [11/16] Fake System Files (/proc/cpuinfo etc.)
# [12/16] AAID Write (GMS SharedPreferences)
# [13/16] Bridge Distribution (alle Ziel-Apps)
# [14/16] Kill-Switch Activation
# [15/16] Module Update Flag
# [16/16] Post-Deploy Verification
```

### Schritt 5: LSPosed Konfiguration

```
1. LSPosed Manager öffnen → Module
2. "Titan Verifier" aktivieren
3. Scope (Ziel-Apps) auswählen:
   ☑ System Framework
   ☑ Google Play Services (com.google.android.gms)
   ☑ Google Services Framework (com.google.android.gsf)
   ☑ Google Play Store (com.android.vending)
   ☑ TikTok (com.zhiliaoapp.musically)
   ☑ TikTok (com.ss.android.ugc.trill)
   ☑ Device ID (tw.reh.deviceid)           [optional, zum Verifizieren]
   ☑ DRM Info (com.androidfung.drminfo)     [optional, zum Verifizieren]
   ☑ Titan Verifier (com.titan.verifier)
4. Neustart
```

> **Wichtig:** Ohne korrekt gesetzten LSPosed-Scope greifen die Java-Hooks nicht!
> Bei fehlenden Apps im Scope → Abschnitt 13 (Fehlerbehebung).

### Schritt 6: Verifikation

```bash
# Titan Verifier App öffnen → sollte 10/10 zeigen
# Zusätzlich unabhängig prüfen:
python3 verify_hooks.py

# Ergebnis: VERTRAUENS-SCORE: 9/10 oder 10/10
```

---

## 6. Identität erstellen & anwenden

### Neue Identität erstellen

```bash
# Standard (AT&T als Carrier)
python3 identity_factory.py --new "Acc_NYC_01"

# Mit spezifischem Carrier
python3 identity_factory.py --new "Acc_LA_02" --carrier tmobile
python3 identity_factory.py --new "Acc_EU_03" --carrier vodafone

# Verfügbare Carrier: att, tmobile, verizon, vodafone
```

### Identitäten anzeigen

```bash
# Alle Profile auflisten
python3 identity_factory.py --list

# Details eines Profils
python3 identity_factory.py --show "Acc_NYC_01"

# Mathematische Validierung (Luhn, OUI etc.)
python3 identity_factory.py --verify "Acc_NYC_01"
```

### Identität auf Gerät laden

```bash
# Nur Bridge-Datei schreiben (schnell, kein Rebuild)
python3 identity_factory.py --apply "Acc_NYC_01"

# Mit TikTok-Datenlöschung (für Accountwechsel)
python3 identity_factory.py --apply "Acc_NYC_01" --wipe
```

### Identität löschen

```bash
python3 identity_factory.py --delete "Acc_NYC_01"
```

---

## 7. Automatisiertes Deployment

Das Script `automate_titan.py` ist der zentrale Deployment-Befehl:

```bash
# Vollständiges Deployment (Build + Deploy + Verify)
python3 automate_titan.py

# Nur Bridge-Datei updaten (kein Rebuild)
python3 automate_titan.py --bridge-only

# Build überspringen (nur Deploy)
python3 automate_titan.py --skip-build

# Neue Identität generieren und deployen
python3 automate_titan.py --generate-identity

# Verbose-Modus
python3 automate_titan.py --verbose
```

### Was passiert bei einem Deployment?

| Step | Name | Beschreibung |
|------|------|-------------|
| 1 | Identity | Identität aus `identities.json` laden oder generieren |
| 2 | APK Build | `./gradlew assembleDebug` — Titan Verifier + LSPosed Module |
| 3 | Native Build | CMake + NDK → `libtitan_zygisk.so` (ARM64) |
| 4 | Module Dir | `/data/adb/modules/titan_verifier/` Struktur erstellen |
| 5 | APK Install | Als Privileged System App installieren |
| 6 | Zygisk SO | `arm64-v8a.so` nach `/data/adb/modules/.../zygisk/` |
| 7 | Bridge | `titan_identity` Datei mit allen 15 Feldern schreiben |
| 8 | SELinux | `u:object_r:system_file:s0` Context setzen |
| 9 | SUSFS | Kernel-Level Overlay (optional) |
| 10 | Permissions | Privileged Runtime Permissions patchen |
| 11 | Fake Files | `/proc/cpuinfo`, `/proc/version` Fake-Dateien |
| 12 | AAID | Advertising ID direkt in GMS SharedPrefs schreiben |
| 13 | Bridge Dist | Bridge-Datei an alle 8 Ziel-Apps verteilen |
| 14 | Kill-Switch | Safety Kill-Switch aktivieren |
| 15 | Module Flag | KernelSU Module Update Flag setzen |
| 16 | Verify | Post-Deploy Verifikation |

---

## 8. Reinstallation / Update

### Szenario A: Code-Änderung (Hooks geändert)

```bash
# Vollständiges Rebuild + Redeploy
python3 automate_titan.py

# Danach: Neustart des Geräts
adb reboot
```

### Szenario B: Nur Identität ändern (kein Code-Änderung)

```bash
# Neues Profil erstellen und anwenden
python3 identity_factory.py --apply "Acc_NYC_02" --wipe

# Oder: Nur Bridge updaten ohne Wipe
python3 automate_titan.py --bridge-only
adb reboot
```

### Szenario C: Komplette Neuinstallation (Clean Install)

```bash
# 1. Altes Modul entfernen
adb shell "su -c 'rm -rf /data/adb/modules/titan_verifier'"

# 2. App deinstallieren
adb uninstall com.titan.verifier

# 3. Bridge-Reste entfernen
adb shell "su -c 'rm -f /sdcard/.titan_identity'"
adb shell "su -c 'rm -f /data/local/tmp/.titan_identity'"

# 4. LSPosed: "Titan Verifier" Modul deaktivieren
#    (manuell im LSPosed Manager)

# 5. Neustart
adb reboot

# 6. Frisch deployen
python3 automate_titan.py
#    → Danach LSPosed Scope neu konfigurieren (siehe Schritt 5)

# 7. Nochmal Neustart
adb reboot
```

### Szenario D: Update nach Git Pull

```bash
cd "Custom Hook Module"
git pull

# Rebuild alles
python3 automate_titan.py

# Neustart
adb reboot
```

---

## 9. Identitätswechsel

Für einen sicheren Account-Wechsel (z.B. von TikTok-Konto A zu Konto B):

```bash
# 1. Neue Identität erstellen (falls noch nicht vorhanden)
python3 identity_factory.py --new "Acc_B" --carrier tmobile

# 2. Anwenden MIT Wipe (löscht TikTok-Daten!)
python3 identity_factory.py --apply "Acc_B" --wipe

# 3. AAID in GMS überschreiben
#    (wird automatisch von automate_titan.py gemacht, oder manuell:)
python3 automate_titan.py --bridge-only

# 4. Neustart (WICHTIG — Zygisk Hooks müssen neu laden)
adb reboot

# 5. Verifizieren
python3 verify_hooks.py
```

**Was `--wipe` macht:**
- `pm clear com.zhiliaoapp.musically` (TikTok Daten löschen)
- `pm clear com.ss.android.ugc.trill` (TikTok International)
- Bridge-Datei neu verteilen
- GMS AAID überschreiben

**Warum Wipe nötig ist:** TikTok cached Geräte-IDs lokal. Ohne Wipe würde TikTok die alte Identität aus dem Cache lesen, obwohl die APIs jetzt neue Werte liefern. Das ist die offensichtlichste Red Flag für Anti-Fingerprinting.

---

## 10. Hook-Referenz (alle 55+ Werte)

### Schicht 1: Memory Patching (46 Properties)

Diese Properties werden **direkt im RAM** überschrieben. Kein API-Call nötig — der Speicher selbst enthält die Fake-Werte.

| Property | Fake-Wert |
|----------|-----------|
| `ro.product.model` | Pixel 6 |
| `ro.product.brand` | google |
| `ro.product.device` | oriole |
| `ro.product.board` | oriole |
| `ro.product.manufacturer` | Google |
| `ro.product.name` | oriole |
| `ro.hardware` | oriole |
| `ro.build.display.id` | AP1A.240505.004 |
| `ro.build.fingerprint` | google/oriole/oriole:14/AP1A.240505.004/... |
| `ro.build.type` | user |
| `ro.build.tags` | release-keys |
| `ro.build.version.release` | 14 |
| `ro.build.version.sdk` | 34 |
| `ro.build.version.security_patch` | 2024-05-05 |
| `ro.build.version.incremental` | 11583682 |
| `ro.build.id` | AP1A.240505.004 |
| `ro.build.host` | abfarm-release-rbe-64-00044 |
| `ro.build.user` | android-build |
| `ro.build.description` | oriole-user 14 AP1A.240505.004 ... |
| `ro.soc.manufacturer` | Google |
| `ro.soc.model` | Tensor |
| `ro.serialno` | (aus Bridge) |
| `ro.boot.serialno` | (aus Bridge) |
| `ro.product.vendor.*` | (Pixel 6 Werte) |
| `ro.product.system.*` | (Pixel 6 Werte) |
| `ro.bootimage.build.fingerprint` | (konsistent) |
| `ro.vendor.build.fingerprint` | (konsistent) |
| ... | (insgesamt 46 Properties) |

### Schicht 2: Native Hooks (17 Funktionen)

| # | Hook | Funktion | Gespoofter Wert |
|---|------|----------|-----------------|
| 1 | `__system_property_get` | Serial, IMEI, GSF, Android ID, Build Props | Bridge-Werte |
| 2 | `__system_property_read_callback` | Moderne Property API (Android 12+) | Bridge-Werte |
| 3 | `__system_property_read` | Legacy Property API | Bridge-Werte |
| 4 | `getifaddrs` | MAC über AF_PACKET struct | Fake-MAC |
| 5 | `ioctl(SIOCGIFHWADDR)` | MAC über ioctl | Fake-MAC |
| 6 | `ioctl(EVIOCGNAME)` | Input-Device Namen | Pixel 6 Devices |
| 7 | `recvmsg` | Netlink RTM_NEWLINK MAC | Fake-MAC |
| 8 | `sendmsg` | Netlink RTM_GETLINK Tracking | Socket-Tracking |
| 9 | `open` | `/sys/class/net/wlan0/address`, `/proc/*` | Redirect zu Fakes |
| 10 | `read` | Fake-Dateiinhalt für gehookte FDs | Fake-Daten |
| 11 | `fopen` | `/proc/bus/input/devices`, MAC-Dateien | Fake-Streams |
| 12 | `fgets` | Liest aus Fake-Streams | Pixel 6 Daten |
| 13 | `opendir` | `/dev/input/` Verzeichnis | Fake-Entries |
| 14 | `readdir` | Virtuelle Input-Events | event0-event4 |
| 15 | `closedir` | Cleanup für Fake-Directories | — |
| 16 | `AMediaDrm_createByUUID` | Widevine DRM Objekt | Fake-DRM Objekt |
| 17 | `AMediaDrm_isCryptoSchemeSupported` | Widevine Check | `true` |

### Schicht 3: Java Hooks (19 Methoden-Gruppen)

| # | Hook-Gruppe | Methoden | Gespoofter Wert |
|---|-------------|----------|-----------------|
| 1 | **Build-Fields** | `Build.MODEL`, `BRAND`, `DEVICE`, `FINGERPRINT`, ... (14 Felder) | Pixel 6 |
| 2 | **Build.VERSION** | `SDK_INT`, `RELEASE`, `SECURITY_PATCH`, `INCREMENTAL` | Android 14 |
| 3 | **SystemProperties** | `SystemProperties.get()` (36 Properties) | Pixel 6 Build |
| 4 | **TelephonyManager** | `getImei()`, `getDeviceId()`, `getSubscriberId()` | Fake-IMEI/IMSI |
| 5 | **TelephonyExtra** | `getLine1Number()`, `getSimOperator()`, `getNetworkType()` | Fake-Carrier |
| 6 | **Settings.Secure** | `getString("android_id")` | Fake Android ID |
| 7 | **GSF ContentResolver** | `query(content://com.google.android.gsf.gservices)` | Fake GSF ID |
| 8 | **GSF ContentProvider** | `ContentProviderClient.query()` | Fake GSF ID |
| 9 | **Gservices Direct** | `Gservices.getLong("android_id")` | Fake GSF ID |
| 10 | **WifiInfo** | `getMacAddress()` | Fake-MAC |
| 11 | **NetworkInterface** | `getHardwareAddress()` | Fake-MAC Bytes |
| 12 | **FileInputStream MAC** | Liest `/sys/class/net/wlan0/address` | Fake-MAC |
| 13 | **File.readText MAC** | Kotlin Extension für MAC-Dateien | Fake-MAC |
| 14 | **MediaDrm Widevine** | `getPropertyByteArray("deviceUniqueId")` | Fake Widevine ID |
| 15 | **InputManager** | `getInputDeviceIds()`, `getInputDevice()` | Pixel 6 Devices |
| 16 | **DisplayMetrics** | `getMetrics()`, `getRealSize()` | 1080x2400 @ 411dpi |
| 17 | **SensorManager** | `getSensorList()`, Vendor/Name | Pixel 6 Sensoren |
| 18 | **BatteryManager** | `getIntProperty()` | Realistische Werte |
| 19 | **AdvertisingId** | `AdvertisingIdClient.Info.getId()`, `ContentResolver.call()` | Deterministic UUID |

### Zusätzlich: Sensor-Jitter

Um Emulator-Erkennung zu umgehen, wird auf `SensorEvent.values` ein Mikro-Jitter addiert (±0.001). Dadurch sehen die Sensordaten "lebendig" aus statt perfekt statisch.

---

## 11. Verifikation & Debugging

### Automatische Verifikation

```bash
# Standardmäßig mit Device ID App
python3 verify_hooks.py

# Gegen eine bestimmte App testen
python3 verify_hooks.py --app com.zhiliaoapp.musically

# Quick-Check (ohne Cross-App Test)
python3 verify_hooks.py --quick
```

**Was das Script prüft:**
1. Shell `getprop` (NICHT gehookt) vs. Bridge-Werte → Beweis dass Hooks selektiv sind
2. Live Hook-Trigger im Logcat der Ziel-App → Beweis dass Hooks feuern
3. Cross-App Konsistenz (Verifier vs. Device ID) → Beweis für Einheitlichkeit

### Manuelle Verifikation

```bash
# Titan Verifier App öffnen → sollte 10/10 zeigen

# Device ID App (tw.reh.deviceid) installieren und vergleichen
# → Alle Werte müssen mit Titan Verifier übereinstimmen

# DRM Info App für Widevine prüfen

# Logcat live mitlesen:
adb logcat -s TitanZygisk:V TITAN-TOTAL:V AuditEngine:V
```

### Logcat-Analyse

```bash
# Alle Titan-Logs nach Neustart
adb logcat | grep -E "TITAN|TitanBridge|TitanZygisk"

# Nur Hook-Installation
adb logcat | grep "hook OK"

# Nur gespoofed Werte
adb logcat | grep "Spoofed"

# Bridge-Laden in Ziel-Apps
adb logcat | grep "Bridge loaded"

# Memory-Patching
adb logcat | grep -E "Privatized|memory patched"
```

### Erwartete Logcat-Ausgabe (gesunder Zustand)

```
[TITAN] Module loaded (Phase 6.0 - Total Stealth)
[TITAN] Bridge loaded from /data/adb/modules/titan_verifier/titan_identity
[TITAN] Target: com.zhiliaoapp.musically
[TITAN] Privatized 54 property regions (MAP_SHARED → MAP_PRIVATE)
[TITAN] Direct memory patched: 46 properties
[TITAN] Property hook OK
[TITAN] __system_property_read_callback hook OK
[TITAN] __system_property_read (legacy) hook OK
[TITAN] sendmsg (Netlink) hook OK
[TITAN] ioctl hook OK
[TITAN] recvmsg (Netlink) hook OK
[TITAN] open hook OK
[TITAN] read hook OK
[TITAN] fopen hook OK
[TITAN] fgets hook OK
[TITAN] opendir hook OK
[TITAN] readdir hook OK
[TITAN] closedir hook OK
[TITAN] AMediaDrm_createByUUID hook OK
[TITAN] AMediaDrm_release hook OK
[TITAN] AMediaDrm_isCryptoSchemeSupported hook OK
[TITAN] Total hooks installed: 17/17
[TITAN] Atomicity OK: Serial=7P7QWXNTY2WG MAC=6e:24:b5:87:e8:ba IMEI=352269118960363
```

---

## 12. Sicherheitsmechanismen

### Kill-Switch

Bei Problemen kann das Modul **sofort deaktiviert** werden, ohne Neustart:

```bash
# Kill-Switch aktivieren (Modul stoppt sofort)
adb shell "su -c 'touch /data/local/tmp/titan_stop'"

# Kill-Switch deaktivieren (Modul läuft wieder nach App-Neustart)
adb shell "su -c 'rm /data/local/tmp/titan_stop'"
```

**Wie es funktioniert:** Zygisk prüft bei jedem `onLoad` ob die Datei existiert. Wenn ja, werden **keine Hooks installiert** und das Modul entlädt sich sofort (`DLCLOSE_MODULE_LIBRARY`).

### No-Brick Policy

- **NIEMALS** wird `/system` direkt modifiziert (Pixel 6 nutzt EROFS/Shared Blocks)
- Alle Änderungen sind **RAM-only** (Memory Patching) oder in `/data/` (Bridge, Module)
- Das Modul kann jederzeit durch Löschen von `/data/adb/modules/titan_verifier/` vollständig entfernt werden
- Ein Bootloop kann durch KernelSU Safe Mode (Volume-Down beim Boot) behoben werden

### Atomicity Check

Vor der Hook-Installation prüft das Modul die **Konsistenz der Identität**:

```cpp
bool verifyIdentityAtomicity() {
    // Prüft: Serial, MAC und IMEI müssen alle geladen sein
    // Wenn eines fehlt → KEINE Hooks (verhindert Teil-Spoofing)
}
```

Wenn die Bridge-Datei fehlt oder korrupt ist, werden **keine Hooks installiert** statt inkonsistente Werte zu liefern.

### Target-App Whitelist

Hooks werden **nur** in diesen Apps injiziert:

```
com.titan.verifier          # Eigener Verifier
com.zhiliaoapp.musically    # TikTok
com.ss.android.ugc.trill    # TikTok International
com.google.android.gms      # Google Play Services
com.androidfung.drminfo     # DRM Info (optional)
tw.reh.deviceid             # Device ID (optional)
```

System-Prozesse und andere Apps bleiben **vollständig unberührt**.

### Anti-Forensics

- **Strings-Verschlüsselung**: Im Stealth-Build werden alle Logging-Strings entfernt (`TITAN_STEALTH` Flag)
- **Feste Buffer-Größen**: Keine dynamische Allokation (verhindert Heap-Analyse)
- **MAP_PRIVATE**: Property-Regionen sind process-local (nicht global sichtbar)
- **Keine ausführbaren Pages**: Kein `mmap(PROT_EXEC)` ohne File-Backing

---

## 13. Fehlerbehebung

### Problem: "Bridge loaded: GSF=null, MAC=null"

**Ursache:** Die Bridge-Datei ist nicht im Datenordner der Ziel-App.

```bash
# Fix: Bridge an alle Apps verteilen
python3 automate_titan.py --bridge-only

# Oder manuell:
adb shell "su -c 'cp /data/adb/modules/titan_verifier/titan_identity /data/data/<app>/files/.titan_identity'"
adb shell "su -c 'chown <uid>:<uid> /data/data/<app>/files/.titan_identity'"
```

### Problem: "LSPosed Hooks greifen nicht in App X"

**Ursache:** App ist nicht im LSPosed-Scope.

```
LSPosed Manager → Module → Titan Verifier → Scope → App aktivieren → Neustart
```

Falls die Checkbox fehlt, per SQLite manuell setzen:

```bash
adb shell "su -c 'sqlite3 /data/adb/lspd/config/modules_config.db \
  \"INSERT INTO scope (mid, app_pkg_name, user_id) VALUES ((SELECT mid FROM modules WHERE module_pkg_name='\''com.titan.verifier'\''), '\''<package>'\'', 0);\"'"
adb reboot
```

### Problem: "Advertising ID stimmt nicht überein"

**Ursache:** GMS cached die AAID in SharedPreferences.

```bash
# Fix: AAID direkt überschreiben
adb shell "su -c 'am force-stop com.google.android.gms'"
# Dann automate_titan.py --bridge-only ausführen (schreibt AAID)
adb reboot
```

### Problem: "Device ID App zeigt alten GSF-Wert"

**Ursache:** App hat den Wert gecacht.

```bash
adb shell "pm clear tw.reh.deviceid"
# Bridge neu kopieren (pm clear löscht auch die Bridge-Kopie):
adb shell "su -c 'cp /data/adb/modules/titan_verifier/titan_identity /data/data/tw.reh.deviceid/files/.titan_identity'"
adb shell "su -c 'chown $(stat -c %u /data/data/tw.reh.deviceid):$(stat -c %g /data/data/tw.reh.deviceid) /data/data/tw.reh.deviceid/files/.titan_identity'"
```

### Problem: "Bootloop nach Update"

```
1. Pixel 6 in KernelSU Safe Mode booten (Volume-Down gedrückt halten)
2. Alle Module sind deaktiviert
3. Kill-Switch aktivieren:
   adb shell "su -c 'touch /data/local/tmp/titan_stop'"
4. Modul entfernen:
   adb shell "su -c 'rm -rf /data/adb/modules/titan_verifier'"
5. Normal neustarten
6. Problem diagnostizieren (logcat), fixen, neu deployen
```

### Problem: "Total hooks installed: X/17" (weniger als erwartet)

**Ursache:** Eine libc-Funktion konnte nicht per Dobby gehookt werden.

```bash
# Logcat nach Fehlern durchsuchen:
adb logcat | grep -E "TITAN.*FAIL|TITAN.*Error|TITAN.*not found"
```

Häufige Gründe:
- `libmediandk.so` ist in manchen Apps nicht geladen → Widevine-Hooks fehlen (normal)
- `dlsym` findet Funktion nicht → NDK-Version überprüfen

### Problem: "SIGILL/SIGSEGV Crash in App"

**Ursache:** Dobby-Hook-Konflikt oder fehlerhafte Function-Pointer.

```bash
# 1. Kill-Switch aktivieren (sofort!)
adb shell "su -c 'touch /data/local/tmp/titan_stop'"

# 2. Logcat für Crash-Analyse
adb logcat | grep -E "SIGILL|SIGSEGV|Fatal|tombstone"

# 3. Spezifischen Hook identifizieren und deaktivieren
```

---

## 14. Bridge-Datei Format

Die Bridge-Datei ist das zentrale Kommunikationsmedium zwischen allen Schichten.

**Pfad:** `/data/adb/modules/titan_verifier/titan_identity`

**Format:** `key=value` (eine Zeile pro Feld, kein JSON)

```ini
serial=7P7QWXNTY2WG
boot_serial=7P7QWXNTY2WG
imei1=352269118960363
imei2=352269112786780
gsf_id=32828001283587705
android_id=5907d4064b07b1d4
wifi_mac=6e:24:b5:87:e8:ba
widevine_id=fd2c714b2151bcec06063f324aa85c13
imsi=3102609846136261
sim_serial=8901265660410968665
phone_number=+16468851050
operator_name=AT&T
sim_operator=310410
sim_operator_name=AT&T
voicemail_number=+18888880800
```

### Felder-Referenz

| Feld | Beschreibung | Validierung |
|------|-------------|-------------|
| `serial` | Geräte-Seriennummer (12 alphanumerisch) | Muss Pixel 6 Format haben |
| `boot_serial` | Boot-Seriennummer (meist = serial) | = serial |
| `imei1` | Primäre IMEI (15 Ziffern) | Luhn-Algorithmus |
| `imei2` | Sekundäre IMEI (15 Ziffern) | Luhn-Algorithmus |
| `gsf_id` | Google Services Framework ID | 17-stellige Dezimalzahl |
| `android_id` | Android SSAID (16 Hex) | `[0-9a-f]{16}` |
| `wifi_mac` | WLAN MAC-Adresse | Google OUI (f4:f5:d8 etc.) |
| `widevine_id` | Widevine DRM Device ID (32 Hex) | `[0-9a-f]{32}` |
| `imsi` | SIM IMSI (15 Ziffern) | Gültiger MCC/MNC Prefix |
| `sim_serial` | SIM ICCID (19-20 Ziffern) | Luhn-Algorithmus |
| `phone_number` | Telefonnummer | US-Format +1XXXXXXXXXX |
| `operator_name` | Carrier-Name | z.B. "AT&T" |
| `sim_operator` | MCC+MNC (5-6 Ziffern) | z.B. "310410" (AT&T) |
| `sim_operator_name` | SIM-Carrier-Name | z.B. "AT&T" |
| `voicemail_number` | Voicemail-Nummer | Carrier-spezifisch |

### Bridge-Verteilung

Die Bridge wird an folgende Pfade kopiert:

| Pfad | Zugriff | Verwendet von |
|------|---------|---------------|
| `/data/adb/modules/titan_verifier/titan_identity` | Root only | Zygisk (Native) |
| `/data/data/<app>/files/.titan_identity` | App-UID | LSPosed (je App) |
| `/sdcard/.titan_identity` | World-readable | Fallback |

---

## 15. Build from Source

### APK (Titan Verifier + LSPosed Module)

```bash
cd "Custom Hook Module"
./gradlew assembleDebug

# Output: app/build/outputs/apk/debug/app-debug.apk
```

### Native SO (Zygisk Module)

```bash
mkdir -p build_native && cd build_native

cmake .. \
  -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake \
  -DANDROID_ABI=arm64-v8a \
  -DANDROID_PLATFORM=android-34 \
  -DCMAKE_BUILD_TYPE=Release

cmake --build . -j$(nproc)

# Output: lib/arm64-v8a/libtitan_zygisk.so
```

### Dobby Library (selten nötig)

Falls die mitgelieferte `libdobby.a` nicht kompatibel ist:

```bash
git clone https://github.com/nickcao/dobby.git
cd dobby
mkdir build && cd build
cmake .. \
  -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake \
  -DANDROID_ABI=arm64-v8a \
  -DANDROID_PLATFORM=android-34 \
  -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# libdobby.a nach libs/dobby/arm64-v8a/ kopieren
```

### Stealth-Build (ohne Logs)

Für den Produktiveinsatz können alle Logs deaktiviert werden:

```bash
cmake .. \
  -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake \
  -DANDROID_ABI=arm64-v8a \
  -DANDROID_PLATFORM=android-34 \
  -DCMAKE_BUILD_TYPE=Release \
  -DTITAN_STEALTH=ON

# Alle LOGI/LOGW/LOGE werden zu no-ops kompiliert
# Keine Strings wie "TITAN" im Binary
```

---

## Schnellreferenz (Cheat Sheet)

```bash
# === Erstmalig ===
python3 identity_factory.py --new "Konto_1" --carrier att
python3 automate_titan.py
# → LSPosed Scope setzen → Neustart

# === Identitätswechsel ===
python3 identity_factory.py --new "Konto_2" --carrier tmobile
python3 identity_factory.py --apply "Konto_2" --wipe
adb reboot

# === Verifikation ===
python3 verify_hooks.py
python3 verify_hooks.py --app com.zhiliaoapp.musically

# === Debugging ===
adb logcat -s TitanZygisk:V TITAN-TOTAL:V
adb logcat | grep "hook OK"
adb logcat | grep "Bridge loaded"

# === Notfall ===
adb shell "su -c 'touch /data/local/tmp/titan_stop'"   # Kill-Switch AN
adb shell "su -c 'rm /data/local/tmp/titan_stop'"       # Kill-Switch AUS
adb shell "su -c 'rm -rf /data/adb/modules/titan_verifier'"  # Modul entfernen
```

---

*Project Titan — Kernel-Level Identity Spoofing für Pixel 6*
*Zuletzt aktualisiert: Februar 2026*
