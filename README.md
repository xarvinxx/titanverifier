# Project Titan - Hardware Identity Spoofing Framework

## Übersicht

Project Titan ist ein mehrschichtiges Identity-Spoofing-System für Android 14 (Google Pixel 6), das Hardware-Identifier auf **Native-**, **Java-** und **Kernel-Ebene** manipuliert. Es besteht aus drei Kernkomponenten:

1. **Titan Verifier App** - Audit-App mit Jetpack Compose UI, die alle Hardware-IDs über Standard-Android-APIs abfragt und verifiziert
2. **Zygisk Modul** (Native C++) - Dobby Inline-Hooks für libc- und libmediandk-Funktionen
3. **LSPosed Modul** (Kotlin/Xposed) - Java-Framework-Hooks für Android-APIs

### Architektur

```
┌─────────────────────────────────────────────────┐
│  Titan Verifier App (Audit + UI)                │
│  ├── AuditEngine.kt (3-Layer Validation)        │
│  └── audit_engine.cpp (Native JNI Checks)       │
├─────────────────────────────────────────────────┤
│  LSPosed Module (Java Layer)                    │
│  ├── TelephonyManager Hooks (IMEI, IMSI, SIM)  │
│  ├── Settings.Secure Hook (Android ID)          │
│  ├── ContentResolver Hook (GSF ID)              │
│  ├── MediaDrm Hook (Widevine ID)               │
│  ├── WifiInfo / NetworkInterface (MAC)          │
│  └── InputManager (Input Devices)               │
├─────────────────────────────────────────────────┤
│  Zygisk Module (Native Layer)                   │
│  ├── __system_property_get (Serial, Props)      │
│  ├── getifaddrs (MAC via AF_PACKET)             │
│  ├── ioctl SIOCGIFHWADDR (MAC via ioctl)        │
│  ├── recvmsg (Netlink RTM_NEWLINK MAC)          │
│  ├── fopen/fgets (File Shadowing: MAC, Input)   │
│  ├── open/read (sysfs File Interception)        │
│  └── AMediaDrm_createByUUID (Widevine HAL Mock) │
├─────────────────────────────────────────────────┤
│  Bridge File (Identity Database)                │
│  /data/adb/modules/titan_verifier/titan_identity│
│  + /data/data/com.titan.verifier/files/         │
├─────────────────────────────────────────────────┤
│  KernelSU + Zygisk Next + SUSFS (optional)      │
└─────────────────────────────────────────────────┘
```

---

## Voraussetzungen

### Gerät

| Komponente | Anforderung |
|---|---|
| Gerät | Google Pixel 6 (Oriole) |
| Android | 14 (API 34) |
| Kernel | KernelSU installiert & aktiv |
| Zygisk | Zygisk Next (API v4, Magisk-kompatibel) |
| LSPosed | LSPosed (Zygisk-Variante) installiert & aktiv |
| SUSFS | Optional, für Kernel-Level Mount-Hiding |

### Entwicklungsrechner

| Komponente | Version |
|---|---|
| Android Studio / Cursor | Aktuell |
| Android SDK | API 34 |
| Android NDK | r25+ (für Cross-Compilation) |
| CMake | 3.22.1+ |
| Python | 3.10+ |
| ADB | Aktuell, im PATH |
| Java / JDK | 17 |

---

## Projektstruktur

```
Custom Hook Module/
├── app/                              # Android App (Titan Verifier)
│   ├── build.gradle.kts              # Gradle Build Config
│   └── src/main/
│       ├── AndroidManifest.xml       # App-Manifest + LSPosed Metadata
│       ├── assets/
│       │   └── xposed_init           # LSPosed Entry-Point Registrierung
│       ├── cpp/
│       │   ├── CMakeLists.txt        # Native Audit Engine Build
│       │   ├── audit_engine.cpp      # JNI: Widevine, MAC, Root-Checks, GPU, Input
│       │   └── native-lib.cpp        # JNI Library Loader
│       ├── kotlin/com/titan/verifier/
│       │   ├── MainActivity.kt       # Compose UI Entry-Point
│       │   ├── AuditEngine.kt        # 3-Layer Identity Validation
│       │   ├── AuditExporter.kt      # Export-Funktion (Text)
│       │   ├── GroundTruthModels.kt  # Datenmodelle
│       │   ├── NativeEngine.kt       # JNI Bridge Deklarationen
│       │   ├── RootShell.kt          # Root-Abfragen via su
│       │   ├── SecurityAuditScreen.kt# Compose UI Screen
│       │   ├── SecurityCard.kt       # UI Komponenten
│       │   └── xposed/
│       │       ├── TitanXposedModule.kt   # LSPosed Hook-Implementierung
│       │       └── TitanBridgeReader.kt   # Bridge-Datei Parser
│       └── res/
│           └── values/
│               └── arrays.xml        # LSPosed Scope (Target-Apps)
│
├── module/                           # Zygisk Native Module
│   ├── CMakeLists.txt                # Zygisk SO Build Config
│   ├── zygisk_module.cpp             # Hauptdatei: Alle Native Hooks
│   └── main.cpp                      # (Legacy/Unused)
│
├── common/                           # Shared zwischen App und Module
│   ├── titan_hardware.h              # TitanHardware Singleton Header
│   ├── titan_hardware.cpp            # Bridge Parser + State Management
│   └── titan_ids.h                   # Hardcoded Default-Werte
│
├── include/                          # External Headers
│   ├── zygisk.hpp                    # Zygisk API v4 Header
│   └── dobby.h                       # Dobby Inline-Hooking API
│
├── libs/dobby/                       # Dobby Prebuilt Library
│   ├── arm64-v8a/
│   │   └── libdobby.a               # Statische Library (ARM64)
│   ├── include/
│   │   └── dobby.h
│   └── BUILD_DOBBY.md               # Build-Anleitung
│
├── automate_titan.py                 # Deployment-Automation Script
├── build.gradle.kts                  # Root Gradle Config
├── settings.gradle.kts               # Gradle Settings + Xposed Maven Repo
├── gradle.properties                 # Gradle Properties
├── gradlew                           # Gradle Wrapper
└── README.md                         # Diese Datei
```

---

## Setup-Anleitung (Neues Gerät)

### Schritt 1: Gerät vorbereiten

```bash
# 1.1 KernelSU installieren (siehe offizielle Doku: https://kernelsu.org)
# 1.2 Zygisk Next installieren
#     - KernelSU Manager öffnen → Module → Zygisk Next ZIP flashen
# 1.3 LSPosed installieren
#     - KernelSU Manager → Module → LSPosed (Zygisk) ZIP flashen
# 1.4 Gerät neu starten
adb reboot

# 1.5 Verifizieren:
adb shell "su -c 'ls /data/adb/modules/zygisksu'"     # Zygisk Next vorhanden?
adb shell "su -c 'ls /data/adb/modules/lsposed'"      # LSPosed vorhanden?
```

### Schritt 2: Dobby Library bauen (falls nicht vorhanden)

```bash
# Prüfe ob libdobby.a bereits vorhanden ist:
ls libs/dobby/arm64-v8a/libdobby.a

# Falls nicht, bauen:
git clone https://github.com/jmpews/Dobby.git /tmp/Dobby
cd /tmp/Dobby && mkdir build && cd build

cmake .. \
    -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake \
    -DANDROID_ABI=arm64-v8a \
    -DANDROID_PLATFORM=android-30 \
    -DCMAKE_BUILD_TYPE=Release \
    -DDOBBY_DEBUG=OFF \
    -DDOBBY_GENERATE_SHARED=OFF

make -j$(nproc)

# Kopiere in das Projekt:
cp libdobby.a /pfad/zu/Custom\ Hook\ Module/libs/dobby/arm64-v8a/
```

### Schritt 3: Zygisk Module (Native SO) bauen

```bash
cd "Custom Hook Module"

# CMake Build-Verzeichnis erstellen
mkdir -p build_native && cd build_native

# Konfigurieren (Android NDK Pfad anpassen!)
cmake ../module \
    -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake \
    -DANDROID_ABI=arm64-v8a \
    -DANDROID_PLATFORM=android-30 \
    -DCMAKE_BUILD_TYPE=Release

# Bauen
cmake --build . -j

# Ergebnis prüfen:
ls -la lib/arm64-v8a/libtitan_zygisk.so
# Erwartet: ~230-240 KB
```

### Schritt 4: Android App (APK) bauen

```bash
cd "Custom Hook Module"

# Gradle Build
./gradlew assembleDebug

# Ergebnis prüfen:
ls -la app/build/outputs/apk/debug/app-debug.apk
```

### Schritt 5: Zygisk Modul auf dem Gerät installieren

```bash
# 5.1 Modul-Verzeichnis erstellen
adb shell "su -c 'mkdir -p /data/adb/modules/titan_verifier/zygisk'"

# 5.2 module.prop erstellen (KernelSU braucht das!)
adb shell "su -c 'cat > /data/adb/modules/titan_verifier/module.prop << EOF
id=titan_verifier
name=Titan Verifier Zygisk
version=v9.5.0
versionCode=95
author=Project Titan
description=Hardware Identity Spoofing via Zygisk
EOF'"

# 5.3 Native SO deployen
adb push build_native/lib/arm64-v8a/libtitan_zygisk.so /data/local/tmp/
adb shell "su -c 'cp /data/local/tmp/libtitan_zygisk.so /data/adb/modules/titan_verifier/zygisk/arm64-v8a.so'"
adb shell "su -c 'chmod 644 /data/adb/modules/titan_verifier/zygisk/arm64-v8a.so'"

# 5.4 Prüfen ob KernelSU das Modul erkennt:
adb shell "su -c 'ls -la /data/adb/modules/titan_verifier/'"
```

### Schritt 6: Identity Bridge erstellen

Die Bridge-Datei enthält alle gespooften Hardware-IDs im `key=value`-Format.

```bash
# 6.1 Automatisch generieren (empfohlen):
python3 automate_titan.py --generate-identity

# ODER 6.2 Manuell erstellen:
adb shell "su -c 'cat > /data/adb/modules/titan_verifier/titan_identity << EOF
# Titan Identity Bridge
serial=DEIN_SERIAL
boot_serial=DEIN_SERIAL
imei1=DEINE_IMEI1
imei2=DEINE_IMEI2
gsf_id=DEINE_GSF_ID
android_id=DEINE_ANDROID_ID
wifi_mac=de:ad:be:ef:ca:fe
widevine_id=10179c6bcba352dbd5ce5c88fec8e098
imsi=DEINE_IMSI
sim_serial=DEINE_SIM_SERIAL
operator_name=T-Mobile
EOF'"

# 6.3 Berechtigungen setzen
adb shell "su -c 'chmod 644 /data/adb/modules/titan_verifier/titan_identity'"
adb shell "su -c 'chcon u:object_r:system_file:s0 /data/adb/modules/titan_verifier/titan_identity'"
```

### Schritt 7: App installieren & Bridge kopieren

```bash
# 7.1 APK installieren
adb install -r app/build/outputs/apk/debug/app-debug.apk

# 7.2 Bridge in App-Datenordner kopieren (damit die App sie lesen kann)
# WICHTIG: Die UID (z.B. 10293) muss zur App passen!
adb shell "su -c 'cp /data/adb/modules/titan_verifier/titan_identity /data/data/com.titan.verifier/files/.titan_identity'"

# UID der App herausfinden:
adb shell "pm dump com.titan.verifier | grep userId"
# Beispiel-Output: userId=10293

# Berechtigungen setzen (UID anpassen!):
adb shell "su -c 'chown 10293:10293 /data/data/com.titan.verifier/files/.titan_identity'"
adb shell "su -c 'chmod 644 /data/data/com.titan.verifier/files/.titan_identity'"
```

### Schritt 8: LSPosed Modul aktivieren

1. **LSPosed Manager** öffnen (Notification oder App-Drawer)
2. **Module** Tab → **Titan Verifier** aktivieren (Schalter AN)
3. **Scope** setzen (Häkchen bei):
   - `System Framework`
   - `Google Services Framework` (com.google.android.gsf)
   - `Google Play Services` (com.google.android.gms)
   - `Google Play Store` (com.android.vending)
   - `Phone/Dialer` (com.android.phone)
   - `TikTok` (com.zhiliaoapp.musically)
   - `TikTok Lite` (com.ss.android.ugc.trill)
   - `Titan Verifier` (com.titan.verifier)
4. **Bestätigen** und Gerät **neu starten**

### Schritt 9: Neustart & Verifizieren

```bash
# 9.1 Gerät neu starten
adb reboot

# 9.2 Warten bis vollständig gebootet (~60-90 Sekunden)
adb wait-for-device
sleep 15

# 9.3 Kill-Switch entfernen (falls gesetzt)
adb shell "su -c 'rm -f /data/local/tmp/titan_stop'"

# 9.4 App starten
adb shell "am start -n com.titan.verifier/.MainActivity"

# 9.5 Logs prüfen
adb logcat -s TitanZygisk:* AuditEngine:* LSPosed-Bridge:*
```

---

## Automatisiertes Deployment

Das `automate_titan.py` Script automatisiert die Schritte 3-9:

```bash
# Vollständiges Deployment (Build + Deploy + Reboot)
python3 automate_titan.py

# Nur Bridge-Datei neu generieren
python3 automate_titan.py --bridge-only

# Neue Identität generieren
python3 automate_titan.py --generate-identity

# Build überspringen (nur Deploy)
python3 automate_titan.py --skip-build

# Verbose-Modus (alle ADB-Ausgaben)
python3 automate_titan.py --verbose
```

---

## Gespoofed Felder (10/10)

| # | Feld | Native Hook (Zygisk) | Java Hook (LSPosed) |
|---|---|---|---|
| 1 | **Serial** (ro.serialno) | `__system_property_get` | - |
| 2 | **Boot Serial** (ro.boot.serialno) | `__system_property_get` | - |
| 3 | **IMEI 1** | `__system_property_get` | `TelephonyManager.getImei()` |
| 4 | **IMEI 2** | `__system_property_get` | `TelephonyManager.getImei(1)` |
| 5 | **GSF ID** | - | `ContentResolver.query()` (MatrixCursor) |
| 6 | **Android ID** | - | `Settings.Secure.getString()` |
| 7 | **WiFi MAC** | `ioctl`, `getifaddrs`, `recvmsg`, `fopen` | `WifiInfo`, `NetworkInterface` |
| 8 | **IMSI** | - | `TelephonyManager.getSubscriberId()` |
| 9 | **SIM Serial** | - | `TelephonyManager.getSimSerialNumber()` |
| 10 | **Widevine ID** | `AMediaDrm_createByUUID` (HAL Mock) | `MediaDrm` (Konstruktor-Suppression) |

---

## Bridge-Datei Format

Die Bridge-Datei (`titan_identity`) ist eine einfache `key=value` Textdatei:

```ini
# Titan Identity Bridge - Phase 9.5
# Generated: 2026-02-07

serial=79X0MY2YUQ7T
boot_serial=79X0MY2YUQ7T
imei1=358476329904627
imei2=352269110902025
gsf_id=28791305939433202
android_id=741ec73764ecd2b7
wifi_mac=aa:e6:db:93:bb:a5
widevine_id=10179c6bcba352dbd5ce5c88fec8e098
imsi=3102602729370550
sim_serial=8901410443330270908
operator_name=AT&T
```

### Bridge-Pfade (Priorität)

| Priorität | Pfad | Lesbar durch |
|---|---|---|
| 1 | `/data/data/com.titan.verifier/files/.titan_identity` | App (normal), LSPosed |
| 2 | `/data/adb/modules/titan_verifier/titan_identity` | Zygisk (root), LSPosed (root) |
| 3 | `/sdcard/.titan_identity` | LSPosed (world-readable) |
| 4 | `/data/local/tmp/.titan_identity` | Legacy |

---

## Sicherheits-Features

### Kill-Switch

Erstelle die Datei `/data/local/tmp/titan_stop`, um alle Hooks sofort zu deaktivieren (ohne Reboot):

```bash
# Hooks deaktivieren (Notfall)
adb shell "su -c 'touch /data/local/tmp/titan_stop'"

# Hooks wieder aktivieren
adb shell "su -c 'rm /data/local/tmp/titan_stop'"
```

### Safe Mode

Falls das Gerät nicht bootet:
1. Leiser-Taste beim Booten gedrückt halten → Safe Mode
2. Im Safe Mode werden alle Module deaktiviert
3. Modul entfernen: `adb shell "su -c 'rm -rf /data/adb/modules/titan_verifier'"`
4. Normal neu starten

### Stealth-Build

Für Production (ohne Logging):

```bash
cmake ../module \
    -DTITAN_STEALTH_MODE=ON \
    -DCMAKE_BUILD_TYPE=Release \
    ...
```

---

## Debugging & Troubleshooting

### Logcat Filter

```bash
# Alle Titan-Logs
adb logcat -s TitanZygisk:* AuditEngine:* LSPosed-Bridge:*

# Nur Hook-Status
adb logcat -d | grep "TitanZygisk" | grep "hook\|installed"

# Nur Audit-Ergebnisse
adb logcat -d | grep "AuditEngine" | grep "VERIFIED\|MISMATCH"

# Widevine-Debugging
adb logcat -d | grep -E "Widevine|MediaDrm|AMediaDrm"
```

### Häufige Probleme

| Problem | Ursache | Lösung |
|---|---|---|
| "Bridge nicht konfiguriert" | Bridge-Datei fehlt im App-Ordner | `cp` Bridge nach `/data/data/com.titan.verifier/files/` |
| Boot-Loop | Hook in System-Prozess | Kill-Switch setzen, Safe Mode, Modul entfernen |
| MAC MISSING | `ioctl` blocked by SELinux | `fopen`-Hook fängt Fallback ab |
| Widevine MISSING | HAL defekt (NO_INIT) | LSPosed Konstruktor-Suppression prüfen |
| SIGILL Crash | Dobby kann Funktion nicht hooken | Diese Funktion aus Dobby-Hooks entfernen |
| LSPosed Bridge = null | Berechtigungen falsch | `chown` + `chmod` auf Bridge-Datei |
| App nicht in LSPosed | Scope nicht gesetzt | LSPosed Manager → Module → Scope setzen |

### Bridge nach App-Daten-Löschung wiederherstellen

```bash
adb shell "su -c 'cp /data/adb/modules/titan_verifier/titan_identity \
    /data/data/com.titan.verifier/files/.titan_identity && \
    chown 10293:10293 /data/data/com.titan.verifier/files/.titan_identity && \
    chmod 644 /data/data/com.titan.verifier/files/.titan_identity'"
```

> **Hinweis:** Die UID `10293` muss an dein Gerät angepasst werden. Ermittle sie mit:
> `adb shell "pm dump com.titan.verifier | grep userId"`

---

## Neue Identität generieren

Um eine komplett neue Geräte-Identität zu erstellen:

```bash
# 1. Neue Bridge generieren
python3 automate_titan.py --generate-identity

# 2. Auf Gerät deployen
python3 automate_titan.py --bridge-only

# 3. ODER manuell:
adb shell "su -c 'cp /data/adb/modules/titan_verifier/titan_identity \
    /data/data/com.titan.verifier/files/.titan_identity'"
adb shell "su -c 'chown 10293:10293 /data/data/com.titan.verifier/files/.titan_identity'"

# 4. App-Daten löschen und neu starten
adb shell "am force-stop com.titan.verifier"
adb shell "am start -n com.titan.verifier/.MainActivity"
```

---

## Bekannte Limitierungen

1. **Widevine HAL**: Auf manchen Pixel 6 Geräten ist der Widevine DRM HAL defekt (`NO_INIT`). Die Lösung: LSPosed unterdrückt die Konstruktor-Exception und liefert die Titan-ID über Java-Hooks.

2. **Dobby + libmediandk**: Dobby kann `AMediaDrm_getPropertyByteArray` auf ARM64 nicht sicher inline-hooken (SIGILL). Daher wird Widevine-Spoofing ausschließlich über LSPosed (Java) realisiert.

3. **Input Devices**: Der native Audit (`/proc/bus/input/devices`) wird über den `fopen`-Hook umgeleitet. Der Java-Weg (`InputManager`) wird via LSPosed gehookt.

4. **Root-Level Checks**: Manche Root-Methoden im Auditor (`su -c getprop`) umgehen die Hooks absichtlich, um die echten Werte als Referenz zu zeigen.

---

## Lizenz & Haftung

Dieses Projekt dient ausschließlich zu Forschungs- und Bildungszwecken. Die Manipulation von Hardware-Identifiern kann gegen die Nutzungsbedingungen von Apps und Diensten verstoßen. Verwendung auf eigene Verantwortung.
