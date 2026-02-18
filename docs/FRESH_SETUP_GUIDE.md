# Fresh Setup Guide — Von Null zum voll operativen System

> Google Pixel 6 (Oriole) | Android 14 | KernelSU | SUSFS v2.0.0
> Zuletzt aktualisiert: 18. Februar 2026

---

## Inhaltsverzeichnis

1. [Voraussetzungen](#1-voraussetzungen)
2. [Phase A: Pixel 6 Grundinstallation](#2-phase-a-pixel-6-grundinstallation)
3. [Phase B: KernelSU Module installieren](#3-phase-b-kernelsu-module-installieren)
4. [Phase C: SUSFS konfigurieren (Stealth)](#4-phase-c-susfs-konfigurieren)
5. [Phase D: Spoofing-Module deployen](#5-phase-d-spoofing-module-deployen)
6. [Phase E: Python Host einrichten](#6-phase-e-python-host-einrichten)
7. [Phase F: Web Dashboard starten](#7-phase-f-web-dashboard-starten)
8. [Phase G: HookGuard aktivieren](#8-phase-g-hookguard-aktivieren)
9. [Phase H: Erster Genesis Flow](#9-phase-h-erster-genesis-flow)
10. [Stealth-Audit Checkliste](#10-stealth-audit-checkliste)
11. [Notfall-Befehle](#11-notfall-befehle)
12. [Modulreferenz (alle KSU-Module)](#12-modulreferenz)

---

## 1. Voraussetzungen

### Hardware
- **Google Pixel 6** (Oriole) mit Tensor G1
- USB-C Kabel fuer ADB

### Host-PC (macOS/Linux)
```bash
# macOS
brew install python android-platform-tools cmake

# Linux
sudo apt install python3 python3-pip adb cmake

# Pruefen
python3 --version   # >= 3.10
adb --version
cmake --version     # >= 3.22
```

### Umgebungsvariablen
```bash
export ANDROID_HOME=$HOME/Library/Android/sdk
export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/26.1.10909125
export PATH=$PATH:$ANDROID_HOME/platform-tools
```

---

## 2. Phase A: Pixel 6 Grundinstallation

### A1. Bootloader entsperren (einmalig, loescht alle Daten)
```bash
adb reboot bootloader
fastboot flashing unlock
# Geraet bestaetige, dann:
fastboot reboot
```

### A2. Custom Kernel mit KernelSU + SUSFS flashen
```bash
# Download: KernelSU-kompatibles boot.img fuer Pixel 6 (oriole) Android 14
# WICHTIG: SUSFS muss im Kernel integriert sein (nicht als separates Modul)
# Empfohlen: Wild+ Kernel oder aehnliches mit SUSFS v2.0.0

adb reboot bootloader
fastboot flash boot kernelsu_susfs_boot.img
fastboot reboot
```

### A3. ADB Verbindung pruefen
```bash
adb devices
# Muss "device" anzeigen (nicht "unauthorized")
adb shell su -c "id"
# Muss "uid=0(root)" anzeigen
```

---

## 3. Phase B: KernelSU Module installieren

Alle Module muessen ueber den KernelSU Manager (oder `ksu module install`) installiert werden.

### Installations-Reihenfolge (WICHTIG — Reihenfolge einhalten!)

| # | Modul | Version | Download | Zweck |
|---|-------|---------|----------|-------|
| 1 | **Zygisk Next** | 1.3.2+ | [GitHub](https://github.com/nickcao/ZygiskNext) | Zygisk-API fuer KernelSU |
| 2 | **SUSFS4KSU** | passend zu Kernel | [GitHub](https://github.com/sidex15/susfs4ksu-module) | Userspace-Konfiguration fuer SUSFS |
| 3 | **Zygisk - LSPosed** | v1.11.0+ | [GitHub](https://github.com/JingMatrix/LSPosed) | Xposed Framework (Zygisk-Variante) |
| 4 | **Zygisk Assistant** | v2.1.4+ | [GitHub](https://github.com/snake-4/Zygisk-Assistant) | Root-Hiding fuer Zygisk |
| 5 | **Play Integrity Fork** | v16+ | [GitHub](https://github.com/osm0sis/PlayIntegrityFork) | DEVICE_INTEGRITY Fix |
| 6 | **Tricky Store** | v1.4.1+ | [GitHub](https://github.com/5ec1cff/TrickyStore) | Keystore-Trick fuer Integrity |
| 7 | **hw_overlay** (unser Modul) | v6.2+ | Aus diesem Repo bauen | Identity-Spoofing (Zygisk + LSPosed) |

### Optional (Hilfsmittel)
| Modul | Zweck |
|-------|-------|
| BetterKnownInstalled | Zeigt installierte Module im System |
| abootloop | Anti-Bootloop Protection |
| wadbd | Wireless ADB |

### Installation via ADB
```bash
# Beispiel fuer ein Modul:
adb push module.zip /data/local/tmp/
adb shell "su -c '/data/adb/ksu/bin/ksud module install /data/local/tmp/module.zip'"
adb reboot
```

### Nach dem Reboot verifizieren
```bash
adb shell su -c "ls /data/adb/modules/"
# Erwartete Ausgabe:
# BetterKnownInstalled  abootloop  hw_overlay  playintegrityfix
# susfs4ksu  tricky_store  wadbd  zygisk-assistant
# zygisk_lsposed  zygisksu
```

---

## 4. Phase C: SUSFS konfigurieren

> SUSFS versteckt Root-Spuren (Module, Libraries, Mounts) vor Apps wie TikTok.
> Ohne korrekte SUSFS-Konfiguration erkennt TikTok KernelSU/LSPosed in `/proc/maps`.

### C1. Config erstellen (`/data/adb/susfs4ksu/config.sh`)

```bash
adb push - /data/local/tmp/susfs_config.sh << 'EOF'
force_hide_lsposed=1
spoof_uname=1
umount_for_zygote_iso_service=0
avc_log_spoofing=1
hide_sus_mnts_for_all_or_non_su_procs=1
hide_cusrom=0
hide_gapps=0
hide_revanced=0
hide_loops=1
hide_vendor_sepolicy=0
hide_compat_matrix=0
fake_service_list=0
susfs_log=1
sus_su=2
auto_try_umount=1
emulate_vold_app_data=0
spoof_cmdline=1
EOF

adb shell "su -c 'cp /data/local/tmp/susfs_config.sh /data/adb/susfs4ksu/config.sh && chmod 644 /data/adb/susfs4ksu/config.sh'"
```

#### Erklaerung der wichtigsten Einstellungen

| Setting | Wert | Was es tut |
|---------|------|-----------|
| `force_hide_lsposed` | `1` | Unmountet LSPosed dex2oat Overlays |
| `avc_log_spoofing` | `1` | Versteckt "su" tcontext in SELinux Audit-Logs |
| `hide_sus_mnts_for_all_or_non_su_procs` | `1` | Versteckt verdaechtige Mounts aus `/proc/self/mountinfo` |
| `spoof_cmdline` | `1` | Spooft `/proc/cmdline` auf `verifiedbootstate=green` |
| `auto_try_umount` | `1` | Automatisches Unmounten von KSU Overlay-Mounts |
| `hide_loops` | `1` | Versteckt Loop-Devices aus `/proc/fs/` |
| `sus_su` | `2` | SUS_SU Mode 2 (versteckte su-Binary) |

### C2. SUS Maps konfigurieren (`/data/adb/susfs4ksu/sus_maps.txt`)

> WICHTIG: `sus_maps` erwartet **exakte .so-Dateipfade**, KEINE Verzeichnisse!
> Diese Libraries werden aus `/proc/self/maps` versteckt.

```bash
adb shell "su -c 'cat > /data/adb/susfs4ksu/sus_maps.txt << MAPEOF
# Zygisk Module Libraries — werden aus /proc/maps versteckt
/data/adb/modules/hw_overlay/zygisk/arm64-v8a.so
/data/adb/modules/zygisk_lsposed/zygisk/arm64-v8a.so
/data/adb/modules/zygisk_lsposed/zygisk/armeabi-v7a.so
/data/adb/modules/zygisk_lsposed/bin/liboat_hook64.so
/data/adb/modules/zygisk_lsposed/bin/liboat_hook32.so
/data/adb/modules/zygisksu/lib64/libzygisk.so
/data/adb/modules/zygisksu/lib64/libpayload.so
/data/adb/modules/zygisksu/lib64/libzn_loader.so
/data/adb/modules/zygisksu/lib/libzygisk.so
/data/adb/modules/zygisksu/lib/libzn_loader.so
/data/adb/modules/playintegrityfix/zygisk/arm64-v8a.so
/data/adb/modules/playintegrityfix/zygisk/armeabi-v7a.so
/data/adb/modules/zygisk-assistant/zygisk/arm64-v8a.so
/data/adb/modules/zygisk-assistant/zygisk/armeabi-v7a.so
/data/adb/modules/tricky_store/libtricky_store.so
MAPEOF'"
```

### C3. SUS Path konfigurieren (`/data/adb/susfs4ksu/sus_path.txt`)

> Diese Verzeichnisse/Dateien werden vor Syscalls wie `stat`, `access`, `open` versteckt.

```bash
# Inhalt von sus_path.txt:
/data/adb/ksu
/data/adb/ksud
/data/adb/modules
/data/adb/lspd
/data/adb/zygisksu
/data/adb/zygisk
/data/adb/modules/zygisk-next
/data/adb/modules/zygisk_lsposed
/data/adb/modules/lsposed
/data/adb/modules/playintegrityfix
/data/adb/modules/hw_overlay
/data/adb/modules/zygisk-assistant
/data/adb/modules/abootloop
/data/adb/modules/wadbd
/data/adb/modules/BetterKnownInstalled
/data/adb/modules/TA_utl
/data/adb/tricky_store
/data/adb/storage-isolation
/data/adb/susfs4ksu
/data/adb/service.d
/data/adb/Box-Brain
/data/adb/VerifiedBootHash
/data/data/com.android1500.androidfaker
/data/data/org.lsposed.manager
/data/app/*com.lsposed.manager*
/data/app/*com.reveny.nativedetector*
/data/app/*com.reveny.nativecheck*
/data/local/tmp
/data/local/tmp/zygisk
/system/framework/core-libart.jar
/apex/com.android.art/javalib/core-libart.jar
/linkat
/proc/net/unix
/dev/socket/lsposed
/dev/socket/zygote
/dev/socket/zygote_secondary
```

### C4. Try Unmount konfigurieren (`/data/adb/susfs4ksu/try_umount.txt`)

```bash
# Inhalt von try_umount.txt:
/data/adb/modules
/data/adb/lspd
/data/adb/zygisksu
/data/adb/modules/playintegrityfix
/data/adb/modules/zygisk_lsposed
/data/app/*com.reveny.nativedetector*
/data/app/*com.reveny.nativecheck*
/data/app/~~*
/apex/com.android.art/javalib/core-libart.jar
```

### C5. Reboot und verifizieren
```bash
adb reboot

# Nach Boot:
adb shell su -c "/data/adb/ksu/bin/ksu_susfs show version"
# → v2.0.0

adb shell su -c "/data/adb/ksu/bin/ksu_susfs show enabled_features"
# → CONFIG_KSU_SUSFS_SUS_PATH, CONFIG_KSU_SUSFS_SUS_MOUNT, ...

# SUSFS Stats pruefen:
adb shell su -c "cat /data/adb/ksu/susfs4ksu/susfs_stats1.txt"
# → sus_path=46, sus_map=30, try_umount=11 (ungefaehre Werte)
```

---

## 5. Phase D: Spoofing-Module deployen

### D1. Xposed-Modul (LSPosed) bauen und installieren
```bash
cd /path/to/titanverifier

# Debug-APK bauen
./gradlew :app:assembleDebug

# Auf Geraet installieren
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

### D2. Zygisk-Modul (C++ Native) bauen und installieren
```bash
cd module/build
make clean && make

# Modul-ZIP auf Geraet pushen
adb push hw_overlay.zip /data/local/tmp/
adb shell "su -c '/data/adb/ksu/bin/ksud module install /data/local/tmp/hw_overlay.zip'"
adb reboot
```

### D3. LSPosed Scope konfigurieren

LSPosed Manager oeffnen → Module → **"Hardware Service"** aktivieren:

| App | Package | Pflicht |
|-----|---------|---------|
| System Framework | `android` | Ja |
| Google Play Services | `com.google.android.gms` | Ja |
| Google Services Framework | `com.google.android.gsf` | Ja |
| Google Play Store | `com.android.vending` | Ja |
| TikTok | `com.zhiliaoapp.musically` | Ja |
| TikTok International | `com.ss.android.ugc.trill` | Falls installiert |
| Hardware Service (eigene App) | `com.oem.hardware.service` | Ja |

**→ Neustart nach Scope-Aenderung erforderlich!**

### D4. Bridge-Datei verifizieren
```bash
# Pruefen ob Bridge existiert und geladen wird
adb shell su -c "cat /data/adb/modules/hw_overlay/.hw_config"
# → Muss key=value Paare zeigen (serial=, imei1=, wifi_mac=, etc.)

# Pruefen ob Bridge in TikTok-Ordner kopiert ist
adb shell su -c "cat /data/data/com.zhiliaoapp.musically/files/.hw_config"
```

---

## 6. Phase E: Python Host einrichten

### E1. Repository klonen
```bash
git clone <repo-url> titanverifier
cd titanverifier
```

### E2. Python-Dependencies installieren
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Abhaengigkeiten (requirements.txt)
| Paket | Version | Zweck |
|-------|---------|-------|
| `fastapi` | >= 0.115.0 | Web-Framework (REST + WebSocket) |
| `uvicorn[standard]` | >= 0.32.0 | ASGI Server |
| `aiosqlite` | >= 0.20.0 | Async SQLite |
| `pydantic` | >= 2.9.0 | Datenvalidierung |
| `jinja2` | >= 3.1.0 | HTML Templates |
| `aiofiles` | >= 24.1.0 | Async File I/O |
| `httpx` | >= 0.27.0 | HTTP Client (IP-Check) |

### E3. Datenbank initialisieren
Die Datenbank (`device_manager.db`) wird beim ersten Start automatisch erstellt.

---

## 7. Phase F: Web Dashboard starten

### F1. Server starten
```bash
cd titanverifier
source .venv/bin/activate
python -m host.main
```

Der Server startet auf `http://localhost:8000`.

### F2. Dashboard oeffnen
Browser oeffnen → `http://localhost:8000`

Das Dashboard zeigt:
- **Device Status**: ADB-Verbindung, aktuelle Identitaet
- **Profile Manager (Vault)**: Alle gespeicherten Profile
- **Control Panel**: Genesis, Switch, Deep Clean Buttons
- **Hook Guard**: Live-Monitoring der Hooks
- **Log Stream**: Echtzeit-Logs via WebSocket

### F3. Server nach Code-Aenderungen neu starten
```bash
# Alte Instanz beenden
lsof -ti :8000 | xargs kill -9

# Neu starten
python -m host.main
```

---

## 8. Phase G: HookGuard aktivieren

Der HookGuard ist ein Live-Monitor der alle 3 Sekunden prueft:
- **28 Xposed Hooks** aktiv und spoofing korrekt
- **Heartbeat** vom Xposed-Modul (alle 3s)
- **Bridge-Integritaet** (MD5 nur Identity-Zeilen)
- **Maps-Detection** (`/proc/maps` aus App-Sicht via SUSFS)

### Aktivierung
1. Dashboard oeffnen (`http://localhost:8000`)
2. Im **Hook Guard** Widget: **START** klicken
3. TikTok oeffnen
4. Erwartete Anzeige (alles gruen):

| Metrik | Erwarteter Wert |
|--------|----------------|
| Status | MONITORING (gruen) |
| Hooks | 28/28 |
| Heartbeat | LIVE (< 5s) |
| Bridge | OK |
| Detection | HIDDEN |
| SPOOF/REAL | > 0 / 0 |

### Kill-Switch Verhalten
Der Guard killt TikTok + aktiviert Flugmodus bei:
- **CRITICAL_REAL**: Ein Hook hat den echten (unspoofed) Wert zurueckgegeben
- **HEARTBEAT_TIMEOUT**: Xposed-Modul antwortet > 45s nicht
- **BRIDGE_MISSING**: Bridge-Datei komplett verschwunden

Maps-Leaks (z.B. `ksu` in Maps bei Root-Lesung) sind nur Warnungen, kein Kill.

### Nach einem Kill-Switch
1. **REACTIVATE** klicken (hebt Flugmodus + Autostart-Blocker auf)
2. **START** klicken (startet Monitoring neu)
3. TikTok manuell oeffnen

---

## 9. Phase H: Erster Genesis Flow

### H1. Vorbereitung
- TikTok muss installiert sein (`com.zhiliaoapp.musically`)
- ADB-Verbindung muss stehen
- Server muss laufen (`python -m host.main`)

### H2. Genesis ausfuehren
1. Dashboard → **GENESIS** Button
2. Flow fuehrt automatisch durch:
   - Deep Clean (TikTok + Tracking-Reste)
   - Neue Identitaet generieren
   - Bridge-Datei schreiben
   - Reboot
   - Netzwerk-Init (Flugmodus Toggle)
   - Audit

### H3. Nach dem Flow
- Profil erscheint im Vault
- TikTok oeffnen → Frische Instanz (kein "Willkommen zurueck")
- HookGuard starten und pruefen

---

## 10. Stealth-Audit Checkliste

Nach jedem Setup oder Reboot diese Checks durchfuehren:

```bash
# 1. /proc/maps (App-Sicht — was TikTok sieht)
adb shell "run-as com.zhiliaoapp.musically cat /proc/self/maps 2>/dev/null" | \
  grep -icE 'ksu|zygisk|xposed|lsp|magisk|frida|dobby|hw_overlay|tricky'
# ERWARTET: 0

# 2. /proc/mountinfo (App-Sicht)
adb shell "run-as com.zhiliaoapp.musically cat /proc/self/mountinfo 2>/dev/null" | \
  grep -icE 'ksu|zygisk|modules|lspd|overlay'
# ERWARTET: 0

# 3. System Properties
adb shell getprop ro.boot.verifiedbootstate
# ERWARTET: green

adb shell getprop ro.build.type
# ERWARTET: user

adb shell getprop ro.debuggable
# ERWARTET: 0

adb shell getprop ro.secure
# ERWARTET: 1

# 4. SUSFS Stats
adb shell su -c "cat /data/adb/ksu/susfs4ksu/susfs_stats1.txt"
# ERWARTET: sus_path > 30, sus_map > 10

# 5. HookGuard (via API)
curl -s http://localhost:8000/api/dashboard/hookguard | python3 -m json.tool
# ERWARTET: status=monitoring, maps_clean=true, bridge_intact=true

# 6. Bridge-Konsistenz
adb shell su -c "grep -v '^#' /data/adb/modules/hw_overlay/.hw_config | grep -v '^$' | md5"
adb shell su -c "grep -v '^#' /data/data/com.zhiliaoapp.musically/files/.hw_config | grep -v '^$' | md5"
# ERWARTET: Beide MD5-Hashes identisch
```

### Schnelltest via HookGuard API
```bash
curl -s http://localhost:8000/api/dashboard/hookguard | python3 -c "
import sys,json,time
d=json.load(sys.stdin)
hb = (time.time()*1000 - d['last_heartbeat_ms'])/1000 if d['last_heartbeat_ms']>0 else -1
checks = [
    ('Status', d['status'] == 'monitoring', d['status']),
    ('Hooks', d['applied_hooks'] == 28, f\"{d['applied_hooks']}/28\"),
    ('Heartbeat', 0 < hb < 10, f'{hb:.1f}s'),
    ('Bridge', d['bridge_intact'], 'OK' if d['bridge_intact'] else 'FAIL'),
    ('Maps', d['maps_clean'], 'HIDDEN' if d['maps_clean'] else 'EXPOSED'),
    ('Leaks', d['real_count'] == 0, f\"spoof={d['spoof_count']} real={d['real_count']}\"),
]
for name, ok, val in checks:
    print(f\"  {'PASS' if ok else 'FAIL'}  {name}: {val}\")
all_ok = all(ok for _, ok, _ in checks)
print(f\"\n{'ALL CHECKS PASSED' if all_ok else 'SOME CHECKS FAILED'}\")
"
```

---

## 11. Notfall-Befehle

```bash
# === Kill-Switch (Modul sofort deaktivieren) ===
adb shell "su -c 'touch /data/local/tmp/.hw_disabled'"    # AN
adb shell "su -c 'rm /data/local/tmp/.hw_disabled'"        # AUS

# === TikTok sofort stoppen ===
adb shell am force-stop com.zhiliaoapp.musically

# === Flugmodus manuell ausschalten ===
adb shell "su -c 'cmd connectivity airplane-mode disable'"

# === Modul komplett entfernen ===
adb shell "su -c 'rm -rf /data/adb/modules/hw_overlay'"
adb reboot

# === Bootloop Recovery (KernelSU Safe Mode) ===
# Volume-Down beim Boot gedrückt halten → alle Module deaktiviert
# Dann:
adb shell "su -c 'rm -rf /data/adb/modules/hw_overlay'"
adb shell "su -c 'rm -f /data/system_ce/0/accounts_ce.db*'"
adb shell "su -c 'rm -f /data/system_de/0/accounts_de.db*'"
adb reboot

# === Server Port belegt ===
lsof -ti :8000 | xargs kill -9

# === ADB Zombie-State ===
adb kill-server && adb start-server && adb devices

# === SUSFS-Config korrupt? ===
adb shell su -c "od -c /data/adb/susfs4ksu/config.sh | head -3"
# Wenn Null-Bytes → config.sh neu erstellen (siehe Phase C1)
```

---

## 12. Modulreferenz

### Auf dem Geraet installierte KSU-Module

| Modul | ID | Version | Funktion |
|-------|----|---------|----------|
| **Zygisk Next** | `zygisksu` | 1.3.2 | Zygisk-API fuer KernelSU |
| **LSPosed** | `zygisk_lsposed` | v1.11.0 | Xposed Framework (Java Hooks) |
| **SUSFS4KSU** | `susfs4ksu` | v2.0.0 | Kernel-Level Stealth (Maps, Mounts, Paths) |
| **HW Overlay** | `hw_overlay` | v6.2 | Identity-Spoofing (17 Native + 28 Java Hooks) |
| **Play Integrity Fork** | `playintegrityfix` | v16 | DEVICE_INTEGRITY Verdict Fix |
| **Tricky Store** | `tricky_store` | v1.4.1 | Keystore-Trick fuer Integrity |
| **Zygisk Assistant** | `zygisk-assistant` | v2.1.4 | Root-Hiding |
| **BetterKnownInstalled** | `BetterKnownInstalled` | v1.4.0 | Modulstatus-Anzeige |
| **abootloop** | `abootloop` | — | Anti-Bootloop Schutz |
| **wadbd** | `wadbd` | — | Wireless ADB |

### Bridge-Datei Pfade

| Pfad | Zweck | Wer liest |
|------|-------|-----------|
| `/data/adb/modules/hw_overlay/.hw_config` | Primaer | Zygisk (C++) |
| `/data/data/<app>/files/.hw_config` | Pro App-Kopie | LSPosed (Kotlin) |

### Getarnte Paketnamen (Stealth-Renaming)

| Intern | Oeffentlich sichtbar als |
|--------|--------------------------|
| `com.oem.hardware.service` | "Hardware Service" (App) |
| `hw_overlay` | "HW Overlay" (Modul) |
| `.hw_config` | Hardware-Config (Bridge) |
| `.hw_disabled` | Service-Flag (Kill-Switch) |

---

## Verwandte Dokumentation

| Datei | Inhalt |
|-------|--------|
| `README.md` | Architektur, Hook-Referenz (55+ Werte), Build-Anleitung |
| `STEALTH_PLAN.md` | Komplett-Rename von "titan" zu getarnten Namen |
| `SPARRING_FIXES.md` | 30 implementierte Fixes (Phase 1-9) |
| `docs/GMSFIX-2026-02-17.md` | GMS/Integrity Troubleshooting |
