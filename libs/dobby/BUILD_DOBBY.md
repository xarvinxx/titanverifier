# Dobby Build-Anleitung für Project Titan

## Voraussetzungen

- Android NDK (r25+ empfohlen)
- CMake 3.10+
- Git

## Build-Schritte

```bash
# 1. Klone Dobby Repository
git clone https://github.com/jmpews/Dobby.git /tmp/Dobby
cd /tmp/Dobby

# 2. Erstelle Build-Verzeichnis
mkdir build && cd build

# 3. Konfiguriere mit CMake (für arm64-v8a)
cmake .. \
    -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake \
    -DANDROID_ABI=arm64-v8a \
    -DANDROID_PLATFORM=android-30 \
    -DCMAKE_BUILD_TYPE=Release \
    -DDOBBY_DEBUG=OFF \
    -DDOBBY_GENERATE_SHARED=OFF

# 4. Build
make -j$(nproc)

# 5. Kopiere libdobby.a in das Projekt
cp libdobby.a /path/to/Custom\ Hook\ Module/libs/dobby/arm64-v8a/

# 6. Kopiere Header (optional, bereits in include/dobby.h definiert)
cp ../include/dobby.h /path/to/Custom\ Hook\ Module/libs/dobby/include/
```

## Verzeichnisstruktur nach Build

```
libs/dobby/
├── arm64-v8a/
│   └── libdobby.a      ← Statische Library
├── include/
│   └── dobby.h         ← API Header (optional)
└── BUILD_DOBBY.md      ← Diese Datei
```

## Alternative: Prebuilt herunterladen

Falls du Dobby nicht selbst bauen möchtest, kannst du ein prebuilt binary verwenden:

```bash
# Beispiel mit GitHub Release (Version prüfen!)
wget https://github.com/jmpews/Dobby/releases/download/latest/libdobby-android-arm64-v8a.a \
    -O libs/dobby/arm64-v8a/libdobby.a
```

## Wichtige Build-Optionen

| Option | Beschreibung |
|--------|-------------|
| `DOBBY_DEBUG=OFF` | Deaktiviert Debug-Logging (Stealth!) |
| `DOBBY_GENERATE_SHARED=OFF` | Baut statische Library |
| `Plugin.SymbolResolver=ON` | Aktiviert DobbySymbolResolver |

## Troubleshooting

### "undefined reference to DobbyHook"
→ libdobby.a nicht gefunden. Prüfe Pfad in CMakeLists.txt

### "DobbyHook returned -1"
→ Zieladresse ist nicht hookbar (z.B. in read-only memory)
→ Prüfe SELinux-Policies

### Hooks werden nicht aktiviert
→ Prüfe ob USE_DOBBY=1 im Build definiert ist
→ Prüfe Logcat: `adb logcat -s TitanZygisk:*`
