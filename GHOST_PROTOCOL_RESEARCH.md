# Operation Ghost Protocol — Deep Research Referenz

> **Zweck**: Konsolidierte Wissensbasis für das v9.0 Refactoring.  
> **Regel**: Dieses Dokument wird NUR gelesen, nie vom Implementierungs-Code referenziert.

---

## Research 1: ART Method Hooking ohne Xposed (Android 14 / Pixel 6)

### ArtMethod Struct Layout (AOSP android-14.0.0_r2, ARM64)

| Offset | Feldname | Datentyp | Beschreibung |
|--------|----------|----------|-------------|
| 0 | `declaring_class_` | `uint32_t` | GcRoot-Referenz auf definierende Klasse |
| 4 | `access_flags_` | `uint32_t` | Modifikatoren (public, static, native) |
| 8 | `dex_code_item_offset_` | `uint32_t` | Offset zum Bytecode in DEX |
| 12 | `dex_method_index_` | `uint32_t` | Index in DEX-Strukturen |
| 16 | `method_index_` | `uint16_t` | vtable/Interface-Table Index |
| 18 | `hotness_count_` | `uint16_t` | JIT-Optimierungszähler |
| 20 | `imt_index_` | `uint32_t` | Interface Method Table Index |
| 24 | `entry_point_from_jni_` | `uint64_t` | Pointer für native Methoden |
| **32** | **`entry_point_from_quick_compiled_code_`** | **`uint64_t`** | **PRIMÄRER HOOK-PUNKT** |

**Kritischer Offset: 32 Bytes** — konsistent unter AOSP 14, sollte aber zur Laufzeit validiert werden.

### ART "Quick" Calling Convention (ARM64)

Die ART-interne Aufrufkonvention weicht **erheblich** von Standard-JNI ab:

| Register | Inhalt |
|----------|--------|
| `x0` | `ArtMethod*` — Pointer auf das ArtMethod-Objekt selbst |
| `x1` | Bei Instanzmethoden: `this` (mirror::Object*, NICHT jobject!). Bei statischen Methoden: erstes Argument |
| `x2-x7` | Weitere Argumente der Java-Methode |
| Stack | Overflow-Argumente |

**KRITISCH**: 
- `x1` ist bei Instanzmethoden ein **direkter Heap-Pointer** (`mirror::Object*`), KEINE JNI-Referenz
- Eine Standard-C++-Funktion kann NICHT direkt als Entry-Point dienen
- Es wird eine **Assembly-Bridge** oder `__attribute__((naked))` benötigt
- Für JNI-Calls muss das Heap-Objekt erst in eine `jobject`-Referenz konvertiert werden

### Methoden-Typen und Hook-Strategien

| Typ | Auflösung | Hook-Strategie | Fallstricke |
|-----|-----------|----------------|-------------|
| **Virtual** (getImei) | vtable | Entry-Point im ArtMethod ersetzen | "Sharpening" kann Aufruf hart kodieren → Entry-Point wird umgangen |
| **Static** (getString) | Direkt via invoke-static | Entry-Point ersetzen | Primärziel für **Inlining** durch JIT → Hook wird nie aufgerufen |
| **Interface** | IMT + Conflict-Trampolin | Konkrete Implementierung hooken, NICHT das Interface | IMT-Hook allein wirkungslos |

### Inlining-Problem und Deoptimierung

Wenn eine Methode durch den JIT-Compiler **ge-inlined** wurde, wird der Entry-Point im ArtMethod nie angesprungen. **Lösung**: Deoptimierung der aufrufenden Methoden erzwingen, damit sie den Entry-Point neu laden. LSPlant bietet hierfür die fortschrittlichsten Funktionen.

### Framework-Empfehlung

| Projekt | Android 14 | Eignung für Zygisk | Empfehlung |
|---------|-----------|-------------------|------------|
| **Pine** (canyie) | Sehr gut (bis Android 15 Beta) | **Hervorragend** — minimaler Fußabdruck, präzise ARM64-Register | **TOP-WAHL** |
| **LSPlant** (LSPosed) | Primärfokus Android 11-15 | Sehr gut — beste Inlining-Deoptimierung | **TOP-WAHL** |
| YAHFA | Bis Android 12 stabil | Bedingt — zu unflexibel für neuere ART | Nicht empfohlen |
| SandHook | Stagniert | Mittel — schwer integrierbar | Nicht empfohlen |

**Entscheidung**: Pine ODER LSPlant integrieren. Pine = minimaler Footprint. LSPlant = bessere Deoptimierung.

### Original-Methode aufrufen (Trampolin)

1. Original `entry_point_from_quick_compiled_code_` sichern
2. **Backup-ArtMethod** erstellen: Neues ArtMethod-Objekt allozieren, Original kopieren, eigenen Entry-Point behalten
3. Original via JNI-Call auf Backup-Methode aufrufen → führt originalen Code aus

### Detektions-Vektoren und Gegenmaßnahmen

| Erkennung | Was geprüft wird | Gegenmaßnahme |
|-----------|-----------------|---------------|
| **dladdr()** | Entry-Point zeigt nicht in libart.so/OAT/App-Code sondern in Zygisk-Modul | Code-Cave in existierender .so ODER One-Shot-Hook (sofort restaurieren) |
| **Stack-Trace** | Unerwartete native Frames im Stack | Assembly-Bridge die keinen eigenen Frame erzeugt |
| **Method-Flag kAccNative** | Java-Methode plötzlich als native markiert | Entry-Point-Replacement OHNE Flag-Änderung (Pine/LSPlant machen das korrekt) |
| **Code-Integrität** | Erste Bytes des Maschinencodes gegen Disk-Kopie vergleichen | Entry-Point-Replacement (keine Inline-Modifikation des Codes) |
| **mprotect-Überwachung** | Syscall-Monitor erkennt Speicherschutz-Änderungen | **/proc/self/mem** statt mprotect verwenden |

### One-Shot-Hook Strategie (maximale Stealth)

1. Hook installieren → Entry-Point auf unsere Bridge setzen
2. Beim ersten Aufruf: **sofort Original-Entry-Point wiederherstellen**
3. Spoofed-Wert zurückgeben (oder cachen lassen)
4. Nachfolgende Integritätschecks finden **saubere, unmodifizierte Methode**
5. Funktioniert weil TikTok die Werte nach erstem Read cached

### Code-Skeleton (Zygisk C++)

```cpp
// Entry-Point Offset (Android 14 ARM64, AOSP-verifiziert)
static constexpr size_t kEntryPointOffset = 32;

struct ArtHookInfo {
    uintptr_t artMethodAddr;
    void*     origEntryPoint;
    bool      fired;
};

static ArtHookInfo g_hooks[32];
static int g_hookCount = 0;

static bool installArtHook(JNIEnv* env, const char* className,
                           const char* methodName, const char* sig,
                           void* replacement) {
    jclass clazz = env->FindClass(className);
    if (!clazz) return false;
    
    jmethodID mid = env->GetMethodID(clazz, methodName, sig);
    if (!mid) return false;
    
    uintptr_t artMethod = reinterpret_cast<uintptr_t>(mid);
    void** entryPtr = reinterpret_cast<void**>(artMethod + kEntryPointOffset);
    
    int idx = g_hookCount++;
    g_hooks[idx].artMethodAddr = artMethod;
    g_hooks[idx].origEntryPoint = *entryPtr;
    g_hooks[idx].fired = false;
    
    // Schreibe via /proc/self/mem (kein mprotect!)
    int memFd = open("/proc/self/mem", O_RDWR);
    lseek(memFd, (off_t)(artMethod + kEntryPointOffset), SEEK_SET);
    write(memFd, &replacement, sizeof(void*));
    close(memFd);
    
    return true;
}
```

**ACHTUNG**: Dieses Skeleton ist vereinfacht. Für Produktion wird Pine oder LSPlant benötigt wegen:
- Assembly-Bridge für korrekte Calling Convention
- mirror::Object* → jobject Konvertierung  
- Backup-ArtMethod für Original-Aufruf
- Deoptimierung ge-inlineter Methoden

---

## Research 2: TikTok Detection-Methoden (msaoaidsec / metasec_ml / sscronet)

### Überblick der ByteDance Security-SDKs

| SDK | Aufgabe | Layer |
|-----|---------|-------|
| **msaoaidsec** | Native Integritätsprüfung, Hook-Detektion, Root-Erkennung, Environment-Audit | Native (C++) |
| **metasec_ml** | Verhaltensanalyse via ML, Sensor-Telemetrie, Anomalie-Erkennung | Native + App |
| **sscronet** | Netzwerk-Forensik, TLS-Fingerprinting (JA4), HTTP/2+3-Analyse, WebRTC-Leak | Network |
| **sec_sdk** | Koordination der SDKs | Meta-Layer |
| **libpangle.so** | Ad-SDK mit eigenen Integritätschecks | Native |
| **libapplog.so** | Telemetrie-Aggregation | Native |

### msaoaidsec — Native Integritätsprüfung (HAUPTGEGNER)

#### 1. Funktions-Prolog-Scanning (Inline-Hook-Detektion)

**Was geprüft wird**: Erste Bytes kritischer libc-Funktionen auf Sprung-Instruktionen.

**Geprüfte Funktionen**: `open`, `read`, `write`, `mmap`, `__system_property_get`

**Erkennungsmuster**: msaoaidsec vergleicht Opcodes im Speicher gegen interne Modelle legitimer Prologe. Unser aktuelles Hook-Pattern wird **direkt erkannt**:

```
LDR X16, #8    ← wird als Hook-Signatur erkannt
BR X16
<64-bit addr>
```

**KRITISCHE IMPLIKATION FÜR UNS**: Unsere 18 Inline-Hooks in `zygisk_module.cpp` verwenden genau dieses Pattern! Das ist der wahrscheinlichste Grund für "Too many attempts".

**Gegenmaßnahmen**:
- **Direkte Syscalls** (inline assembly) statt libc-Wrapper → msaoaidsec kann Hooks in libc nicht prüfen, weil sie nie aufgerufen werden
- msaoaidsec prüft gleichzeitig, ob App-eigene Aufrufe die libc-Wrapper nutzen oder verdächtige direkte Syscalls machen → Balanceakt nötig

#### 2. GOT/PLT-Integritätsprüfung

**Was geprüft wird**: Zieladressen in der Global Offset Table gegen `/proc/self/maps`

**Detektionslogik**: Wenn ein GOT-Eintrag (z.B. für `malloc`) auf eine anonyme Speicherregion oder eine verdächtige Library zeigt → Kompromittierung erkannt.

**IMPLIKATION**: PLT-Hooking ist komplett ausgeschlossen. Unsere Inline-Hooks umgehen das, aber die Trampoline in `memfd`-Regionen sind über `/proc/self/maps` sichtbar.

#### 3. Signal-Handler-Monitoring

**Was geprüft wird**: 
- Absichtliches Auslösen von `BRK #0` / illegalen Opcodes → prüft ob Debugger/Hook das Signal abfängt
- `PTRACE_TRACEME` auf eigenen Prozess → wenn fehlschlägt = Debugger aktiv
- **Dedizierter Watchdog-Thread** überwacht `TracerPid` in `/proc/self/status` in Endlosschleife

**IMPLIKATION**: Unsere alte SIGILL-Dispatcher-Methode wäre hier direkt aufgefallen. Gut dass wir gewechselt haben. Aber: msaoaidsec registriert eigene Signal-Handler und prüft deren Integrität.

#### 4. Environment-Audit (Dateisystem-Scan)

**Gescannte Artefakte**:

| Kategorie | Pfade/Artefakte | Methode |
|-----------|----------------|---------|
| **Magisk/KSU** | `/data/adb/modules`, `/data/adb/ksu`, `/sbin/.magisk` | stat, opendir |
| **Binaries** | `su`, `magisk`, `busybox`, `daemonsu` | Pfad-Traversierung |
| **Xposed/LSPosed** | `XposedBridge.jar`, `/data/adb/lspd`, `liblspd.so` | maps + Klassen-Inspektion |
| **Frida** | `re.frida.server`, `frida-agent.so`, Pipes mit "frida" | Socket-Scans, Port-Checks |
| **OverlayFS** | Mount-Optionen in `/proc/mounts`, Inode-Inkonsistenzen | mount-Analyse |

**IMPLIKATION**: SUSFS muss diese Pfade **komplett maskieren**. Aktuell haben wir SUSFS aber nur für den Bridge-File-Pfad konfiguriert.

#### 5. System-Properties Überwachung

| Property | Alarm bei | Unser Status |
|----------|----------|-------------|
| `ro.debuggable` | `1` | Muss `0` sein (resetprop) |
| `ro.secure` | `0` | Muss `1` sein (resetprop) |
| `persist.sys.usb.config` | enthält `adb` | Problematisch wenn ADB aktiv |
| `ro.boot.verifiedbootstate` | `orange` oder `red` | **KRITISCH** — unlocked Bootloader! |

**KRITISCH**: `ro.boot.verifiedbootstate` zeigt unseren entsperrten Bootloader. resetprop kann das überschreiben, aber msaoaidsec könnte auch den Kernel direkt über `/proc/cmdline` oder die Keystore-Attestation abfragen.

#### 6. Zygisk-spezifische Detektion

| Vektor | Was geprüft wird | Unsere Exposure |
|--------|-----------------|-----------------|
| **Fork-Timing** | Verzögerung zwischen fork() und App-Entry | Minimal, aber messbar |
| **File-Deskriptoren** | Offene FDs/Unix-Sockets nach fork (Magisk-Daemon) | SUSFS sollte das maskieren |
| **Anonyme r-x Mappings** | Code in `/proc/self/maps` ohne Datei-Backing | **DIREKT BETROFFEN** — unsere `memfd` Trampolines! |
| **Opcode-Signaturen** | Bekannte Patterns von Dobby, Substrate, Frida in r-x Regionen | Unser Code ist custom, aber das LDR/BR-Pattern ist generisch erkennbar |

#### 7. ArtMethod Entry-Point Validierung (HOCHKRITISCH)

**Was geprüft wird**: `entry_point_from_quick_compiled_code_` für kritische Java-Methoden

**Detektionslogik**:
- Entry-Point muss in `base.odex`/`base.vdex` oder einer geladenen System-Library liegen
- Wenn Entry-Point in **anonymer Speicherregion** oder **beschreibbarem Bereich** → Hook-Alarm
- **Dedizierter Watchdog-Thread** prüft Entry-Points **periodisch** (alle 2-3 Sekunden auf verdächtigen Geräten!)
- Vergleich gegen "Known-Good"-Hash der beim App-Start berechnet wurde
- vtable-Layout-Integrität von Systemklassen
- Detektion von Shadow-Methoden

**KRITISCHE IMPLIKATION**: One-Shot-Hooks allein reichen NICHT wenn der Watchdog den Hook vor dem ersten Aufruf entdeckt! Race Condition: Unser Hook muss VOR dem Watchdog-Thread-Start installiert und idealerweise VOR dem ersten Watchdog-Scan schon wieder restauriert sein.

**Lösungsansatz**: 
1. Hook so FRÜH wie möglich installieren (in `postAppSpecialize`, bevor msaoaidsec seinen Watchdog startet)
2. One-Shot sofort beim ersten Call restaurieren
3. Alternativ: Den Watchdog-Thread selbst neutralisieren (riskant, aber effektiv)

#### 8. /proc/self/maps Real-Time Monitoring

**Was geprüft wird**:

| maps-Spalte | Prüfung |
|-------------|---------|
| **Address Range** | ASLR-Konsistenz |
| **Permissions** | `rwx` Regionen = Shellcode-Indikator |
| **Inode** | Datei-auf-Disk-Manipulation |
| **Pathname** | Suche nach `/data/local/tmp`, `frida`, verdächtige .so-Namen |
| **Fehlender Pathname** | Anonyme r-x Regionen = injizierter Code |

**Scan-Frequenz**: Alle 2-3 Sekunden auf verdächtigen Geräten, seltener auf "sauberen".

**IMPLIKATION FÜR UNSERE TRAMPOLINES**: Unsere `memfd`-Trampolines erscheinen als `memfd:tramp` (oder ähnlich) in `/proc/self/maps`. Das ist ein **direkter Detektor**. Selbst mit einem unauffälligen Namen ist eine `memfd`-Region mit `r-x` Permissions ohne echtes File-Backing verdächtig.

**Lösung**: Code-Cave-Injection in existierende `.text`-Padding-Bereiche von System-Libraries. Dann zeigt der maps-Eintrag auf eine legitime .so-Datei.

### sscronet — Netzwerk-Forensik

#### TLS-Fingerprinting (JA4)

ByteDance nutzt seit 2025 **JA4** statt JA3. Komponenten:
- **JA4_a**: Protokoll-Version, Cipher-Suite-Anzahl, Extension-Anzahl, ALPN
- **JA4_b**: Hash der Cipher-Suites
- **JA4_c**: Hash der Extensions + Signatur-Algorithmen

**IMPLIKATION**: Wenn wir API-Calls über Python/requests machen, ist der TLS-Fingerprint komplett anders als der native TikTok-Client. Für unser Szenario (Spoofing auf dem Gerät selbst) ist das kein Problem, da TikTok seine eigene sscronet-Library für Netzwerk nutzt. Relevant wird es nur wenn wir Server-seitig TikTok-API direkt ansprechen.

#### HTTP/2 + HTTP/3 (QUIC) Priorisierung

sscronet analysiert Stream-Priorisierung und HPACK/QPACK-Tabellen. Ein echter Client folgt striktem Muster. Automatisierte Tools weichen statistisch ab.

#### WebRTC-Leaks & DNS

- **STUN-Anfragen** außerhalb des Proxys → ermittelt echte IP
- **Eigenes DoH** (DNS-over-HTTPS) → verhindert lokale DNS-Manipulation

**IMPLIKATION FÜR UNS**: Weniger relevant für Device-Spoofing, aber kritisch wenn VPN/Proxy genutzt wird.

### metasec_ml — Verhaltensbasierte ML-Erkennung

#### Biometrische Telemetrie

| Datenquelle | Was analysiert wird | Bot-Indikator |
|------------|-------------------|---------------|
| **Touchscreen** | Tipp-Rhythmus, Druckintensität | Gleichmäßige Intervalle |
| **Scroll-Events** | Beschleunigungs-/Abbremskurven | Lineare statt organische Kurven |
| **Gyroskop** | Gerätehaltung und -bewegung | Gerät liegt flach = Farm-Indikator |
| **Accelerometer** | Mikrobewegungen | Keine Variation = Emulator/Farm |

**IMPLIKATION**: Hardware-ID-Spoofing allein reicht langfristig nicht. metasec_ml erkennt Bots über Verhaltensmuster. Für Account-Erstellung müssen wir realistische Touch-/Sensor-Events simulieren oder die Telemetrie neutralisieren.

#### Anomalieerkennung im App-Umfeld

- Häufung von Apps mit **Accessibility Services** = Automatisierungs-Indikator
- Kombination aus Root-Spuren + verdächtige Apps + unnatürliches Verhalten = niedriger Trust-Score
- **Probabilistisches Scoring** — kein einzelner Faktor, sondern die Gesamtheit

### Kryptografische Signaturen (X-Argus, X-Bogus etc.)

| Header | Krypto-Basis | Komplexität | Für uns relevant? |
|--------|-------------|-------------|-------------------|
| **X-Gorgon** | Custom XOR / MD5 | Mittel | Nur bei direkter API-Nutzung |
| **X-Bogus** | RC4 / Custom Base64 | Hoch | Nur bei direkter API-Nutzung |
| **X-Argus** | Simon Cipher / SM3 / Protobuf | Sehr hoch | Nur bei direkter API-Nutzung |
| **X-Ladon** | HMAC-basiert | Hoch | Nur bei direkter API-Nutzung |

**IMPLIKATION**: Da wir auf dem Gerät selbst spoofen und TikTok seine eigenen Krypto-Routinen nutzt, werden diese Signaturen automatisch korrekt generiert — mit unseren gespooften Werten als Input. Kein Handlungsbedarf.

### Zusammenfassung: Bedrohungsmatrix für unser Ghost Protocol

| # | Detektions-Vektor | Unser aktueller Status | Priorität | Lösung |
|---|-------------------|----------------------|-----------|--------|
| 1 | **Inline-Hook Prolog-Scan** (LDR X16/BR X16) | **EXPOSED** — alle 18 nativen Hooks | **P0** | Direkte Syscalls für libc-Funktionen ODER Code-Cave mit polymorphem Prolog |
| 2 | **memfd r-x in /proc/self/maps** | **EXPOSED** — Trampolines sichtbar | **P0** | Code-Cave in System-.so Padding ODER SUSFS maps-Filterung |
| 3 | **ArtMethod Entry-Point Watchdog** | **NICHT BETROFFEN** (noch kein ART-Hooking) — wird P0 wenn wir Pine/LSPlant einbauen | **P1** | One-Shot + Installation VOR msaoaidsec-Init |
| 4 | **Root/KSU-Artefakte** | **TEILWEISE GESCHÜTZT** (SUSFS, aber nicht alle Pfade) | **P1** | SUSFS-Konfiguration erweitern |
| 5 | **ro.boot.verifiedbootstate = orange** | **EXPOSED** | **P1** | resetprop in post-fs-data.sh |
| 6 | **persist.sys.usb.config = adb** | **EXPOSED** während Entwicklung | **P2** | resetprop oder ADB vor App-Start deaktivieren |
| 7 | **Xposed/LSPosed Klasseninspektion** | **EXPOSED** — TelephonyServiceModule.kt | **P0** | Xposed komplett eliminieren (Pine/LSPlant) |
| 8 | **Fork-Timing-Anomalie** | Minimal, schwer zu beheben | **P3** | Akzeptiertes Risiko |
| 9 | **Sensor-Telemetrie (metasec_ml)** | **NICHT ADRESSIERT** | **P2** | Realistische Touch-Simulation oder Telemetrie-Hook |
| 10 | **TLS JA4 Fingerprint** | **NICHT BETROFFEN** (App nutzt eigenes sscronet) | **—** | Kein Handlungsbedarf |

---

## Research 3: Kernel-Level Spoofing — SUSFS, procfs/sysfs, Pro-UID Isolation (Pixel 6)

### SUSFS Architektur-Kernkonzepte

SUSFS arbeitet auf **VFS-Layer** (Virtual File System) direkt im Kernel. Es markiert Inodes mit speziellen Flags, statt bei jedem Zugriff String-Vergleiche durchzuführen.

#### Inode State Flags

| Flag | Bit | Funktion |
|------|-----|----------|
| `INODE_STATE_SUS_PATH` | BIT(24) | Pfad vor nicht-autorisierten Prozessen verbergen |
| `INODE_STATE_SUS_MOUNT` | BIT(25) | Mount-Punkt aus `/proc/self/mounts` filtern |
| `INODE_STATE_SUS_KSTAT` | BIT(26) | `stat()`-Aufrufe mit Fake-Metadaten beantworten |
| `INODE_STATE_OPEN_REDIRECT` | BIT(27) | `open()` transparent auf anderen Pfad umleiten |

### Die 3 SUSFS-Mechanismen (in Prioritätsreihenfolge)

#### 1. `open_redirect` — Transparente Datei-Umleitung (BEVORZUGT)

Leitet `open()`-Syscalls auf Kernel-Ebene um. **Kein Mount-Punkt**, kein Eintrag in `/proc/self/mountinfo`, komplett unsichtbar.

```bash
ksu_susfs add_open_redirect /proc/net/arp /data/adb/ksu/bin/.fake_arp 0
```

**Vorteile**: Kein Mount-Leak, kein Inode-Inkonsistenz-Risiko, performanter als Bind-Mounts.

#### 2. `sus_kstat` — stat()-Metadaten Spoofing

**KRITISCH**: Wenn `/proc/net/arp` (procfs, Inode ≈ 0, Größe = 0) durch `/data/adb/.fake_arp` (ext4/f2fs, hohe Inode-Nr., reale Größe) ersetzt wird, sind die Metadaten **komplett anders**. Apps prüfen das via `stat()`.

`sus_kstat` fängt `stat`, `lstat`, `newfstatat` Syscalls ab und ersetzt die `struct kstat` mit gespeicherten Original-Werten.

**Richtige Reihenfolge**:
```bash
# 1. ZUERST kstat sichern (vor redirect!)
ksu_susfs add_sus_kstat /proc/net/arp
# 2. DANN redirect einrichten
ksu_susfs add_open_redirect /proc/net/arp /data/adb/ksu/bin/.fake_arp 0
# 3. Kstat aktualisieren
ksu_susfs update_sus_kstat /proc/net/arp
```

#### 3. `sus_mount` + Bind-Mount — Fallback

Bind-Mount funktioniert auf procfs/sysfs, erzeugt aber einen Eintrag in der Mount-Tabelle. `add_sus_mount` filtert diesen Eintrag heraus:

```bash
mount --bind /data/adb/.fake_arp /proc/net/arp
ksu_susfs add_sus_mount /proc/net/arp
```

**Nachteile**: Komplexer, leicht inkonsistent bei dynamischem procfs. **`open_redirect` ist bevorzugt.**

### Konkrete Spoofing-Strategien pro Ziel-Datei

| Ziel-Datei | Was Apps daraus lesen | Strategie | Fake-Inhalt |
|-----------|----------------------|-----------|-------------|
| `/proc/net/arp` | ARP-Tabelle → MAC-Adressen im Netzwerk | `open_redirect` + `sus_kstat` | Nur Header-Zeile, keine Daten |
| `/sys/class/net/wlan0/address` | WLAN MAC-Adresse | `open_redirect` + `sus_kstat` | Gespoofed MAC (z.B. `00:a0:c9:14:c8:29`) |
| `/proc/bus/input/devices` | Eingabegeräte → Device-Fingerprint | `open_redirect` + `sus_kstat` | Clean-Dump von unmodifiziertem Pixel 6 |
| `/proc/cpuinfo` | CPU-Info | **Keine Aktion** (bleibt unverändert) | — |
| `/proc/version` | Kernel-Version | **Keine Aktion** (bleibt unverändert) | — |

### Pro-UID Isolation (nur TikTok spoofen)

**Problem**: `open_redirect` wirkt **global** für alle Nicht-Root-Prozesse. Andere Apps sehen ebenfalls die Fake-Daten.

**3 Lösungsansätze** (von einfach bis komplex):

#### Option A: Namespace-basierte Isolation via KernelSU App-Profile

KernelSU kann für jede App einen **separaten Mount-Namespace** erstellen. Bind-Mount nur innerhalb TikToks Namespace:

```bash
# Nur in TikToks Namespace:
mount --bind /data/adb/.fake_arp /proc/net/arp
ksu_susfs add_sus_mount /proc/net/arp  # Mount aus mountinfo filtern
```

**Vorteil**: Keine globale Auswirkung.
**Nachteil**: TikTok könnte `/proc/self/mountinfo` mit `/proc/1/mountinfo` (init) vergleichen — `sus_mount` entschärft das aber.

#### Option B: SUSFS Kernel-Patch modifizieren

In `fs/susfs.c` eine UID-Bedingung einbauen:

```c
uid_t target_uid = 10301; // TikTok
if (current_uid().val == target_uid) {
    if (strcmp(path_name, "/proc/net/arp") == 0) {
        redirect_to_fake_file(path);
    }
}
```

**Vorteil**: Absolut sauber, performant, kernel-intern.
**Nachteil**: Erfordert Custom-Kernel-Build pro UID-Änderung.

#### Option C: Custom procfs-Handler (proc_ops Hooking)

Den `seq_file`-Handler von `/proc/net/arp` direkt im Kernel überschreiben:

```c
// Originaler Handler in net/ipv4/arp.c:
static const struct seq_operations arp_seq_ops = {
    .start = arp_seq_start,
    .next  = arp_seq_next,
    .stop  = arp_seq_stop,
    .show  = arp_seq_show,  // ← hier hooken
};

// Custom Handler:
static int hooked_arp_seq_show(struct seq_file *m, void *v) {
    uid_t uid = from_kuid_munged(current_user_ns(), current_uid());
    if (uid == 10301) { // TikTok
        if (v == SEQ_START_TOKEN)
            seq_puts(m, "IP address       HW type     Flags       HW address            Mask     Device\n");
        return 0;
    }
    return orig_arp_seq_show(m, v);
}
```

**Vorteil**: Perfekte pro-UID Kontrolle, absolut unsichtbar.
**Nachteil**: Erfordert Kernel-Modul oder Kernel-Patch.

**EMPFEHLUNG**: **Option A** (Namespace) für den Anfang, **Option C** als Upgrade wenn nötig.

### Alternative Ansätze (bewertet)

| Ansatz | Eignung | Warum |
|--------|---------|-------|
| **eBPF** | Schlecht | `bpf_probe_write_user` auf Android 14 / Kernel 5.10 stark eingeschränkt |
| **SECCOMP-BPF** (`SECCOMP_RET_USER_NOTIF`) | Mittel | Funktioniert, aber hohe Latenz + SELinux-Probleme + Userspace-Daemon nötig |
| **SUSFS `open_redirect`** | **Exzellent** | Alles im Kernel, kein Mount-Leak, performant |
| **Bind-Mount + `sus_mount`** | Gut | Funktioniert, aber `open_redirect` ist sauberer |
| **procfs-Handler Override** | Exzellent | Perfekte Pro-UID-Kontrolle, aber aufwendiger |

### Vollständiges Boot-Skript (post-fs-data.sh / service.d)

```bash
#!/system/bin/sh
FAKE_DIR="/data/adb/ksu/bin"

# --- Fake-Dateien vorbereiten ---
# ARP: Nur Header, keine Einträge
echo "IP address       HW type     Flags       HW address            Mask     Device" > "$FAKE_DIR/.fake_arp"

# MAC: Gespoofed (wird pro Identity vom Orchestrator geschrieben)
echo "00:a0:c9:14:c8:29" > "$FAKE_DIR/.fake_mac"

# Input Devices: Clean-Dump von Stock Pixel 6 (vorher erstellt)
# cp /path/to/clean_input_dump "$FAKE_DIR/.fake_input"

chmod 644 "$FAKE_DIR"/.*
chown root:root "$FAKE_DIR"/.*

# --- SUSFS: kstat ZUERST (vor redirect!) ---
ksu_susfs add_sus_kstat /proc/net/arp
ksu_susfs add_sus_kstat /sys/class/net/wlan0/address
ksu_susfs add_sus_kstat /proc/bus/input/devices

# --- SUSFS: open_redirect ---
ksu_susfs add_open_redirect /proc/net/arp "$FAKE_DIR/.fake_arp" 1
ksu_susfs add_open_redirect /sys/class/net/wlan0/address "$FAKE_DIR/.fake_mac" 1
ksu_susfs add_open_redirect /proc/bus/input/devices "$FAKE_DIR/.fake_input" 1

# --- SUSFS: Fake-Dateien selbst verstecken ---
ksu_susfs add_sus_path "$FAKE_DIR"

# --- SUSFS: Root-Artefakte verstecken ---
ksu_susfs add_sus_path /data/adb/modules
ksu_susfs add_sus_path /data/adb/ksu
```

### Erkenntnisse für unsere Architektur

| Erkenntnis | Implikation |
|-----------|-------------|
| `open_redirect` funktioniert auf procfs UND sysfs | Wir brauchen **keine** Userspace-Hooks für `/proc/net/arp`, `/sys/class/net/*/address` |
| `sus_kstat` ist **zwingend** nötig bei redirect | Ohne kstat-Spoofing verraten die Metadaten die Manipulation |
| Pro-UID Isolation via KernelSU Namespaces möglich | TikTok kann isoliert gespooft werden ohne andere Apps zu beeinflussen |
| `add_sus_path` versteckt SUSFS-eigene Fake-Dateien | `/data/adb/ksu/bin/.fake_*` wird unsichtbar |
| Kein eBPF nötig | SUSFS deckt alles ab was eBPF könnte, aber besser |
| Boot-Skript-Reihenfolge kritisch | kstat → redirect → sus_path (in dieser Reihenfolge!) |

---

## Research 4: System Properties, resetprop, Telephony RIL & Identifikatoren (Pixel 6 / Android 14)

### resetprop vs. setprop — Fundamentaler Unterschied

| | `setprop` | `resetprop` |
|--|----------|-------------|
| Mechanismus | Anfrage an `property_service` (init) | Direkte Manipulation von `/dev/__properties__` im Memory |
| SELinux | Wird gegen Policy geprüft | **Umgeht** SELinux-Policy |
| `ro.*` Properties | **Blockiert** (read-only) | **Funktioniert** — umgeht In-Memory-Schreibschutz |
| Sichtbarkeit | Normal | Für Userspace-Apps unsichtbar (kein Trace) |

### Property-Kategorien und resetprop-Verhalten

| Kategorie | Beispiel | resetprop zuverlässig? | Persistenz | Besonderheit |
|-----------|---------|----------------------|-----------|-------------|
| `ro.*` | `ro.serialno`, `ro.build.fingerprint` | **Ja** | Bis Reboot (Script in post-fs-data nötig) | Systemdienste cachen früh → Timing kritisch |
| `persist.*` | `persist.sys.timezone` | **Ja** | Überlebt Reboots (Datei in `/data/property/`) | resetprop schreibt auch ins Dateisystem |
| `gsm.*` | `gsm.sim.operator.numeric` | **Ja, ABER wird überschrieben** | Flüchtig — bei jedem Modem-Reset neu | RIL-Daemon überschreibt permanent |
| `sys.*` | `sys.boot_completed` | **Ja** | Flüchtig | Trigger für init-Aktionen |

### gsm.* Properties — RIL-Überschreibungsproblem (KRITISCH)

Der `rild`-Daemon kommuniziert mit dem Exynos-Modem und aktualisiert gsm.* Properties **ereignisbasiert**:

| Property | Update-Trigger | Frequenz |
|----------|---------------|----------|
| `gsm.sim.operator.numeric` | Modem-Init, SIM READY | Bei jedem Modem-Reset |
| `gsm.sim.operator.alpha` | SIM EF-Dateien lesen | Einmalig bei SIM-Start |
| `gsm.operator.numeric` | Zellwechsel, Netzregistrierung | **Bei Bewegung häufig!** |
| `gsm.operator.alpha` | NITZ-Daten, Zell-Broadcasts | Bei Zellwechsel |
| `gsm.sim.state` | SIM einlegen/entfernen, PIN | Physische Änderung |
| `gsm.nitz.time` | Zeit-Update vom Mast | Regelmäßig bei Zellwechsel |
| `gsm.version.ril-impl` | rild-Start | Einmalig |

**Stabile Umgebung** (kein Ortswechsel): `gsm.operator.numeric` wird selten überschrieben.
**Flugmodus-Toggle**: ALLE gsm.* werden innerhalb von Sekunden **mehrfach** neu geschrieben.

### 3 Strategien gegen RIL-Überschreibung

#### Strategie 1: Watchdog-Loop (Einfach, aber nicht perfekt)

```bash
while true; do
    current=$(getprop gsm.sim.operator.numeric)
    if [ "$current" != "26207" ]; then
        resetprop gsm.sim.operator.numeric 26207
        resetprop gsm.operator.numeric 26207
        resetprop gsm.sim.operator.alpha "o2 - de"
        resetprop gsm.operator.alpha "o2 - de"
    fi
    sleep 5
done
```

**Nachteil**: 5-Sekunden-Fenster in dem der echte Wert sichtbar ist. Race Condition.

#### Strategie 2: SELinux Policy-Injection (Elegant)

Dem `rild`-Kontext (`u:r:rild:s0`) die Schreibberechtigung auf bestimmte Property-Typen entziehen:

```bash
# Via KernelSU supolicy
supolicy --live "deny rild gsm_prop:property_service set"
```

rild versucht zu schreiben → `property_service` lehnt ab → AVC Denial im dmesg. Unser resetprop-Wert bleibt intakt.

**Vorteil**: Kein Timing-Problem, kein Watchdog nötig.
**Risiko**: Könnte Telephony-Framework-Fehler verursachen wenn andere Properties auch blockiert werden.

#### Strategie 3: Kernel-Level LSM Hook (Perfekt, aber aufwendig)

KernelSU ermöglicht Hooks über das LSM-Framework direkt im Kernel. Schreibzugriffe von `rild` (PID) auf spezifische Offsets in `/dev/__properties__` blockieren.

**Vorteil**: Komplett transparent für den schreibenden Prozess.
**Nachteil**: Erfordert Custom-Kernel-Code.

**EMPFEHLUNG**: **Strategie 2 (SELinux)** für den Anfang, **Strategie 3** als Upgrade.

### Android ID (SSAID) — Per-App Scoping seit Android 8.0

**BESTÄTIGT**: Seit Android 8.0 ist die Android ID **pro App skoped**.

| Aspekt | Detail |
|--------|--------|
| Scoping | Pro Kombination aus Paketname + Signaturschlüssel + Benutzerprofil |
| Speicherort | `/data/system/users/0/settings_ssaid.xml` |
| `settings put secure android_id <value>` | Ändert nur den **globalen Standardwert**, NICHT den per-App Wert |
| Für TikTok ändern | Eintrag in `settings_ssaid.xml` für `com.zhiliaoapp.musically` direkt editieren |

**IMPLIKATION**: Unser Orchestrator muss den SSAID-Eintrag **per App** in der XML manipulieren, nicht über `settings put`.

### Google Advertising ID (GAID)

| Aspekt | Detail |
|--------|--------|
| Verwaltet von | Google Play Services (GMS) |
| Speicherort | `/data/data/com.google.android.gms/shared_prefs/adid_settings.xml` |
| Reset-Methode | XML-Datei löschen + GMS-Prozess killen → neue UUID wird generiert |

```bash
rm /data/data/com.google.android.gms/shared_prefs/adid_settings.xml
killall com.google.android.gms
```

### Google Services Framework (GSF) ID

| Aspekt | Detail |
|--------|--------|
| Speicherort | `/data/data/com.google.android.gsf/databases/gservices.db` |
| Tabelle/Key | `main` / `android_id` |
| Read | `sqlite3 gservices.db "SELECT value FROM main WHERE name='android_id';"` |
| Write | Direkt via sqlite3 möglich |
| Nebenwirkung | Push-Dienste (FCM) können brechen ohne Server-seitige Re-Registrierung |
| Sauberer Reset | GSF-Daten komplett löschen → bei nächstem Google-Kontakt wird neue ID generiert |

### Build-Properties und Play Integrity

| Property | Zweck | Kritische Punkte |
|----------|-------|-----------------|
| `ro.build.fingerprint` | Geräteidentifikation für Play Integrity | Muss zu einem zertifizierten Gerät passen |
| `ro.build.version.security_patch` | Sicherheitspatch-Level | **Muss chronologisch exakt zum Fingerprint passen** (Google validiert serverseitig) |
| `ro.serialno` / `ro.boot.serialno` | Seriennummer | Per resetprop änderbar, sofort wirksam |
| `ro.boot.verifiedbootstate` | Bootloader-Status | `green` = locked, `orange` = unlocked → **muss auf `green` gespooft werden** |

**Timing-Problem**: Viele Systemdienste (insbesondere GMS) lesen `ro.*` Properties **sehr früh** und cachen sie. resetprop in `post-fs-data.sh` ist daher zwingend (vor GMS-Start).

### Vollständige resetprop-Sequenz für post-fs-data.sh

```bash
#!/system/bin/sh

# --- Bootloader/Verified-Boot Spoofing ---
resetprop ro.boot.verifiedbootstate green
resetprop ro.boot.flash.locked 1
resetprop ro.boot.vbmeta.device_state locked
resetprop ro.debuggable 0
resetprop ro.secure 1

# --- Device Identity (vom Orchestrator dynamisch gesetzt) ---
resetprop ro.serialno "${SPOOFED_SERIAL}"
resetprop ro.boot.serialno "${SPOOFED_SERIAL}"
resetprop ro.build.fingerprint "${SPOOFED_FINGERPRINT}"
resetprop ro.build.version.security_patch "${MATCHING_PATCH_LEVEL}"

# --- ADB verstecken (wenn in Produktion) ---
resetprop persist.sys.usb.config mtp
```

### Erkenntnisse für unsere Architektur

| Erkenntnis | Implikation für Ghost Protocol |
|-----------|-------------------------------|
| `ro.*` Properties sind per resetprop in post-fs-data zuverlässig änderbar | **Xposed-Hooks für Build.SERIAL, Build.FINGERPRINT etc. werden überflüssig** |
| `gsm.*` Properties werden vom RIL überschrieben | SELinux-Policy-Injection oder Watchdog nötig |
| Android ID ist per-App skoped seit Android 8 | Orchestrator muss `settings_ssaid.xml` pro App editieren |
| GAID wird durch Löschen der XML + GMS-Kill resetted | Einfach in den Genesis-Flow integrierbar |
| GSF ID in SQLite-DB direkt manipulierbar | Bereits im Orchestrator vorhanden, Methode bestätigt |
| `ro.boot.verifiedbootstate` muss `green` sein | **Ohne das erkennt msaoaidsec den unlocked Bootloader sofort** |
| Timing ist kritisch — post-fs-data.sh vor GMS-Start | resetprop MUSS im frühesten Boot-Stage laufen |

### Was durch resetprop + SELinux KOMPLETT aus Xposed/Zygisk eliminiert werden kann

| Bisher gehookt in Xposed/Native | Neue Methode | Hook überflüssig? |
|----------------------------------|-------------|-------------------|
| `Build.SERIAL` | `resetprop ro.serialno` | **JA** |
| `Build.FINGERPRINT` | `resetprop ro.build.fingerprint` | **JA** |
| `Build.MODEL`, `Build.MANUFACTURER` etc. | `resetprop ro.product.*` | **JA** |
| `TelephonyManager.getSimOperator()` | `resetprop gsm.sim.operator.numeric` + SELinux-Lock | **JA** |
| `TelephonyManager.getNetworkOperatorName()` | `resetprop gsm.operator.alpha` + SELinux-Lock | **JA** |
| `Settings.Secure.getString(ANDROID_ID)` | `settings_ssaid.xml` pro App editieren | **JA** |
| `AdvertisingIdClient.getAdvertisingIdInfo()` | GAID XML löschen + GMS kill | **JA** |
| `TelephonyManager.getImei()` | **NEIN — kein Property, kommt direkt vom Modem via Binder** | **NEIN — Hook weiterhin nötig** |
| `TelephonyManager.getSubscriberId()` | **NEIN — direkte Modem-Abfrage** | **NEIN — Hook weiterhin nötig** |
| `Settings.Secure.getString(content://...)` (GSF ID) | SQLite direkt | **JA** |
| `WifiInfo.getMacAddress()` | SUSFS `open_redirect` + ggf. ART-Hook | **TEILWEISE** |

---

## Research 5: Kernel-Level MAC-Spoofing — WiFi & Bluetooth (Pixel 6 / bcmdhd / Android 14)

### Schlüssel-Erkenntnis: `ip link set` funktioniert NICHT persistent auf Pixel 6

Der `bcmdhd`-Treiber (Broadcom bcm4389) **lädt die MAC bei jedem Interface-Up aus der Persist-Partition oder dem NVRAM neu**. Die Sequenz `ip link set wlan0 down && ip link set wlan0 address XX:XX && ip link set wlan0 up` wird innerhalb von Sekunden überschrieben weil:

1. bcmdhd validiert die MAC bei jedem "Interface Up" gegen Firmware/NVRAM
2. Android WiFi-Stack de-/reaktiviert das Interface regelmäßig (Scans, Reconnects)
3. WiFi-HAL fragt beim Start die "Factory MAC" ab und nutzt diese als Referenz
4. Kernel 5.10 hat Schutzmechanismen gegen direkte `net_device->dev_addr` Schreibzugriffe

**LÖSUNG**: SUSFS `open_redirect` auf die **Hardware-Quelldateien** in der Persist-Partition.

### Hardware-Identitäts-Dateien auf dem Pixel 6 (Oriole)

| Identifikator | Dateipfad | Format |
|--------------|-----------|--------|
| **WiFi MAC** | `/mnt/vendor/persist/wlan/macaddr0` | Hex-String (ASCII) |
| **Bluetooth BD_ADDR** | `/mnt/vendor/persist/bluetooth/bt_addr` | Binär (6 Bytes) oder Hex-String |
| WiFi-Kalibrierung | `/mnt/vendor/persist/wlan/bcm_cal.bin` | Binärer Blob |
| NVRAM-Overrides | `/vendor/firmware/bcmdhd.cal` | Text/Key-Value |

**KRITISCH**: Die Persist-Partition (`/mnt/vendor/persist`) ist read-only und enthält Produktions-Kalibrierungsdaten. Fehlende/korrupte Dateien können dazu führen, dass WiFi **komplett nicht startet** (PCIe-Bus-Init schlägt fehl).

### SUSFS-basiertes MAC-Spoofing (die einzig zuverlässige Methode)

#### Warum SUSFS die einzige Lösung ist

```
Treiber-Init → liest /mnt/vendor/persist/wlan/macaddr0
                         ↓
              SUSFS open_redirect fängt ab
                         ↓
              liefert /data/adb/mac_spoof/wifi_mac_fake
                         ↓
              bcmdhd registriert Interface mit Fake-MAC
                         ↓
              net_device->dev_addr = Fake-MAC
                         ↓
              ALLE APIs lesen automatisch Fake-MAC:
              - /sys/class/net/wlan0/address ✓
              - ioctl(SIOCGIFHWADDR) ✓
              - /proc/net/arp ✓
              - WifiInfo.getMacAddress() ✓
              - getifaddrs() ✓
```

Da die Manipulation **an der Quelle** ansetzt (Persist-Partition), propagiert der Fake-Wert **automatisch durch den gesamten Stack**. Kein einziger Userspace-Hook nötig.

#### Implementierung in post-fs-data.sh

```bash
#!/system/bin/sh
SUSFS="/data/adb/ksu/bin/ksu_susfs"
SPOOF_DIR="/data/adb/mac_spoof"

mkdir -p "$SPOOF_DIR"

# --- WiFi MAC (ASCII Hex ohne Trenner, wie bcmdhd es erwartet) ---
echo -n "001122334455" > "$SPOOF_DIR/wifi_mac_fake"

# --- Bluetooth MAC (Hex-String mit Doppelpunkten) ---
echo -n "00:11:22:33:44:55" > "$SPOOF_DIR/bt_mac_fake"

chmod 644 "$SPOOF_DIR"/*
chown root:root "$SPOOF_DIR"/*

# --- SUSFS: Persist-Partition Quelldateien umleiten ---
$SUSFS add_open_redirect /mnt/vendor/persist/wlan/macaddr0 "$SPOOF_DIR/wifi_mac_fake" 0
$SUSFS add_open_redirect /mnt/vendor/persist/bluetooth/bt_addr "$SPOOF_DIR/bt_mac_fake" 0

# --- SUSFS: sysfs als Backup (falls Treiber dev_addr nach Init überschreibt) ---
# Formatiert mit Doppelpunkten für sysfs-Kompatibilität
echo "00:11:22:33:44:55" > "$SPOOF_DIR/wifi_mac_formatted"
$SUSFS add_open_redirect /sys/class/net/wlan0/address "$SPOOF_DIR/wifi_mac_formatted" 0

# --- Spoof-Dateien selbst verstecken ---
$SUSFS add_sus_path "$SPOOF_DIR"
```

**TIMING**: MUSS in `post-fs-data.sh` laufen — **vor** Treiber-Initialisierung und vor Zygote-Start.

### WiFi MAC-Randomisierung deaktivieren

Android 14 randomisiert die MAC pro SSID standardmäßig. Die Randomisierung basiert auf:

$$MAC_{random} = LAA\_Bit\_Set(Hash(SSID, MAC_{factory}, Secret))$$

Da wir `MAC_factory` auf Kernel-Ebene manipulieren, ändert sich auch der randomisierte Wert. Um **absolute Konsistenz** zu garantieren, muss die Randomisierung deaktiviert werden:

```bash
# In service.sh (nach system_server Start):
settings put global wifi_connected_mac_randomization_enabled 0
settings put global wifi_scan_always_enabled 0
```

### Bluetooth: BLE Privacy Addresses (IRK)

**Oft übersehen**: Selbst nach MAC-Änderung können **gekoppelte Geräte** das Smartphone über den Identity Resolving Key (IRK) identifizieren. RPAs (Random Private Addresses) rotieren alle 15 Minuten, werden aber aus dem IRK berechnet.

**Vollständige Anonymisierung erfordert**:
1. Persist-Partition MAC ändern (SUSFS) ✓
2. **Pairing-Informationen löschen**: `/data/misc/bluetooth/` komplett leeren
3. Stack generiert neuen IRK basierend auf neuer Identität

### Auswirkung auf ARP-Tabelle

Wenn die MAC auf **net_device-Ebene** (via Persist-Redirect) korrekt gesetzt ist:
- `/proc/net/arp` reflektiert automatisch die Fake-MAC für lokale Einträge
- **Separater ARP-Redirect ist theoretisch nicht mehr nötig** für die eigene MAC
- ABER: ARP zeigt auch MACs **anderer Geräte** im Netzwerk → für vollständige Stealth trotzdem SUSFS-Redirect auf leere Tabelle beibehalten

### Vergleich WiFi vs. Bluetooth

| Feature | WiFi (wlan0) | Bluetooth (hci0) |
|---------|-------------|-----------------|
| Primärer Identifikator | MAC-Adresse | BD_ADDR |
| Kernel-Struktur | `struct net_device` | `struct hci_dev` |
| Persist-Pfad | `/mnt/vendor/persist/wlan/macaddr0` | `/mnt/vendor/persist/bluetooth/bt_addr` |
| Java-API | `WifiInfo.getMacAddress()` | `BluetoothAdapter.getAddress()` |
| Nach Reboot | Aus Persist/NVRAM geladen | Aus Persist geladen |
| SUSFS-Redirect nötig | **Ja** — auf Persist-Datei | **Ja** — auf Persist-Datei |
| Zusätzliche Cleanup | MAC-Randomisierung deaktivieren | Pairing-Daten + IRK löschen |

### Validierung nach Implementierung

| Methode | Erwartetes Ergebnis | Prüft |
|---------|-------------------|-------|
| `ip link show wlan0` | Fake-MAC unter `link/ether` | Kernel net_device |
| `cat /sys/class/net/wlan0/address` | Fake-MAC | sysfs-Konsistenz |
| `cat /proc/net/arp` | Fake-MAC für eigene Einträge | procfs-Konsistenz |
| `dumpsys wifi` | Fake-MAC | Framework-Übernahme |
| `dumpsys bluetooth_manager` | Fake-BD_ADDR | BT-Stack-Übernahme |
| `getprop persist.vendor.service.bdaddr` | Fake-BD_ADDR | Property-Ebene |

### Nebenwirkungen beachten

| Effekt | Beschreibung | Handlung |
|--------|-------------|---------|
| **DHCP-Lease** | Router sieht neues Gerät → neue IP | Erwartet, kein Problem |
| **WiFi Saved Networks** | Randomisierte MACs ändern sich (anderer Factory-Seed) | Netzwerke neu verbinden |
| **BT Paired Devices** | Alle Pairings ungültig nach BD_ADDR-Änderung | Erwartet, Teil des Genesis-Flow |
| **dm-verity** | SUSFS umgeht dm-verity da keine physische Partition geändert wird | ✓ Kein Problem |

### Erkenntnisse für unsere Architektur

| Erkenntnis | Implikation |
|-----------|-------------|
| `ip link set` ist auf Pixel 6 **nicht persistent** | Bestätigt: Userspace-Methoden funktionieren nicht |
| SUSFS auf Persist-Partition ist die **einzige zuverlässige Methode** | Alle MAC-relevanten Hooks in Zygisk werden überflüssig |
| Fake-MAC propagiert automatisch durch gesamten Stack | `getifaddrs()` Hook, `ioctl` Hook, sysfs-Read Hook → **ALLE ÜBERFLÜSSIG** |
| WiFi-Randomisierung muss deaktiviert werden | `settings put global` in service.sh |
| BT Pairing-Daten müssen bei Identity-Wechsel gelöscht werden | In Genesis-Flow integrieren |
| Timing: post-fs-data.sh MUSS vor Treiber-Init laufen | SUSFS-Redirect vor WiFi/BT-Initialisierung |

---

## Research 6: LSPlant/Pine Integration in Zygisk-Module (C++/NDK)

### Build-Integration (CMake)

LSPlant als **statische Library** einbinden (kein Shared Object im Dateisystem = weniger Detektionsfläche):

```cmake
set(LSPLANT_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/external/lsplant)
set(LSPLANT_BUILD_SHARED OFF CACHE BOOL "" FORCE)
add_subdirectory(${LSPLANT_ROOT} lsplant_build)

target_include_directories(my_zygisk_mod PRIVATE ${LSPLANT_ROOT}/include)
target_link_libraries(my_zygisk_mod lsplant android log)
target_compile_options(my_zygisk_mod PRIVATE -fvisibility=hidden)
```

**Kritisch**: Zygisk-Module brauchen eine spezielle leichtgewichtige libc++ um Kollisionen mit der System-libc++ in Zygote zu vermeiden. Das offizielle Zygisk-Template enthält diese.

### Initialisierung

LSPlant muss **einmalig** initialisiert werden bevor Hooks installiert werden. Zwei Optionen:

| Zeitpunkt | Code | Vorteil |
|-----------|------|---------|
| `JNI_OnLoad` | `lsplant::Init(env, info)` | Frühestmöglich, Symbole aus libart.so werden aufgelöst |
| `postAppSpecialize` | `lsplant::Init(env, info)` | Pro-App, aber JNIEnv* direkt verfügbar |

**Empfehlung**: Init in `postAppSpecialize` (wird pro App-Fork aufgerufen, sauberer Lifecycle).

### Hook-Installation (konkretes Codebeispiel)

LSPlant arbeitet mit **Reflection-Objekten** (jobject von java.lang.reflect.Method), nicht mit jmethodID:

```cpp
void setup_hooks(JNIEnv *env) {
    jclass tmClass = env->FindClass("android/telephony/TelephonyManager");
    jmethodID getImeiID = env->GetMethodID(tmClass, "getImei", "()Ljava/lang/String;");
    
    // Konvertierung jmethodID -> java.lang.reflect.Method
    jobject getImeiMethod = env->ToReflectedMethod(tmClass, getImeiID, JNI_FALSE);
    
    // LSPlant Hook (braucht hooker_object + callback_method)
    jobject backup = lsplant::Hook(env, getImeiMethod, hooker_object, callback_method);
    // backup = Referenz auf Original-Methode fuer spaetere Aufrufe
}
```

**WICHTIG**: LSPlant erwartet einen **Java-Callback** mit Signatur `public Object callback(Object... args)`. Da wir aus C++ arbeiten, muessen wir:
1. Eine Java-Hilfsklasse mit nativer Methode als Callback registrieren, ODER
2. LSPlant-interne Mechanismen nutzen um den Aufruf nativ zu routen

### Rueckgabewerte (jstring / jbyteArray)

```cpp
// getImei() -> String
jobject fake_getImei(JNIEnv *env, jobject thiz, jobjectArray args) {
    return (jobject)env->NewStringUTF("358241000000000");
}

// MediaDrm.getPropertyByteArray() -> byte[]
jobject fake_getWidevineId(JNIEnv *env, jobject thiz, jobjectArray args) {
    jbyteArray arr = env->NewByteArray(32);
    jbyte data[32] = { /* spoofed bytes */ };
    env->SetByteArrayRegion(arr, 0, 32, data);
    return (jobject)arr;
}
```

**Keine Besonderheiten** bei der ART Quick Calling Convention fuer den Entwickler — LSPlant abstrahiert den Uebergang. Aber: **Primitive Rueckgabewerte** (boolean, int) muessen in Java-Wrapper geboxt werden (java.lang.Boolean etc.), da die Callback-Signatur auf Object basiert.

### One-Shot Pattern

```cpp
static std::atomic<bool> g_imeiHooked{true};
static jobject g_imeiBackup = nullptr; // Backup der Original-Methode

jobject oneshot_getImei(JNIEnv *env, jobject thiz, jobjectArray args) {
    if (g_imeiHooked.exchange(false)) {
        // Ersten Aufruf: Hook entfernen
        lsplant::UnHook(env, getImeiMethod);
    }
    // Immer den gespooften Wert zurueckgeben (auch beim ersten Call)
    return (jobject)env->NewStringUTF(g_spoofedImei);
}
```

**Thread-Sicherheit**: LSPlant ist thread-safe fuer verschiedene Methoden. Hook + UnHook auf **dieselbe** Methode gleichzeitig ist **undefiniert** → `std::atomic<bool>` als Guard verwenden. Backup-Methode **vor** UnHook sichern.

### Deoptimierung (Anti-Inlining)

LSPlant bietet `lsplant::Deoptimize(env, method)`:

| Strategie | Wann | Effektivitaet |
|-----------|------|--------------|
| Callee deoptimieren | `Deoptimize(env, getImeiMethod)` | Oft nicht ausreichend |
| **Caller deoptimieren** | Aufrufer-Klassen im SDK identifizieren, deren Methoden deoptimieren | **Empfohlen** |
| Globale Deoptimierung | Interpreter-Modus fuer gesamten Prozess | 100% aber massive Performance-Degradierung |

**Fuer TikTok**: Selektive Deoptimierung der aufrufenden Klassen innerhalb von msaoaidsec/metasec.

### Pine als Alternative

| Aspekt | LSPlant | Pine |
|--------|---------|------|
| Hidden-API-Bypass | Braucht FreeReflection oder eigene Loesung | **Integriert** |
| Deoptimierung | Explizite API | Weniger dokumentiert |
| ARM64-Optimierung | Gut | **Sehr gut** (Fokus auf ARM64) |
| Android 14+ Support | Bis Android 15 | Bis Android 15 Beta |
| CMake-Integration | Komplex (viele Deps) | Einfacher (weniger Deps) |
| Footprint | Mittel | **Kleiner** |

**Entscheidung**: Mit LSPlant starten (bessere Deoptimierung). Falls Build-Probleme → Pine als Fallback.

### Pixel 6 Spezifika: PAC (Pointer Authentication)

Android 14 auf Pixel 6 nutzt **PAC-Instruktionen** (paciasp, retaa) in ART-Binaries. Hooking-Engines muessen PAC-Signaturen korrekt handhaben. LSPlant und Pine unterstuetzen PAC seit Android 12. Trotzdem: **Testen auf dem Geraet**, da falsche PAC-Behandlung sofort zu SIGSEGV fuehrt.

---

## Research 7: SUSFS Befehlsreferenz (Revision 25+) und Boot-Timing

### Vollstaendige Befehlsreferenz (ksu_susfs, Stand 2025/2026)

| Befehl | Syntax | Funktion |
|--------|--------|----------|
| **add_sus_path** | `ksu_susfs add_sus_path <Pfad>` | Pfad fuer nicht-root Prozesse unsichtbar machen |
| **add_sus_mount** | `ksu_susfs add_sus_mount <Pfad>` | Mount-Punkt aus /proc/self/mounts + mountinfo filtern |
| **add_sus_kstat** | `ksu_susfs add_sus_kstat <Pfad>` | Metadaten-Faelschung aktivieren, aktuellen Zustand speichern |
| **add_sus_kstat_statically** | `ksu_susfs add_sus_kstat_statically <Pfad> <Ino> <Dev>` | Manuelle Inode/Device-ID Vorgabe |
| **update_sus_kstat** | `ksu_susfs update_sus_kstat <Pfad>` | Gespeicherte Metadaten aktualisieren (NACH Redirect/Mount!) |
| **add_open_redirect** | `ksu_susfs add_open_redirect <Source> <Target>` | open()-Aufrufe transparent umleiten |
| **add_try_umount** | `ksu_susfs add_try_umount <Pfad>` | Mount-Punkt bei Zygote-Fork automatisch aushaengen |
| **add_sus_map** | `ksu_susfs add_sus_map <Pfad>` | **NEU in v1.5.12+**: Eintraege aus /proc/pid/maps filtern |
| **sus_su** | `ksu_susfs sus_su <Mode>` | su-Binary Zugriffsmodus (Mode 2 = maximale Tarnung) |
| **set_sdcard_root_path** | `ksu_susfs set_sdcard_root_path /sdcard` | SD-Karten-Root fuer Isolation setzen |

### KRITISCHE NEUENTDECKUNG: `add_sus_map`

**add_sus_map** kann Eintraege aus `/proc/<pid>/maps`, `smaps`, `smaps_rollup` und `map_files` filtern! Das aendert unsere Strategie fundamental:

- Wirkt auf Mappings die mit einem **Dateipfad** verknuepft sind
- **EINSCHRAENKUNG**: Kann **keine rein anonymen Speicherregionen** verstecken
- memfd-Mappings liegen im shmem-Bereich ohne permanenten Pfadnamen → pfadbasierte Filter greifen **moeglicherweise nicht**
- Wenn msaoaidsec nach anonymen r-x Regionen sucht die nicht zu bekannten System-Libraries gehoeren, bleibt dies ein Vektor

**Loesung**: Eigene Library laden (mit unauffaelligem Pfad wie `/system/lib64/libcompat_core.so`), Trampolines dort platzieren, dann:
1. `add_sus_map` um den maps-Eintrag sauber zu halten
2. `add_open_redirect` um die physische .so auf dem Dateisystem zu tarnen

### Pro-UID Filterung

**SUSFS Rev. 25 hat KEINE pro-UID Befehle.** Die Filterung unterscheidet nur zwischen:
- SU-Prozesse (UID 0 / KernelSU Root-Kontext) → sehen alles
- Nicht-Root-Prozesse → sehen gefilterte Sicht

Konfiguration: `hide_sus_mnts_for_all_or_non_su_procs` steuert ob Mounts fuer **alle** oder nur fuer **nicht-root** Prozesse versteckt werden.

### Boot-Timing auf Pixel 6 (Tensor GS101, Kernel 5.10)

```
1. Early-Init + post-fs     → Partitionen mounten, Sensor-Kalibrierung
2. post-fs-data             → KernelSU Skripte (HIER unsere SUSFS-Befehle!) ★
3. on boot / vendor.ready   → WiFi-HAL + bcmdhd Firmware laden (liest macaddr0)
4. on boot                  → Bluetooth-HAL Start (liest bt_addr)
5. Zygote Start             → App-Prozesse forken
6. system_server            → Framework initialisieren
```

**BESTAETIGT**: `post-fs-data.sh` laeuft **VOR** WiFi/BT-Treiber-Initialisierung auf Pixel 6. SUSFS-Redirects auf `/mnt/vendor/persist/wlan/macaddr0` sind rechtzeitig aktiv.

**Fallback** (falls ein Treiber extrem frueh im Kernel-Built-in laedt): Statische Pfadlisten in SUSFS-Kernel-Config. Fuer 99% der Faelle auf Pixel 6 ist `post-fs-data.sh` ausreichend.

### sus_kstat: Welche Felder werden gefaelscht?

| stat-Feld | Gefaelscht? | Beschreibung |
|-----------|------------|-------------|
| `st_ino` | **Ja** | Inode-Nummer der Original-Datei |
| `st_dev` | **Ja** | Device-ID der Original-Partition |
| `st_size` | **Ja** (optional) | Groesse der Original-Datei |
| `st_mtime` | **Ja** | Modifikationszeitpunkt |
| `st_atime` | **Ja** | Zugriffszeitpunkt |
| `st_ctime` | **Ja** | Statusaenderungszeitpunkt |
| `st_mode` | **Ja** | Berechtigungen und Dateityp |

**Workflow**: `add_sus_kstat` → Modifikation (redirect/mount) → `update_sus_kstat` (ZWINGEND nach Aenderung!)

### SELinux-Kontext bei Persist-Redirect

**WARNUNG**: Wenn `/mnt/vendor/persist/wlan/macaddr0` (SELinux-Typ: `persist_file`) auf `/data/adb/fake_mac` (Typ: `system_data_file`) umgeleitet wird, kann der WiFi-HAL den Zugriff durch SELinux-Denial verlieren.

**Loesung**: Eigene `sepolicy.rule` im KernelSU-Modul:
```
allow hal_wifi_default system_data_file:file { read open getattr };
```
Oder die Fake-Datei korrekt labeln:
```bash
chcon u:object_r:persist_file:s0 /data/adb/ksu/bin/.fake_wifi_persist
```

### Code-Cave vs. SUSFS Maps-Filter: Finale Bewertung

| Kriterium | Code-Cave | SUSFS add_sus_map |
|-----------|-----------|-------------------|
| Komplexitaet | **Sehr hoch** (ELF-Parsing, Padding finden) | **Niedrig** (ein Befehl) |
| maps-Sichtbarkeit | Keine Anomalie (zeigt auf legitime .so) | Eintrag wird gefiltert, aber "Ghost Mapping" moeglich |
| Platz fuer Code | Begrenzt (Padding-Groesse) | Unbegrenzt |
| msaoaidsec-Resistenz | **Exzellent** | **Gut** (aber "Luecken" im Adressraum koennen auffallen) |
| Empfehlung | Fuer die 3-4 nativen Hooks | Als Fallback wenn Code-Caves nicht reichen |

**FINALE STRATEGIE**: Hybrid-Ansatz:
1. Eigene Library mit unauffaelligem Namen laden (z.B. als `/system/lib64/libsurfacecontrol.so`)
2. `add_open_redirect` auf den Pfad damit Checksummen-Vergleich gegen Disk fehlschlaegt
3. `add_sus_map` als zusaetzliche Absicherung
4. Code-Caves in dieser Library fuer die wenigen Trampolines nutzen

---

## Research 8: LSPosed-Elimination und Artefakt-Bereinigung

### Deinstallations-Checkliste

| Schritt | Befehl / Aktion | Was wird entfernt |
|---------|----------------|-------------------|
| 1 | KSU Manager → LSPosed deaktivieren + loeschen | Modul-Dateien in `/data/adb/modules/zygisk_lsposed/` |
| 2 | `rm -rf /data/adb/lspd/` | **KRITISCH**: Datenbanken, Logs, Caches, Modul-Konfig |
| 3 | `rm -rf /data/adb/lspd/config/` | Modulspezifische Einstellungen |
| 4 | `rm -rf /data/adb/lspd/bin/` | Hilfsprogramme |
| 5 | LSPosed Manager APK deinstallieren | `org.lsposed.manager` Paket |
| 6 | System-UI Cache leeren | Benachrichtigungs-Reste |
| 7 | **Reboot** | Handles auf geloeschte Dateien in /proc bereinigen |

### Artefakte die msaoaidsec sucht

| Vektor | Artefakt | Bereinigung |
|--------|---------|-------------|
| Datei-Praesenz | `/data/adb/lspd/` | rm -rf (Schritt 2) |
| Datei-Praesenz | `/data/local/tmp/lsposed` | rm -rf |
| Memory Maps | `liblsposed.so` in /proc/self/maps | Reboot (Schritt 7) |
| System Properties | `ro.lsposed.manager_app` | Wird zur Laufzeit gesetzt, nach Reboot weg |
| Paketname | `org.lsposed.manager` | APK deinstallieren (Schritt 5) |
| Klassen im Speicher | `de.robv.android.xposed.XposedBridge` | Reboot (Schritt 7) |

**Nach sauberer Deinstallation + Reboot**: Keine LSPosed-Spuren mehr sichtbar.

### Zygisk postAppSpecialize fuer ALLE Apps

**BESTAETIGT**: `postAppSpecialize` wird fuer **jeden** neuen App-Prozess aufgerufen. Das Modul kann intern eine Whitelist fuehren:

```cpp
static const char* TARGET_APPS[] = {
    "com.zhiliaoapp.musically",
    "com.ss.android.ugc.trill",
    "com.instagram.android",
    "com.snapchat.android",
    nullptr
};

void postAppSpecialize(const AppSpecializeArgs *args) override {
    const char *name = env->GetStringUTFChars(args->nice_name, nullptr);
    if (is_target(name, TARGET_APPS)) {
        lsplant::Init(env, info);
        apply_hooks(env);
    }
}
```

Dies simuliert exakt das LSPosed-Scope-System, aber **ohne** externe Datenbank oder IPC.

### SUSFS + LSPlant Koexistenz

**BESTAETIGT: Keine Konflikte.** SUSFS operiert auf Kernel/VFS-Ebene, LSPlant auf ART-Objekt-Ebene. SUSFS-Regeln sind aktiv **bevor** Zygote forkt → LSPlant sieht bereits das manipulierte Dateisystem.

### Shamiko + LSPlant Koexistenz

- Shamiko versteckt **Infrastruktur** (Modul-Dateien, Zygisk-Injection)
- LSPlant-Hooks im Speicher (manipulierte ArtMethod Entry-Points) werden von Shamiko **NICHT** versteckt
- Das Modul selbst muss One-Shot-Hooks oder andere Stealth-Techniken nutzen
- **Kein Konflikt** zwischen Shamiko Namespace-Cloning und SUSFS open_redirect (SUSFS-Flags werden vererbt)

### Rollback-Strategie

1. **Vor Migration**: `/data/adb/lspd/` komplett sichern
2. **Parallelbetrieb** moeglich: LSPosed aktiv lassen, aber Ziel-App aus LSPosed-Scope entfernen → natives Modul uebernimmt
3. **Notfall-Rollback**: LSPosed-Modul + Datenbank wiederherstellen, natives Modul im KSU Manager deaktivieren, reboot

---

## Implementierungs-Entscheidungen (FINALISIERT nach allen 8 Research-Results)

### FINALE Entscheidungen (alle 8 Researches konsolidiert):

| Entscheidung | Wahl | Begründung |
|-------------|------|-----------|
| ART-Hook-Framework | **Pine oder LSPlant** (nicht selbst implementieren) | Calling Convention, Deoptimierung und Backup-Methoden sind zu komplex für Eigenimplementierung |
| Entry-Point Offset | **32 Bytes** (Runtime-Validierung) | AOSP 14 verifiziert, aber Offset zur Laufzeit bestätigen |
| Speicherschreibmethode | **/proc/self/mem** | Kein mprotect → kein Syscall-Monitor-Alarm |
| Hook-Persistenz | **One-Shot für cacheable Werte** | getImei, getSubscriberId etc. werden gecached → nach erstem Call restaurieren |
| Hook-Persistenz | **Permanent für dynamische Werte** | ContentResolver.query (GSF ID) muss bei jedem Call intercepted werden |
| Xposed-Elimination | **Ja, komplett** | Pine/LSPlant ersetzt XposedBridge vollständig im nativen Zygisk-Code |

### Zusaetzliche Entscheidungen nach Research 2-8:

| Entscheidung | Wahl | Begründung |
|-------------|------|-----------|
| ART-Hook-Framework | **LSPlant** (Pine als Fallback) | Bessere Deoptimierung, PAC-Support, statische Verlinkung moeglich (R6+R8) |
| Trampolines | **Hybrid: Eigene .so mit add_sus_map + add_open_redirect** | Code-Caves zu komplex; add_sus_map filtert maps-Eintraege; open_redirect tarnt Disk-Checksumme (R7) |
| ART-Hook Timing | **Installation in postAppSpecialize VOR msaoaidsec Watchdog-Init** | Periodischer Watchdog prüft Entry-Points alle 2-3s (R2) |
| Xposed-Elimination | **BESTÄTIGT: P0 KRITISCH** | msaoaidsec scannt nach LSPosed-Artefakten (R2+R8) |
| LSPosed-Deinstallation | **Komplett entfernen + /data/adb/lspd/ loeschen + Reboot** | Alle Artefakte muessen weg (R8) |
| System Properties | **resetprop in post-fs-data.sh** | verifiedbootstate, debuggable, secure, serialno, fingerprint (R4) |
| SUSFS maps-Filter | **add_sus_map fuer injizierte Libraries** | Filtert /proc/pid/maps Eintraege (R7) |
| SUSFS Persist-Redirect | **add_open_redirect auf macaddr0 + bt_addr** | Timing bestaetigt: post-fs-data vor WiFi/BT-HAL (R7) |
| SELinux fuer Redirect | **chcon persist_file auf Fake-Dateien ODER sepolicy.rule** | WiFi-HAL braucht persist_file Kontext (R7) |
| gsm.* Schutz | **SELinux deny rild + Watchdog als Backup** | RIL ueberschreibt bei Modem-Reset (R4) |
| SUSFS-Pfade | **Erweitern: /data/adb/modules, /data/adb/ksu, /data/adb/lspd** | msaoaidsec scannt alle (R2+R8) |
| Rollback-Strategie | **LSPosed-Backup behalten, Parallelbetrieb moeglich** | Scope entfernen statt deinstallieren waehrend Entwicklung (R8) |

### Offene Fragen (abhängig von Research 3-5):

- [x] Welche konkreten Checks macht msaoaidsec? → **BEANTWORTET** (Research 2): Prolog-Scan, GOT/PLT, Signal-Handler, ptrace, /proc/self/maps, ArtMethod Entry-Points, Environment-Audit
- [x] Funktioniert `ip link set` für MAC auf Pixel 6? → **NEIN, nicht persistent** (Research 5): bcmdhd-Treiber überschreibt bei jedem Interface-Up. **SUSFS `open_redirect` auf `/mnt/vendor/persist/wlan/macaddr0` ist die einzige Lösung.**
- [x] Kann SUSFS auf /proc bind-mounten? → **JA** (Research 3): Bind-Mounts funktionieren, aber `open_redirect` ist **bevorzugt** (kein Mount-Leak, keine Mount-Tabellen-Einträge)
- [x] Werden gsm.* Properties vom RIL überschrieben? → **JA** (Research 4): rild überschreibt bei Modem-Reset, Zellwechsel, Flugmodus. Lösung: SELinux-Policy deny oder Watchdog-Loop.
- [x] Ist android_id per-app scoped seit Android 8? → **JA** (Research 4): SSAID ist pro App+Signatur+User skoped. Globaler `settings put` ändert nur Default. Muss pro App in `settings_ssaid.xml` geändert werden.

---

## FINALE SYNTHESE: Ghost Protocol Implementierungs-Blueprint

> Alle 5 Research-Ergebnisse konsolidiert. Dies ist die definitive Referenz für die Implementierung.

### Die neue Architektur in einem Bild

```
┌─────────────────────────────────────────────────────────────────┐
│                    BOOT-PHASE (post-fs-data.sh)                 │
│                                                                 │
│  resetprop ro.boot.verifiedbootstate green                      │
│  resetprop ro.serialno / ro.build.fingerprint / ro.product.*    │
│  resetprop gsm.sim.operator.* + SELinux deny rild               │
│                                                                 │
│  SUSFS open_redirect:                                           │
│    /mnt/vendor/persist/wlan/macaddr0 → fake WiFi MAC            │
│    /mnt/vendor/persist/bluetooth/bt_addr → fake BT MAC          │
│    /proc/net/arp → leere Tabelle                                │
│    /sys/class/net/wlan0/address → fake MAC                      │
│    /proc/bus/input/devices → clean Pixel 6 dump                 │
│                                                                 │
│  SUSFS add_sus_path: /data/adb/modules, /data/adb/ksu, ...     │
│  SUSFS add_sus_kstat: alle redirected Pfade                     │
├─────────────────────────────────────────────────────────────────┤
│                    ZYGOTE-PHASE (Zygisk postAppSpecialize)       │
│                                                                 │
│  Pine/LSPlant ART-Hooks (NUR für Werte ohne Property/Datei):   │
│    • TelephonyManager.getImei() → One-Shot                     │
│    • TelephonyManager.getSubscriberId() → One-Shot              │
│    • WifiInfo.getMacAddress() → One-Shot (Backup für SUSFS)     │
│    • MediaDrm (Widevine ID) → Permanent                        │
│                                                                 │
│  Native Inline-Hooks (NUR für verbleibende Lücken):             │
│    • __system_property_get (Fallback für props die Apps          │
│      direkt via libc lesen statt über Java)                     │
│    • AMediaDrm_* (NDK Widevine)                                │
│                                                                 │
│  ⚠️ Prolog: KEIN LDR X16/BR X16 Pattern!                       │
│  ⚠️ Trampolines: Code-Cave statt memfd!                        │
│  ⚠️ Speicher: /proc/self/mem statt mprotect!                   │
├─────────────────────────────────────────────────────────────────┤
│                    ORCHESTRATOR (Python Host)                    │
│                                                                 │
│  Genesis-Flow:                                                  │
│    1. Identity generieren (MAC, Serial, IMEI, Fingerprint...)   │
│    2. resetprop-Werte in post-fs-data.sh schreiben              │
│    3. SUSFS Fake-Dateien aktualisieren (MAC, ARP, Input)        │
│    4. settings_ssaid.xml pro App editieren (Android ID)         │
│    5. GAID XML löschen + GMS kill                               │
│    6. GSF ID in SQLite ändern oder GSF-Daten löschen            │
│    7. BT Pairing-Daten löschen (/data/misc/bluetooth/)          │
│    8. Reboot → neue Identität aktiv                             │
└─────────────────────────────────────────────────────────────────┘
```

### Hook-Reduktion: Vorher vs. Nachher

| Kategorie | VORHER (aktuell) | NACHHER (Ghost Protocol) |
|-----------|-----------------|------------------------|
| **Xposed Java-Hooks** | ~91 (TelephonyServiceModule.kt) | **0** (Xposed komplett eliminiert) |
| **ART-Hooks (Pine/LSPlant)** | 0 | **~4-6** (getImei, getSubscriberId, getMacAddress, MediaDrm, ggf. ContentResolver) |
| **Native Inline-Hooks** | 18 (zygisk_module.cpp) | **~3-5** (__system_property_get, AMediaDrm_*, ggf. open/fopen Fallbacks) |
| **Kernel-Level (SUSFS)** | 0 | **~8-10** open_redirects + sus_kstat + sus_path |
| **resetprop** | 0 | **~15-20** Properties in post-fs-data.sh |
| **SELinux Policy** | 0 | **1** (deny rild gsm_prop set) |
| **Gesamte Angriffsfläche** | **~109 Hooks** (alle im Userspace, alle detektierbar) | **~8-11 Hooks** (minimal, temporal, One-Shot) |

### Priorisierte Implementierungs-Reihenfolge

| Phase | Was | Warum zuerst | Risiko wenn nicht |
|-------|-----|-------------|-------------------|
| **0** | `post-fs-data.sh`: resetprop + SUSFS redirects | Eliminiert ~80% der Hooks sofort | Alle Properties und Dateien weiterhin über Hooks |
| **1** | Pine/LSPlant Integration in Zygisk | Ersetzt Xposed komplett | msaoaidsec findet XposedBridge |
| **2** | Native Hook Hardening (Prolog, Code-Cave) | msaoaidsec erkennt LDR/BR Pattern | "Too many attempts" |
| **3** | Orchestrator-Anpassung (Genesis-Flow) | Neue Architektur braucht neuen Flow | Inkonsistente Identitäten |
| **4** | Anti-Forensik (maps, Strings) | Feinschliff für Stealth | Forensische Spuren bleiben |

### Verbleibende Risiken (nach vollständiger Implementierung)

| Risiko | Schwere | Mitigierung |
|--------|---------|-------------|
| **metasec_ml Verhaltensanalyse** (Sensor, Touch) | Mittel | Realistische Interaktion oder Telemetrie-Neutralisierung |
| **ArtMethod Watchdog-Thread** (periodischer Entry-Point-Check) | Hoch | One-Shot-Hooks + Installation vor msaoaidsec-Init |
| **Fork-Timing-Anomalie** (Zygisk-Injection) | Niedrig | Akzeptiertes Risiko, schwer zu eliminieren |
| **Hardware-Attestation** (Titan M2) | Hoch | Tricky Store (bereits ausgeschlossen aus Scope) |
| **Neue msaoaidsec-Version** mit unbekannten Checks | Mittel | Regelmäßiges Reverse-Engineering |
