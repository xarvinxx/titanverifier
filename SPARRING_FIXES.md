# Project Titan — Sparring Fixes Kontextsheet
## CTO-Analyse: Was ausgebessert werden muss

**Erstellt**: 2026-02-12
**Quelle**: Vergleich Titan (aktuell) vs. Ares/Maschina (alt) + CTO-Sparring (Block 1-17)
**Status**: ✅ ALLE PHASEN ABGESCHLOSSEN (Phase 1-8)
**Fixes**: 28 dokumentiert — 27 implementiert ✅ | 1 bereits korrekt (Block 10 GMS-Ausschluss)
**Sparring**: ABGESCHLOSSEN — Alle 17 Blöcke analysiert, alle Fragen beantwortet

---

## PRIORITÄT: KRITISCH

### FIX-1: ByteDance Deep-Search in Deep Sanitize
**Problem**: TikTok erkennt den User nach Genesis-Flow wieder — verhält sich nicht wie Fresh Install.
**Ursache**: Titan löscht nur statische Pfade. ByteDance/TikTok legt versteckte Tracking-Verzeichnisse an mehreren Orten ab, die `pm clear` und statische `rm -rf` nicht erfassen.

**Fehlende Pfade/Pattern**:
```
/sdcard/.com.ss.android*          — ByteDance Cross-App SDK
/sdcard/Documents/com.zhiliaoapp* — TikTok Document-Tracking
/sdcard/Download/.log/            — Versteckte Logs
/sdcard/.msync/                   — ByteDance Cross-App Sync
/sdcard/Documents/.tmlog/         — Versteckte TikTok-Logs
/sdcard/DCIM/.thumbnails/         — TikTok-Metadata in Thumbnails
```

**Fehlende Aktionen** (aus Ares `deep_sanitize()` + CTO-Analyse Block 1):
1. `find /sdcard -name '.tt*' -o -name '*.tt*'` — Alle versteckten TT-Dateien finden und löschen
2. `find /sdcard -type d -name '*zhiliaoapp*'` — Alle zhiliaoapp-Verzeichnisse (außerhalb Android/data)
3. `find /sdcard -type d -name '*com.ss.android*'` — ByteDance SDK-Reste
4. `find /sdcard -type d -name '.msync'` — ByteDance Cross-App Sync Verzeichnisse
5. Explizites Löschen der `BYTEDANCE_PATTERNS`:
   - `/sdcard/.com.ss.android*`
   - `/sdcard/Documents/com.zhiliaoapp*`
   - `/sdcard/.tt*`
   - `/sdcard/.msync/`
   - `/sdcard/Documents/.tmlog/`
   - `/sdcard/Download/.log/`
   - `/sdcard/Android/data/com.zhiliaoapp.musically/.tt*`

**Wo**: `host/engine/shifter.py` → `deep_clean()` — nach Schritt 4 (Tracking-Globs) einfügen.

**Referenz**: Ares `core/shifter.py` Zeilen 1066-1108

---

### FIX-2: Cache-Verzeichnisse explizit prüfen und löschen
**Problem**: `pm clear` löscht `/data/data/<pkg>/` aber nicht alle Cache-Pfade zuverlässig. Manche Cache-Verzeichnisse werden von Android/System nach `pm clear` automatisch neu erstellt und enthalten Reste.

**Fehlende Cache-Pfade**:
```
/data/data/com.zhiliaoapp.musically/cache
/data/data/com.zhiliaoapp.musically/code_cache
/storage/emulated/0/Android/data/com.zhiliaoapp.musically/cache
```

**Aktion**: Nach `pm clear` explizit prüfen ob diese Pfade existieren und nochmal `rm -rf` mit Root.

**Wo**: `host/engine/shifter.py` → `deep_clean()` — nach den ByteDance-Pattern-Suchläufen.

**Referenz**: Ares `core/shifter.py` Zeilen 1110-1124

---

## PRIORITÄT: HOCH

### FIX-3: Backup-Whitelist (nur Login-relevante Ordner)
**Problem**: Titans `backup()` und `backup_tiktok_dual()` erstellen ein volles tar von `/data/data/<pkg>/`. Das inkludiert auch Cache, Crash-Reports und andere Daten die beim Restore Probleme verursachen können (veraltete Caches, korrupte Temp-Dateien).

**Empfohlene Änderung**: Statt `tar -cf - -C / data/data/com.zhiliaoapp.musically` nur die relevanten Unterordner sichern:
```bash
su -c 'tar -C /data/data/com.zhiliaoapp.musically -cf - shared_prefs databases files 2>/dev/null'
```

**Warum Whitelist besser ist**:
- `shared_prefs/` = Login-Session, Cookies, User-Preferences
- `databases/` = SQLite-DBs mit Account-Daten
- `files/` = Token-Dateien, Konfiguration
- `cache/`, `code_cache/`, `no_backup/` = Nicht nötig, kann Probleme verursachen

**Wo**: `host/engine/shifter.py` → `backup_tiktok_dual()` → Pfad A tar-Befehl anpassen.

**Referenz**: Ares `core/shifter.py` Zeilen 1506-1512

---

### FIX-4: Integrity Guard (Dateianzahl + Größenvergleich) ✅ IMPLEMENTIERT
**Problem**: Titan prüft nur ob tar > 0 Bytes ist. Das erkennt keine teilweise korrupten Backups (z.B. wenn ADB-Verbindung während Stream abbricht und nur 10% der Daten übertragen wurden).

**Empfohlene Änderung**: Nach Backup die Statistiken auf dem Gerät vs. lokal vergleichen:
1. Device: `find <path> -type f | wc -l` + `du -sb <path>`
2. Lokal: tar inspizieren oder entpacken + vergleichen
3. Toleranz: 5% Dateianzahl, 10% Größe (Dateisystem-Unterschiede)

**Wo**: `host/engine/shifter.py` → `backup_tiktok_dual()` — nach dem tar-Stream als Validierung.

**Referenz**: Ares `core/shifter.py` Zeilen 1159-1300

---

### FIX-5: CE-Storage Unlock-Check via `dumpsys window` ✅ IMPLEMENTIERT
**Problem**: Titans `_check_ce_storage()` prüft nur ob `/data/data/com.google.android.gms/shared_prefs` existiert. Das ist ein schwacher Proxy. Ares hat eine robustere Methode die den tatsächlichen Lock-Screen-State prüft.

**Empfohlene Änderung**: Zusätzlich `dumpsys window` prüfen:
```bash
# Keyguard im Fokus = gesperrt
dumpsys window windows | grep -i mCurrentFocus
# → "Keyguard" oder "LockScreen" = gesperrt
# → "Launcher" oder "Activity" = entsperrt
```

**Wo**: `host/engine/shifter.py` → `_check_ce_storage()` erweitern.

**Referenz**: Ares `core/shifter.py` Zeilen 759-790

---

## PRIORITÄT: MITTEL

### FIX-6: USB-Reconnect Simulation nach Reboot ✅ IMPLEMENTIERT
**Problem**: Nach Reboot bleibt ADB manchmal in einem "Zombie-State" hängen — der Daemon meldet "device" aber Shell-Befehle scheitern. Ein USB-Modus-Toggle löst das.

**Empfohlene Änderung**: In `host/adb/client.py` → `ensure_connection()` als Fallback:
```bash
# USB-Modus auf "none" setzen (trennt Verbindung)
setprop sys.usb.config none
sleep 2
# USB-Modus auf "mtp,adb" setzen (verbindet neu)
setprop sys.usb.config mtp,adb
sleep 3
```

**Wann triggern**: Nur wenn normaler Reconnect (kill-server/start-server) nach 2 Versuchen fehlschlägt.

**Referenz**: Ares `core/shifter.py` Zeilen 189-226

---

### FIX-7: `wm dismiss-keyguard` als Unlock-Fallback ✅ IMPLEMENTIERT
**Problem**: Titans Unlock (Wakeup + Swipe) funktioniert meistens, aber nach Reboot kann der WindowManager träge sein und Swipes ignorieren. `wm dismiss-keyguard` umgeht das komplett.

**Empfohlene Änderung**: Nach dem Swipe-Unlock als Fallback:
```bash
su -c 'wm dismiss-keyguard'
```

**Wo**: `host/adb/client.py` → `unlock_device()` — nach dem Swipe als zusätzlichen Schritt.

**Referenz**: Ares `core/shifter.py` Zeilen 450-462

---

## SPARRING BLOCK 1 — Sterilize Logik (zusätzliche Findings)

### FIX-13: `pm clear` durch `pm uninstall --user 0` + `pm install-existing` ersetzen
**Priorität**: HOCH
**Problem**: `pm clear` löscht zwar `/data/data/<pkg>/`, aber es behält:
- Die App selbst (APK + OAT-optimierte Dateien)
- Die Berechtigungen/Permission-Grants
- Den Android-internen Package-State (first-run Flag, Notification-Channels, etc.)

Das bedeutet: TikTok erkennt nach `pm clear`, dass die App **nicht zum ersten Mal** gestartet wird. Die „Welcome"-Screens, Onboarding-Flows und erste Setup-Dialoge können übersprungen werden, was Anti-Fraud-Systemen auffällt.

**Empfohlene Änderung**:
```bash
# Statt:
pm clear com.zhiliaoapp.musically

# Besser:
pm uninstall --user 0 com.zhiliaoapp.musically   # Deinstalliert für User 0
pm install-existing com.zhiliaoapp.musically       # Re-installiert aus System-Cache
```

**Vorteil**: Erzwingt einen echten "First Launch"-State — App verhält sich wie frisch installiert.

**Risiko**: `pm install-existing` funktioniert nur wenn die APK noch im System-Cache liegt (bei User-Apps immer der Fall). Bei System-Apps ohnehin kein Problem.

**Alternative** (falls `install-existing` Probleme macht):
```bash
pm uninstall com.zhiliaoapp.musically
pm install /data/app/<pkg-path>/base.apk
```
Erfordert aber das Merken des APK-Pfads vorher.

**Wo**: `host/engine/shifter.py` → `deep_clean()` — `pm clear` durch `pm uninstall --user 0` + `pm install-existing` ersetzen.

---

### FIX-14: TikTok Settings-ContentProvider Werte bereinigen ✅ IMPLEMENTIERT
**Priorität**: MITTEL
**Problem**: TikTok kann eigene Werte über den Android `Settings`-ContentProvider schreiben (`Settings.Global` oder `Settings.Secure`). Diese Werte überleben `pm clear` und sogar `pm uninstall`, weil sie nicht App-spezifisch sondern **System-global** gespeichert werden.

Beispiele für TikTok-Tracking via Settings:
- Custom Device-IDs die TikTok über `Settings.Secure.putString()` persistiert
- ByteDance SDK Tracking-Tokens
- Install-Referrer oder Attribution-Daten

**Empfohlene Aktion**: Nach `pm clear` / `pm uninstall` alle verdächtigen `Settings`-Einträge löschen:
```bash
# Alle Settings durchsuchen nach TikTok/ByteDance-Referenzen
settings list secure | grep -i 'tiktok\|bytedance\|musically\|tt_\|ss_android'
settings list global | grep -i 'tiktok\|bytedance\|musically\|tt_\|ss_android'

# Gefundene Einträge löschen
settings delete secure <key>
settings delete global <key>
```

**Wo**: `host/engine/shifter.py` → `deep_clean()` — nach `pm clear` / `pm uninstall` als neuer Schritt.

**Hinweis**: Die genauen Keys müssen einmal manuell ermittelt werden (TikTok installieren, starten, dann `settings list` prüfen). Alternativ kann der Xposed Debug-Log-Mode (FIX-12) diese Keys aufdecken.

---

## SPARRING BLOCK 4 — Genesis Flow Logik

### FIX-9: Bridge-Verifikation auf ALLE Pfade ausweiten (Post-Reboot) ✅ IMPLEMENTIERT
**Priorität**: MITTEL
**Problem**: Nach dem Reboot in Schritt 7 (Hard Reset) wird nur der primäre Bridge-Pfad verifiziert (`/data/adb/modules/titan_verifier/titan_identity`). Die weiteren Kopien (`/sdcard/`, App-Ordner) werden nicht geprüft. Wenn eine Kopie fehlt oder korrupt ist, merkt der Flow das nicht.

**Aktuell verifizierte Pfade** (nur 1):
```
/data/adb/modules/titan_verifier/titan_identity   ← NUR DIESER
```

**Soll verifiziert werden** (alle 3 Hauptpfade):
```
/data/adb/modules/titan_verifier/titan_identity   ← Primär (Zygisk liest hier)
/sdcard/.titan_identity                            ← Backup (LSPosed liest hier)
/data/data/com.titan.verifier/files/.titan_identity ← App-Kopie (Audit)
```

**Aktion**: `serial=` Grep auf allen 3 Pfaden nach dem Reboot. Bei Mismatch → WARNING (nicht FAIL, da Primärpfad reicht). Bei Primärpfad-Mismatch → FAIL wie bisher.

**Wo**: `host/flows/genesis.py` → Schritt 7 (Hard Reset), Abschnitt "POST-REBOOT BRIDGE VERIFICATION" (Zeile 509-540).

---

### FIX-10: GMS Ready vereinfachen (Option A — nur Connectivity-Check)
**Priorität**: HOCH
**Problem**: Schritt 9 (GMS Ready) führt Finsky Kill + MinuteMaid + GMS Kickstart durch. Das ist ein Relikt aus der alten Architektur (vor v4.0 GMS-Schutz), als GMS bei jedem Genesis-Flow gelöscht wurde. Seit v4.0 wird GMS NIE gelöscht — die Trust-Chain bleibt intakt. Der Kickstart-Code verursacht unnötige Wartezeiten und lässt den Flow manchmal hängen.

**Aktueller Ablauf** (Schritt 9):
1. Konnektivitäts-Check ← BEHALTEN
2. Finsky Kill (`am force-stop com.android.vending`) ← ENTFERNEN
3. MinuteMaid GMS Repair ← ENTFERNEN
4. GMS Kickstart (Checkin triggern) ← ENTFERNEN
5. GSF-ID Logging ← BEHALTEN (reine Info)

**Neuer Ablauf** (Schritt 9):
1. Konnektivitäts-Check (IP bereits in Schritt 8 bestätigt → schnell)
2. GSF-ID Logging (informativ, kein Wait)

**Timing-Ersparnis**: ~`GMS_KICKSTART_SETTLE_SECONDS` (3s) + MinuteMaid-Wartezeit + potenzielle Hänger.

**Wo**: `host/flows/genesis.py` → Schritt 9 (GMS Ready), Zeilen 634-721.

---

### FIX-11: TikTok Backup-Logik — Auto-Backup wenn `tiktok_username` gesetzt
**Priorität**: HOCH
**Problem**: Die Auto-Backup-Entscheidung im Genesis- und Switch-Flow berücksichtigt nicht, ob der User für das aktive Profil überhaupt einen TikTok-Account eingerichtet hat. Es wird entweder blind gesichert (Switch) oder nur per Checkbox gesteuert (Genesis). Das führt zu leeren/unnötigen Backups oder fehlenden Backups.

**Gewünschte Logik (für BEIDE Flows — Genesis + Switch)**:
```
VOR JEDEM FLOW:
1. Finde aktives Profil (profiles.status = 'active')

2. WENN aktives Profil gefunden:
   a) Lade tiktok_username aus DB für dieses Profil
   b) WENN tiktok_username gesetzt (NOT NULL, nicht leer):
      → IMMER backup_tiktok_dual() ausführen
      → Grund: "User hat TikTok-Account eingerichtet → Daten sichern"
   c) WENN tiktok_username NICHT gesetzt:
      → KEIN Backup (kein Account → nichts zu sichern)

3. WENN KEIN aktives Profil:
   a) Prüfe Checkbox (backup_before) in der WebUI
   b) WENN Checkbox gesetzt → Versuche Backup (User Override)
   c) WENN Checkbox NICHT gesetzt → Überspringe
```

**DB-Feld für Prüfung**: `profiles.tiktok_username` (TEXT, nullable)

**Betroffene Methoden**:
- `GenesisFlow._find_active_profile()` → muss `tiktok_username` mit zurückgeben
- `GenesisFlow.execute()` → Schritt 2 (Auto-Backup) — Logik erweitern
- `SwitchFlow._find_active_profile()` → muss `tiktok_username` mit zurückgeben
- `SwitchFlow.execute()` → Schritt 2 (Auto-Backup) — Logik erweitern

**Wo**:
- `host/flows/genesis.py` → `_find_active_profile()` + Schritt 2
- `host/flows/switch.py` → `_find_active_profile()` + Schritt 2

---

### FIX-12: Xposed Debug-Log-Mode (Hook-Monitoring für WebUI) ✅ IMPLEMENTIERT
**Priorität**: MITTEL
**Problem**: Aktuell gibt es keine Möglichkeit zu sehen, welche Hooks TikTok tatsächlich trifft und was TikTok für Werte empfängt. Die Titan Verifier App prüft aus ihrer eigenen Perspektive, aber nicht aus TikToks Prozess heraus.

**Lösung**: Debug-Log-Mode im `TitanXposedModule.kt` einbauen, der pro gehooktem API-Call mitloggt:
```
[HOOK] TikTok → TelephonyManager.getDeviceId()     → Spoofed: 355543XXXXXXX
[HOOK] TikTok → Settings.Secure.getString(android_id) → Spoofed: a1b2c3d4...
[HOOK] TikTok → Build.SERIAL                        → Spoofed: ABC123DEF456
[HOOK] TikTok → WifiInfo.getMacAddress()             → Spoofed: F4:F5:D8:XX:XX:XX
✗ TikTok → getAccounts()                             → NOT HOOKED (!)
```

**Steuerung**: Über einen Flag in der Bridge-Datei (`debug_hooks=1/0`) oder über eine Shared-Pref die vom Host gesetzt wird.

**WebUI-Integration**: Logs via `logcat --pid=<tiktok_pid> -s TitanHook` in den Live-Log-Stream der WebUI einspeisen.

**Nutzen**: Zeigt sofort welche APIs gehooked werden, welche Werte gespooft werden, und wo Lücken sind. Essenziell für Debugging wenn TikTok den User trotz Genesis-Flow wiedererkennt.

**Wo**:
- `app/src/main/java/.../TitanXposedModule.kt` → Log-Wrapper um jeden Hook
- `host/api/dashboard.py` → Optional: Logcat-Filter für Hook-Logs
- Bridge-Datei → neues Feld `debug_hooks=0` (Default: aus)

---

## SPARRING BLOCK 5 — Switch Flow Logik

### FIX-15: Sandbox-Lücke — Full-State Restore ohne TikTok Sandbox
**Priorität**: HOCH
**Problem**: Wenn der Switch Flow im Full-State-Modus läuft (`profile_name` angegeben), ruft Schritt 5 (`restore_full_state()`) GMS + Accounts + TikTok **App-Daten** her. Schritt 6 (Restore TikTok) wird dann SKIPPED mit "Bereits in Schritt 5 enthalten".

ABER: `restore_full_state()` restored NUR `/data/data/<pkg>/` (App-Daten). Die **TikTok Sandbox** (`/sdcard/Android/data/<pkg>/`) wird NICHT restored! Die Sandbox enthält:
- ByteDance SDK Device-Fingerprints
- Download-Cache und Medien
- TikTok SDK-Konfiguration

Das bedeutet: **Bei jedem Switch gehen TikToks Sandbox-Daten verloren**, auch wenn ein Sandbox-Backup existiert. TikTok muss die Sandbox beim nächsten Start komplett neu aufbauen — das kann als verdächtig erkannt werden.

**Lösung**: Schritt 6 darf bei Full-State NICHT übersprungen werden. Stattdessen:
```
Schritt 5 (Restore State): GMS + Accounts (wie bisher)
Schritt 6 (Restore TikTok): IMMER Dual-Path Restore ausführen:
  → Pfad A: App-Daten aus tiktok/ Unterordner
  → Pfad B: Sandbox aus sandbox/ Unterordner
```
Falls `restore_full_state()` bereits TikTok App-Daten restored hat, soll Schritt 6 nur noch die Sandbox nachladen.

**Betroffener Code**:
```python
# switch.py Zeile 390-393 — AKTUELL (falsch):
if use_full_state:
    step.status = FlowStepStatus.SKIPPED
    step.detail = "Bereits in Schritt 5 (Full-State) enthalten"

# SOLL: Sandbox-Restore immer ausführen
```

**Wo**: `host/flows/switch.py` → Schritt 6 (Restore TikTok), Zeilen 386-438.

---

### FIX-16: Mini-Clean vor Switch-Restore (ByteDance-Reste bereinigen)
**Priorität**: HOCH
**Problem**: Der Switch Flow macht kein `pm clear` und kein Deep Clean vor dem Restore. Er überschreibt nur die Daten via tar. Aber: Wenn TikTok zwischen dem letzten Backup und dem Switch neue Tracking-Dateien auf `/sdcard/` geschrieben hat, bleiben diese Reste liegen. Sie könnten das **alte** Profil verraten.

**Beispiel-Szenario**:
1. Profil A ist aktiv, TikTok läuft → schreibt `/sdcard/.tt_device_id_v2`
2. Switch zu Profil B → TikTok App-Daten werden aus Backup B restored
3. ABER: `/sdcard/.tt_device_id_v2` enthält noch die Device-ID von Profil A!
4. TikTok liest die alte Tracking-Datei → Cross-Profile Correlation möglich

**Lösung**: Vor dem Restore (nach Safety Kill, vor Inject) einen gezielten Mini-Clean durchführen:
```
Neuer Sub-Schritt in Schritt 3 oder als eigener Schritt:
  1. rm -f /sdcard/.tt* /sdcard/.tg* /sdcard/.tobid*
  2. rm -rf /sdcard/.msync/ /sdcard/.com.ss.android*
  3. rm -rf /sdcard/Documents/com.zhiliaoapp* /sdcard/Documents/.tmlog/
  4. rm -rf /sdcard/Download/.log/
  5. find /sdcard -name '.tt*' -delete (vollständiger Sweep)
```

Dies ist eine Teilmenge von FIX-1 (ByteDance Deep-Search), aber speziell für den Switch-Kontext — ohne `pm clear`, nur `/sdcard/` Tracking-Reste.

**Wo**: `host/flows/switch.py` → nach Schritt 3 (Safety Kill), vor Schritt 4 (Inject). Alternativ: Eigene Methode `TitanShifter.clean_tracking_remnants()` die sowohl von Genesis (deep_clean) als auch Switch aufgerufen wird.

---

## SPARRING BLOCK 7 — Auditor Lücken

### FIX-17: Host-Side Auditor erweitern (Full + Quick Audit) ✅ IMPLEMENTIERT
**Priorität**: HOCH
**Status**: ✅ Implementiert (Phase 3)
**Problem**: Der `TitanAuditor` prüft aktuell nur **4 Dinge**: Bridge existiert, Bridge-Serial, Input-Devices, Bridge-MAC. Er prüft NICHT ob die kritischsten Spoofing-Felder korrekt in der Bridge stehen:

| Feld | Status | Risiko wenn fehlerhaft |
|---|---|---|
| `serial` + `boot_serial` | ✅ Geprüft | Niedrig (wird geprüft) |
| `wifi_mac` | ✅ Geprüft | Niedrig (wird geprüft) |
| `imei1` | ❌ NICHT geprüft | **HOCH** — TikTok Hauptidentifikator |
| `imei2` | ❌ NICHT geprüft | Mittel |
| `gsf_id` | ❌ NICHT geprüft | **HOCH** — Google Correlation |
| `android_id` | ❌ NICHT geprüft | **HOCH** — SSAID, von TikTok oft abgefragt |
| `widevine_id` | ❌ NICHT geprüft | Mittel — DRM Fingerprint |
| `imsi` | ❌ NICHT geprüft | Mittel — SIM-Fingerprint |
| `sim_serial` | ❌ NICHT geprüft | Mittel |
| `build_fingerprint` | ❌ NICHT geprüft | Mittel — Build-Consistency |

Wenn die Bridge korrupt ist aber zufällig den richtigen Serial + MAC hat, meldet der Auditor **100%** — aber IMEI/GSF-ID/Android-ID könnten falsch sein.

**Lösung — Full Audit (Genesis Schritt 11)**:
Alle Felder der Bridge gegen die erwartete Identity prüfen:
```python
# Neue Checks hinzufügen:
result.checks.append(self._check_bridge_field(bridge, expected, "imei1"))
result.checks.append(self._check_bridge_field(bridge, expected, "imei2"))
result.checks.append(self._check_bridge_field(bridge, expected, "gsf_id"))
result.checks.append(self._check_bridge_field(bridge, expected, "android_id"))
result.checks.append(self._check_bridge_field(bridge, expected, "widevine_id"))
result.checks.append(self._check_bridge_field(bridge, expected, "imsi"))
result.checks.append(self._check_bridge_field(bridge, expected, "sim_serial"))
result.checks.append(self._check_bridge_field(bridge, expected, "build_fingerprint", critical=False))
```

**Lösung — Quick Audit (Switch Schritt 9)**:
Erweitern von nur Serial auf die 5 wichtigsten Felder:
```python
# Statt nur serial:
fields_to_check = ["serial", "imei1", "gsf_id", "android_id", "wifi_mac"]
for field in fields_to_check:
    actual = bridge.get(field, "")
    expected_val = getattr(expected, field, "")
    if actual != expected_val:
        return False  # Mismatch
return True
```

**Wichtig — App-Ebene**: Der Host-Side Auditor prüft die Bridge-Datei (was die Hooks LESEN SOLLEN). Ob die Apps die gespooften Werte auch tatsächlich EMPFANGEN, wird durch FIX-12 (Xposed Debug-Log-Mode) abgedeckt. Beides zusammen ergibt die vollständige Verifikation.

**Wo**: `host/engine/auditor.py` → `audit_device()` + `quick_audit()`

---

## SPARRING BLOCK 8 — Network & IP

### FIX-18: IP-Duplikat-Erkennung (IP-Datenbank mit Collision-Check) ✅ IMPLEMENTIERT
**Priorität**: HOCH
**Status**: ✅ Implementiert (Phase 3)
**Problem**: Die IP-Rotation via Flugmodus-Cycle erzwingt eine neue Modem-Session. ABER: Der Carrier (O2) kann dieselbe IP erneut zuweisen (IP-Pool ist begrenzt, Lease-Zuordnung erfolgt server-seitig). Aktuell wird die IP in `ip_history` gespeichert, aber es gibt **keinen Check** ob diese IP bereits von einem ANDEREN Profil benutzt wurde.

**Risiko**: Wenn Profil A und Profil B dieselbe öffentliche IP verwenden, kann TikTok (oder jeder Netzwerk-Analyst) die beiden Accounts korrelieren — identische IP = wahrscheinlich dasselbe Gerät.

**Lösung — IP-Collision-Detection**:
Nach jedem IP-Check (in Genesis Schritt 8 und Switch Schritt 8) gegen die `ip_history` Tabelle prüfen:

```sql
-- Prüfe ob diese IP jemals von einem ANDEREN Profil benutzt wurde
SELECT DISTINCT profile_id, identity_id, flow_type, created_at
FROM ip_history
WHERE public_ip = ?
  AND profile_id != ?        -- Nicht das aktuelle Profil
ORDER BY created_at DESC
LIMIT 5
```

**Verhalten bei Collision**:
```
1. IP war noch NIE benutzt      → ✅ OK, Flow fortsetzen
2. IP war von DIESEM Profil     → ✅ OK (gleiches Profil, erwartbar)
3. IP war von ANDEREM Profil    → ⚠️ WARNING ins Log + WebUI:
   "IP {ip} wurde bereits von Profil '{name}' am {datum} benutzt!
    Cross-Profile Korrelation möglich."
4. IP war von 3+ Profilen       → 🔴 CRITICAL WARNING:
   "IP {ip} wurde von {n} verschiedenen Profilen benutzt!
    Empfehlung: Wartezeit vor nächstem Flow erhöhen."
```

**KEIN Flow-Abbruch** bei IP-Collision — nur Warning. Grund: Wir können die IP nicht ändern (Carrier kontrolliert den Pool). Aber der User muss informiert werden.

**Zusätzliche Metriken für WebUI**:
- "Unique IPs": Anzahl verschiedener IPs die je benutzt wurden
- "IP Reuse Rate": Prozentsatz der Flows die eine bereits benutzte IP bekommen haben
- "Letzte IP-Collision": Wann war der letzte Vorfall

**ZUSÄTZLICH ENTDECKT**: Der Switch Flow speichert die IP aktuell **NICHT** in `ip_history` oder `identities`! Nur der Genesis Flow ruft `record_ip()` und `update_identity_network()` auf. Das bedeutet: Beim Switch wird die IP zwar ermittelt und geloggt, aber nie in die DB geschrieben. → FIX-18 muss auch den Switch Flow patchen, damit IPs dort ebenfalls persistiert werden.

**Außerdem**: Die Indizes auf `ip_history` sind im Schema **auskommentiert**:
```sql
-- CREATE INDEX IF NOT EXISTS idx_ip_ip        ON ip_history(public_ip);
-- CREATE INDEX IF NOT EXISTS idx_ip_identity  ON ip_history(identity_id);
-- CREATE INDEX IF NOT EXISTS idx_ip_time      ON ip_history(detected_at DESC);
```
Diese müssen für die Collision-Detection aktiv sein (sonst Full-Table-Scan bei jedem Check).

**Wo**:
- `host/engine/db_ops.py` → Neue Funktion `check_ip_collision(ip, current_profile_id)`
- `host/flows/genesis.py` → Schritt 8 (Network Init), nach IP-Check
- `host/flows/switch.py` → Schritt 8 (Network Init), nach IP-Check **+ `record_ip()` + `update_identity_network()` hinzufügen**
- `host/database.py` → Indizes auf `ip_history` aktivieren
- `host/frontend/templates/dashboard.html` → IP-Status im Header (optional)

---

## SPARRING BLOCK 13 — Error Handling & Resilience

### FIX-22: Genesis Rollback erweitern — `corrupted` nach Inject bei späterem Fehler ✅ IMPLEMENTIERT
**Priorität**: HOCH
**Status**: ✅ Implementiert (Phase 4)
**Problem**: Wenn Genesis Schritt 6 (Inject) erfolgreich ist, aber ein späterer Schritt fehlschlägt (Hard Reset, Network Init, Capture State), bleibt die Identity in der DB als `active` — obwohl der Flow FAILED ist. Das Gerät ist in einem unbekannten Zustand.

**Lösung**: Auch nach erfolgreichem Inject die Identity als `corrupted` markieren wenn der Flow danach fehlschlägt. Zusätzlich eine **Info-Meldung in der WebUI** anzeigen:
```
"⚠ Identity '{name}' als corrupted markiert — Genesis Flow nach Inject abgebrochen 
(Schritt {step_name} fehlgeschlagen). Bitte neuen Genesis-Flow starten."
```

**Aktueller Rollback** (nur bei Inject-Fehler):
```python
if db_identity_id and not any(
    s.name == "Inject" and s.status == FlowStepStatus.SUCCESS
    for s in result.steps
):
    await self._update_identity_status(db_identity_id, IdentityStatus.CORRUPTED)
```

**Neuer Rollback** (auch nach Inject bei späterem Fehler):
```python
# Bei JEDEM Flow-Fehler die Identity als corrupted markieren
if db_identity_id:
    await self._update_identity_status(db_identity_id, IdentityStatus.CORRUPTED)
    logger.warning("Identity %d als corrupted markiert (Flow nach Inject fehlgeschlagen)", db_identity_id)
```

**Wo**: `host/flows/genesis.py` → `except ADBError` + `except Exception` Handler (Zeilen 891-927).

---

### FIX-23: Backup-Resilience — Atomic Write + Retry bei ADB-Abbruch ✅ IMPLEMENTIERT
**Priorität**: HOCH
**Status**: ✅ Implementiert (Phase 4)
**Problem**: Backup schreibt direkt in die finale Datei. Wenn ADB während des tar-Streams die Verbindung verliert, bleibt eine korrupte Teildatei liegen. Beim nächsten Restore wird diese als gültiges Backup behandelt.

**Lösung — Dreistufig**:

**Stufe 1: Atomic Write**
```
1. Schreibe nach app_data.tar.tmp (nicht direkt in .tar)
2. Bei Erfolg: rename .tmp → .tar
3. Bei Fehler: lösche .tmp, altes .tar bleibt intakt
```

**Stufe 2: Retry bei ADB-Abbruch**
```
1. Fange ADBError/ADBTimeoutError beim tar-Stream
2. Lösche korrupte .tmp Datei
3. ADB-Verbindung wiederherstellen (ensure_connection)
4. Erneuter Versuch (max. 3 Retries mit exponential backoff)
5. Wenn alle Retries fehlschlagen → Flow abbrechen
```

**Stufe 3: Info-Meldung bei Abbruch**
```
"🔴 Backup fehlgeschlagen nach 3 Versuchen — ADB-Verbindung instabil.
 Bestehendes Backup bleibt erhalten. Flow abgebrochen."
```
→ WebUI zeigt die Meldung als Error-Notification an.

**Wichtig**: Altes Backup darf NIE mit korrupten Daten überschrieben werden. Erst rename wenn vollständig + validiert.

**Wo**: `host/engine/shifter.py` → `backup_tiktok_dual()`, `backup()` — Atomic Write + Retry-Wrapper.

---

### ENTSCHEIDUNG Block 14.1 — String-Verschlüsselung: SEPARATE PHASE
**Status**: Dokumentiert als eigene Phase NACH allen funktionalen Fixes.
**Begründung**: TikTok scannt nicht aktiv Zygisk-Module-Binaries. Die funktionalen Fixes (TikTok-Erkennung, Backup-Lücken, Auditor) haben höhere Priorität. String-Verschlüsselung wird als Phase 7 eingeplant.

### FIX-24: String-Verschlüsselung + Raw Syscalls + memfd_create (Stealth-Hardening) ✅ IMPLEMENTIERT
**Priorität**: MITTEL — Eigene Phase nach allen Flow-Fixes
**Problem**: Alle sensitiven Strings in `zygisk_module.cpp` und `titan_hardware.cpp` sind Klartext. `strings libtitan_zygisk.so` enthüllt das komplette Modul. Zusätzlich nutzt das Modul libc-Wrapper statt raw syscalls. Und es werden Temp-Dateien in `/data/local/tmp/` erstellt die nie gelöscht werden.

**Umfang (3 Teilbereiche)**:

**A) XOR-Verschlüsselung** für alle Strings (Pfade, Package-Namen, Log-Tags, Defaults):
```cpp
// Compile-Time XOR Macro
#define XOR_KEY 0x5A
#define DECRYPT(enc, len) ({ char* d = (char*)alloca(len+1); \
    for(int i=0;i<len;i++) d[i]=enc[i]^XOR_KEY; d[len]=0; d; })
```

**B) Raw Syscalls** (`syscall(__NR_openat, ...)`) statt `open()`, `read()`, `close()`, `stat()`:
```cpp
// Statt: int fd = open(path, O_RDONLY);
// Besser:
int fd = syscall(__NR_openat, AT_FDCWD, path, O_RDONLY, 0);
```

**C) `memfd_create` statt Temp-Dateien** (unauffindbarste Lösung):
```cpp
// Statt: open("/data/local/tmp/.titan_cpuinfo_1234", O_CREAT|O_RDWR, 0600)
// Besser:
int fd = syscall(__NR_memfd_create, "", MFD_CLOEXEC);
write(fd, fake_content, content_len);
lseek(fd, 0, SEEK_SET);
// → Kein Dateisystem-Eintrag, nur anonymer RAM-FD
// → find / -name '.titan*' findet NICHTS
// → Existiert nur solange der Prozess lebt
// → Funktioniert auf Android 14 (Kernel 5.10+, Pixel 6)
```

Betrifft folgende Temp-Dateien die aktuell erstellt werden:
- `/data/local/tmp/.titan_mac_open_<pid>` → memfd_create
- `/data/local/tmp/.titan_input_open_<pid>` → memfd_create
- `/data/local/tmp/.titan_cpuinfo_<pid>` → memfd_create
- `/data/local/tmp/.titan_version_<pid>` → memfd_create
- `/data/local/tmp/.titan_if_inet6_<pid>` → memfd_create

Host-seitige Staging-Dateien (nach Push löschen):
- `/data/local/tmp/.titan_bridge_staging` → `adb shell rm` nach Push
- `/data/local/tmp/.titan_pif_staging.prop` → `adb shell rm` nach Push

**Geschätzter Aufwand**: 2-3 Tage (eigene Phase)

**Wo**: `module/zygisk_module.cpp`, `common/titan_hardware.cpp`, `common/titan_hardware.h`, `host/engine/injector.py` (Staging-Cleanup)

---

## SPARRING BLOCK 15 — Logging & Observability

### FIX-25: Persistenter File-Logger mit Rotation ✅ IMPLEMENTIERT
**Priorität**: MITTEL
**Problem**: Logs existieren nur in-memory (Ring-Buffer, 500 Einträge) und im Terminal. Wenn der Server crasht oder neustartet, sind alle Logs weg. Post-Mortem-Analyse ist unmöglich.

**Lösung**: `RotatingFileHandler` in `host/main.py` hinzufügen:
```python
from logging.handlers import RotatingFileHandler

file_handler = RotatingFileHandler(
    "titan.log",
    maxBytes=10_000_000,    # 10 MB pro Datei
    backupCount=3,           # 3 alte Dateien behalten
    encoding="utf-8",
)
file_handler.setFormatter(_BerlinFormatter(...))
file_handler.setLevel(logging.DEBUG)  # Alles loggen, auch DEBUG
logging.root.addHandler(file_handler)
```

**Vorteile**:
- Max ~40MB Disk (10MB × 4 Dateien)
- DEBUG-Level im File (WebSocket bleibt auf INFO)
- Post-Mortem bei 3-Uhr-Nachts-Crashes möglich
- ~10 Zeilen Code

**Wo**: `host/main.py` → nach dem Console-Handler.

---

## SPARRING BLOCK 17 — Frontend Konsistenz

### FIX-27: Unbenutzte Backend-Endpoints bereinigen ✅ IMPLEMENTIERT
**Priorität**: NIEDRIG
**Problem**: 7 Backend-Endpoints werden im Frontend nicht aufgerufen. Toter Code erhöht Wartungsaufwand.

**Aktion — Selektives Aufräumen**:

**BEHALTEN** (werden für Backup-Features gebraucht):
- `POST /api/control/backup` — Backup-Flow manuell triggern
- `GET /api/vault/{id}/backups` — Backup-Liste für ein Profil
- `POST /api/vault/{id}/backup` — Manuelles Backup für ein Profil

**LÖSCHEN** (redundant oder über andere Wege erreichbar):
- `GET /api/dashboard/profiles` — redundant mit `/api/vault`
- `GET /api/dashboard/farm-stats` — redundant mit `/api/dashboard/stats`
- `PUT /api/vault/{id}/credentials` — bereits über `PUT /api/vault/{id}` (Edit) abgedeckt
- `PUT /api/vault/{id}/status` — bereits über Edit oder Bulk-Status abgedeckt

**Wo**: `host/api/dashboard.py` (profiles, farm-stats), `host/api/vault.py` (credentials, status)

---

### FIX-26: Polling-Guard gegen Race-Conditions ✅ IMPLEMENTIERT
**Priorität**: NIEDRIG
**Problem**: `pollFlowStatus()` im Dashboard wird alle 2s aufgerufen. Wenn ein API-Request länger als 2s dauert, starten parallele Polls → Doppel-Updates, UI-Flackern.

**Lösung**:
```javascript
let pollInProgress = false;
async function pollFlowStatus() {
    if (pollInProgress) return;
    pollInProgress = true;
    try {
        // ... bestehende Logik
    } finally {
        pollInProgress = false;
    }
}
```

Gleiches Muster für `refreshHeaderStatus()` und `pollFlowForHeader()` in `vault.html`.

**Wo**: `host/frontend/templates/dashboard.html` + `host/frontend/templates/vault.html`

---

## SPARRING BLOCK 9 — Injector / Distribution

### FIX-19: Bridge-Distribution an Instagram + Snapchat (Vorbereitung) ✅ IMPLEMENTIERT
**Priorität**: NIEDRIG (erst relevant wenn Insta/Snap aktiv genutzt werden)
**Problem**: Die `BRIDGE_TARGET_APPS` in `host/config.py` enthält TikTok, GMS, Titan Verifier, DRM Info und Device ID — aber NICHT Instagram (`com.instagram.android`) und Snapchat (`com.snapchat.android`). 

Gleichzeitig hooked der **Zygisk-Module** (C++) und das **LSPosed-Module** (Kotlin) BEIDE Apps bereits aktiv. Wenn die Bridge-Datei fehlt, fallen die Hooks auf **hardcoded Default-Werte** zurück (Zeile 83-89 in `zygisk_module.cpp`):
```cpp
static const char* DEFAULT_SERIAL = "28161FDF6006P8";
static const char* DEFAULT_IMEI1 = "352269111271008";
// ... etc.
```

Das bedeutet: Wenn Insta/Snap installiert und geöffnet werden, sehen sie ALLE die gleichen statischen Default-IDs → sofortige Cross-App Correlation möglich.

**Lösung (wenn Insta/Snap aktiviert werden)**:
1. `BRIDGE_TARGET_APPS` in `host/config.py` um `com.instagram.android` und `com.snapchat.android` erweitern
2. Der Injector verteilt die Bridge dann automatisch in die App-Ordner

**Status**: ✅ Implementiert. `SOCIAL_MEDIA_PACKAGES` enthält jetzt TikTok + Instagram + Snapchat. Bridge-Distribution prüft via `test -d` ob die App installiert ist — nicht installierte Apps werden übersprungen.

**Wo**: `host/config.py` → `BRIDGE_TARGET_APPS` via `SOCIAL_MEDIA_PACKAGES` erweitert.

---

### ERGEBNIS Block 10 — GMS-Ausschluss in Zygisk: ✅ BEREITS KORREKT
**Analyse**: Der Zygisk-Module hat eine explizite `TARGET_APPS[]` Whitelist (Zeile 71-80 in `zygisk_module.cpp`). GMS/GSF/Vending sind **bewusst ausgeschlossen** (Kommentar Zeile 66-70). In `preAppSpecialize()` (Zeile 1923) wird geprüft: Wenn das Package NICHT in `TARGET_APPS` steht → Modul wird mit `DLCLOSE_MODULE_LIBRARY` entladen. **Play Integrity ist sicher.**

---

### FIX-20: Hardcoded Default-Werte im Zygisk-Module entfernen ✅ IMPLEMENTIERT
**Priorität**: MITTEL
**Problem**: `zygisk_module.cpp` Zeilen 83-89 definieren statische Default-Werte:
```cpp
static const char* DEFAULT_SERIAL = "28161FDF6006P8";
static const char* DEFAULT_IMEI1 = "352269111271008";
static const char* DEFAULT_IMEI2 = "358476312016587";
static const char* DEFAULT_ANDROID_ID = "d7f4b30e1b210a83";
static const char* DEFAULT_GSF_ID = "3a8c4f72d91e50b6";
static const char* DEFAULT_WIFI_MAC = "be:08:6e:16:a6:5d";
static const char* DEFAULT_WIDEVINE_ID = "10179c6bcba352dbd5ce5c88fec8e098";
```

Diese werden als Fallback verwendet wenn die Bridge-Datei nicht geladen werden kann. Das Risiko: Wenn die Bridge aus irgendeinem Grund fehlt (Datei gelöscht, Permissions falsch, Race-Condition beim Boot), bekommen ALLE Target-Apps **dieselben statischen IDs**. Das ist schlimmer als keine Hooks — weil es ein eindeutiger Fingerprint ist den kein echtes Gerät hat.

**Empfohlene Änderung**: Statt statische Defaults → **Hooks deaktivieren** wenn Bridge nicht geladen werden kann:
```cpp
// Statt:
if (!loadBridge()) { useDefaults(); }

// Besser:
if (!loadBridge()) {
    LOGW("[TITAN] Bridge nicht geladen — Hooks DEAKTIVIERT");
    m_shouldInject = false;  // Keine Hooks → echte Werte durchlassen
    return;
}
```

**Warum besser**: Echte Werte durchlassen ist weniger verdächtig als falsche statische Werte. Und der Auditor (FIX-17) würde den Fehler sofort erkennen.

**Wo**: `module/zygisk_module.cpp` → Zeilen 83-89 (Defaults) + `loadBridge()` / `postAppSpecialize()` Fehlerbehandlung.

---

## SPARRING BLOCK 12 — Datenbank-Konsistenz

### FIX-21: Foreign Key von RESTRICT auf CASCADE ändern ✅ IMPLEMENTIERT
**Priorität**: MITTEL
**Problem**: `profiles.identity_id` hat `ON DELETE RESTRICT`. Wenn eine Identität gelöscht wird die noch ein Profil hat, schlägt der DELETE fehl mit `FOREIGN KEY constraint failed`.

**Gewünschtes Verhalten** (User-Entscheidung): Identität löschen → verlinktes Profil wird **automatisch mitgelöscht**.

**Änderung**:
```sql
-- ALT:
identity_id INTEGER NOT NULL REFERENCES identities(id) ON DELETE RESTRICT

-- NEU:
identity_id INTEGER NOT NULL REFERENCES identities(id) ON DELETE CASCADE
```

**Achtung**: SQLite unterstützt kein `ALTER TABLE ... ALTER COLUMN`. Die Änderung erfordert eine **Schema-Migration**:
1. Neue Tabelle `profiles_new` mit `ON DELETE CASCADE` erstellen
2. Daten von `profiles` → `profiles_new` kopieren
3. Alte Tabelle löschen
4. Neue Tabelle umbenennen

**Wo**: `host/database.py` → Schema `_SQL_CREATE_PROFILES` + Migration-Logik in `_run_migrations()`.

---

## SPARRING BLOCK 9 — Flow-Robustheit (Genesis + Switch)

### FIX-28: Genesis — Sichere App-Reinstallation (FIX-13 Fallback-Bug) ✅ IMPLEMENTIERT
**Priorität**: KRITISCH
**Problem**: FIX-13 (`pm uninstall --user 0` + `pm install-existing`) hat einen kritischen Bug in der Fallback-Kette:
1. `pm uninstall --user 0 <pkg>` wird ausgeführt → App für User 0 entfernt
2. `pm install-existing --user 0 <pkg>` schlägt fehl (Pixel 6 / Android 14 — TikTok ist kein System-Package, Cache nicht verfügbar)
3. Fallback: `pm clear <pkg>` → tut **nichts**, weil die App bereits deinstalliert ist
4. Ergebnis: TikTok ist nach dem Hard Reset in Step 7 **verschwunden**

**Lösung**: APK-Pfad vor Uninstall sichern + mehrstufige Rettungskette:
1. **Schritt 0**: `pm path <pkg>` → APK-Pfad sichern (z.B. `/data/app/~~abc/base.apk`)
2. **Schritt 1**: `pm uninstall --user 0 <pkg>`
3. **Schritt 2**: `pm install-existing --user 0 <pkg>` versuchen
4. **Schritt 3**: `pm path <pkg>` → Verifikation ob App noch da ist
5. **Schritt 4** (Rettung): `pm install -r --user 0 <gespeicherter_pfad>` wenn App weg
6. **Schritt 5** (Letzter Fallback): `cmd package install-existing <pkg>`
7. **Sicherer Modus**: Wenn APK-Pfad nicht ermittelbar → kein `pm uninstall`, nur `pm clear`

**Neue Methoden in `shifter.py`**:
- `_get_apk_path(pkg)` → Ermittelt APK-Pfad via `pm path`
- `_verify_app_installed(pkg)` → Prüft ob App für User 0 verfügbar ist

**Wo**: `host/engine/shifter.py` → `deep_clean()` Schritt 1 (komplett überarbeitet)

---

### FIX-29: Switch — Gründlicher State-Wipe vor Restore ✅ IMPLEMENTIERT
**Priorität**: HOCH
**Problem**: Zwei Schwachstellen im Switch Flow:

**A) Kein Clean vor Restore:**
Zwischen Safety Kill (Step 3) und Restore (Step 5/6) sitzen die alten App-Daten unangetastet. Der Mini-Clean (FIX-16) bereinigt nur `/sdcard/` Tracking-Dateien, nicht die App-Daten in `/data/data/`. Wenn der Restore nur teilweise überschreibt, leaken alte Profil-Daten durch.

**B) Hidden-File-Bug in Restore-Methoden:**
`restore()` und `restore_tiktok_dual()` verwenden `rm -rf <path>/*` — der `/*`-Glob verpasst **dot-files** (z.B. `.device_id`, `.tt_session`, `.tobid_v2`). TikTok legt bewusst versteckte Tracking-Dateien an, die so den Restore überleben.

**Lösung**:

**Teil 1 — Neue `prepare_switch_clean()` Methode** (ersetzt FIX-16 Mini-Clean):
- Löscht `/data/data/<pkg>/` **komplett** (nicht nur `/*`) + neu erstellen
- Löscht TikTok Sandbox-Verzeichnisse auf `/sdcard/`
- Bereinigt alle Tracking-Globs + ByteDance Deep-Search Patterns
- Löscht ART Compiler Cache + Runtime Profiles
- Bereinigt Settings-ContentProvider (FIX-14 Werte)

**Teil 2 — Hidden-File-Bug Fix in `restore()` + `restore_tiktok_dual()`:**
```python
# ALT (verpasst dot-files):
rm -rf /data/data/<pkg>/*

# NEU (löscht ALLES):
rm -rf /data/data/<pkg>
mkdir -p /data/data/<pkg>
```

**Teil 3 — Switch Flow Step 3 erweitert:**
`clean_tracking_remnants()` (FIX-16) durch `prepare_switch_clean()` (FIX-29) ersetzt.

**Wo**:
- `host/engine/shifter.py` → Neue Methode `prepare_switch_clean()`, `restore()` rm-Fix, `restore_tiktok_dual()` rm-Fix
- `host/flows/switch.py` → Step 3→4 Transition: `prepare_switch_clean()` statt `clean_tracking_remnants()`

---

### FIX-30: Switch — Post-Restore Verifikation + Zombie-Schutz ✅ IMPLEMENTIERT
**Priorität**: HOCH
**Problem**: Nach dem Restore gibt es keine Prüfung ob die App-Daten tatsächlich geschrieben wurden. Wenn der Restore stillschweigend fehlschlägt:
- Bridge zeigt auf Identity B (neu)
- App-Daten sind leer oder gehören zu Identity A (alt)
- TikTok startet als "neue App" mit der falschen Identität → Detection

**Lösung**:

**Neue `verify_app_data_restored(pkg)` Methode in `shifter.py`:**
Prüft drei Kriterien:
1. `/data/data/<pkg>/` existiert
2. Mindestens `shared_prefs/`, `databases/` oder `files/` existiert
3. Verzeichnis hat > 0 Einträge (nicht leer)

Gibt detailliertes Dict zurück: `{ok, dir_exists, has_prefs, has_databases, has_files, file_count, detail}`

**Post-Restore Check im Switch Flow (zwischen Step 6 und 7):**
- Wird nach TikTok Restore ausgeführt (nur bei Full-State oder profile_name Modus)
- Bei Fehlschlag: **Zombie-Schutz** — `pm clear <pkg>` um inkonsistenten State zu verhindern
- Step 6 wird nachträglich als FAILED markiert
- Klares Error-Logging mit Verifikations-Details

**Wo**:
- `host/engine/shifter.py` → Neue Methode `verify_app_data_restored()`
- `host/flows/switch.py` → Neuer Zwischenschritt 6→7: Post-Restore Verifikation

---

## BEREITS GEFIXTE FINDINGS

### FIX-8: Genesis Flow meldet FEHLGESCHLAGEN bei SKIPPED Steps
**Status**: ✅ BEREITS GEFIXT (in dieser Session)
**Was**: `all(s.status == FlowStepStatus.SUCCESS ...)` zählte SKIPPED als Failure.
**Fix**: `s.status in (FlowStepStatus.SUCCESS, FlowStepStatus.SKIPPED)`

---

## UMSETZUNGSREIHENFOLGE

### Phase 1: TikTok Fresh-Install Fix (KRITISCH)
1. **FIX-1 + FIX-2** — ByteDance Deep-Search + Cache-Cleanup → behebt TikTok-Wiedererkennung
2. **FIX-13** — `pm uninstall --user 0` + `pm install-existing` → echter First-Launch-State

### Phase 2: Flow-Stabilität + Switch-Integrität (HOCH)
3. **FIX-15** — Sandbox-Lücke im Switch Flow → TikTok Sandbox-Restore reparieren
4. **FIX-16** — Mini-Clean vor Switch-Restore → ByteDance-Tracking-Reste entfernen
5. **FIX-10** — GMS Ready vereinfachen → eliminiert Flow-Hänger
6. **FIX-11** — TikTok Backup-Logik → intelligentes Auto-Backup
7. **FIX-3** — Backup-Whitelist → sauberere Backups

### Phase 3: Verifikation & IP-Sicherheit (HOCH)
8. **FIX-17** — Auditor Full + Quick Audit erweitern → alle Spoofing-Felder prüfen
9. **FIX-18** — IP-Collision-Detection → Cross-Profile IP-Korrelation erkennen

### Phase 4: Error Handling & Resilience (HOCH)
10. **FIX-22** — Genesis Rollback erweitern → `corrupted` nach Inject bei Fehler + WebUI-Info
11. **FIX-23** — Backup Atomic Write + Retry → keine korrupten Backups + WebUI-Info bei Abbruch

### Phase 5: Robustheit (HOCH → MITTEL)
12. **FIX-7** — `wm dismiss-keyguard` → 3 Zeilen, sofort wirksam
13. **FIX-5** — CE-Storage Check → robusterer Unlock-Check
14. **FIX-6** — USB-Reconnect → ADB-Zombie-State Fallback

### Phase 6: Verifikation & Monitoring (MITTEL)
15. **FIX-9** — Bridge-Verifikation alle Pfade → vollständige Post-Reboot-Prüfung
16. **FIX-4** — Integrity Guard → Backup-Validierung (braucht Testing)
17. **FIX-14** — Settings-ContentProvider Cleanup → TikTok System-Settings bereinigen
18. **FIX-12** — Xposed Debug-Log-Mode → Hook-Monitoring in WebUI
19. **FIX-20** — Hardcoded Defaults im Zygisk entfernen → Bridge-Fehler = Hooks aus
20. **FIX-21** — ON DELETE CASCADE → Profil wird mit Identität mitgelöscht
21. **FIX-25** — Persistenter File-Logger mit Rotation → Post-Mortem möglich
22. **FIX-26** — Polling-Guard → keine Race-Conditions im Frontend
23. **FIX-27** — Unbenutzte Endpoints löschen (4 von 7), Backup-Endpoints behalten

### Phase 7: Stealth-Hardening (MITTEL — eigene Phase) ✅ ABGESCHLOSSEN
24. **FIX-24** — String-Verschlüsselung + Raw Syscalls + memfd_create ✅

### Phase 8: Vorbereitung Multi-App (NIEDRIG — erst wenn Insta/Snap aktiviert) ✅ ABGESCHLOSSEN
25. **FIX-19** — Bridge-Distribution an Instagram + Snapchat ✅

### Phase 9: Flow-Robustheit — Genesis + Switch (KRITISCH) ✅ ABGESCHLOSSEN
26. **FIX-28** — Genesis: Sichere App-Reinstallation (APK-Pfad sichern + Verifikation) ✅
27. **FIX-29** — Switch: Gründlicher State-Wipe vor Restore (Hidden-File-Bug + prepare_switch_clean) ✅
28. **FIX-30** — Switch: Post-Restore Verifikation + Zombie-Schutz ✅

---

## DATEIEN DIE GEÄNDERT WERDEN

| Datei | Fixes |
|-------|-------|
| `host/engine/shifter.py` | FIX-1, FIX-2, FIX-3, FIX-4, FIX-5, FIX-13, FIX-14, FIX-16, FIX-28, FIX-29, FIX-30 |
| `host/adb/client.py` | FIX-6, FIX-7 |
| `host/flows/genesis.py` | FIX-9, FIX-10, FIX-11, FIX-18 |
| `host/flows/switch.py` | FIX-11, FIX-15, FIX-16, FIX-18, FIX-29, FIX-30 |
| `host/engine/auditor.py` | FIX-17 |
| `host/engine/db_ops.py` | FIX-18 |
| `host/database.py` | FIX-18 (Indizes aktivieren) |
| `app/.../TitanXposedModule.kt` | FIX-12 |
| `host/models/identity.py` | FIX-12 (Bridge-Feld `debug_hooks`) |
| `host/frontend/templates/dashboard.html` | FIX-18 (optional: IP-Metriken), FIX-22 + FIX-23 (WebUI-Meldungen) |
| `host/config.py` | FIX-19 (BRIDGE_TARGET_APPS erweitern) |
| `module/zygisk_module.cpp` | FIX-20 (Defaults entfernen), FIX-24 (XOR + Syscalls) |
| `common/hw_compat.cpp` (ehem. titan_hardware.cpp) | FIX-24 (XOR + Syscalls + memfd_create), FIX-31 (Stealth-Rename) |
| `host/main.py` | FIX-25 (File-Logger) |
| `host/frontend/templates/vault.html` | FIX-26 (Polling-Guard) |
| `host/api/vault.py` | FIX-27 (Endpoints löschen: credentials, status) |
| `host/api/dashboard.py` | FIX-27 (Endpoints löschen: profiles, farm-stats) |

---

## REFERENZ-PROJEKT

Ares/Maschina Pfad: `/Users/arvin/Documents/Android/Chaos/Android Automatisierung Maschina/`
Relevante Dateien:
- `core/shifter.py` — Deep Sanitize, Dual-Path Backup, Permissions, Integrity Guard
- `core/generator.py` — Identity Generator (ähnlich wie Titan, aber JSON-basiert)
- `core/injector.py` — Android Faker Injection (anderer Ansatz)
- `config.py` — ADB/Unlock-Konfiguration (Referenz für Timing-Werte)

---

## FIX-31: Operation Tarnkappe — Stealth-Hardening (Komplett-Rename)

**Problem:** Alle identifizierbaren Strings ("titan", "verifier", Package-Name, Log-Tags, Klassen-
namen, Dateipfade) waren im Klartext im Code und Binary. Anti-Cheat-Engines könnten diese via
`strings`, `logcat`, `ls /data/adb/modules/`, oder Package-Scanning erkennen.

**Lösung:** Umfassendes Renaming über das GESAMTE Projekt:

| Kategorie | Alt | Neu |
|-----------|-----|-----|
| Package-Name | `com.titan.verifier` | `com.oem.hardware.service` |
| Modul-ID | `titan_verifier` | `hw_overlay` |
| Bridge-Datei | `.titan_identity` | `.hw_config` |
| Kill-Switch | `titan_stop` | `.hw_disabled` |
| SO-Datei | `libtitan_zygisk.so` | `libhw_overlay.so` |
| App-Label | `Titan Verifier` | `Hardware Service` |
| Log-Tags | `TitanZygisk` / `TitanBridge` | DEAKTIVIERT (STEALTH_MODE) |
| C++ Klassen | `TitanModule` / `TitanHardware` | `CompatModule` / `HwCompat` |
| Kotlin Klassen | `TitanXposedModule` / `TitanBridgeReader` | `TelephonyServiceModule` / `ServiceConfigReader` |
| Python Klassen | `TitanShifter` / `TitanAuditor` / `TitanInjector` | `AppShifter` / `DeviceAuditor` / `BridgeInjector` |
| Logger | `titan.*` | `host.*` |
| API-Titel | `Project Titan — Command Center` | `Device Manager` |
| Datenbank | `titan.db` | `device_manager.db` |
| Log-Datei | `titan.log` | `host.log` |

**Betroffene Dateien:** 40+ (C++, Kotlin, Python, XML, HTML, Gradle, CMake)

**Verifikation:** `grep -ri "titan" --include="*.{py,cpp,h,kt,kts,xml,pro,html}" .` → **0 Treffer**
(Nur Build-Cache in `.cxx/` enthält noch alte Referenzen — wird beim nächsten Build regeneriert)

**WICHTIG — Device-Deployment erforderlich:**
1. Altes Modul deinstallieren: `adb shell rm -rf /data/adb/modules/titan_verifier`
2. Alte App deinstallieren: `adb uninstall com.titan.verifier`
3. Alte Bridge-Dateien entfernen: `adb shell rm /sdcard/.titan_identity /data/local/tmp/titan_stop`
4. Neues Modul deployen (hw_overlay) + neue App installieren (com.oem.hardware.service)
5. `.cxx/` Build-Cache löschen und Android-App neu bauen

Siehe: **STEALTH_PLAN.md** für vollständige Details.
