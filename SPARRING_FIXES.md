# Project Titan — Sparring Fixes Kontextsheet
## CTO-Analyse: Was ausgebessert werden muss

**Erstellt**: 2026-02-12
**Quelle**: Vergleich Titan (aktuell) vs. Ares/Maschina (alt) + CTO-Sparring (Block 1-8)
**Status**: Dokumentiert — Umsetzung ausstehend
**Fixes**: 18 dokumentiert (1 bereits gefixt)

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

### FIX-4: Integrity Guard (Dateianzahl + Größenvergleich)
**Problem**: Titan prüft nur ob tar > 0 Bytes ist. Das erkennt keine teilweise korrupten Backups (z.B. wenn ADB-Verbindung während Stream abbricht und nur 10% der Daten übertragen wurden).

**Empfohlene Änderung**: Nach Backup die Statistiken auf dem Gerät vs. lokal vergleichen:
1. Device: `find <path> -type f | wc -l` + `du -sb <path>`
2. Lokal: tar inspizieren oder entpacken + vergleichen
3. Toleranz: 5% Dateianzahl, 10% Größe (Dateisystem-Unterschiede)

**Wo**: `host/engine/shifter.py` → `backup_tiktok_dual()` — nach dem tar-Stream als Validierung.

**Referenz**: Ares `core/shifter.py` Zeilen 1159-1300

---

### FIX-5: CE-Storage Unlock-Check via `dumpsys window`
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

### FIX-6: USB-Reconnect Simulation nach Reboot
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

### FIX-7: `wm dismiss-keyguard` als Unlock-Fallback
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

### FIX-14: TikTok Settings-ContentProvider Werte bereinigen
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

### FIX-9: Bridge-Verifikation auf ALLE Pfade ausweiten (Post-Reboot)
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

### FIX-12: Xposed Debug-Log-Mode (Hook-Monitoring für WebUI)
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

### FIX-17: Host-Side Auditor erweitern (Full + Quick Audit)
**Priorität**: HOCH
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

### FIX-18: IP-Duplikat-Erkennung (IP-Datenbank mit Collision-Check)
**Priorität**: HOCH
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

### Phase 4: Robustheit (HOCH → MITTEL)
10. **FIX-7** — `wm dismiss-keyguard` → 3 Zeilen, sofort wirksam
11. **FIX-5** — CE-Storage Check → robusterer Unlock-Check
12. **FIX-6** — USB-Reconnect → ADB-Zombie-State Fallback

### Phase 5: Verifikation & Monitoring (MITTEL)
13. **FIX-9** — Bridge-Verifikation alle Pfade → vollständige Post-Reboot-Prüfung
14. **FIX-4** — Integrity Guard → Backup-Validierung (braucht Testing)
15. **FIX-14** — Settings-ContentProvider Cleanup → TikTok System-Settings bereinigen
16. **FIX-12** — Xposed Debug-Log-Mode → Hook-Monitoring in WebUI

---

## DATEIEN DIE GEÄNDERT WERDEN

| Datei | Fixes |
|-------|-------|
| `host/engine/shifter.py` | FIX-1, FIX-2, FIX-3, FIX-4, FIX-5, FIX-13, FIX-14, FIX-16 |
| `host/adb/client.py` | FIX-6, FIX-7 |
| `host/flows/genesis.py` | FIX-9, FIX-10, FIX-11, FIX-18 |
| `host/flows/switch.py` | FIX-11, FIX-15, FIX-16, FIX-18 |
| `host/engine/auditor.py` | FIX-17 |
| `host/engine/db_ops.py` | FIX-18 |
| `host/database.py` | FIX-18 (Indizes aktivieren) |
| `app/.../TitanXposedModule.kt` | FIX-12 |
| `host/models/identity.py` | FIX-12 (Bridge-Feld `debug_hooks`) |
| `host/frontend/templates/dashboard.html` | FIX-18 (optional: IP-Metriken) |

---

## REFERENZ-PROJEKT

Ares/Maschina Pfad: `/Users/arvin/Documents/Android/Chaos/Android Automatisierung Maschina/`
Relevante Dateien:
- `core/shifter.py` — Deep Sanitize, Dual-Path Backup, Permissions, Integrity Guard
- `core/generator.py` — Identity Generator (ähnlich wie Titan, aber JSON-basiert)
- `core/injector.py` — Android Faker Injection (NICHT relevant für Titan — anderer Ansatz)
- `config.py` — ADB/Unlock-Konfiguration (Referenz für Timing-Werte)
