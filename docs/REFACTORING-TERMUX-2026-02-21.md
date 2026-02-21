# Refactoring: ADB → On-Device (Termux) — 2026-02-21

## Ziel

Das System soll ohne Laptop funktionieren. Der gesamte Python-Stack
(FastAPI, Flows, HookGuard, DB) läuft direkt auf dem Pixel 6 in Termux.
ADB-Befehle werden durch direkte Root-Shell-Aufrufe (`su -c`) ersetzt.

## Backup

Vor dem Refactoring wurde der komplette Stand gepusht:

```
Repository: https://github.com/xarvinxx/TitanTermux.git
Branch:     main
Commit:     af933c4 (modifieed)
Datum:      2026-02-21
```

**Rollback:** `git clone https://github.com/xarvinxx/TitanTermux.git` → identischer Stand vor allen Änderungen.

---

## Übersicht der Änderungen

| # | Datei | Änderung | Rollback |
|---|-------|----------|----------|
| 1 | `host/adb/local_client.py` | **NEU** — LocalShellClient als ADB-Ersatz | Datei löschen |
| 2 | `host/adb/__init__.py` | Export von LocalShellClient hinzugefügt | Zeile entfernen |
| 3 | `host/adb/client.py` | **UNVERÄNDERT** — ADBClient bleibt komplett erhalten | — |
| 4 | `host/config.py` | `EXECUTION_MODE` Config hinzugefügt (`adb` / `local`) | Zeilen entfernen |
| 5 | `host/main.py` | Client-Auswahl basierend auf `EXECUTION_MODE` | Alten Code wiederherstellen |
| 6 | `host/flows/genesis.py` | `adb.reboot()` → Zygote-Restart (nur im `local` Mode) | Revert |
| 7 | `host/flows/switch.py` | Keine `is_connected`/`ensure_connection` Aufrufe im `local` Mode | Revert |
| 8 | `setup_termux.sh` | **NEU** — Termux Setup-Script | Datei löschen |
| 9 | `termux_boot/titan_start.sh` | **NEU** — Autostart-Script für Termux:Boot | Datei löschen |

---

## Architektur: Vorher vs. Nachher

### Vorher (Laptop + USB)
```
┌─────────────┐    USB/ADB    ┌──────────────┐
│  MacBook     │──────────────│  Pixel 6     │
│  Python      │  adb shell   │  Zygisk      │
│  FastAPI     │◄────────────►│  KernelSU    │
│  SQLite      │  adb push    │  TikTok      │
│  Web UI      │              │              │
└─────────────┘              └──────────────┘
```

### Nachher (Alles auf dem Pixel 6)
```
┌──────────────────────────────────────────┐
│  Pixel 6                                 │
│  ┌────────────────────────────────────┐  │
│  │  Termux                            │  │
│  │  Python + FastAPI + SQLite + WebUI │  │
│  │  LocalShellClient (su -c)          │  │
│  └──────────┬─────────────────────────┘  │
│             │ su -c "..."                 │
│  ┌──────────▼─────────────────────────┐  │
│  │  Android System                    │  │
│  │  Zygisk / KernelSU / SUSFS        │  │
│  │  TikTok                            │  │
│  └────────────────────────────────────┘  │
└──────────────────────────────────────────┘
  Browser: localhost:8000
```

---

## Detaillierte Änderungen

### 1. `host/adb/local_client.py` (NEU)

Drop-in-Ersatz für `ADBClient`. Gleiche API (`shell()`, `push()`, `pull()`,
`is_connected()`, `ensure_connection()`, `reboot()`, `wait_for_device()`,
`exec_out_to_file()`, `exec_in_from_file()`, `unlock_device()`,
`has_root()`, `check_wadbd_available()`, `connect_wireless()`), aber:

- `shell(cmd, root=True)` → `su -c "cmd"` via `asyncio.create_subprocess_exec`
- `shell(cmd, root=False)` → `sh -c "cmd"` via subprocess
- `push(local, remote)` → `su -c "cp local remote"` (selbes Filesystem)
- `pull(remote, local)` → `su -c "cp remote local"`
- `is_connected()` → immer `True` (wir SIND das Gerät)
- `ensure_connection()` → immer `True`
- `reboot()` → `su -c "svc power reboot"` (**WARNUNG: killt Termux!**)
- `wait_for_device()` → wartet bis `sys.boot_completed == 1`
- `exec_out_to_file()` → `su -c "cmd"` mit stdout → Datei
- `exec_in_from_file()` → Datei → stdin von `su -c "cmd"`
- `unlock_device()` → `input keyevent` + Swipe + `wm dismiss-keyguard`
- `has_root()` → prüft `su -c "id"` enthält `uid=0`
- `check_wadbd_available()` → Nicht relevant, gibt leeres Result
- `connect_wireless()` → Nicht relevant, gibt `False` zurück

**Gibt `ADBResult` zurück** — identisch zum Original, damit alle Aufrufer
ohne Änderung funktionieren.

### 2. `host/config.py` — EXECUTION_MODE + Factory

```python
# Neuer Config-Wert:
EXECUTION_MODE = os.environ.get("TITAN_MODE", "adb")  # "adb" oder "local"

def create_adb_client():
    """Factory: Erstellt den richtigen Client basierend auf EXECUTION_MODE."""
    if EXECUTION_MODE == "local":
        from host.adb.local_client import LocalShellClient
        return LocalShellClient()
    else:
        from host.adb.client import ADBClient
        return ADBClient()
```

- `"adb"` = Originales Verhalten (Laptop + USB). **Default** wenn keine Env-Variable gesetzt.
- `"local"` = On-Device Modus (Termux). LocalShellClient wird verwendet.
- `create_adb_client()` wird überall statt direktem `ADBClient()` verwendet.

### 3. `host/main.py` — Client-Auswahl

```python
from host.config import EXECUTION_MODE, create_adb_client
adb = create_adb_client()
```

### 4. API-Module — Factory statt direkte Instanziierung

In allen API-Modulen (`host/api/control.py`, `host/api/dashboard.py`,
`host/api/vault.py`) wurde `from host.adb.client import ADBClient` durch
`from host.config import create_adb_client` ersetzt und alle `ADBClient()`
Aufrufe durch `create_adb_client()`.

### 5. Genesis Flow — Reboot-Ersatz

Im `local` Mode wird `adb.reboot()` in Genesis Step 7 durch einen
Zygote-Restart ersetzt:

```python
if EXECUTION_MODE == "local":
    # Zygote-Restart statt Hard-Reboot (killt sonst Termux)
    await self._adb.shell("killall zygote", root=True, timeout=10)
    await asyncio.sleep(20)
    booted = await self._adb.wait_for_device(timeout=60, poll_interval=3)
else:
    await self._adb.reboot()
    # ... ADB Reconnect + wait_for_device ...
```

### 6. Switch Flow — Auto-Recovery Anpassung

Im `local` Mode wird der Bootloop-Recovery `reboot bootloader` durch
einen Zygote-Restart ersetzt (Fastboot nicht möglich ohne Laptop):

```python
if EXECUTION_MODE == "local":
    await self._adb.shell("killall zygote", root=True)
else:
    await self._adb.shell("reboot bootloader", root=True)
```

### 7. `is_connected()` / `ensure_connection()` Aufrufe

Im `local` Mode geben diese immer `True` zurück. Kein Code muss
geändert werden — der LocalShellClient handled das intern.

### 8. `setup_termux.sh` (NEU)

Automatisches Setup-Script für Termux:
- Installiert `python`, `python-pip`, `git`, `tsu`
- Installiert Python-Abhängigkeiten via `pip install -r requirements.txt`
- Setzt `TITAN_MODE=local` in `~/.bashrc`
- Erstellt Termux:Boot Autostart-Script (`~/.termux/boot/titan_start.sh`)
- Prüft Root-Zugriff via `su`

---

## SUSFS-Hiding für Termux

Termux muss vor TikTok versteckt werden, da TikTok nach installierten
Apps scannt und Root-Tools/Termux als Manipulation-Hinweis wertet.

### Was versteckt werden muss

| Was | Pfad | Warum |
|-----|------|-------|
| Termux App | `com.termux` | Package-Name in Installed-Apps-Liste |
| Termux:Boot | `com.termux.boot` | Package-Name |
| Termux-Dateien | `/data/data/com.termux/` | Datei-Scan |
| Python Server | Port 8000 | Netzwerk-Scan (`/proc/net/tcp`) |

### Wie verstecken (SUSFS + KernelSU)

**1. Apps verstecken (KernelSU App-Hide)**
```bash
# In KernelSU → Module Manager → Termux:
# "Hide from app list" aktivieren für:
#   - com.termux
#   - com.termux.boot
#   - com.termux.api (falls installiert)
```

**2. SUSFS Konfiguration**

SUSFS kann `/proc/net/tcp` Einträge und Dateisystem-Pfade verstecken:

```bash
# /data/adb/modules/susfs/.susfs_config

# Termux-Paket von Package-Liste verstecken
sus_mount /data/app/*/com.termux-*/
sus_mount /data/app/*/com.termux.boot-*/

# /proc/net/tcp Eintrag für Port 8000 verstecken
sus_sus_port 8000
```

**3. Unser Zygisk-Modul**

Das bestehende Zygisk-Modul hookt bereits `fopen`/`open` für
`/proc/self/maps`. Für den On-Device Modus sollte es zusätzlich
`/proc/net/tcp` filtern um Port 8000 zu verstecken.

**Status**: Diese SUSFS-Anpassungen sind **manuell** auf dem Gerät
durchzuführen nachdem Termux installiert ist. Sie sind NICHT Teil
des automatischen Setups.

---

## Rollback-Anleitung (Komplett)

Falls das Refactoring rückgängig gemacht werden soll:

### Option A: Git Reset (schnellste Methode)
```bash
cd /Users/arvin/Documents/Android/Chaos/TitanXFarm/titanverifier
git log --oneline -5    # Letzten pre-refactoring Commit finden
git reset --hard af933c4  # Auf den Backup-Commit zurücksetzen
```

### Option B: Vom Backup-Repo klonen
```bash
git clone https://github.com/xarvinxx/TitanTermux.git
# → Identischer Stand vor dem Refactoring
```

### Option C: Manuell (einzelne Dateien)

Folgende Änderungen rückgängig machen:

1. **Dateien löschen**:
   - `rm host/adb/local_client.py`
   - `rm setup_termux.sh`
   
2. **`host/adb/__init__.py`**: `LocalShellClient` Import und Export entfernen

3. **`host/config.py`**:
   - `import os` entfernen (wenn nur dafür hinzugefügt)
   - `EXECUTION_MODE` Zeilen entfernen (Zeile 20-29)
   - `create_adb_client()` Funktion entfernen

4. **`host/main.py`**: 
   - `from host.config import EXECUTION_MODE, create_adb_client` → `from host.adb.client import ADBClient`
   - `adb = create_adb_client()` → `adb = ADBClient()`

5. **`host/api/control.py`**:
   - `from host.config import create_adb_client` → `from host.adb.client import ADBClient`
   - Alle `create_adb_client()` → `ADBClient()`

6. **`host/api/dashboard.py`**:
   - `from host.config import create_adb_client` → `from host.adb.client import ADBClient`
   - `create_adb_client()` → `ADBClient()`

7. **`host/api/vault.py`**:
   - Alle `from host.config import create_adb_client` → `from host.adb.client import ADBClient`
   - Alle `create_adb_client()` → `ADBClient()`

8. **`host/flows/genesis.py`**:
   - `EXECUTION_MODE` aus Import entfernen
   - Zygote-Restart Conditional entfernen, zurück zum originalen Reboot-Block

9. **`host/flows/switch.py`**:
   - `EXECUTION_MODE` aus Import entfernen
   - Auto-Recovery Conditional entfernen, zurück zu `reboot bootloader`

---

## Geräte-Sicherheit

Dieses Refactoring ändert **nichts** am Gerät selbst:
- Kein Kernel-Modul wird verändert
- Keine System-Partition wird berührt
- KernelSU, Zygisk, SUSFS bleiben unverändert
- Die Bridge-Datei (.hw_config) wird nicht verändert
- Alle Änderungen sind rein Python-seitig

Falls Termux Probleme macht: App deinstallieren → alles weg.

**WARNUNG**: Der `reboot()` Befehl im On-Device Modus beendet Termux
und damit den Server. Nach einem Reboot muss Termux manuell gestartet
werden ODER Termux:Boot übernimmt den Autostart.

---

## Fortschritt

- [x] Backup gepusht (TitanTermux.git)
- [x] ADBClient Interface analysiert (13 Methoden, ~180 shell-Aufrufe)
- [x] LocalShellClient implementiert (host/adb/local_client.py)
- [x] Config EXECUTION_MODE + Factory hinzugefügt (host/config.py)
- [x] main.py Client-Auswahl (create_adb_client)
- [x] API-Module: ADBClient() → create_adb_client() (control, dashboard, vault)
- [x] Genesis Reboot → Zygote-Restart (EXECUTION_MODE conditional)
- [x] Switch Auto-Recovery → Zygote-Restart (EXECUTION_MODE conditional)
- [x] Termux Setup-Script (setup_termux.sh)
- [x] SUSFS-Hiding Anleitung dokumentiert
- [ ] End-to-End Test auf dem Gerät

---

*Letzte Aktualisierung: 2026-02-21*
