#!/data/data/com.termux/files/usr/bin/bash
# ================================================================
# Titan Verifier — Termux Setup Script
# ================================================================
# Installiert alle Abhängigkeiten und konfiguriert den On-Device
# Server in Termux auf dem Pixel 6.
#
# Voraussetzungen:
#   - Termux (F-Droid Version, NICHT Play Store!)
#   - Termux:Boot (für Autostart)
#   - KernelSU mit Root-Zugriff
#
# Aufruf:
#   pkg install git -y
#   git clone <repo-url> ~/titan
#   cd ~/titan && bash setup_termux.sh
# ================================================================

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log()  { echo -e "${GREEN}[TITAN]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ── 1. Termux-Pakete ──
log "Installiere Termux-Pakete..."
pkg update -y
pkg install -y python python-pip git tsu

# ── 2. Python Dependencies ──
log "Installiere Python-Pakete..."
pip install --upgrade pip
pip install -r requirements.txt

# ── 3. Umgebungsvariablen ──
PROFILE="$HOME/.bashrc"
if ! grep -q "TITAN_MODE" "$PROFILE" 2>/dev/null; then
    log "Setze TITAN_MODE=local in $PROFILE..."
    echo '' >> "$PROFILE"
    echo '# Titan On-Device Modus' >> "$PROFILE"
    echo 'export TITAN_MODE=local' >> "$PROFILE"
    echo 'export TITAN_HOME="$HOME/titan"' >> "$PROFILE"
fi
export TITAN_MODE=local

# ── 4. Backup-Verzeichnis ──
log "Erstelle Backup-Verzeichnis..."
mkdir -p backups

# ── 5. Termux:Boot Autostart ──
BOOT_DIR="$HOME/.termux/boot"
mkdir -p "$BOOT_DIR"
BOOT_SCRIPT="$BOOT_DIR/titan_start.sh"

cat > "$BOOT_SCRIPT" << 'BOOTEOF'
#!/data/data/com.termux/files/usr/bin/bash
# Titan Autostart — wird von Termux:Boot bei Geräte-Boot ausgeführt
termux-wake-lock

export TITAN_MODE=local
cd "$HOME/titan" || exit 1

# Warte bis Android vollständig gebootet ist
while [ "$(getprop sys.boot_completed)" != "1" ]; do
    sleep 3
done
sleep 10

# Server starten (Hintergrund + Log)
nohup python -m uvicorn host.main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --log-level info \
    > "$HOME/titan/host.log" 2>&1 &

echo "Titan Server gestartet (PID: $!)"
BOOTEOF
chmod +x "$BOOT_SCRIPT"
log "Autostart konfiguriert: $BOOT_SCRIPT"

# ── 6. Termux Storage Permission ──
if [ ! -d "$HOME/storage" ]; then
    log "Termux Storage-Zugriff wird angefordert..."
    termux-setup-storage || warn "Storage-Setup fehlgeschlagen (manuell: termux-setup-storage)"
fi

# ── 7. Root-Check ──
log "Prüfe Root-Zugriff..."
if su -c "id" 2>/dev/null | grep -q "uid=0"; then
    log "Root via su: OK"
else
    warn "Root-Zugriff nicht verfügbar! Stelle sicher dass KernelSU Termux erlaubt."
    warn "KernelSU → Module Manager → Termux → 'Superuser' aktivieren"
fi

# ── 8. Zusammenfassung ──
echo ""
echo "================================================================"
log "Setup abgeschlossen!"
echo "================================================================"
echo ""
echo "  Server starten:  cd ~/titan && TITAN_MODE=local python -m uvicorn host.main:app --host 0.0.0.0 --port 8000"
echo "  Web UI:          http://localhost:8000"
echo "  Autostart:       Automatisch bei Geräte-Boot (via Termux:Boot)"
echo "  Modus:           TITAN_MODE=local (On-Device, kein ADB nötig)"
echo ""
echo "  Rollback:        Einfach Termux deinstallieren oder:"
echo "                   rm -rf ~/titan ~/.termux/boot/titan_start.sh"
echo ""
