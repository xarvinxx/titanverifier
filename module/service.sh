#!/system/bin/sh
# Ghost Protocol v9.0 — Post-Boot Service
# Runs after system_server is ready (settings commands available)
TAG="ghost"
log() { log -t "$TAG" -p i "$1" 2>/dev/null; }

# ---------------------------------------------------------------------------
# 1. WiFi MAC-Randomisierung deaktivieren
#    Damit das Framework unsere gespoofed MAC konsistent nutzt
# ---------------------------------------------------------------------------
settings put global wifi_connected_mac_randomization_enabled 0 2>/dev/null
settings put global wifi_scan_always_enabled 0 2>/dev/null

# ---------------------------------------------------------------------------
# 2. ADB-Spuren verbergen (fuer Produktion)
#    persist.sys.usb.config = mtp (ohne adb)
#    Auskommentiert waehrend Entwicklung — aktivieren fuer Production
# ---------------------------------------------------------------------------
# resetprop persist.sys.usb.config mtp

# ---------------------------------------------------------------------------
# 3. Carrier Properties Watchdog (Backup fuer SELinux deny)
#    Prueft alle 10s ob rild unsere Werte ueberschrieben hat
# ---------------------------------------------------------------------------
(
    while true; do
        cur_sim=$(getprop gsm.sim.operator.numeric)
        cur_op=$(getprop gsm.operator.numeric)
        if [ "$cur_sim" != "26207" ] || [ "$cur_op" != "26207" ]; then
            resetprop gsm.sim.operator.numeric 26207
            resetprop gsm.sim.operator.alpha "o2 - de"
            resetprop gsm.operator.numeric 26207
            resetprop gsm.operator.alpha "o2-de"
            resetprop gsm.sim.operator.iso-country de
            resetprop gsm.operator.iso-country de
        fi
        sleep 10
    done
) &

# ---------------------------------------------------------------------------
# 4. Revert mount hiding nach Boot (optional, fuer Stabilitaet)
#    Manche Module brauchen sichtbare Mounts nach dem Boot
# ---------------------------------------------------------------------------
SUSFS="/data/adb/ksu/bin/ksu_susfs"
if [ -x "$SUSFS" ]; then
    $SUSFS hide_sus_mnts_for_non_su_procs 0 2>/dev/null
fi

log "Post-boot service completed"
