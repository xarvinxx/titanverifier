#!/system/bin/sh
# Ghost Protocol v9.0 — Kernel-Boot-Layer
# Runs as root in post-fs-data (before Zygote, before WiFi/BT HAL)
MODDIR="${0%/*}"
BF="$MODDIR/.hw_config"
SUSFS="/data/adb/ksu/bin/ksu_susfs"
FAKE_DIR="/data/adb/ksu/bin"
TAG="ghost"

log() { log -t "$TAG" -p i "$1" 2>/dev/null; }

[ -f "$BF" ] && chcon u:object_r:system_file:s0 "$BF" 2>/dev/null
[ -f "$BF" ] && chmod 644 "$BF" 2>/dev/null

# ---------------------------------------------------------------------------
# 1. Boot-Security Properties (unlocked bootloader verbergen)
# ---------------------------------------------------------------------------
resetprop ro.boot.verifiedbootstate green
resetprop ro.boot.flash.locked 1
resetprop ro.boot.vbmeta.device_state locked
resetprop ro.debuggable 0
resetprop ro.secure 1
resetprop ro.adb.secure 1
resetprop ro.build.selinux 0

# ---------------------------------------------------------------------------
# 2. Identity Properties aus Bridge-Datei lesen und setzen
# ---------------------------------------------------------------------------
if [ -f "$BF" ]; then
    while IFS='=' read -r key value; do
        # Kommentare und leere Zeilen ueberspringen
        case "$key" in
            ""|\#*) continue ;;
        esac
        # Whitespace trimmen
        key=$(echo "$key" | tr -d '[:space:]')
        value=$(echo "$value" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        [ -z "$key" ] || [ -z "$value" ] && continue

        # ro.* Properties direkt per resetprop setzen
        case "$key" in
            ro.*)
                resetprop "$key" "$value"
                ;;
            serial)
                resetprop ro.serialno "$value"
                resetprop ro.boot.serialno "$value"
                ;;
            boot_serial)
                resetprop ro.boot.serialno "$value"
                ;;
        esac
    done < "$BF"
    log "Identity properties loaded from bridge"
fi

# ---------------------------------------------------------------------------
# 3. Carrier Properties setzen (O2 DE)
# ---------------------------------------------------------------------------
resetprop gsm.sim.operator.numeric 26207
resetprop gsm.sim.operator.alpha "o2 - de"
resetprop gsm.operator.numeric 26207
resetprop gsm.operator.alpha "o2-de"
resetprop gsm.sim.operator.iso-country de
resetprop gsm.operator.iso-country de

# ---------------------------------------------------------------------------
# 4. SELinux: RIL daran hindern, gsm.* Properties zu ueberschreiben
# ---------------------------------------------------------------------------
if command -v supolicy >/dev/null 2>&1; then
    supolicy --live "deny rild radio_prop:property_service set" 2>/dev/null
    supolicy --live "deny rild telephony_status_prop:property_service set" 2>/dev/null
    log "SELinux: rild property write blocked"
fi

# ---------------------------------------------------------------------------
# 5. SUSFS: Virtuelle Dateisystem-Umleitungen
# ---------------------------------------------------------------------------
if [ -x "$SUSFS" ]; then
    # 5a. /proc/net/arp — leere Tabelle (keine MAC-Leaks)
    if [ -f "$FAKE_DIR/.fake_arp" ]; then
        $SUSFS add_sus_kstat /proc/net/arp 2>/dev/null
        $SUSFS add_open_redirect /proc/net/arp "$FAKE_DIR/.fake_arp" 2>/dev/null
        $SUSFS update_sus_kstat /proc/net/arp 2>/dev/null
    fi

    # 5b. /sys/class/net/wlan0/address — gespoofed MAC
    if [ -f "$FAKE_DIR/.fake_mac" ]; then
        $SUSFS add_sus_kstat /sys/class/net/wlan0/address 2>/dev/null
        $SUSFS add_open_redirect /sys/class/net/wlan0/address "$FAKE_DIR/.fake_mac" 2>/dev/null
        $SUSFS update_sus_kstat /sys/class/net/wlan0/address 2>/dev/null
    fi

    # 5c. /proc/bus/input/devices — Clean Pixel 6 Dump
    if [ -f "$FAKE_DIR/.fake_input" ]; then
        $SUSFS add_sus_kstat /proc/bus/input/devices 2>/dev/null
        $SUSFS add_open_redirect /proc/bus/input/devices "$FAKE_DIR/.fake_input" 2>/dev/null
        $SUSFS update_sus_kstat /proc/bus/input/devices 2>/dev/null
    fi

    # 5d. /proc/cpuinfo — Fake Tensor G1 CPU Info
    if [ -f "$FAKE_DIR/.fake_cpuinfo" ]; then
        $SUSFS add_sus_kstat /proc/cpuinfo 2>/dev/null
        $SUSFS add_open_redirect /proc/cpuinfo "$FAKE_DIR/.fake_cpuinfo" 2>/dev/null
        $SUSFS update_sus_kstat /proc/cpuinfo 2>/dev/null
    fi

    # 5e. /proc/version — Stock Kernel Version String
    if [ -f "$FAKE_DIR/.fake_version" ]; then
        $SUSFS add_sus_kstat /proc/version 2>/dev/null
        $SUSFS add_open_redirect /proc/version "$FAKE_DIR/.fake_version" 2>/dev/null
        $SUSFS update_sus_kstat /proc/version 2>/dev/null
    fi

    # 5f. /proc/net/if_inet6 — nur Loopback (keine EUI-64 MAC Leaks)
    if [ -f "$FAKE_DIR/.fake_if_inet6" ]; then
        $SUSFS add_sus_kstat /proc/net/if_inet6 2>/dev/null
        $SUSFS add_open_redirect /proc/net/if_inet6 "$FAKE_DIR/.fake_if_inet6" 2>/dev/null
        $SUSFS update_sus_kstat /proc/net/if_inet6 2>/dev/null
    fi

    # 5h. Root-Artefakte verstecken
    $SUSFS add_sus_path /data/adb/modules 2>/dev/null
    $SUSFS add_sus_path /data/adb/ksu 2>/dev/null
    $SUSFS add_sus_path /data/adb/lspd 2>/dev/null

    # 5i. Mount-Hiding fuer nicht-root Prozesse
    $SUSFS hide_sus_mnts_for_non_su_procs 1 2>/dev/null

    # 5j. AVC Log Spoofing (su -> kernel)
    $SUSFS enable_avc_log_spoofing 1 2>/dev/null

    # 5k. Kernel uname spoofing (verstecke Custom-Kernel-Kennung)
    STOCK_RELEASE="5.10.209-android13-4-00553-g39ffc30b7e63"
    STOCK_VERSION="#1 SMP PREEMPT Thu Mar 21 19:14:36 UTC 2024"
    $SUSFS set_uname "$STOCK_RELEASE" "$STOCK_VERSION" 2>/dev/null

    # 5l. /proc/cmdline oder /proc/bootconfig spoofing
    if [ -f "$FAKE_DIR/.fake_bootconfig" ]; then
        $SUSFS set_cmdline_or_bootconfig "$FAKE_DIR/.fake_bootconfig" 2>/dev/null
    fi

    log "SUSFS redirects and hiding configured"
else
    log "WARNING: ksu_susfs not found at $SUSFS"
fi
