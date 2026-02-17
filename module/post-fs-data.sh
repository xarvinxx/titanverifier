#!/system/bin/sh
MODDIR="${0%/*}"
BF="$MODDIR/.hw_config"
[ -f "$BF" ] && chcon u:object_r:system_file:s0 "$BF" 2>/dev/null
[ -f "$BF" ] && chmod 644 "$BF" 2>/dev/null
