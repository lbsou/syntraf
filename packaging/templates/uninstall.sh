#!/bin/sh
# Désinstallation de SYNTRAF (serveur ou sonde). --purge efface aussi la configuration, les données et les journaux.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROLE=$(cat "$HERE/payload/ROLE")
OS=$(uname -s)
PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1
if [ "$OS" = Darwin ]; then
    PREFIX=/usr/local/syntraf-$ROLE; CONF_DIR=/usr/local/etc/syntraf-$ROLE
    DATA_DIR=/usr/local/var/syntraf-$ROLE; LOG_DIR=/usr/local/var/log/syntraf-$ROLE
    for c in syntraf-$ROLE syntraf-grafana syntraf-victoriametrics; do
        launchctl bootout "system/org.syntraf.$c" 2>/dev/null || true
        rm -f "/Library/LaunchDaemons/org.syntraf.$c.plist"
    done
else
    PREFIX=/opt/syntraf-$ROLE; CONF_DIR=/etc/syntraf-$ROLE
    DATA_DIR=/var/lib/syntraf-$ROLE; LOG_DIR=/var/log/syntraf-$ROLE
    if [ -d /run/systemd/system ]; then
        for c in syntraf-$ROLE syntraf-grafana syntraf-victoriametrics; do
            systemctl disable --now "$c" 2>/dev/null || true
            rm -f "/etc/systemd/system/$c.service"
        done
        systemctl daemon-reload
    elif command -v rc-service >/dev/null 2>&1; then
        for c in syntraf-$ROLE syntraf-grafana syntraf-victoriametrics; do
            [ -f "/etc/init.d/$c" ] || continue
            rc-service "$c" stop 2>/dev/null || true
            rc-update del "$c" default 2>/dev/null || true
            rm -f "/etc/init.d/$c"
        done
    fi
fi
rm -rf "$PREFIX"
if [ "$PURGE" = 1 ]; then
    rm -rf "$CONF_DIR" "$DATA_DIR" "$LOG_DIR"
    echo "SYNTRAF $ROLE désinstallé (configuration, données et journaux effacés)."
else
    echo "SYNTRAF $ROLE désinstallé. Gardés : $CONF_DIR, $DATA_DIR, $LOG_DIR (--purge pour les effacer)."
fi
