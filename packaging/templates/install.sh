#!/bin/sh
# Installation hors ligne de SYNTRAF (serveur ou sonde) : Debian, RHEL, Alpine, macOS.
#
#   sudo ./install.sh --server 10.0.0.5 --token <jeton>             # sonde
#   sudo ./install.sh                                               # serveur + VictoriaMetrics + Grafana, reliés
#   ./install.sh --help
#
# Réinstaller par-dessus une installation existante la met à jour : la configuration et les données (clés, jeton,
# mesures, tableaux de bord) sont gardées ; le code, Python, iperf3v, VictoriaMetrics et Grafana sont remplacés.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ROLE=$(cat "$HERE/payload/ROLE")
VERSION=$(cat "$HERE/payload/VERSION")
OS=$(uname -s)

if [ "$OS" = "Darwin" ]; then
    PREFIX=/usr/local/syntraf-$ROLE; CONF_DIR=/usr/local/etc/syntraf-$ROLE
    DATA_DIR=/usr/local/var/syntraf-$ROLE; LOG_DIR=/usr/local/var/log/syntraf-$ROLE
    # Archive téléchargée par un navigateur : macOS met en quarantaine tout ce qui en sort et bloquerait iperf3v,
    # Python, VictoriaMetrics et Grafana (non notariés) ; le package a été vérifié par son empreinte (SHA256SUMS)
    xattr -dr com.apple.quarantine "$HERE" 2>/dev/null || true
else
    PREFIX=/opt/syntraf-$ROLE; CONF_DIR=/etc/syntraf-$ROLE
    DATA_DIR=/var/lib/syntraf-$ROLE; LOG_DIR=/var/log/syntraf-$ROLE
fi
SERVER=""; TOKEN=""; UID_NAME=""; SERVER_PORT=6531; WEBUI_PORT=5000; GRAFANA_PORT=3000; RETENTION=12
SERVICE=1; STACK=1

usage() {
    cat <<EOF
SYNTRAF $ROLE $VERSION : installation hors ligne.

Options :
  --prefix DIR        code, Python et iperf3v (défaut : $PREFIX)
  --config-dir DIR    configuration (défaut : $CONF_DIR)
  --data-dir DIR      clés, jeton, releases de mise à jour (défaut : $DATA_DIR)
  --log-dir DIR       journaux (défaut : $LOG_DIR)
  --no-service        ne crée ni ne démarre de service
Sonde :
  --server ADRESSE    serveur SYNTRAF (obligatoire à la première installation)
  --token JETON       jeton d'enrôlement (Server › Tokens du serveur)
  --uid NOM           nom de la sonde (défaut : nom de la machine)
  --server-port PORT  canal de contrôle (défaut : 6531)
Serveur :
  --webui-port PORT   interface web (défaut : 5000)
  --server-port PORT  canal de contrôle des sondes (défaut : 6531)
  --grafana-port PORT Grafana (défaut : 3000)
  --retention MOIS    conservation des mesures dans VictoriaMetrics (défaut : 12)
  --no-stack          sans VictoriaMetrics ni Grafana (vous avez déjà les vôtres)
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix) PREFIX=$2; shift ;;
        --config-dir) CONF_DIR=$2; shift ;;
        --data-dir) DATA_DIR=$2; shift ;;
        --log-dir) LOG_DIR=$2; shift ;;
        --no-service) SERVICE=0 ;;
        --server) SERVER=$2; shift ;;
        --token) TOKEN=$2; shift ;;
        --uid) UID_NAME=$2; shift ;;
        --server-port) SERVER_PORT=$2; shift ;;
        --webui-port) WEBUI_PORT=$2; shift ;;
        --grafana-port) GRAFANA_PORT=$2; shift ;;
        --retention) RETENTION=$2; shift ;;
        --no-stack) STACK=0 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "option inconnue : $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done
[ "$ROLE" = server ] && [ -f "$HERE/payload/stack/victoria-metrics.tar.gz" ] || STACK=0

if [ "$SERVICE" = 1 ] && [ "$(id -u)" != 0 ]; then
    echo "Lancer en root (sudo), ou avec --no-service et des répertoires accessibles." >&2
    exit 1
fi

CONF=$CONF_DIR/config.toml
if [ -n "$TOKEN" ] && { [ ${#TOKEN} -lt 5 ] || [ ${#TOKEN} -gt 255 ]; }; then
    echo "Le jeton doit faire de 5 à 255 caractères." >&2
    exit 2
fi
SERVICE_NAME=syntraf-$ROLE
if [ "$ROLE" = probe ] && [ ! -f "$CONF" ] && { [ -z "$SERVER" ] || [ -z "$TOKEN" ]; }; then
    echo "Première installation d'une sonde : --server et --token sont nécessaires." >&2
    exit 2
fi

COMPONENTS=$SERVICE_NAME
[ "$STACK" = 1 ] && COMPONENTS="syntraf-victoriametrics syntraf-grafana $SERVICE_NAME"

service_stop() {
    if [ "$OS" = Darwin ]; then launchctl bootout "system/org.syntraf.$1" 2>/dev/null || true
    elif [ -d /run/systemd/system ]; then systemctl stop "$1" 2>/dev/null || true
    elif command -v rc-service >/dev/null 2>&1; then rc-service "$1" stop 2>/dev/null || true; fi
}

# Crée et démarre le service NAME, qui exécute le script de lancement RUN
service_add() {
    name=$1; run=$2
    if [ "$OS" = Darwin ]; then
        plist=/Library/LaunchDaemons/org.syntraf.$name.plist
        cat > "$plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>org.syntraf.$name</string>
  <key>ProgramArguments</key><array><string>$run</string></array>
  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>$LOG_DIR/$name.err</string>
</dict></plist>
EOF
        launchctl bootstrap system "$plist"
        INIT=launchd
    elif [ -d /run/systemd/system ]; then
        cat > "/etc/systemd/system/$name.service" <<EOF
[Unit]
Description=SYNTRAF ($name)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$run
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable --now "$name" >/dev/null 2>&1
        INIT=systemd
    elif command -v rc-service >/dev/null 2>&1; then
        cat > "/etc/init.d/$name" <<EOF
#!/sbin/openrc-run
description="SYNTRAF ($name)"
supervisor=supervise-daemon
command="$run"
respawn_delay=5
depend() { need net; }
EOF
        chmod 755 "/etc/init.d/$name"
        rc-update add "$name" default >/dev/null
        rc-service "$name" start
        INIT=openrc
    fi
}

# glibc trop ancienne pour le Python et les wheels du package : le dire avant de rien toucher
if [ -f "$HERE/payload/GLIBC_MIN" ] && [ "$OS" = Linux ]; then
    NEED=$(cat "$HERE/payload/GLIBC_MIN")
    HAVE=$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}')
    if [ -n "$HAVE" ] && [ "$(printf '%s\n%s\n' "$NEED" "$HAVE" | sort -t. -k1,1n -k2,2n | head -n1)" != "$NEED" ]; then
        echo "Ce package demande glibc $NEED ou plus ; ce système a glibc $HAVE." >&2
        [ "$ROLE" = server ] && echo "Le serveur demande RHEL 8, Debian 10, Ubuntu 20.04 ou plus récent." >&2
        exit 2
    fi
fi

echo "SYNTRAF $ROLE $VERSION → $PREFIX"
if [ "$SERVICE" = 1 ]; then for c in $COMPONENTS; do service_stop "$c"; done; fi
mkdir -p "$PREFIX" "$CONF_DIR" "$DATA_DIR" "$LOG_DIR"

# Python portable, puis les dépendances depuis les wheels du package (aucun accès réseau)
rm -rf "$PREFIX/python"
tar -xzf "$HERE/payload/python.tar.gz" -C "$PREFIX"
PY=$PREFIX/python/bin/python3
"$PY" -m pip install --no-index --find-links "$HERE/payload/wheels" --disable-pip-version-check --quiet --root-user-action=ignore --no-warn-script-location \
    -r "$HERE/payload/requirements.txt"

# Code
rm -rf "$PREFIX/app"
cp -R "$HERE/payload/app" "$PREFIX/app"

# iperf3v : celui du package (Linux, macOS 15+), sinon celui du système
mkdir -p "$PREFIX/bin"
if [ -f "$HERE/payload/bin/iperf3v" ]; then
    cp "$HERE/payload/bin/iperf3v" "$PREFIX/bin/iperf3v"
    chmod 755 "$PREFIX/bin/iperf3v"
    IPERF=$PREFIX/bin/iperf3v
else
    IPERF=$(command -v iperf3v || command -v iperf3 || true)
    if [ -z "$IPERF" ]; then
        IPERF=/usr/local/bin/iperf3
        echo "ATTENTION : aucun iperf3 trouvé. Installez iperf3 3.17 ou plus récent (ou iperf3v), puis ajustez" >&2
        echo "            IPERF3_BINARY_PATH dans $CONF." >&2
    fi
fi

# VictoriaMetrics (écoute en local seulement) et Grafana, provisionné : source de données et tableaux de bord SYNTRAF
if [ "$STACK" = 1 ]; then
    rm -rf "$PREFIX/victoriametrics" "$PREFIX/grafana" "$PREFIX/grafana-dashboards"
    mkdir -p "$PREFIX/victoriametrics" "$PREFIX/grafana" "$DATA_DIR/victoriametrics" "$DATA_DIR/grafana" "$LOG_DIR/grafana"
    tar -xzf "$HERE/payload/stack/victoria-metrics.tar.gz" -C "$PREFIX/victoriametrics"
    tar -xzf "$HERE/payload/stack/grafana.tar.gz" -C "$PREFIX/grafana" --strip-components=1
    cp -R "$HERE/payload/grafana-dashboards" "$PREFIX/grafana-dashboards"
    cat > "$CONF_DIR/victoriametrics-scrape.yml" <<EOF
# Santé de SYNTRAF : /metrics du serveur toutes les 15 s (tableau « Santé de SYNTRAF »)
scrape_configs:
  - job_name: syntraf
    scrape_interval: 15s
    scheme: https
    tls_config:
      insecure_skip_verify: true
    static_configs:
      - targets: ["127.0.0.1:$WEBUI_PORT"]
EOF
    PROV=$CONF_DIR/grafana-provisioning
    mkdir -p "$PROV/datasources" "$PROV/dashboards" "$PROV/plugins" "$PROV/alerting"
    cat > "$PROV/datasources/syntraf.yml" <<EOF
apiVersion: 1
datasources:
  - name: VictoriaMetrics
    uid: syntraf-vm
    type: prometheus
    access: proxy
    url: http://127.0.0.1:8428
    isDefault: true
    editable: false
    jsonData: {timeInterval: 1s, httpMethod: POST}
EOF
    cat > "$PROV/dashboards/syntraf.yml" <<EOF
apiVersion: 1
providers:
  - name: syntraf
    folder: SYNTRAF
    type: file
    disableDeletion: true
    allowUiUpdates: false
    options: {path: "$PREFIX/grafana-dashboards"}
EOF
    if [ ! -f "$CONF_DIR/grafana.ini" ]; then  # mise à jour : la vôtre est gardée
        GF_PASS=$("$PY" -c 'import secrets; print(secrets.token_urlsafe(18))')
        printf '%s\n' "$GF_PASS" > "$CONF_DIR/grafana-admin-password"
        chmod 600 "$CONF_DIR/grafana-admin-password"
        cat > "$CONF_DIR/grafana.ini" <<EOF
# Grafana de SYNTRAF, sans accès à Internet. Mot de passe admin initial : $CONF_DIR/grafana-admin-password
[server]
http_port = $GRAFANA_PORT
[paths]
data = $DATA_DIR/grafana
logs = $LOG_DIR/grafana
plugins = $DATA_DIR/grafana/plugins
provisioning = $PROV
[security]
admin_user = admin
admin_password = $GF_PASS
[users]
allow_sign_up = false
[analytics]
reporting_enabled = false
check_for_updates = false
check_for_plugin_updates = false
[news]
news_feed_enabled = false
[plugins]
preinstall_disabled = true
[dashboards]
default_home_dashboard_path = $PREFIX/grafana-dashboards/syntraf.json
EOF
        chmod 600 "$CONF_DIR/grafana.ini"
    fi
    cat > "$PREFIX/bin/run-victoriametrics" <<EOF
#!/bin/sh
exec "$PREFIX/victoriametrics/victoria-metrics-prod" -storageDataPath="$DATA_DIR/victoriametrics" \\
    -retentionPeriod=$RETENTION -httpListenAddr=127.0.0.1:8428 -promscrape.config="$CONF_DIR/victoriametrics-scrape.yml"
EOF
    cat > "$PREFIX/bin/run-grafana" <<EOF
#!/bin/sh
cd "$PREFIX/grafana"
exec "$PREFIX/grafana/bin/grafana" server --homepath "$PREFIX/grafana" --config "$CONF_DIR/grafana.ini"
EOF
    chmod 755 "$PREFIX/bin/run-victoriametrics" "$PREFIX/bin/run-grafana"
fi

# Sonde déjà installée et --server ou --token donnés : réinscription (serveur réinstallé ou remplacé). L'adresse et
# le jeton sont remplacés ; la clé du serveur mémorisée et le jeton propre donné par l'ancien serveur sont oubliés,
# sinon la sonde refuserait le nouveau serveur (clé différente) ou lui présenterait un jeton qu'il ne connaît pas.
if [ "$ROLE" = probe ] && [ -f "$CONF" ] && { [ -n "$SERVER" ] || [ -n "$TOKEN" ]; }; then
    [ -n "$SERVER" ] && sed -i.bak "s|^SERVER = .*|SERVER = \"$SERVER\"|; s|^SERVER_PORT = .*|SERVER_PORT = \"$SERVER_PORT\"|" "$CONF"
    [ -n "$TOKEN" ] && sed -i.bak "s|^TOKEN = .*|TOKEN = \"$TOKEN\"|" "$CONF"
    rm -f "$CONF.bak" "$CONF_DIR/syntraf_server_pin" "$CONF_DIR/syntraf_client_token"
    echo "Réinscription : nouveau serveur ou jeton enregistré ; la clé du serveur sera mémorisée à la prochaine connexion."
fi

# Configuration : écrite seulement à la première installation (une mise à jour garde la vôtre)
if [ ! -f "$CONF" ]; then
    if [ "$ROLE" = probe ]; then
        [ -n "$UID_NAME" ] || UID_NAME=$(hostname | cut -d. -f1 | tr -cd 'A-Za-z0-9_-')
        cat > "$CONF" <<EOF
# Sonde SYNTRAF ($VERSION). Ses flux viennent du serveur ; ici, seulement comment le joindre.
[CLIENT]
CLIENT_UID = "$UID_NAME"
SERVER = "$SERVER"
SERVER_PORT = "$SERVER_PORT"
TOKEN = "$TOKEN"

[GLOBAL]
IPERF3_BINARY_PATH = "$IPERF"
LOG_TO = "file"
LOG_LEVEL = "INFO"
EOF
    else
        LAB_TOKEN=$("$PY" -c 'import secrets; print(secrets.token_urlsafe(24))')
        TODAY=$(date +%Y-%m-%d)
        {
            echo "# Serveur SYNTRAF ($VERSION). Le reste se règle dans l'interface web (https://<ce serveur>:$WEBUI_PORT)."
            echo "[SERVER]"
            echo 'BIND_ADDRESS = "0.0.0.0"'
            echo "SERVER_PORT = \"$SERVER_PORT\""
            echo "WEBUI_PORT = \"$WEBUI_PORT\""
            echo "WEBUI_TLS = true"
            [ "$STACK" = 1 ] && echo 'METRICS_ALLOW = "127.0.0.1"  # le VictoriaMetrics local lit /metrics'
            echo
            echo "# Jeton d'enrôlement des sondes (install.sh --token sur chaque sonde) ; gérable ensuite dans Server › Tokens"
            echo "[SERVER.TOKEN]"
            echo "$TODAY = \"$LAB_TOKEN\""
            echo
            if [ "$STACK" = 1 ]; then
                echo "# VictoriaMetrics installé avec SYNTRAF"
                echo "[[DATABASE]]"
                echo 'DB_UID = "VICTORIAMETRICS"'
                echo 'DB_ENGINE = "VictoriaMetrics"'
                echo 'DB_SERVER = "127.0.0.1"'
                echo 'DB_PORT = "8428"'
                echo "DB_SERVER_USE_SSL = false"
                echo
            fi
            echo '# Profils de départ (page Profils) : un mesh group en choisit un au lieu de saisir ses valeurs'
            echo '[[IPERF3_PROFILE]]'
            echo 'UID = "VOIX_G711"'
            echo 'DESCRIPTION = "Téléphonie standard (G.711, 20 ms)"'
            echo 'BANDWIDTH = "87K"'
            echo 'DSCP = "46"'
            echo 'PACKET_SIZE = "172"'
            echo 'INTERVAL = "1"'
            echo 'CODEC = "G711"'
            echo
            echo '[[IPERF3_PROFILE]]'
            echo 'UID = "VOIX_G729"'
            echo 'DESCRIPTION = "Téléphonie compressée (G.729, 20 ms)"'
            echo 'BANDWIDTH = "31K"'
            echo 'DSCP = "46"'
            echo 'PACKET_SIZE = "32"'
            echo 'INTERVAL = "1"'
            echo 'CODEC = "G729"'
            echo
            echo '[[IPERF3_PROFILE]]'
            echo 'UID = "VIDEO"'
            echo 'DESCRIPTION = "Vidéoconférence (AF41)"'
            echo 'BANDWIDTH = "2M"'
            echo 'DSCP = "34"'
            echo 'PACKET_SIZE = "1200"'
            echo 'INTERVAL = "1"'
            echo
            echo '[[IPERF3_PROFILE]]'
            echo 'UID = "DONNEES"'
            echo 'DESCRIPTION = "Trafic ordinaire (best effort)"'
            echo 'BANDWIDTH = "1M"'
            echo 'DSCP = "0"'
            echo 'PACKET_SIZE = "1400"'
            echo 'INTERVAL = "1"'
            echo
            echo '[[IPERF3_PROFILE]]'
            echo 'UID = "LIEN_FAIBLE"'
            echo 'DESCRIPTION = "Liens lents ou facturés : Starlink, LTE/5G"'
            echo 'BANDWIDTH = "64K"'
            echo 'DSCP = "0"'
            echo 'PACKET_SIZE = "1200"'
            echo 'INTERVAL = "1"'
            echo
            echo "[GLOBAL]"
            echo "IPERF3_BINARY_PATH = \"$IPERF\""
            echo 'LOG_TO = "file"'
            echo 'LOG_LEVEL = "INFO"'
        } > "$CONF"
    fi
    chmod 600 "$CONF"
fi

cat > "$PREFIX/bin/run-syntraf" <<EOF
#!/bin/sh
export SYNTRAF_BASE_DIR="$DATA_DIR"
cd "$DATA_DIR"
exec "$PY" "$PREFIX/app/syntraf.py" -c "$CONF" -l "$LOG_DIR"
EOF
chmod 755 "$PREFIX/bin/run-syntraf"

INIT=aucun
if [ "$SERVICE" = 1 ]; then
    if [ "$STACK" = 1 ]; then
        service_add syntraf-victoriametrics "$PREFIX/bin/run-victoriametrics"
        service_add syntraf-grafana "$PREFIX/bin/run-grafana"
    fi
    service_add "$SERVICE_NAME" "$PREFIX/bin/run-syntraf"
    [ "$INIT" = aucun ] && echo "Aucun gestionnaire de services reconnu : lancer soi-même les scripts de $PREFIX/bin." >&2
fi

echo
echo "SYNTRAF $ROLE $VERSION installé."
echo "  code       : $PREFIX"
echo "  config     : $CONF"
echo "  données    : $DATA_DIR"
echo "  journaux   : $LOG_DIR"
echo "  iperf3     : $IPERF"
if [ "$SERVICE" = 1 ]; then echo "  services   : $COMPONENTS ($INIT)"
else echo "  démarrer   :$(for c in "$PREFIX"/bin/run-*; do printf ' %s' "$c"; done)"; fi
if [ "$ROLE" = server ]; then
    grep -q "^\[SERVER.TOKEN\]" "$CONF" && echo "  jeton des sondes : $(sed -n '/^\[SERVER.TOKEN\]/{n;p;}' "$CONF" | cut -d'"' -f2)"
    echo "  interface  : https://<ce serveur>:$WEBUI_PORT (mot de passe admin initial : $CONF.initial_admin_password)"
    [ "$STACK" = 1 ] && echo "  grafana    : http://<ce serveur>:$GRAFANA_PORT (admin ; mot de passe : $CONF_DIR/grafana-admin-password)"
fi
exit 0
