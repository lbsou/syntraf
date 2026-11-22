#!/bin/sh
# Copie le code (montÃ© en lecture seule sur /src) dans /app, gÃ©nÃ¨re la config, lance SYNTRAF.
set -eu

rm -rf /app/* /app/.[!.]* 2>/dev/null || true
tar -C /src \
    --exclude='./venv*' --exclude='./.git' --exclude='./.idea' --exclude='./.superpowers' \
    --exclude='./crypto' --exclude='./proc' --exclude='./log' --exclude='./lab' \
    --exclude='./test' --exclude='./fake_data' --exclude='./iperf3_temp' \
    --exclude='./lib/web_ui' --exclude='./lib/webui_kindafixed' --exclude='./doc' --exclude='./docs' \
    --exclude='*.pid' --exclude='__pycache__' --exclude='users.db' \
    -cf - . | tar -C /app -xf -

subst() {
    sed -e "s|\${LAB_TOKEN}|${LAB_TOKEN}|g" \
        -e "s|\${CLIENT_UID}|${CLIENT_UID:-}|g" \
        "$1" > /etc/syntraf/config.toml
}

# Nœud derrière un routeur du lab (NAT) : route par défaut vers lui
if [ -n "${LAB_GATEWAY:-}" ]; then
    ip route replace default via "${LAB_GATEWAY}"
fi

case "${ROLE:-}" in
    server) subst /src/lab/config/server.toml ;;
    client) subst /src/lab/config/client.toml.tmpl ;;
    *) echo "ROLE doit valoir server ou client" >&2; exit 2 ;;
esac

exec python /app/syntraf.py -c /etc/syntraf/config.toml -l /logs
