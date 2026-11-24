#!/bin/sh
# Essai d'installation hors ligne d'un package dans un conteneur, puis démarrage :
#   docker run --rm --network none -v "$PWD/dist:/dist:ro" -v "$PWD/packaging/test_install.sh:/t.sh:ro" \
#       debian:12-slim sh /t.sh syntraf-server-0.45-linux-x86_64
# Images : debian:12-slim, rockylinux:9 (paquets linux-x86_64), alpine:3 (linux-musl-x86_64).
# Serveur : SYNTRAF, VictoriaMetrics et Grafana démarrés, puis vérifie qu'ils sont reliés (mesures de SYNTRAF dans
# VictoriaMetrics, /metrics lu, source de données et tableaux de bord dans Grafana).
set -e
PKG=$1
cd /tmp && tar xzf /dist/$PKG.tar.gz && cd $PKG
ROLE=$(cat payload/ROLE)
if [ "$ROLE" = probe ]; then ./install.sh --no-service --server 192.0.2.10 --token enroll-token-123 >/tmp/inst.log 2>&1; else ./install.sh --no-service >/tmp/inst.log 2>&1; fi
tail -11 /tmp/inst.log
PY=/opt/syntraf-$ROLE/python/bin/python3
/opt/syntraf-$ROLE/bin/iperf3v --version | head -1
for run in /opt/syntraf-$ROLE/bin/run-*; do "$run" >"/tmp/$(basename "$run").log" 2>&1 & done
sleep 60
if [ "$ROLE" = server ]; then
  GF_PASS=$(cat /etc/syntraf-server/grafana-admin-password)
  $PY - "$GF_PASS" <<'EOF'
import base64, json, ssl, sys, urllib.parse, urllib.request
c = ssl._create_unverified_context()
def get(url, auth=None):
    r = urllib.request.Request(url)
    if auth:
        r.add_header("Authorization", "Basic " + base64.b64encode(auth.encode()).decode())
    return urllib.request.urlopen(r, context=c, timeout=10)
print("syntraf /healthz", get("https://127.0.0.1:5000/healthz").status)
def vm(q):
    u = "http://127.0.0.1:8428/api/v1/query?query=" + urllib.parse.quote(q)
    return json.load(get(u))["data"]["result"]
print("VM : /metrics lu (up)", [r["value"][1] for r in vm('up{job="syntraf"}')])
print("VM : séries écrites par SYNTRAF", len(vm('{__name__=~"SYNTRAF_.*"}')))
auth = "admin:" + sys.argv[1]
print("grafana /api/health", get("http://127.0.0.1:3000/api/health").status)
ds = json.load(get("http://127.0.0.1:3000/api/datasources/uid/syntraf-vm/health", auth))
print("grafana source de données", ds.get("status"))
dash = json.load(get("http://127.0.0.1:3000/api/search?type=dash-db", auth))
print("grafana tableaux de bord", len(dash), sorted({d.get("folderTitle") for d in dash}))
EOF
else
  grep -hE " (ERROR|CRITICAL) " /var/log/syntraf-probe/*.log | head -4 | cut -c30-200
fi
grep -h -c " ERROR \| CRITICAL " /var/log/syntraf-$ROLE/*.log | head -1 | sed 's/^/erreurs dans le journal : /'
