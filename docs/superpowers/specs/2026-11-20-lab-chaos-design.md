# Lab de robustesse SYNTRAF (Docker, Linux) — conception

Date : 2026-11-20
Branche de départ : `dev-readlog-independent` (commit `2805bef`, identique à `github/dev`)

## 1. Intention

SYNTRAF (serveur + clients qui montent un maillage iperf3 UDP et envoient les mesures
au serveur, qui les écrit dans InfluxDB) a souvent eu un comportement erratique lors
des déconnexions réseau, principalement à cause de la façon dont iperf3 est piloté.
L'objectif de reprise est la **stabilité**.

Ce projet construit l'outil qui permet de l'atteindre : un **lab local reproductible**
où l'on injecte à volonté latence, pertes et coupures, et où des **scénarios
automatisés** disent si SYNTRAF a réagi correctement. Le lab sert à :

1. reproduire les comportements erratiques connus (preuve du bogue) ;
2. valider chaque correctif (preuve de la correction) ;
3. empêcher les régressions et valider les montées de version (iperf3, Python,
   dépendances).

Le projet commence par **migrer SYNTRAF vers Python 3.14** (demande de
l'utilisateur), puis monte le lab directement sur le code migré. L'utilisateur a
choisi cet ordre (migration d'abord, sans référence préalable en 3.11) en sachant
qu'un échec du lab ne pourra pas être attribué à coup sûr à un bogue ancien plutôt
qu'à la migration.

Les **correctifs de robustesse eux-mêmes sont un projet distinct**, conçu après les
premiers résultats du lab. Recoder iperf3 est un dernier recours, à décider à la
lumière de ces résultats.

## 2. Objectifs, non-objectifs, anti-objectifs

**Objectifs**
- SYNTRAF (serveur, client, webui) démarre et fonctionne sous Python 3.14 (voir § 5.0).
- Lab de 1 serveur SYNTRAF + 4 clients SYNTRAF + InfluxDB, dans Docker Desktop.
- Démarrage complet par un raccourci Windows (double-clic).
- RAM plafonnée : ~1,3 Go au total pour le lab (plafonds par conteneur).
- Pilotage entièrement scriptable par Claude via `lab/labctl.py` (démarrer, arrêter,
  dégrader, couper, rétablir, changer la version d'iperf3, lire l'état).
- Scénarios de panne automatisés (pytest) avec verdict clair et rapport.
- Version d'iperf3 paramétrable (compilée depuis les sources).

**Non-objectifs (pour l'instant)**
- Clients Windows (le comportement d'iperf3/Cygwin diffère ; reporté).
- Correction des bogues de SYNTRAF (projet suivant).
- Webui : elle tourne si elle démarre, mais aucun scénario ne la teste.
- Intégration continue GitHub Actions (possible plus tard, le lab s'y prête).

**Anti-objectifs (échec même si « ça marche »)**
- Le lab perturbe les autres conteneurs de Docker Desktop (Smokeping,
  slam-companion/cloudflared) ou la connectivité du PC. Toute injection de panne
  se fait **dans** les conteneurs du lab, jamais sur l'hôte ni sur la VM WSL.
- Le lab dépasse son budget RAM ou modifie `.wslconfig`.
- Le code SYNTRAF est modifié pour « faire passer » le lab pendant ce projet. En
  dehors de la migration Python (§ 5.0), qui se limite à la compatibilité, le lab
  exécute le code tel quel ; seul l'emballage (Dockerfile, configs) est ajouté.
- La migration change le comportement réseau de SYNTRAF (logique de reconnexion,
  pilotage d'iperf3, détection de panne) : ces changements appartiennent au projet
  de correctifs, pas à la migration.
- Les scénarios sont non déterministes au point d'être ignorés (faux positifs
  fréquents).

## 3. Constat de départ (recon du 2026-11-20)

- Docker Desktop 29.9.3, moteur Linux sur WSL2, noyau `6.6.87.1-microsoft-standard-WSL2`.
  Vérifié : dans un conteneur avec `NET_ADMIN`, `tc qdisc add dev eth0 root netem delay
  100ms loss 5%` fonctionne (ping mesuré 106 ms) et `iptables -A OUTPUT ... -j DROP`
  fonctionne.
- Aucun `.wslconfig` : WSL peut prendre ~32 Go. Non modifié par ce projet.
- Python hôte : 3.14 (défaut), 3.11 à 3.13 disponibles via `py`.
- Aucun test automatisé dans le dépôt (`test/` est un venv).
- Suspects identifiés dans le code, que le lab doit confirmer ou infirmer :
  1. `lib/st_iperf3_readlog.py:57` — `next(subproc.stdout)` est une lecture bloquante ;
     si iperf3 se tait sans mourir, le thread reste figé et l'appel à
     `outage_management` est commenté → pas de pertes 100 % enregistrées.
  2. `lib/st_iperf.py:204` et `:267` — `stderr=PIPE` jamais lu ; risque de blocage
     d'iperf3 quand le tampon se remplit.
  3. Serveur iperf3 en `--one-off` : la reprise dépend du cycle du watchdog.
  4. `--timestamps='%F %T '` passé sans shell (apostrophes littérales), et en double
     côté serveur quand l'authentification est active.

## 4. Approches considérées

| Approche | Pour | Contre |
|---|---|---|
| **A. Docker Compose + `labctl.py` (retenue)** | Aucun outil nouveau, tourne sur le Docker Desktop existant, entièrement scriptable, léger | Dégradation par nœud plutôt que par lien (contournable par filtres `tc` par IP) |
| B. Containerlab dans WSL Ubuntu | Topologie déclarative, netem par lien natif | Hors Docker Desktop, couche de plus, pensé pour émuler des routeurs, raccourci via `wsl` fragile |
| C. VM Hyper-V dédiée exécutant A | Plafond RAM strict, isolation totale | 2–3 Go réservés, VM à gérer, démarrage lent |

Écartées : Toxiproxy (TCP seulement, or iperf3 est en UDP), Pumba (n'apporte rien de
plus que `tc` direct). **L'utilisateur a choisi A.** C reste une évolution possible
sans réécriture si l'isolation devient nécessaire.

## 5. Conception

### 5.0 Migration Python 3.14 (première étape)

Portée : rendre le code compatible, sans changer son comportement.
- `lib/st_mesh.py:1096` : remplacer `ssl.wrap_socket` (supprimé en 3.12) par un
  `ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)` + `context.wrap_socket(..., server_side=True)`,
  avec les mêmes certificat, clé et options qu'aujourd'hui.
- `lib/st_crypto.py` : `datetime.utcnow()` → `datetime.now(timezone.utc)`.
- Dépendances : `requirements_client.txt` et `requirements_server.txt` mis à jour
  vers des versions récentes compatibles 3.14 et **épinglées** (Flask 3.x,
  Flask-Login, Flask-SQLAlchemy 3.x, flask-wtf, influxdb-client, gevent,
  cryptography, psutil, scapy…). Adapter la webui aux changements d'API (notamment
  Flask-SQLAlchemy 3 : contexte d'application obligatoire, `Model.query` déprécié).
- Faire tourner le code avec `python -W error::DeprecationWarning` au démarrage pour
  débusquer les autres incompatibilités ; corriger celles qui viennent du code
  SYNTRAF (pas celles des bibliothèques tierces).
- Vérification de cette étape : serveur + 1 client démarrent dans le conteneur
  3.14, le client s'authentifie, reçoit sa config, lance iperf3, et des points
  arrivent dans InfluxDB ; la webui répond sur sa page de connexion. Cette
  vérification devient le scénario S0 du lab.

`PYTHON_VERSION` reste un paramètre de `lab.env` (défaut 3.14) pour valider plus
tard la 3.15.

### 5.1 Arborescence

```
lab/
  README.md                 # mode d'emploi court (humain et Claude)
  docker-compose.yml
  docker/
    Dockerfile              # image unique syntraf (serveur et clients)
    entrypoint.sh
  config/
    server.toml             # config serveur du lab (MESH_GROUP, SERVER_CLIENT, DATABASE)
    client.toml.tmpl        # gabarit client ; CLIENT_UID injecté par variable d'env
    lab.env                 # versions et paramètres (IPERF3_VERSION, PYTHON_VERSION, ...)
  labctl.py                 # pilote (stdlib uniquement)
  start-lab.ps1             # cible du raccourci
  scenarios/
    conftest.py             # fixtures : lab démarré, client Influx, helpers
    test_*.py               # un fichier par famille de scénarios
  reports/                  # sorties (ignoré par git)
```

### 5.2 Conteneurs et budget RAM

Réseau bridge dédié `syntraf_lab` (`172.30.0.0/24`), IP statiques côté Docker.

Modes d'adressage SYNTRAF mélangés pour couvrir les deux chemins du code :
`client1` et `client2` sont déclarés avec leur IP fixe dans `server.toml`, `client3`
et `client4` avec `IP_ADDRESS = "0.0.0.0"` (IP dynamique). En mode dynamique, la perte
du canal de contrôle fait volontairement oublier l'IP du client et arrêter les flux
vers lui (`server_forget_dynamic_client_ip`, `lib/st_mesh.py:879`) : les résultats
attendus des scénarios sont donc définis **par mode**.

| Service | Image | IP | `mem_limit` |
|---|---|---|---|
| `influxdb` | `influxdb:2.7-alpine` | .10 | 400 Mo |
| `server` | `syntraf-lab` | .20 | 256 Mo |
| `client1`…`client4` | `syntraf-lab` | .31–.34 | 128 Mo chacun |
| `grafana` (profil `viz`, non démarré par défaut) | `grafana/grafana-oss` | .40 | 200 Mo |

Total par défaut ≈ 1,2 Go. Les clients et le serveur reçoivent `cap_add: [NET_ADMIN]`.
`restart: "no"` : un plantage doit rester visible, pas être masqué par Docker.

Rôles : le serveur SYNTRAF est aussi client (`ST_SERVER`, comme dans
`etc/config_example.toml`) **ou non** — choix du constructeur selon ce que le code
supporte le plus simplement ; les 4 clients forment un maillage dans un MESH_GROUP
`LAB` (12 flux unidirectionnels). Intervalle iperf3 de 1 s ou 2 s pour que les
scénarios restent courts.

### 5.3 Image `syntraf-lab`

- Multi-étapes : étape 1 compile iperf3 depuis les sources officielles
  (`esnet/iperf`, tag `${IPERF3_VERSION}`, défaut : dernière version stable au moment
  de la construction, à figer dans `lab.env`) ; étape 2 `python:${PYTHON_VERSION}-slim`
  avec `iproute2`, `iptables`, `procps`, le binaire iperf3 et `requirements_server.txt`.
- Python : `python:3.14-slim` par défaut, avec les `requirements_server.txt` migrés
  (§ 5.0).
- iperf3 : le code passe `--cntl-ka` au client et au serveur ; la version choisie doit
  l'accepter. `lab.env` permet deux sources : `IPERF3_SOURCE=esnet` + tag, ou
  `IPERF3_SOURCE=fork` (dépôt `davidBar-On/iperf`, branche
  `issue-812-835-control-connection-keepalive`, recommandée dans le README). Le
  constructeur vérifie à la construction (`iperf3 --help | grep cntl-ka`) et échoue
  clairement sinon.
- Le code SYNTRAF est **monté en volume lecture seule** sur `/src`, puis **copié** au
  démarrage dans un dossier propre à chaque conteneur (`/app`) : le code écrit dans
  son propre dossier (`syntraf.pid`, `proc/`, `crypto/`) et 5 conteneurs ne doivent
  pas partager ces fichiers. Une modification du code se teste par un simple
  redémarrage, sans reconstruction.
- `entrypoint.sh` choisit le rôle (`server`/`client`), génère la config client depuis
  le gabarit, et lance `syntraf.py` au premier plan (logs sur stdout + fichier dans un
  volume `lab/reports/logs/<service>/`).
- Secrets du lab (TOKEN, identifiants iperf3, InfluxDB) : valeurs factices fixes dans
  `lab.env`, propres au lab. Jamais réutilisées ailleurs.

### 5.4 `labctl.py` — l'interface de pilotage

Python, bibliothèque standard uniquement (appelle la CLI `docker`), exécutable avec le
Python de l'hôte. Sortie lisible par un humain, option `--json` pour Claude.

| Commande | Effet |
|---|---|
| `up [--build]` | Démarre le lab, attend la santé (Influx prêt, 4 clients authentifiés, flux qui écrivent) |
| `down [--volumes]` | Arrête (et efface les données si demandé) |
| `status` | État des conteneurs, RAM utilisée, nb d'iperf3 par nœud, dégradations actives, dernier point Influx par flux |
| `logs <svc> [--since]` | Logs d'un service |
| `degrade <svc> [--delay] [--jitter] [--loss] [--rate] [--to <svc>]` | `tc netem` sur la sortie du nœud ; `--to` restreint à une destination (filtre `tc` par IP) |
| `cut <svc> --mode {drop,disconnect,pause} [--to <svc>] [--for <s>]` | Coupure : perte silencieuse (iptables DROP), interface retirée (`docker network disconnect`), hôte figé (`docker pause`) |
| `kill-iperf <svc> [--signal]` | Tue les processus iperf3 du nœud |
| `restart <svc>` | Redémarre un service (p. ex. le serveur SYNTRAF) |
| `flap <svc> --mode <m> --off <s> --on <s> --count <n>` | Coupures répétées |
| `heal [<svc>\|--all]` | Retire toute dégradation/coupure |
| `set-version iperf3 <x.y>` | Met à jour `lab.env`, reconstruit, redémarre |
| `test [<filtre>]` | Lance les scénarios pytest, écrit le rapport dans `lab/reports/` |

`heal --all` est appelé automatiquement à `down` et à la fin de chaque scénario.

### 5.5 Démarrage par raccourci

`start-lab.ps1` : vérifie que Docker Desktop tourne (sinon le lance et attend le
moteur, délai max 3 min), lance `labctl up`, affiche `labctl status`, garde la
fenêtre ouverte. Un raccourci `SYNTRAF Lab.lnk` sur le Bureau pointe vers
`pwsh -File <repo>\lab\start-lab.ps1` (créé par `labctl install-shortcut`). Un second
raccourci « SYNTRAF Lab – arrêt » appelle `labctl down`.

### 5.6 Scénarios et critères de réussite

Chaque scénario : état stable → injection → observation → `heal` → vérification de la
reprise. Observations disponibles : requêtes InfluxDB (API HTTP), `ps` dans les
conteneurs (iperf3 et zombies), nombre de threads Python, `docker stats` (RAM), logs.

`I` = intervalle iperf3, `W` = `WATCHDOG_CHECK_RATE`. Seuils initiaux (décision de
Claude, ajustables) : reprise ≤ `2·I + W + 10 s`.

| # | Scénario | Réussite |
|---|---|---|
| S1 | Régime stable 10 min | Aucun trou > 2·I dans aucun flux ; pertes ≈ 0 |
| S2 | Dégradation 200 ms / 10 % sur client2 | Pertes mesurées des flux concernés dans [5 %, 15 %] ; autres flux intacts |
| S3 | Perte silencieuse 60 s (client3) | Points à 100 % de pertes écrits pour la durée ; reprise des vraies mesures dans le délai |
| S4 | Interface retirée 60 s (client3) | Idem S3 ; client se réauthentifie auprès du serveur |
| S5 | Hôte figé 60 s (client3) | Idem S3 ; les pairs ne restent pas bloqués |
| S6 | iperf3 tué sur client1 | Relancé dans le délai ; aucun zombie |
| S7 | Redémarrage du serveur SYNTRAF | Les 4 clients se reconnectent ; aucun point perdu au-delà de la fenêtre de redémarrage |
| S8 | Flapping 30 × (5 s coupé / 10 s rétabli) | Après coup : nb d'iperf3 = nominal, 0 zombie, threads et RAM stables (±10 %) |
| S9 | Coupure serveur↔client seulement (canal de contrôle) | IP fixe : les mesures client↔client continuent ou sont mises en tampon puis livrées. IP dynamique : les flux vers ce client s'arrêtent proprement (sans zombie) et reprennent après reconnexion |

S3 à S5 sont exécutés une fois sur un client à IP fixe et une fois sur un client à IP
dynamique.

Un échec **attendu** sur le code actuel n'est pas un problème : la liste des échecs
de la première exécution est le livrable qui alimente le projet de correctifs. Le
rapport indique pour chaque échec l'observation brute (extrait de logs, compteurs).

Gestion de l'état de référence : après la première exécution, les scénarios en échec
sont listés dans `lab/scenarios/known_failures.txt` (avec la raison). `labctl test`
distingue alors trois verdicts : **réussi**, **échec connu**, **régression** (un
scénario qui passait et échoue). Un correctif qui fait passer un échec connu le
retire de la liste. Le code de sortie n'est non nul qu'en cas de régression.

Mode endurance (plus tard, hors périmètre initial) : pannes aléatoires pendant N heures.

## 6. Laissé au constructeur

- Version exacte d'iperf3 par défaut et épinglages Python du lab.
- Format exact du rapport (JUnit XML + résumé Markdown suggéré).
- Mécanisme de filtre `tc` par destination (prio + u32, ou équivalent).
- Si le serveur doit aussi être client du maillage.
- Contenu de `.gitignore` pour `lab/reports/`.

## 7. Décisions prises par Claude (à valider en relecture)

- Python 3.14 comme cible (3.15 trop récente pour les wheels des dépendances).
- Référence iperf3 par défaut : esnet officiel, dernière version stable acceptant
  `--cntl-ka` ; le fork davidBar-On reste sélectionnable. (Question posée à
  l'utilisateur, sans réponse pour l'instant.)
- Mode `BEHIND_NAT` / `--bidir` hors périmètre initial. (Question posée, sans réponse.)
- Scénarios dérivés des suspects du code, faute de description des pannes vues en
  production ; à enrichir quand l'utilisateur en décrira.
- Code monté en lecture seule puis copié par conteneur au démarrage.
- Modes IP fixe et dynamique mélangés dans le lab.
- Fichier `known_failures.txt` pour distinguer échecs connus et régressions.
- Intervalle iperf3 court (1–2 s) dans le lab.
- Seuils de reprise ci-dessus.
- Grafana optionnel, éteint par défaut, pour tenir le budget RAM.
- `labctl` en Python stdlib (pas de SDK Docker) pour n'exiger aucune installation.

## 8. Addendum du 2026-11-20 — VictoriaMetrics et Grafana (décision de l'utilisateur)

Décisions de l'utilisateur :
- SYNTRAF gagne un **vrai moteur `DB_ENGINE = "VictoriaMetrics"`**, à côté du moteur
  InfluxDB2 existant, qui reste en place et inchangé.
- **VictoriaMetrics remplace InfluxDB comme base du lab.**
- Le lab inclut une **instance Grafana avec un tableau de bord SYNTRAF provisionné**.

### 8.1 Moteur VictoriaMetrics dans SYNTRAF

- Nouveau module `lib/st_victoriametrics.py`, classe `VictoriaMetricsObj`, avec la même
  interface publique que `InfluxObj` : `status`, `status_time`, `database_uid`,
  `save_metrics_to_database_with_buffer(payload, address, client_uid) -> "OK" | "ERROR"`,
  `force_status_check()`, `get_Database_UID()`.
- Bibliothèque standard uniquement (HTTP via `urllib`). Écriture en **line protocol
  InfluxDB** sur `/api/v2/write` (accepté nativement par VictoriaMetrics), en **une
  requête synchrone** par lot : `"OK"` seulement si la réponse est 2xx, sinon `"ERROR"`.
  Le client garde alors ses mesures en tampon, contrairement au moteur InfluxDB actuel,
  qui répond `"OK"` même quand l'écriture échoue (constat à signaler dans le rapport).
- Santé : `GET /health` (réponse 200 = `ONLINE`).
- Le payload reçu est la liste de dicts produite par `generate_json` (mesure `SYNTRAF`,
  tags, `time` sous forme de chaîne ISO après sérialisation JSON avec `default=str`,
  champs) ; les métriques deviennent `SYNTRAF_RX_PCT_LOSS{UID=…,CLIENT=…,SERVER=…,MESH_GROUP=…}`, etc.
- Config : `DB_ENGINE = "VictoriaMetrics"` ; `DB_SERVER`, `DB_PORT`, `DB_SERVER_USE_SSL`
  comme aujourd'hui ; `DB_TOKEN` facultatif (envoyé en `Authorization: Bearer`) ;
  `DB_ORG`, `DB_BUCKET`, `DB_MODE` non requis pour ce moteur.
- `syntraf.py` choisit la classe selon `DB_ENGINE`.

### 8.2 Lab

- Service `victoriametrics` (image `victoriametrics/victoria-metrics`, IP 172.30.0.10,
  port hôte 127.0.0.1:18428, rétention 30 jours) à la place d'`influxdb`.
- Le lab lit les points bruts par `GET /api/v1/export` (horodatages exacts, nécessaires
  à la détection des trous).
- Service `grafana` démarré par défaut (IP .40, port hôte 127.0.0.1:18300), source de
  données Prometheus vers VictoriaMetrics et tableau de bord SYNTRAF provisionnés depuis
  des fichiers du dépôt (pertes, débit, gigue, paquets perdus par flux ; variables
  groupe, client, serveur). Accès anonyme en lecture ; compte admin au mot de passe
  factice de `lab.env`.
- Budget RAM : victoriametrics 192m, server 192m, c1–c4 192m, grafana 200m (≈ 1,35 Go).
- S0 vérifie aussi que Grafana répond, que la source de données est saine et que le
  tableau de bord existe.
