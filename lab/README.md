# Lab de robustesse SYNTRAF

Lab local (Docker Desktop, Linux) pour vérifier que SYNTRAF réagit correctement aux
dégradations et aux coupures réseau. Conception : `docs/superpowers/specs/2026-11-20-lab-chaos-design.md`.

## Démarrer / arrêter

- Double-cliquer **SYNTRAF Lab** sur le Bureau. Le script lance Docker Desktop au besoin,
  démarre le lab, attend que les 12 flux écrivent, puis affiche l'état.
- **SYNTRAF Lab - arrêt** arrête le lab. Les pannes actives sont retirées d'abord, et les
  données VictoriaMetrics sont conservées.
- En ligne de commande, depuis la racine du dépôt : `python lab/labctl.py up` / `down`.
  `down --volumes` efface aussi les données.
- Les raccourcis se recréent avec `python lab/labctl.py install-shortcut`.

| Service | Adresse depuis le PC | Rôle |
|---|---|---|
| Grafana | http://127.0.0.1:18300 | Tableaux de bord « SYNTRAF — mesures du maillage » (séries temporelles) et « SYNTRAF — matrice source × destination » (lecture anonyme ; admin : mot de passe de `config/lab.env`) |
| Webui SYNTRAF | http://127.0.0.1:18080 | Interface du serveur |
| VictoriaMetrics | http://127.0.0.1:18428 | Base des mesures (`SYNTRAF_RX_PCT_LOSS{UID=…}`, etc.) |

## Tableaux de bord Grafana

Les deux tableaux de bord sont générés par `lab/grafana/build_dashboards.py` : ne pas éditer les
JSON à la main. Après une modification : `python lab/grafana/build_dashboards.py`, puis
`python lab/labctl.py restart grafana`, puis Ctrl+F5 dans le navigateur.

La matrice reprend le principe de grallama-panel (plugin Angular, incompatible avec Grafana 13)
avec des tables natives : sources (CLIENT, émetteur iperf3) en lignes, destinations (SERVER, qui
mesure) en colonnes, cellules colorées selon des seuils. Elle montre les pertes (30 s et sur la
période), le silence, la gigue, le débit et les paquets perdus.

## Topologie

Réseau `syntraf_lab` (172.30.0.0/24) :

| Service | IP | Rôle |
|---|---|---|
| victoriametrics | .10 | base de données |
| server | .20 | serveur SYNTRAF (canal de contrôle 6531, webui) |
| c1, c2 | .31, .32 | clients `LAB_C1`, `LAB_C2`, déclarés en IP fixe |
| c3 | .33 | client `LAB_C3`, déclaré en IP dynamique (`0.0.0.0`) |
| c4 | 10.99.0.34 | client `STARLINK`, IP dynamique, derrière le routeur NAT `starlink-gw` (.35) |
| c5 | 10.98.0.35 | client `LTE_5G`, IP dynamique, derrière le routeur CGNAT `mobile-gw` (.36) |
| grafana | .40 | visualisation |

Les clients forment un maillage dans le groupe `LAB_MESH` (18 flux UDP iperf3 : STARLINK et LTE_5G, tous deux derrière un NAT, ne se mesurent pas entre eux à 100 kbit/s,
intervalle 1 s). Le code du dépôt est monté en lecture seule et copié dans chaque conteneur
au démarrage : une modification du code se teste par `labctl down` puis `labctl up`, sans
reconstruire l'image.

## Commandes `labctl`

```
python lab/labctl.py status [--json]          # conteneurs, RAM, iperf3, zombies, pannes, âge des flux
python lab/labctl.py logs <service> [--since 10m]
python lab/labctl.py degrade c2 --delay 200 --jitter 20 --loss 10 [--rate 1mbit] [--to c3] [--reorder]
python lab/labctl.py cut c3 --mode drop|disconnect|pause [--to server] [--for 60]
python lab/labctl.py flap c2 --mode drop --off 5 --on 10 --count 30
python lab/labctl.py kill-iperf c1 [--signal TERM]
python lab/labctl.py restart server
python lab/labctl.py heal [c2 | --all]
python lab/labctl.py versions
python lab/labctl.py set-version iperf3 3.22.1 [--source esnet|fork]
python lab/labctl.py set-version python 3.15 | victoriametrics v1.157.0 | grafana 13.1.0
python lab/labctl.py test [-k s3] [--quick]
```

Avec de la gigue, netem retarderait chaque paquet indépendamment et les réordonnerait, ce qu'un vrai lien (files FIFO)
ne fait presque jamais, et qui fait échouer l'établissement d'iperf3 --bidir (voir `docker/iperf3-patches/`). `degrade`
ajoute donc un débit (1 Gbit/s si aucun n'est donné) : netem garde alors l'ordre des paquets. `--reorder` garde l'ancien
comportement (tests de robustesse).

### Nœud satellite STARLINK (c4), derrière un NAT

c4 porte l'UID `STARLINK` et simule un site satellite derrière un routeur NAT (comme le CGNAT de Starlink) :

- il est sur son propre réseau `syntraf_starlink_lan` (10.99.0.34) ; le routeur `starlink-gw` (10.99.0.2 côté LAN,
  172.30.0.35 côté lab) le masque derrière son adresse. Aucun nœud ne peut ouvrir de connexion vers lui ;
- `BEHIND_NAT = true` dans `config/server.toml` : STARLINK n'ouvre aucun port et mesure les deux sens lui-même
  (`iperf3 --bidir`) ; un datagramme vide toutes les 15 s garde ouvertes les correspondances NAT des flux de retour ;
- lien satellite : 30 ms ± 12 ms et 0,5 % de pertes dans chaque sens (environ 60 ms d'aller-retour).

La dégradation (tc netem) ne survit pas au redémarrage d'un conteneur ; pour la réappliquer :

```
python lab/labctl.py degrade c4 --delay 30 --jitter 12 --loss 0.5            # STARLINK → les autres
python lab/labctl.py degrade starlink-gw --delay 30 --jitter 12 --loss 0.5   # les autres → STARLINK
```

### Nœud mobile 5G/LTE (c5), derrière un CGNAT

c5 porte l'UID `LTE_5G` : une sonde sur un accès mobile (LTE ou 5G NSA), derrière le CGNAT de l'opérateur (routeur
`mobile-gw`, 10.98.0.2 côté LAN, 172.30.0.36 côté lab), `BEHIND_NAT = true`. Profil typique d'un accès commercial
chargé normalement, asymétrique comme un vrai lien radio (la montée est la plus mauvaise) :

```
python lab/labctl.py degrade c5 --delay 22 --jitter 8 --loss 0.8 --rate 20mbit           # montée : LTE_5G → les autres
python lab/labctl.py degrade mobile-gw --delay 18 --jitter 5 --loss 0.3 --rate 100mbit  # descente : les autres → LTE_5G
```

Mesuré : RTT ≈ 43 ms, gigue 4,5 ms en montée et 3 ms en descente, pertes 1 % et 0,3 %, MOS G.711 ≈ 4,3.


Les trois modes de coupure ne sont pas équivalents pour iperf3 :
- `drop` : perte silencieuse (règles iptables), comme une panne WAN ;
- `disconnect` : interface retirée, les sockets reçoivent des erreurs immédiates ;
- `pause` : hôte figé, les processus ne répondent plus du tout.

## Banc d'essai des alertes

`python lab/bench_alerts.py` injecte des pannes à des instants connus sur des nœuds sains (pertes sur c2, gigue
puis latence sur c3), relève les alertes de SYNTRAF (`/api/v1/alerts`) et écrit un rapport dans `lab/reports/` :
détectée ou ratée, délai de détection, fausses alertes, alerte refermée après le retour. Il sert à juger le
détecteur de baseline, et à comparer tout détecteur de remplacement (un modèle appris ne s'ajoute que s'il fait
mieux ici). Il faut 24 h d'historique sur les flux visés ; environ 51 min (`--only loss`, `--hold`, `--rest`).
Variables : `SYNTRAF_URL`, `SYNTRAF_TOKEN` ou `SYNTRAF_TOKEN_FILE`.

## Tests

- `lab/.venv` contient pytest ; `python lab/labctl.py bootstrap` le crée.
- Tests unitaires (sans Docker) : `lab/.venv/Scripts/python -m pytest lab/tests -m "not docker"`.
- Tests d'intégration des pannes (lab démarré) : `… -m docker`.
- Scénarios : `python lab/labctl.py test`. Le rapport est écrit dans `lab/reports/<date>/`.
  Les échecs connus sont listés dans `scenarios/known_failures.txt` ; seul un échec non
  listé (régression) fait échouer la commande.
- Ajouter un scénario : un fichier `scenarios/test_sN_<nom>.py` qui utilise les fixtures
  `lab_up`, `metrics` et `window`, et les fonctions de `lablib` (`faults`, `health`, `series`).

## Budget RAM

Plafonds : victoriametrics 256 Mio, server 192 Mio, c1–c5 192 Mio chacun, grafana 768 Mio,
soit environ 2,2 Go. Consommation mesurée : environ 135 Mio par client, 75 à 90 Mio pour le
serveur, 110 à 165 Mio pour VictoriaMetrics (croît avec les données), et pour Grafana 130 Mio au repos mais plus de 200 Mio dès
qu'un navigateur affiche le tableau de bord.

## Ce que le lab ne touche pas

- Aucune panne n'est injectée sur le PC ni sur la VM WSL : uniquement dans les conteneurs
  du lab (`tc`, `iptables`, `docker network disconnect`, `docker pause`).
- `.wslconfig` et les autres conteneurs de Docker Desktop ne sont jamais modifiés.
- Les secrets de `config/lab.env` sont factices et propres au lab.
