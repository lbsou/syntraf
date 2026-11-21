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
| Grafana | http://127.0.0.1:18300 | Tableau de bord « SYNTRAF — mesures du maillage » (lecture anonyme ; admin : mot de passe de `config/lab.env`) |
| Webui SYNTRAF | http://127.0.0.1:18080 | Interface du serveur |
| VictoriaMetrics | http://127.0.0.1:18428 | Base des mesures (`SYNTRAF_RX_PCT_LOSS{UID=…}`, etc.) |

## Topologie

Réseau `syntraf_lab` (172.30.0.0/24) :

| Service | IP | Rôle |
|---|---|---|
| victoriametrics | .10 | base de données |
| server | .20 | serveur SYNTRAF (canal de contrôle 6531, webui) |
| c1, c2 | .31, .32 | clients `LAB_C1`, `LAB_C2`, déclarés en IP fixe |
| c3, c4 | .33, .34 | clients `LAB_C3`, `LAB_C4`, déclarés en IP dynamique (`0.0.0.0`) |
| grafana | .40 | visualisation |

Les clients forment un maillage dans le groupe `LAB_MESH` (12 flux UDP iperf3 à 100 kbit/s,
intervalle 1 s). Le code du dépôt est monté en lecture seule et copié dans chaque conteneur
au démarrage : une modification du code se teste par `labctl down` puis `labctl up`, sans
reconstruire l'image.

## Commandes `labctl`

```
python lab/labctl.py status [--json]          # conteneurs, RAM, iperf3, zombies, pannes, âge des flux
python lab/labctl.py logs <service> [--since 10m]
python lab/labctl.py degrade c2 --delay 200 --jitter 20 --loss 10 [--rate 1mbit] [--to c3]
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

Les trois modes de coupure ne sont pas équivalents pour iperf3 :
- `drop` : perte silencieuse (règles iptables), comme une panne WAN ;
- `disconnect` : interface retirée, les sockets reçoivent des erreurs immédiates ;
- `pause` : hôte figé, les processus ne répondent plus du tout.

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

Plafonds : victoriametrics 192 Mio, server 192 Mio, c1–c4 192 Mio chacun, grafana 200 Mio,
soit environ 1,35 Go. Consommation mesurée : environ 135 Mio par client, 75 à 90 Mio pour le
serveur, environ 110 Mio pour VictoriaMetrics et 130 Mio pour Grafana.

## Ce que le lab ne touche pas

- Aucune panne n'est injectée sur le PC ni sur la VM WSL : uniquement dans les conteneurs
  du lab (`tc`, `iptables`, `docker network disconnect`, `docker pause`).
- `.wslconfig` et les autres conteneurs de Docker Desktop ne sont jamais modifiés.
- Les secrets de `config/lab.env` sont factices et propres au lab.
