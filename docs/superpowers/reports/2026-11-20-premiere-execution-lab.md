# Lab de robustesse SYNTRAF : rapport de première exécution

Date : 2026-11-20, branche `lab-chaos`.
Code testé : SYNTRAF migré en Python 3.14, moteur VictoriaMetrics, iperf3 3.22.1 (esnet).
Exécutions :
- `lab/reports/2026-11-20_211650` : suite rapide, sans S1 ni S8 ;
- `lab/reports/2026-11-20_215533` : suite complète ;
- `lab/reports/2026-11-20_225600` : suite rapide de contrôle, avec l'état de référence. Code de sortie 0 :
  12 réussis, 9 échecs connus, aucune régression.

## 1. Verdicts

| Scénario | Exéc. 1 | Exéc. 2 | Exéc. 3 | Statut |
|---|---|---|---|---|
| S0 démarrage, migration, Grafana, page de statut | ✅ | ✅ | ✅ | stable |
| S1 régime stable 10 min | – | ✅ | – | réussi |
| S2 dégradation 200 ms / 10 % | ✅ | ✅ | ✅ | stable |
| S3 perte silencieuse (c2 IP fixe, c3 IP dynamique) | ❌❌ | ❌❌ | ❌❌ | échec connu |
| S4 interface retirée (c2, c3) | ❌❌ | ❌❌ | ❌❌ | échec connu |
| S5 hôte figé (c2, c3) | ❌❌ | ❌❌ | ❌❌ | échec connu |
| S6 iperf3 tués | ✅ | ❌ | ✅ | **instable** (1 flux sur 6 non repris en 14 s, 1 fois sur 3) |
| S7 redémarrage du serveur | ❌ | ❌ | ❌ | échec connu |
| S8 30 coupures (flapping) | – | ✅ | – | réussi, mais SYNTRAF non sain 60 s après |
| S9 canal de contrôle seul (c2, c4) | ❌❌ | ❌❌ | ❌❌ | échec connu |

Après 7 des 9 scénarios de coupure, SYNTRAF n'était pas redevenu sain 60 s après le
rétablissement, et le lab a dû le redémarrer. À deux reprises (après S3 sur c2 et après S7, dans
l'exécution 2), même un redémarrage complet n'a pas suffi : un flux est resté muet 180 s.

## 2. Observations brutes

| Constat | Mesure | Scénarios |
|---|---|---|
| Les pertes à 100 % ne sont presque pas enregistrées pendant une coupure | couverture 0,05 à 0,08 sur 60 s (≈ 4 s, celles qu'iperf3 rapporte avant `--rcv-timeout` = 5 s), quel que soit le mode | S3, S4, S5 |
| Le client coupé ne met rien en tampon | couverture 0,0 des mesures prises par c2 pendant sa coupure | S3, S4, S5 (c2), S9 (c2) |
| Les mesures sont perdues pendant un redémarrage du serveur | couverture 0,0 de la fenêtre de redémarrage, pour les 12 flux | S7 |
| Les clients ne reviennent pas après un redémarrage du serveur | 12 flux muets 44 s après ; constaté aussi à la main (150 s) | S7 |
| Les flux vers un client à IP dynamique tardent à reprendre | aucune vraie mesure 14 s, ni même 44 s, après le rétablissement | S3, S4 (c3), S9 (c4) |
| Le canal de contrôle se fige | le serveur garde 4 connexions TCP établies sur 6531 mais n'écrit plus rien ; threads 42 → 8 ; aucun log d'erreur | série des tests de pannes (tâche 4c) |
| Zombie iperf3 | 1 zombie sur c1, 1 fois sur 2 | S4 (c3) |
| Artefacts de mesure à la reprise | 3212 paquets perdus comptés en un seul intervalle ; gigue de 1,25 s | après une coupure de c2 (Grafana) |
| **Course au démarrage** | après un démarrage à froid, les clients à IP fixe n'ouvrent parfois jamais leurs flux vers un client à IP dynamique (c1, c2 : 5 iperf3 au lieu de 6 ; flux vers LAB_C3 ou LAB_C4 muets). La nouvelle IP est bien reçue (« DESTINATION IP ADDRESS UPDATED ») mais l'iperf3 n'est pas relancé. Fréquent (environ 1 démarrage sur 3) | nettoyage après S3 (c2) et S7 ; démarrages du lab |

## 3. Les quatre suspects de la conception (§ 3)

1. **Lecture bloquante et détection de panne désactivée** (`st_iperf3_readlog.py:57`, appel à
   `outage_management` commenté) : **confirmé quant à ses effets.** Aucune perte à 100 % n'est
   générée pendant le silence d'iperf3. Le blocage du thread lui-même n'a pas été mesuré
   directement (non concluant).
2. **`stderr=PIPE` jamais lu** (`st_iperf.py:204`, `:267`) : **non concluant.** Aucun blocage
   attribuable, et S8 ne montre aucune fuite d'iperf3.
3. **Serveur iperf3 en `--one-off`, relancé par le watchdog** : **plausible, non concluant.** La
   reprise est lente ou absente vers les clients à IP dynamique, et S6 est instable. Il faudrait
   instrumenter le watchdog pour trancher.
4. **Arguments `--timestamps` (apostrophes, doublon)** : **infirmé comme cause d'instabilité.**
   L'analyse des lignes fonctionne (S1, S2). Le défaut reste cosmétique.

## 4. Autres constats (hors scénarios)

- **Corrigés pendant ce chantier :**
  - `tabulate` manquait dans `requirements_server.txt` ;
  - la section `[CLIENT]` était effacée au premier démarrage sans certificat, d'où une boucle `KeyError` ;
  - `ssl.wrap_socket` a été supprimé en Python 3.12 ;
  - l'import `flask.safe_join` n'existe plus dans Flask 3 ;
  - l'API `GET_SYSTEM_STATS` répondait 500 depuis janvier 2023 (date non sérialisable), si bien que la page de statut était inerte.
- **Non corrigés :**
  - le moteur InfluxDB2 répond `"OK"` même quand l'écriture échoue (lot asynchrone, erreurs avalées), ce qui fait perdre des mesures si la base est indisponible ;
  - le serveur sort avec le code 0 quand sa config est invalide ;
  - la page de connexion de la webui est une façade sans traitement (`/login` commenté) et sans thème ;
  - l'édition d'un groupe n'est implémentée ni dans la page ni dans l'API (`EDIT_MESH_GROUP` : `pass`).

## 5. RAM

Consommation mesurée après environ 2 h de fonctionnement :

| Service | Mesuré | Plafond |
|---|---|---|
| clients c1 à c4 | 131 à 133 Mio chacun | 192 Mio |
| server | 71 Mio | 192 Mio |
| victoriametrics | 163 Mio | 192 → **256 Mio** |
| grafana | 129 Mio au repos, plus de 200 Mio avec un navigateur ouvert | 200 → **384 Mio** |

Le total des plafonds passe à environ 1,6 Go, contre 1,3 Go prévus. Grafana 13 a été tué par
manque de mémoire à 200 Mio, et VictoriaMetrics s'approchait de son plafond en accumulant des
données. Les clients se stabilisent autour de 135 Mio, et S8 ne montre aucune dérive. Correction : les flux C1/C2 → C3 muets attribués au départ au plafond de 128 Mio relevaient en fait de la course au démarrage ; le relèvement à 192 Mio reste justifié par la consommation mesurée (environ 135 Mio).

## 6. Pistes pour le projet de correctifs

Ce sont des pistes à concevoir, pas des décisions :
- **en premier : la course au démarrage.** Relancer le connecteur quand l'IP de destination d'un client dynamique est mise à jour. Tant qu'elle n'est pas corrigée, environ un démarrage du lab sur trois n'atteint pas l'état sain (contournement manuel : `docker restart syntraf-lab-c1 syntraf-lab-c2`). Un scénario « démarrage à froid » répété devrait l'accompagner ;
- réactiver la détection du silence (pertes à 100 % générées par SYNTRAF) avec une lecture non bloquante de la sortie d'iperf3 ;
- mettre en tampon côté client et rejouer après reconnexion, avec un acquittement réel côté serveur ;
- reconnexion du canal de contrôle avec délai de garde et heartbeat applicatif, pour sortir du gel constaté ;
- examiner le cycle `-t 0` / `--one-off` : des tests courts enchaînés se terminent proprement.

Les données ne justifient pas de réécrire iperf3 : les défauts observés sont dans la couche
SYNTRAF qui le pilote.
