SYNTRAF : installation hors ligne
=================================

Ce package contient tout ce qu'il faut, sans accès Internet : Python, les dépendances, SYNTRAF et iperf3v
(sauf macOS : iperf3 du système, 3.17 ou plus récent).

Sonde
-----
Linux / macOS :  sudo ./install.sh --server <adresse du serveur> --token <jeton>
Windows       :  .\install.ps1 -Server <adresse du serveur> -Token <jeton>        (PowerShell en administrateur)

Le jeton est dans Server > Tokens de l'interface du serveur (ou affiché à l'installation du serveur). La sonde se
présente au serveur, qui l'admet et lui envoie ses flux.

Serveur
-------
Linux / macOS :  sudo ./install.sh
Windows       :  .\install.ps1

Le serveur installe aussi VictoriaMetrics (les mesures, en local seulement) et Grafana (port 3000), déjà reliés :
source de données et tableaux de bord SYNTRAF provisionnés. --no-stack / -NoStack si vous avez déjà les vôtres.
L'installation affiche l'adresse de l'interface web, celle de Grafana, le jeton d'enrôlement des sondes et
l'emplacement des mots de passe admin initiaux.

Ports à ouvrir sur le serveur : 6531/tcp (sondes), 5000/tcp (interface web), 3000/tcp (Grafana).

Mise à jour : relancer le script d'installation d'une version plus récente ; la configuration et les données sont
gardées. Les sondes peuvent aussi être mises à jour depuis le serveur (page Updates).

Désinstallation : ./uninstall.sh (ou .\uninstall.ps1) ; --purge / -Purge efface aussi configuration et données.

Emplacements
------------
                Linux                     macOS                          Windows
code            /opt/syntraf-<rôle>        /usr/local/syntraf-<rôle>       C:\Program Files\SYNTRAF\<rôle>
configuration   /etc/syntraf-<rôle>        /usr/local/etc/syntraf-<rôle>   C:\ProgramData\SYNTRAF\<rôle>
données         /var/lib/syntraf-<rôle>    /usr/local/var/syntraf-<rôle>   C:\ProgramData\SYNTRAF\<rôle>\data
journaux        /var/log/syntraf-<rôle>    /usr/local/var/log/...          C:\ProgramData\SYNTRAF\<rôle>\log
services        systemd / OpenRC           launchd                         tâches planifiées « SYNTRAF … »
                (serveur : syntraf-server, syntraf-victoriametrics, syntraf-grafana)
