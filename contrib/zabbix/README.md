# Modèle Zabbix « SYNTRAF by HTTP »

Santé de SYNTRAF et ses alertes dans Zabbix (6.0 ou plus récent), à partir de `/metrics` du serveur.

1. Importer `syntraf_by_http.json` : *Data collection › Templates › Import*.
2. Lier le modèle *SYNTRAF by HTTP* à un hôte (par exemple le serveur SYNTRAF).
3. Régler `{$SYNTRAF.URL}` (ex. `https://syntraf.example.com:5000`), puis :
   - soit ajouter l'adresse du serveur ou du proxy Zabbix dans SYNTRAF, *Server › Web interface › Collectors
     allowed to read /metrics without a token* ;
   - soit mettre un jeton d'API SYNTRAF dans `{$SYNTRAF.TOKEN}`.

Une requête HTTP par minute ; le reste en éléments dépendants et découvertes : un élément et un déclencheur par sonde
(déconnectée, mesures qui s'accumulent), par base (injoignable, en retard), par fil du serveur (arrêté), et par alerte
SYNTRAF (hors baseline, ou santé de l'outil) : elle devient un problème Zabbix, résolu quand elle se ferme.

Le modèle est généré : `python contrib/zabbix/build_template.py` (ne pas modifier le JSON à la main).
