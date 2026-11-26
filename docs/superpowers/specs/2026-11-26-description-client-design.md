# Description d'un client (sonde) — conception courte

Date : 2026-11-26
Branche de départ : `fix-course-demarrage`.
État : approuvée par l'utilisateur.

## Intention

Mieux documenter chaque nœud : un texte libre écrit par l'admin dans la page Clients (emplacement, réseau, contact,
particularités). C'est un pense-bête d'administration, pas une étiquette pour lire les résultats.

## Objectifs / non-objectifs

- Objectif : saisir, modifier, effacer et consulter la description d'un client depuis la page Clients.
- Non-objectifs : l'afficher dans Stats, la carte en direct ou Grafana ; l'envoyer aux sondes.
- Anti-objectif : qu'une modification de la description reconnecte la sonde ou touche aux mesures.

## Approches considérées

1. **Clé `DESCRIPTION` dans `SERVER_CLIENT`, sur le modèle de `DEPLOYMENT_GROUP`** (retenue). La documentation vit
   avec la déclaration du client, suit les sauvegardes de la config, et réutilise la validation, l'écriture du
   formulaire et le classement en clé « sans reconnexion » (`METADATA_CLIENT_KEYS`).
2. Fichier de notes séparé par sonde : une seconde chose à sauvegarder et à garder synchronisée (renommage,
   suppression d'un client), sans gain. Écartée.
3. Affichage aussi dans Stats / carte / Grafana : hors du besoin exprimé (documentation pour l'admin). Écartée.

## Conception

- **Donnée** : clé facultative `DESCRIPTION` d'un `SERVER_CLIENT`. Texte libre multiligne, 500 caractères au plus
  après `strip()` ; au-delà, erreur de champ (refus, pas de troncature). Vide : la clé est retirée.
- **Sans reconnexion** : `DESCRIPTION` ajoutée à `METADATA_CLIENT_KEYS` (donc à `LIVE_CLIENT_KEYS`). Elle ne doit
  pas apparaître dans la configuration envoyée aux sondes ; à vérifier dans le code qui la génère.
- **Compatibilité** : un appel (API ou ancien formulaire) sans `DESCRIPTION` laisse la valeur en place, comme
  `DEPLOYMENT_GROUP` dans `_apply_client_form`.
- **Formulaire** (`client_config.html`) : zone de texte « Description (optional) » sous le groupe de déploiement,
  `maxlength="500"`, avec retour d'erreur de champ.
- **Tableau** : colonne « Description » montrant la première ligne, coupée vers 60 caractères avec « … » ; texte
  complet en infobulle (`title`). Tout passe par `st.esc`.
- **API** : la documentation OpenAPI des clients (`st_api_v1.py`) décrit le champ s'il y a un schéma des clients.
- **i18n** : nouveaux libellés ajoutés dans `lib/webui/static/i18n/fr.json`.

## Tests

Limite de 500 caractères (499/500 acceptés, 501 refusé), effacement par texte vide, valeur conservée quand le champ
est absent, multiligne conservé, changement de description classé sans reconnexion.

## Laissé au builder

Emplacement exact des tests (suivre ceux de `DEPLOYMENT_GROUP`), libellé exact de l'aide du champ.
