# Changelog

Toutes les modifications notables apportées à ce projet seront documentées dans ce fichier.

## [1.1.0] - 2025-04-23

### Ajouté
- Support standard des logs au format syslog pour la détection d'élévation de privilèges domain admin
- Extraction automatique du hostname à partir des logs syslog
- Configuration améliorée pour la surveillance active des fichiers de logs dans Docker

### Modifié
- Simplification du parser pour utiliser la détection par mots-clés avec `contains` plutôt que des regex complexes
- Architecture améliorée avec un marqueur `domain_admin: true` pour la communication entre parser et scénario
- Amélioration de la configuration du scénario pour une détection plus précise

### Supprimé
- Suppression du parser raw personnalisé au profit d'une solution plus standard et maintenable
- Retrait des configurations inutiles ou redondantes dans les fichiers acquis.yaml

### Corrigé
- Résolution du problème de détection automatique des nouvelles entrées de logs
- Correction de l'extraction du hostname, qui apparaît maintenant correctement dans les alertes
- Amélioration de la fiabilité des déclenchements d'alertes et notifications
