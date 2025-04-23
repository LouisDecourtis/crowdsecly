# Détection d'élévation de privilèges Domain Admin avec CrowdSec

Ce projet implémente une solution de détection d'élévation de privilèges domain admin en utilisant CrowdSec, une solution open-source de sécurité collaborative. Le système analyse les logs pour détecter quand un utilisateur devient domain admin et génère des alertes en temps réel.

## Table des matières

- [Architecture](#architecture)
- [Prérequis](#prérequis)
- [Installation](#installation)
- [Configuration](#configuration)
  - [Structure des fichiers](#structure-des-fichiers)
  - [Parsers personnalisés](#parsers-personnalisés)
  - [Scénario de détection](#scénario-de-détection)
- [Utilisation](#utilisation)
  - [Démarrage](#démarrage)
  - [Test](#test)
  - [Visualisation des alertes](#visualisation-des-alertes)
- [Dépannage](#dépannage)
- [Fonctionnement technique](#fonctionnement-technique)

## Architecture

Le projet utilise une architecture basée sur Docker pour faciliter le déploiement et l'isolation. Les composants principaux sont :

- **CrowdSec** : Moteur d'analyse et de détection
- **Parsers personnalisés** : Pour traiter les logs spécifiques d'élévation de privilèges
- **Scénario de détection** : Règle qui déclenche une alerte lorsqu'un utilisateur devient domain admin

Le flux de données est le suivant :
1. Les logs sont écrits dans un fichier de test
2. CrowdSec surveille ce fichier et analyse les nouvelles entrées
3. Les parsers extraient les informations pertinentes
4. Le scénario évalue si une élévation de privilèges a eu lieu
5. Une alerte est générée si le scénario est déclenché

## Prérequis

- Docker
- Accès en lecture/écriture au répertoire du projet

## Installation

1. Clonez ce dépôt :
   ```bash
   git clone https://github.com/LouisDecourtis/crowdsecly.git
   cd crowdsecly
   ```

2. Lancez le conteneur CrowdSec :
   ```bash
   docker run -d --name crowdsec \
     -v $(pwd)/config:/etc/crowdsec \
     -v $(pwd)/data:/var/lib/crowdsec/data \
     -v $(pwd)/tests:/tests:ro \
     -p 8080:8080 \
     crowdsecurity/crowdsec:latest
   ```
> **Note**: Le port 8080 est utilisé pour l'API locale (LAPI) de CrowdSec, qui permet aux bouncers et à l'interface de communication avec le moteur CrowdSec.

## Configuration

### Structure des fichiers

```
crowdsec-local/
├── config/                      # Configuration CrowdSec
│   ├── acquis.yaml              # Configuration d'acquisition des logs
│   ├── parsers/
│   │   ├── s00-raw/
│   │   │   └── custom-domain-admin-parser.yaml  # Parser initial
│   │   └── s01-parse/
│   │       └── domain-admin-s01.yaml           # Parser de préservation
│   └── scenarios/
│       └── detect-domain-admin.yaml            # Scénario de détection
├── data/                        # Données persistantes CrowdSec
└── tests/                       # Répertoire de test
    └── nginx/
        └── nginx.log            # Fichier de log de test
```

### Parsers personnalisés

Deux parsers personnalisés ont été créés pour traiter correctement les logs d'élévation de privilèges :

#### 1. Parser initial (s00-raw)

Ce parser extrait les informations de base du log au format syslog :

```yaml
# config/parsers/s00-raw/custom-domain-admin-parser.yaml
filter: "evt.Line.Labels.type == 'syslog'"
name: local/domain-admin-parser
description: "Parser pour détecter les logs d'élévation de privilèges domain admin"
debug: true
onsuccess: next_stage
nodes:
  - grok:
      pattern: "%{SYSLOGTIMESTAMP:timestamp} %{HOSTNAME:hostname} %{DATA:program}: %{GREEDYDATA:message}"
      apply_on: Line.Raw
statics:
  - meta: program
    expression: evt.Parsed.program
  - meta: message
    expression: evt.Parsed.message
  - meta: log_type
    value: domain_admin_log
```

#### 2. Parser de préservation (s01-parse)

Ce parser s'assure que les logs identifiés comme "domain_admin_log" ne sont pas abandonnés au stage s01-parse :

```yaml
# config/parsers/s01-parse/domain-admin-s01.yaml
filter: "evt.Meta.log_type == 'domain_admin_log'"
name: local/domain-admin-s01
description: "Parser pour préserver les logs domain admin en s01-parse"
debug: true
onsuccess: next_stage
statics:
  - parsed: domain_admin
    value: "true"
```

### Scénario de détection

Le scénario qui déclenche une alerte lorsqu'un utilisateur devient domain admin :

```yaml
# config/scenarios/detect-domain-admin.yaml
type: trigger
name: local/detect-domain-admin
description: "Détecte le log 'Est devenu domain Admin'"
filter: "Match('Est devenu domain Admin', evt.Parsed.message) || Match('Est devenu domain Admin', evt.Meta.message)"
scope:
  type: Hostname
  expression: evt.Parsed.hostname
labels:
  severity: info
  service: custom
```

## Utilisation

### Démarrage

Pour démarrer le conteneur CrowdSec :

```bash
docker start crowdsec
```

Si vous devez le redémarrer après des modifications de configuration :

```bash
docker restart crowdsec
```

### Test

Pour tester la détection, ajoutez une entrée de log simulant une élévation de privilèges :

```bash
echo "May 1 12:34:56 host Process: Est devenu domain Admin" >> tests/nginx/nginx.log
```

### Visualisation des alertes

Pour vérifier si une alerte a été générée :

```bash
docker exec crowdsec cscli alerts list
```

## Dépannage

### Logs de débogage

Pour voir les logs détaillés de CrowdSec :

```bash
docker logs crowdsec
```

### Mode trace

Pour exécuter CrowdSec en mode trace et voir comment les logs sont traités :

```bash
docker exec -it crowdsec crowdsec -c /etc/crowdsec/config.yaml -dsn file:///tests/nginx/nginx.log -type syslog -no-api -trace
```

### Problèmes courants

1. **Aucune alerte n'est générée** :
   - Vérifiez que le format du log correspond au pattern attendu
   - Assurez-vous que les parsers sont correctement chargés (`docker exec crowdsec cscli parsers list`)
   - Vérifiez que le scénario est actif (`docker exec crowdsec cscli scenarios list`)

2. **Container qui crash** :
   - Vérifiez la syntaxe YAML des fichiers de configuration
   - Assurez-vous que les expressions dans les filtres sont valides

## Fonctionnement technique

### Pipeline de traitement CrowdSec

CrowdSec traite les logs en plusieurs étapes :

1. **s00-raw** : Parsing initial des logs bruts
   - Notre parser `custom-domain-admin-parser.yaml` extrait les champs de base

2. **s01-parse** : Parsing spécifique par application
   - Notre parser `domain-admin-s01.yaml` préserve les logs pour qu'ils ne soient pas abandonnés

3. **s02-enrich** : Enrichissement des données
   - Les parsers standard ajoutent des informations contextuelles

4. **Évaluation des scénarios**
   - Notre scénario `detect-domain-admin.yaml` vérifie si le message contient "Est devenu domain Admin"

5. **Génération d'alertes**
   - Une alerte est créée avec le hostname comme scope

Cette architecture modulaire permet d'adapter facilement le système à d'autres types de détection en ajoutant de nouveaux parsers et scénarios.
