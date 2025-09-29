# Architecture du Security Monitoring Agent

## Vue d'ensemble

```
┌─────────────────────────────────────────────────────────────────┐
│                    Security Monitoring Agent                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────┐ │
│  │   Cron Job      │    │  Manual Run     │    │   CI/CD     │ │
│  │   (5 minutes)   │    │  (scripts)      │    │ (GitHub)    │ │
│  └─────────┬───────┘    └─────────┬───────┘    └─────┬───────┘ │
│            │                      │                  │         │
│            └──────────────────────┼──────────────────┘         │
│                                   │                            │
│            ┌──────────────────────▼──────────────────┐         │
│            │           Main Entry Point              │         │
│            │         (agent/__main__.py)             │         │
│            └─────────────────────┬───────────────────┘         │
│                                  │                            │
│            ┌─────────────────────▼───────────────────┐         │
│            │        Collector Manager                │         │
│            │     (collectors/manager.py)             │         │
│            └─────────────────────┬───────────────────┘         │
│                                  │                            │
│  ┌───────────────┬───────────────┼───────────────┬───────────┐ │
│  │               │               │               │           │ │
│  ▼               ▼               ▼               ▼           ▼ │
│ ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────┐ │
│ │Network  │   │System   │   │   USB   │   │ AppSec  │   │State│ │
│ │Collector│   │Collector│   │Collector│   │Collector│   │Mgr  │ │
│ └─────────┘   └─────────┘   └─────────┘   └─────────┘   └─────┘ │
│     │             │             │             │           │     │
│     ▼             ▼             ▼             ▼           ▼     │
│ ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────┐ │
│ │ Ports   │   │  CPU    │   │ Events  │   │ HTTP    │   │Cache│ │
│ │Services │   │ Memory  │   │  USB    │   │ TLS     │   │Deltas│ │
│ │Interfaces│   │ Disk    │   │         │   │ SBOM    │   │     │ │
│ │Connections│   │Processes│   │         │   │ DAST    │   │     │ │
│ └─────────┘   └─────────┘   └─────────┘   │ Policies │   └─────┘ │
│                                           └─────────┘           │
└─────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Output & Storage                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────┐ │
│  │   JSON Output   │    │   State Cache   │    │   Logs      │ │
│  │ (monitoring-*.  │    │ (state.json)    │    │ (security-  │ │
│  │  json)          │    │                 │    │  monitor.   │ │
│  └─────────────────┘    └─────────────────┘    │  log)       │ │
│                                                └─────────────┘ │
│                                                                 │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────┐ │
│  │   Alerts        │    │   Policies      │    │   Reports   │ │
│  │ (HIGH/WARN/INFO)│    │ (YAML config)   │    │ (Summary)   │ │
│  └─────────────────┘    └─────────────────┘    └─────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## Composants Détaillés

### 1. Point d'Entrée Principal
```
agent/__main__.py
├── Gestion des arguments de ligne de commande
├── Initialisation des managers
├── Orchestration de la collection
├── Sauvegarde des résultats
└── Génération des rapports
```

### 2. Gestionnaire de Collecteurs
```
collectors/manager.py
├── Orchestration de tous les collecteurs
├── Calcul des deltas et alertes
├── Gestion des seuils configurables
├── Dé-duplication des alertes
└── Intégration avec le state manager
```

### 3. Collecteurs de Données

#### Collecteur Réseau
```
collectors/network.py
├── Détection des ports ouverts (ss -tulpen)
├── Identification des services actifs
├── Monitoring des interfaces réseau
├── Statistiques de connexions
└── Validation des politiques réseau
```

#### Collecteur Système
```
collectors/system.py
├── Métriques CPU (loadavg, /proc/stat)
├── Utilisation mémoire (/proc/meminfo)
├── Espace disque (df -hT)
├── Top processus (ps aux)
└── Surveillance des ressources
```

#### Collecteur USB
```
collectors/usb.py
├── Événements d'ajout/suppression (lsusb)
├── Monitoring des changements d'appareils
├── Classification des périphériques
├── Historique des événements
└── Détection des anomalies
```

#### Collecteur AppSec
```
collectors/appsec.py
├── Orchestration des modules AppSec
├── Découverte des services web
├── Coordination des vérifications
└── Agrégation des résultats
```

### 4. Modules AppSec

#### Vérificateur HTTP/TLS
```
appsec/http_checker.py
├── Vérification des headers de sécurité
├── Validation de la configuration TLS
├── Analyse des cookies sécurisés
├── Détection des vulnérabilités
└── Génération de rapports de sécurité
```

#### Générateur SBOM
```
appsec/sbom_generator.py
├── Collecte des packages système (APT/RPM)
├── Inventaire des packages Python
├── Scan des packages Node.js
├── Enrichissement avec les CVEs
└── Export au format CycloneDX
```

#### Scanner DAST
```
appsec/dast_scanner.py
├── Intégration OWASP ZAP
├── Scans automatisés de sécurité
├── Détection de vulnérabilités web
├── Génération de rapports
└── Gestion des timeouts
```

#### Moteur de Politiques
```
appsec/policy_engine.py
├── Évaluation des politiques de sécurité
├── Validation des configurations
├── Génération d'alertes
├── Documentation des violations
└── Recommandations de remédiation
```

### 5. Gestionnaire d'État
```
state/manager.py
├── Cache des données précédentes
├── Calcul des deltas
├── Gestion des alertes (dé-duplication)
├── Nettoyage automatique
└── Persistance des états
```

### 6. Modèles de Données
```
models/schema.py
├── JSON Schema (Draft 2020-12)
├── Modèles Pydantic
├── Validation des données
├── Sérialisation/désérialisation
└── Exemples de données
```

## Flux de Données

### 1. Collection
```
Cron/Manual → Main → Manager → Collectors → System Tools → Raw Data
```

### 2. Traitement
```
Raw Data → Parsers → Validators → Models → Structured Data
```

### 3. Analyse
```
Structured Data → State Manager → Deltas → Alert Generator → Alerts
```

### 4. Sortie
```
Alerts + Data → JSON Serializer → File Output → Logs + Reports
```

## Intégrations

### CI/CD
```
GitHub Actions
├── Linting et validation
├── Tests unitaires
├── Validation des politiques
├── Tests AppSec
└── Build et packaging
```

### Système
```
Linux System Tools
├── ss (sockets)
├── systemctl (services)
├── ip (interfaces)
├── ps (processus)
├── free (mémoire)
├── df (disques)
└── journalctl (logs)
```

### AppSec
```
External Tools
├── OWASP ZAP (DAST)
├── CVE Databases (SBOM)
├── TLS/SSL Libraries
└── HTTP Libraries
```

## Sécurité

### Isolation
- Collecteurs en mode read-only
- Timeouts sur toutes les opérations
- Validation stricte des entrées
- Gestion gracieuse des erreurs

### Audit
- Logs détaillés de toutes les opérations
- Traçabilité complète des actions
- Signatures des fichiers critiques
- Rotation automatique des logs

### Conformité
- Politiques de sécurité configurables
- Validation automatique des règles
- Rapports de conformité
- Alertes sur les violations

Cette architecture garantit un monitoring de sécurité complet, robuste et maintenable.
