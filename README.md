=======
# Security Monitoring Agent

Un agent de monitoring de sécurité et système pour Linux, exécuté toutes les 5 minutes via cron. Il collecte des métriques réseau/système, détecte les changements, et déclenche des alertes. Inclut un pont AppSec avec des vérifications HTTP/TLS, SBOM+CVEs, DAST léger, et policy-as-code intégrables en CI.

## 🎯 Objectifs

- **Monitoring système** : CPU, mémoire, disque, processus, ports réseau
- **Détection de changements** : Nouveaux ports, services, interfaces
- **Alerting intelligent** : Seuils configurables avec dé-duplication
- **AppSec intégré** : Vérifications HTTP/TLS, SBOM, DAST, politiques
- **CI/CD ready** : Intégration GitHub Actions avec validation des politiques

## 🏗️ Architecture

```
agent/
├── collectors/          # Collecteurs de données
│   ├── network.py      # Ports, services, interfaces
│   ├── system.py       # CPU, mémoire, disque
│   ├── usb.py          # Événements USB
│   └── manager.py      # Orchestrateur principal
├── appsec/             # Modules AppSec
│   ├── http_checker.py # Vérifications HTTP/TLS
│   ├── sbom_generator.py # Génération SBOM
│   ├── dast_scanner.py # Scan DAST (ZAP)
│   └── policy_engine.py # Moteur de politiques
├── models/             # Schémas et modèles
│   └── schema.py       # JSON Schema + Pydantic
└── state/              # Gestion d'état
    └── manager.py      # Cache et deltas
```

## 🚀 Installation

### Prérequis

- Python 3.11+
- Linux (Debian/Ubuntu/CentOS/RHEL)
- Outils système : `ss`, `systemctl`, `ip`, `ps`, `free`, `df`

### Installation rapide

```bash
# Cloner le projet
git clone <repository-url>
cd monitoring

# Configuration initiale
make setup
make install

# Test initial
make test
make collect
```

### Installation avec cron

```bash
# Installer le job cron (toutes les 5 minutes)
sudo ./scripts/install_cron.sh

# Vérifier l'installation
make status
```

## 📊 Utilisation

### Commandes de base

```bash
# Collection unique
make collect

# Test complet
make test

# Statut du système
make status

# Logs récents
make logs

# Vérification des politiques
make policy-check
```

### Scripts utilitaires

```bash
# Collection manuelle
./scripts/run.sh

# Test de collection
./scripts/run.sh --test

# Mode démon (continu)
./scripts/run.sh --daemon

# Installation cron
sudo ./scripts/install_cron.sh

# Désinstallation cron
sudo ./scripts/install_cron.sh --remove
```

## 🔧 Configuration

### Fichier de politiques (`config/policies.yaml`)

```yaml
policies:
  - id: "POL_NO_TELNET"
    name: "No Telnet Service"
    severity: "high"
    rule: "no_telnet"
    enabled: true
    
  - id: "POL_WIFI_DISABLE_IF_ETHERNET"
    name: "WiFi Disabled with Ethernet"
    severity: "warn"
    rule: "wifi_disable_ethernet"
    enabled: true

thresholds:
  cpu:
    load1: 2.0
  memory:
    usage_percent: 90.0
  disk:
    usage_percent: 85.0
```

### Variables d'environnement

```bash
# Répertoire d'état (défaut: /var/lib/security-monitor)
export SECURITY_MONITOR_STATE_DIR="/var/lib/security-monitor"

# Fichier de configuration
export SECURITY_MONITOR_CONFIG="config/policies.yaml"

# Niveau de log
export SECURITY_MONITOR_LOG_LEVEL="INFO"
```

## 📈 Format de sortie

### Structure JSON

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "host": "security-monitor.local",
  "run_id": "uuid-here",
  "network": {
    "open_ports": [...],
    "services": [...],
    "interfaces": [...],
    "connections": {...},
    "policy": {...}
  },
  "system": {
    "cpu": {...},
    "memory": {...},
    "disk": [...],
    "top_processes": {...}
  },
  "usb": {
    "recent_events": [...]
  },
  "appsec": {
    "http_checks": [...],
    "sbom": {...},
    "dast": {...},
    "policies": [...]
  },
  "diff": {
    "new_open_ports": [...],
    "closed_ports": [...],
    "service_state_changes": [...],
    "alerts": [...]
  }
}
```

### Exemple de sortie

```bash
# Générer un exemple
python -m agent --example

# Collection complète
python -m agent --collect
```

## 🚨 Alerting

### Types d'alertes

- **HIGH** : Services à haut risque (Telnet, SMB exposé)
- **WARN** : Seuils système dépassés, WiFi avec Ethernet
- **INFO** : Changements de configuration

### Seuils par défaut

- CPU load1 > 2.0
- Mémoire > 90%
- Disque > 85%
- I/O wait > 20%

### Dé-duplication

Les alertes identiques ne sont pas répétées pendant 1 heure.

## 🔒 AppSec

### Vérifications HTTP/TLS

- Headers de sécurité (HSTS, CSP, X-Frame-Options)
- Configuration TLS (version, cipher suites)
- Cookies sécurisés (Secure, HttpOnly, SameSite)

### SBOM (Software Bill of Materials)

- Packages système (APT/RPM)
- Packages Python (pip)
- Packages Node.js (npm)
- Enrichissement CVE

### DAST (Dynamic Application Security Testing)

- Scan OWASP ZAP (optionnel)
- Détection de vulnérabilités web
- Tests automatisés

### Policy-as-Code

- Règles YAML configurables
- Validation automatique
- Intégration CI/CD

## 🧪 Tests

### Tests unitaires

```bash
# Tests de base
make test

# Tests AppSec
make appsec-check

# Génération SBOM
make sbom-generate

# Validation des politiques
make policy-check
```

### Scénarios de validation

Voir [PLAYBOOK.md](docs/PLAYBOOK.md) pour les scénarios de test détaillés.

## 🔄 CI/CD

### GitHub Actions

Le pipeline CI/CD valide automatiquement :

1. **Code Quality** : Linting, validation des schémas
2. **Security Policies** : Vérification des politiques critiques
3. **Integration Tests** : Tests de collection complète
4. **AppSec Validation** : Tests HTTP/TLS, SBOM, politiques
5. **Build** : Création du package de déploiement

### Échec sur politiques critiques

Le build échoue si des politiques critiques sont violées :

```yaml
# Exemple de politique critique
- id: "POL_NO_TELNET"
  severity: "high"
  rule: "no_telnet"
```

## 📚 Documentation

- [PLAYBOOK.md](docs/PLAYBOOK.md) - Scénarios de test et validation
- [THREAT_MODEL.md](docs/THREAT_MODEL.md) - Modèle de menaces STRIDE
- [API.md](docs/API.md) - Documentation des APIs (si applicable)

## 🛠️ Développement

### Structure du projet

```bash
# Développement
make dev-setup

# Tests rapides
make quick-test

# Validation de configuration
make validate-config

# Informations système
make info
```

### Ajout de nouveaux collecteurs

1. Créer la classe dans `agent/collectors/`
2. Hériter de `BaseCollector`
3. Implémenter la méthode `collect()`
4. Ajouter au `CollectorManager`

### Ajout de nouvelles politiques

1. Ajouter la règle dans `config/policies.yaml`
2. Implémenter l'évaluateur dans `PolicyEngine`
3. Ajouter les tests correspondants

## 🐛 Dépannage

### Problèmes courants

```bash
# Vérifier les dépendances
make info

# Vérifier les permissions
ls -la /var/lib/security-monitor

# Vérifier les logs
tail -f /var/log/security-monitor.log

# Test de connectivité
python -m agent --test
```

### Logs

- **Agent** : `/var/log/security-monitor.log`
- **Cron** : `/var/log/security-monitor-cron.log`
- **État** : `/var/lib/security-monitor/state.json`

### Nettoyage d'urgence

```bash
# Arrêt d'urgence
make emergency-stop

# Nettoyage complet
make emergency-clean
```

## 📋 Roadmap

- [ ] Interface web pour visualisation
- [ ] Intégration avec SIEM (Splunk, ELK)
- [ ] Support des conteneurs Docker
- [ ] API REST pour intégration externe
- [ ] Dashboards Grafana
- [ ] Support multi-sites

## 🤝 Contribution

1. Fork le projet
2. Créer une branche feature (`git checkout -b feature/AmazingFeature`)
3. Commit les changements (`git commit -m 'Add some AmazingFeature'`)
4. Push vers la branche (`git push origin feature/AmazingFeature`)
5. Ouvrir une Pull Request

### Standards de code

- Python 3.11+ avec type hints
- Tests unitaires pour nouveaux collecteurs
- Documentation des nouvelles fonctionnalités
- Validation des politiques critiques

## 📄 Licence

Ce projet est sous licence MIT. Voir [LICENSE](LICENSE) pour plus de détails.

## 🆘 Support

- **Issues** : [GitHub Issues](https://github.com/your-repo/issues)
- **Documentation** : [Wiki](https://github.com/your-repo/wiki)
- **Email** : security-monitor@example.com

---

**Note** : Ce système est conçu pour un usage en production. Assurez-vous de tester toutes les configurations avant le déploiement.
>>>>>>> 2704059 (chore(repo): snapshot working monitoring app (schema, collectors, policy engine, make targets))
