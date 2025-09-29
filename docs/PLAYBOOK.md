# Security Monitoring Agent - Playbook de Tests

Ce document décrit les scénarios de test et de validation pour le Security Monitoring Agent.

## 🎯 Objectifs des tests

- Valider le bon fonctionnement des collecteurs
- Vérifier la détection de changements
- Tester le système d'alerting
- Valider les modules AppSec
- S'assurer de la robustesse du système

## 📋 Scénarios de test

### 1. Tests de base du système

#### 1.1 Test de collecte complète
```bash
# Objectif : Vérifier que tous les collecteurs fonctionnent
make collect

# Validation :
# - Fichier JSON généré dans /var/lib/security-monitor/
# - Toutes les sections présentes (network, system, usb, appsec)
# - Pas d'erreurs dans les logs
```

#### 1.2 Test de génération d'exemple
```bash
# Objectif : Vérifier la génération d'exemple
python -m agent --example

# Validation :
# - Fichier example-output.json créé
# - Structure JSON valide
# - Données réalistes
```

#### 1.3 Test de validation de schéma
```bash
# Objectif : Vérifier le schéma JSON
python -m agent --schema

# Validation :
# - Fichier monitoring-schema.json créé
# - Schéma JSON valide (draft 2020-12)
# - Compatible avec les exemples
```

### 2. Tests des collecteurs réseau

#### 2.1 Test de détection des ports
```bash
# Préparation : Démarrer un service HTTP sur port 8080
python3 -m http.server 8080 &

# Test :
make collect

# Validation :
# - Port 8080 détecté dans open_ports
# - Service HTTP identifié
# - Alerte générée pour nouveau port (si non baseliné)
```

#### 2.2 Test de détection des services
```bash
# Préparation : Activer/désactiver un service
sudo systemctl start telnet  # Si disponible

# Test :
make collect

# Validation :
# - Service telnet détecté comme actif
# - Alerte HIGH générée (politique no_telnet)
```

#### 2.3 Test des interfaces réseau
```bash
# Préparation : Changer l'état d'une interface
sudo ip link set eth0 down
sudo ip link set eth0 up

# Test :
make collect

# Validation :
# - Changement d'état détecté
# - Statistiques RX/TX calculées
# - Deltas corrects
```

### 3. Tests du système d'alerting

#### 3.1 Test d'alerte CPU
```bash
# Préparation : Simuler une charge CPU élevée
stress-ng --cpu 4 --timeout 60s &

# Test :
make collect

# Validation :
# - Load1 > 2.0 détecté
# - Alerte WARN générée
# - Dé-duplication fonctionne (pas de répétition)
```

#### 3.2 Test d'alerte mémoire
```bash
# Préparation : Consommer de la mémoire
python3 -c "
import time
data = []
for i in range(1000):
    data.append('x' * 1000000)
    time.sleep(0.1)
" &

# Test :
make collect

# Validation :
# - Utilisation mémoire > 90% détectée
# - Alerte WARN générée
# - Top processus identifiés
```

#### 3.3 Test d'alerte disque
```bash
# Préparation : Remplir le disque
dd if=/dev/zero of=/tmp/fill_disk bs=1M count=1000

# Test :
make collect

# Validation :
# - Utilisation disque > 85% détectée
# - Alerte WARN générée
# - Nettoyage recommandé
```

### 4. Tests des événements USB

#### 4.1 Test d'ajout d'appareil USB
```bash
# Préparation : Brancher un appareil USB
# (Test manuel - brancher une clé USB)

# Test :
make collect

# Validation :
# - Événement USB détecté
# - Informations device récupérées
# - Timestamp correct
```

#### 4.2 Test de suppression d'appareil USB
```bash
# Préparation : Débrancher l'appareil USB
# (Test manuel - débrancher la clé USB)

# Test :
make collect

# Validation :
# - Événement de suppression détecté
# - État mis à jour
```

### 5. Tests AppSec

#### 5.1 Test des vérifications HTTP
```bash
# Préparation : Démarrer un serveur web local
python3 -m http.server 8000 &

# Test :
make appsec-check

# Validation :
# - Service HTTP détecté
# - Vérifications de sécurité effectuées
# - Headers manquants identifiés
# - Alerte pour HTTP non-TLS
```

#### 5.2 Test de génération SBOM
```bash
# Test :
make sbom-generate

# Validation :
# - Packages système détectés
# - Packages Python détectés
# - CVEs associés (si disponibles)
# - Format CycloneDX correct
```

#### 5.3 Test des politiques
```bash
# Test :
make policy-check

# Validation :
# - Toutes les politiques évaluées
# - Résultats cohérents
# - Évidences fournies
```

### 6. Tests de changement d'état

#### 6.1 Test de nouveaux ports
```bash
# Préparation : Démarrer un nouveau service
nc -l 9999 &

# Test :
make collect

# Validation :
# - Port 9999 dans new_open_ports
# - Alerte générée
# - Baseline mise à jour
```

#### 6.2 Test de fermeture de ports
```bash
# Préparation : Arrêter le service précédent
killall nc

# Test :
make collect

# Validation :
# - Port 9999 dans closed_ports
# - Changement détecté
```

### 7. Tests de robustesse

#### 7.1 Test de timeout
```bash
# Préparation : Simuler une commande lente
sudo mv /bin/ss /bin/ss.backup
echo '#!/bin/bash\nsleep 60' | sudo tee /bin/ss
sudo chmod +x /bin/ss

# Test :
timeout 30s make collect

# Validation :
# - Timeout respecté
# - Erreur gérée gracieusement
# - Système reste fonctionnel

# Nettoyage :
sudo mv /bin/ss.backup /bin/ss
```

#### 7.2 Test de permissions
```bash
# Préparation : Changer les permissions
sudo chmod 000 /var/lib/security-monitor

# Test :
make collect

# Validation :
# - Erreur de permission gérée
# - Message d'erreur clair
# - Système ne crash pas

# Nettoyage :
sudo chmod 755 /var/lib/security-monitor
```

### 8. Tests de performance

#### 8.1 Test de charge
```bash
# Préparation : Lancer plusieurs collections simultanées
for i in {1..5}; do
  make collect &
done
wait

# Validation :
# - Toutes les collections réussissent
# - Pas de corruption de données
# - Performance acceptable
```

#### 8.2 Test de mémoire
```bash
# Préparation : Surveiller l'utilisation mémoire
while true; do
  make collect
  ps aux | grep python | grep agent
  sleep 5
done

# Validation :
# - Pas de fuite mémoire
# - Utilisation stable
# - Nettoyage correct
```

### 9. Tests d'intégration CI/CD

#### 9.1 Test du pipeline local
```bash
# Test :
make ci-dry-run

# Validation :
# - Tous les tests passent
# - Politiques validées
# - Aucune alerte critique
```

#### 9.2 Test de validation des politiques
```bash
# Préparation : Violer une politique
sudo systemctl start telnet

# Test :
make policy-check

# Validation :
# - Politique no_telnet échoue
# - Évidence correcte
# - CI devrait échouer
```

## 🔧 Scripts de test automatisés

### Script de test complet
```bash
#!/bin/bash
# test-complete.sh - Test complet du système

set -e

echo "🧪 Début des tests complets"

# Test 1: Collecte de base
echo "Test 1: Collecte de base"
make collect
echo "✅ Collecte réussie"

# Test 2: Génération d'exemple
echo "Test 2: Génération d'exemple"
python -m agent --example
echo "✅ Exemple généré"

# Test 3: Validation des politiques
echo "Test 3: Validation des politiques"
make policy-check
echo "✅ Politiques validées"

# Test 4: AppSec
echo "Test 4: Tests AppSec"
make appsec-check
echo "✅ AppSec validé"

# Test 5: SBOM
echo "Test 5: Génération SBOM"
make sbom-generate
echo "✅ SBOM généré"

echo "🎉 Tous les tests sont passés!"
```

### Script de test de charge
```bash
#!/bin/bash
# test-load.sh - Test de charge

echo "🚀 Test de charge"

# Lancer 10 collections simultanées
for i in {1..10}; do
  echo "Lancement collection $i"
  make collect &
done

# Attendre la fin
wait

echo "✅ Test de charge terminé"
```

## 📊 Métriques de validation

### Critères de succès

- **Collecte** : 100% des collecteurs fonctionnent
- **Alertes** : Détection correcte des seuils
- **Performance** : < 30 secondes par collection
- **Mémoire** : < 100MB d'utilisation
- **Robustesse** : Gestion gracieuse des erreurs

### Métriques à surveiller

- Temps de collecte par module
- Nombre d'alertes générées
- Taux d'erreur par collecteur
- Utilisation mémoire/CPU
- Taille des fichiers de sortie

## 🐛 Dépannage des tests

### Problèmes courants

1. **Permissions insuffisantes**
   ```bash
   sudo chown -R $USER /var/lib/security-monitor
   ```

2. **Services non disponibles**
   ```bash
   # Vérifier les services requis
   systemctl status systemd-udevd
   ```

3. **Ports déjà utilisés**
   ```bash
   # Vérifier les ports disponibles
   ss -tlnp | grep :8080
   ```

### Logs de debug

```bash
# Activer les logs détaillés
export SECURITY_MONITOR_LOG_LEVEL=DEBUG
make collect

# Vérifier les logs
tail -f /var/log/security-monitor.log
```

## 📝 Rapport de test

Après chaque série de tests, générer un rapport :

```bash
#!/bin/bash
# generate-test-report.sh

REPORT_FILE="test-report-$(date +%Y%m%d-%H%M%S).md"

cat > "$REPORT_FILE" << EOF
# Rapport de Test - $(date)

## Résumé
- Date: $(date)
- Environnement: $(uname -a)
- Python: $(python3 --version)

## Tests effectués
- [ ] Collecte de base
- [ ] Génération d'exemple
- [ ] Validation des politiques
- [ ] Tests AppSec
- [ ] Génération SBOM

## Résultats
- Succès: X/Y
- Échecs: X
- Alertes: X

## Recommandations
- [ ] Actions correctives nécessaires
- [ ] Améliorations suggérées
EOF

echo "Rapport généré: $REPORT_FILE"
```

---

Ce playbook doit être exécuté régulièrement pour s'assurer du bon fonctionnement du système de monitoring.
