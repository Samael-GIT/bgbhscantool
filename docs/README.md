# BgBhScan - Outil d'automatisation pour Bug Bounty

BgBhScan est un outil en ligne de commande conçu pour automatiser les tâches courantes dans le processus de Bug Bounty, incluant la reconnaissance passive, active, le scan de vulnérabilités et des tests basiques d'exploitation.

## Fonctionnalités actuelles

### Reconnaissance Passive
- Collecte d'informations WHOIS
- Énumération DNS (enregistrements A, AAAA, NS, MX, TXT, SOA)
- Découverte de sous-domaines via certificats SSL et brute force basique
- Présentation des données sous forme structurée

### Reconnaissance Active
- Scan de ports avec Nmap, incluant détection de services et versions
- Détection des technologies web avec WhatWeb
- Capture d'écran des sites web découverts

### Scan de Vulnérabilités
- Scan web via Nikto et OWASP ZAP (si disponibles)
- Scan réseau avec scripts de vulnérabilité Nmap
- Analyse des en-têtes de sécurité HTTP
- Détection des vulnérabilités courantes dans les configurations web

### Tests d'Exploitation Simples
- Tests basiques d'injection SQL
- Tests de Cross-Site Scripting (XSS)
- Tests de directory traversal
- Rapport des vulnérabilités potentielles

### Rapports
- Génération de rapports au format JSON
- Organisation des résultats par type de reconnaissance/scan
- Inclusion de métadonnées pour le suivi des tests

## Usage

```bash
# Reconnaissance passive d'un domaine
python3 src/main.py passive -t exemple.com

# Reconnaissance active avec scan de ports spécifiques
python3 src/main.py active -t exemple.com -p 80,443,8080

# Scan de vulnérabilités web
python3 src/main.py scan -t exemple.com --type web

# Tests d'exploitation basiques
python3 src/main.py exploit -t exemple.com

# Processus complet (reconnaissance + scan + exploitation)
python3 src/main.py full -t exemple.com

# Enregistrer les résultats dans un fichier
python3 src/main.py passive -t exemple.com -o rapport.json
```

## Installation

### Prérequis
- Python 3.7 ou supérieur
- Outils externes (recommandés mais non obligatoires) :
  - nmap
  - whois
  - whatweb
  - nikto
  - cutycapt (pour les captures d'écran)

### Installation simple
```bash
# Cloner le dépôt
git clone [url-du-repo] bgbhscan
cd bgbhscan

# Exécuter le script d'installation
chmod +x install.sh
./install.sh
```

## Limitations actuelles
- Analyses basiques d'exploitation sans intégration avancée avec des frameworks d'exploitation
- Dépendance aux outils externes pour certaines fonctionnalités
- Tests d'injection basiques sans analyse approfondie des résultats
- Interface uniquement en ligne de commande

## Contribuer
Les contributions sont les bienvenues! N'hésitez pas à soumettre des issues ou des pull requests pour améliorer l'outil.

## License
Ce projet est sous licence MIT.

