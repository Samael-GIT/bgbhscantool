[ BgBhScan - Outil d'automatisation pour Bug Bounty ]
[ Version 1.0.0                                     ]
[ Auteur: 丂卂爪卂乇ㄥ                               ]

## Description
BgBhScan est un outil en ligne de commande puissant conçu pour automatiser les différentes phases du Bug Bounty et des tests de pénétration. Il intègre plusieurs outils populaires dans une interface unifiée pour accélérer le processus de reconnaissance et d'identification des vulnérabilités.

## Fonctionnalités

### Reconnaissance Passive
- Collecte d'informations WHOIS sur les domaines cibles
- Énumération DNS complète (A, AAAA, NS, MX, TXT, SOA)
- Découverte automatique de sous-domaines via:
  - Certificats SSL (via crt.sh)
  - Brute force de sous-domaines communs
- Analyses historiques des domaines

### Reconnaissance Active
- Scan de ports personnalisable avec Nmap
- Détection de services et versions
- Identification des technologies web (via WhatWeb)
- Prise de captures d'écran des sites découverts

### Scan de Vulnérabilités 
- Scan web avec Nikto
- Intégration optionnelle avec OWASP ZAP
- Analyse des en-têtes de sécurité HTTP
- Vérification des configurations de sécurité courantes
- Scan de vulnérabilités réseau

### Tests d'Exploitation Basiques
- Tests automatisés d'injection SQL
- Détection de vulnérabilités XSS
- Vérification de directory traversal
- Rapports détaillés des résultats

### Interface Utilisateur
- Mode CLI pour l'intégration dans des scripts
- Mode interactif avec interface utilisateur colorée
- Affichage détaillé des résultats de scan
- Rapport de progression en temps réel

### Rapports
- Génération de rapports au format JSON
- Organisation claire des résultats par catégorie
- Horodatage et métadonnées pour le suivi
- Options d'exportation flexibles

## Installation

### Prérequis
- Python 3.6+
- pip

### Méthode 1: Installation rapide
```bash
# Cloner le dépôt
git clone https://github.com/samael/bgbhscan.git
cd bgbhscan

# Exécuter le script d'installation
chmod +x install.sh
./install.sh

### Méthode 2: Installation manuelle

# Cloner le dépôt
git clone https://github.com/samael/bgbhscan.git
cd bgbhscan

# Créer un environnement virtuel
python3 -m venv venv
source venv/bin/activate

# Installer les dépendances
pip install -r requirements.txt

# Rendre le script principal exécutable
chmod +x src/main.py

# Créer un lien symbolique (optionnel)
mkdir -p ~/.local/bin
ln -s $(pwd)/src/main.py ~/.local/bin/bgbhscan

Dépendances externes
BgBhScan peut utiliser les outils suivants s'ils sont installés sur votre système:

nmap: Pour les scans de ports et vulnérabilités
whois: Pour la collecte d'informations WHOIS
whatweb: Pour l'identification de technologies web
nikto: Pour les scans de vulnérabilité web
cutycapt/wkhtmltopdf: Pour les captures d'écran
OWASP ZAP: Pour les scans de sécurité web avancés
Utilisation
Mode Ligne de Commande

# Afficher l'aide
bgbhscan --help

# Reconnaissance passive
bgbhscan passive -t exemple.com

# Reconnaissance active avec ports personnalisés
bgbhscan active -t exemple.com -p 80,443,8080-8090

# Scan de vulnérabilités
bgbhscan scan -t exemple.com --type web

# Test d'exploitation
bgbhscan exploit -t exemple.com

# Analyse complète
bgbhscan full -t exemple.com -o rapport.json

# Mode débogage
bgbhscan debug

# Mode interactif
bgbhscan -i


Structure des fichiers

BgBhScan/
├── config/
│   └── tools.json         # Configuration des outils et paramètres
├── docs/                  # Documentation
├── reports/               # Rapports générés automatiquement
├── src/
│   ├── core.py            # Fonctions principales de scan
│   ├── debug.py           # Outils de débogage
│   ├── main.py            # Point d'entrée principal
│   ├── ui.py              # Interface utilisateur
│   └── utils.py           # Fonctions utilitaires
├── install.sh             # Script d'installation
└── requirements.txt       # Dépendances Python




Configuration
Le fichier config/tools.json permet de personnaliser:

Les chemins vers les outils externes
Les paramètres de scan
Les niveaux de log
Les répertoires de sortie
Résolution de problèmes
Si vous rencontrez des problèmes:

Exécutez bgbhscan debug pour diagnostiquer les problèmes courants
Vérifiez que les dépendances sont installées
Assurez-vous que les outils externes sont disponibles dans votre PATH
Consultez les logs pour plus de détails
Génération de rapports d'erreur
En cas d'erreur lors de l'exécution, BgBhScan génère automatiquement un rapport d'erreur détaillé dans le dossier reports/errors/. Ce rapport inclut:

Un timestamp précis
La commande exécutée
La trace complète de l'erreur
L'état du système au moment de l'erreur
Ces rapports facilitent le débogage et peuvent être partagés pour obtenir de l'aide.

Contribuer
Les contributions sont les bienvenues! Pour contribuer:

Forkez le dépôt
Créez une branche pour votre fonctionnalité
Ajoutez vos modifications
Soumettez une pull request



Licence
Ce projet est sous licence MIT - voir le fichier LICENSE pour plus de détails.

Crédits
Développé avec passion par 丂卂爪卂乇ㄥ

Note: Cet outil est destiné à des fins éducatives et de sécurité légitimes uniquement. L'utilisation de BgBhScan contre des systèmes sans autorisation préalable est illégale et non encouragée.

"La sécurité n'est pas un produit, mais un processus." - Bruce Schneier
