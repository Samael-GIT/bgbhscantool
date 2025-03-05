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

