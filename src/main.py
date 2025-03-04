#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import sys
import json
from pathlib import Path
import warnings

# Supprimer les avertissements SSL
warnings.filterwarnings("ignore", category=Warning)

# Import des modules internes
from core import passive_recon, active_recon, vulnerability_scan, exploit_vulnerabilities
from utils import setup_logging, generate_report, banner

def load_config():
    """Charge la configuration depuis le fichier config.json"""
    config_path = Path(__file__).resolve().parent.parent / "config" / "config.json"
    try:
        with open(config_path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Erreur: Le fichier de configuration n'a pas été trouvé à {config_path}")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Erreur: Le fichier de configuration contient un JSON invalide")
        sys.exit(1)

def main():
    # Chargement de la configuration
    config = load_config()
    
    # Configuration du logging
    logger = setup_logging(config["logging"]["level"])
    
    # Affichage du banner
    banner()
    
    # Création du parser d'arguments
    parser = argparse.ArgumentParser(description="BgBhScan - Un outil tout-en-un pour l'automatisation de Bug Bounty")
    subparsers = parser.add_subparsers(dest="command", help="Commandes disponibles")
    
    # Sous-commande pour la reconnaissance passive
    passive_parser = subparsers.add_parser("passive", help="Reconnaissance passive")
    passive_parser.add_argument("-t", "--target", required=True, help="Domaine ou IP cible")
    passive_parser.add_argument("-o", "--output", help="Fichier de sortie pour les résultats")
    
    # Sous-commande pour la reconnaissance active
    active_parser = subparsers.add_parser("active", help="Reconnaissance active")
    active_parser.add_argument("-t", "--target", required=True, help="Domaine ou IP cible")
    active_parser.add_argument("-p", "--ports", default="1-1000", help="Plages de ports (ex: 80,443,8080 ou 1-1000)")
    active_parser.add_argument("-o", "--output", help="Fichier de sortie pour les résultats")
    
    # Sous-commande pour le scan de vulnérabilités
    scan_parser = subparsers.add_parser("scan", help="Scan de vulnérabilités")
    scan_parser.add_argument("-t", "--target", required=True, help="Domaine ou IP cible")
    scan_parser.add_argument("--type", choices=["web", "network", "full"], default="full", 
                           help="Type de scan à effectuer")
    scan_parser.add_argument("-o", "--output", help="Fichier de sortie pour les résultats")
    
    # Sous-commande pour l'exploitation
    exploit_parser = subparsers.add_parser("exploit", help="Exploitation de vulnérabilités")
    exploit_parser.add_argument("-t", "--target", required=True, help="Domaine ou IP cible")
    exploit_parser.add_argument("--vuln", help="Vulnérabilité spécifique à exploiter")
    exploit_parser.add_argument("-o", "--output", help="Fichier de sortie pour les résultats")
    
    # Sous-commande pour le lancement complet
    full_parser = subparsers.add_parser("full", help="Exécution complète (reconnaissance, scan et exploitation)")
    full_parser.add_argument("-t", "--target", required=True, help="Domaine ou IP cible")
    full_parser.add_argument("-o", "--output", help="Fichier de sortie pour les résultats")
    
    # Analyse des arguments
    args = parser.parse_args()
    
    # Si aucun argument n'est fourni, afficher l'aide
    if not args.command:
        parser.print_help()
        sys.exit(1)
        
    # Traitement des commandes
    if args.command == "passive":
        results = passive_recon(args.target, config)
        generate_report(results, args.output, "passive_recon")
        
    elif args.command == "active":
        results = active_recon(args.target, args.ports, config)
        generate_report(results, args.output, "active_recon")
        
    elif args.command == "scan":
        results = vulnerability_scan(args.target, args.type, config)
        generate_report(results, args.output, "vulnerability_scan")
        
    elif args.command == "exploit":
        results = exploit_vulnerabilities(args.target, args.vuln, config)
        generate_report(results, args.output, "exploitation")
        
    elif args.command == "full":
        logger.info("Démarrage du processus complet sur %s", args.target)
        
        logger.info("Étape 1: Reconnaissance passive...")
        recon_passive_results = passive_recon(args.target, config)
        
        logger.info("Étape 2: Reconnaissance active...")
        recon_active_results = active_recon(args.target, "1-1000", config)
        
        logger.info("Étape 3: Scan de vulnérabilités...")
        scan_results = vulnerability_scan(args.target, "full", config)
        
        logger.info("Étape 4: Exploitation...")
        exploit_results = exploit_vulnerabilities(args.target, None, config)
        
        # Assemblage des résultats
        all_results = {
            "passive_recon": recon_passive_results,
            "active_recon": recon_active_results,
            "vulnerability_scan": scan_results,
            "exploitation": exploit_results
        }
        
        generate_report(all_results, args.output, "full_process")
        logger.info("Processus complet terminé!")

if __name__ == "__main__":
    main()
