#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import sys
import warnings
from pathlib import Path

# Ajouter les chemins d'importation
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# Correction des chemins d'importation
def _fix_import_paths():
    """Corriger les chemins d'importation pour permettre l'exécution du script"""
    script_path = Path(__file__).resolve()
    src_dir = script_path.parent
    base_dir = src_dir.parent
    
    # Ajouter les chemins nécessaires au sys.path
    if str(src_dir) not in sys.path:
        sys.path.insert(0, str(src_dir))
    if str(base_dir) not in sys.path:
        sys.path.insert(0, str(base_dir))

# Appliquer la correction des chemins immédiatement
_fix_import_paths()

# Supprimer les avertissements SSL
warnings.filterwarnings("ignore", category=Warning)

# Import du module de débogage pour permettre le mode debug
try:
    from debug import debug_mode
except ImportError:
    def debug_mode():
        """Mode débogage de secours simplifié."""
        print("\nERREUR: Module de débogage non trouvé. Impossible de lancer le mode debug.")
        print("Vérifiez que le fichier debug.py est présent dans le répertoire src/.")
        sys.exit(1)

# Importer les modules nécessaires
try:
    from utils import setup_logging, generate_report, banner, load_config
    from ui import ConsoleUI
    from core import passive_recon, active_recon, vulnerability_scan, exploit_vulnerabilities
    import_successful = True
except ImportError as e:
    print(f"\033[91mERREUR D'IMPORTATION:\033[0m {e}")
    print(f"Chemin Python actuel: {sys.path}")
    import_successful = False

def main():
    """Fonction principale du programme."""
    # Si l'importation a échoué, passer en mode debug
    if not import_successful:
        debug_mode()
        return
    
    # Essayer de charger la configuration
    try:
        config = load_config()
    except Exception as e:
        print(f"\033[91mErreur lors du chargement de la configuration:\033[0m {e}")
        print("Passage en mode debug pour résoudre le problème...")
        debug_mode()
        return

    # Configurer le logging
    logger = setup_logging(config.get("logging", {}).get("level", "INFO"))
    
    # Créer le parser d'arguments
    parser = argparse.ArgumentParser(description="BgBhScan - Un outil tout-en-un pour l'automatisation de Bug Bounty")
    parser.add_argument("-i", "--interactive", action="store_true", help="Mode interactif avec interface utilisateur améliorée")
    subparsers = parser.add_subparsers(dest="command", help="Commandes disponibles")
    
    # Sous-commande pour la reconnaissance passive
    passive_parser = subparsers.add_parser("passive", help="Reconnaissance passive")
    passive_parser.add_argument("-t", "--target", required=True, help="Domaine ou IP cible")
    passive_parser.add_argument("-o", "--output", help="Fichier de sortie pour les résultats")
    passive_parser.add_argument("--pretty", action="store_true", help="Affichage amélioré des résultats")
    
    # Sous-commande pour la reconnaissance active
    active_parser = subparsers.add_parser("active", help="Reconnaissance active")
    active_parser.add_argument("-t", "--target", required=True, help="Domaine ou IP cible")
    active_parser.add_argument("-p", "--ports", default="1-1000", help="Plages de ports (ex: 80,443,8080 ou 1-1000)")
    active_parser.add_argument("-o", "--output", help="Fichier de sortie pour les résultats")
    active_parser.add_argument("--pretty", action="store_true", help="Affichage amélioré des résultats")
    
    # Sous-commande pour le scan de vulnérabilités
    scan_parser = subparsers.add_parser("scan", help="Scan de vulnérabilités")
    scan_parser.add_argument("-t", "--target", required=True, help="Domaine ou IP cible")
    scan_parser.add_argument("--type", choices=["web", "network", "full"], default="full", help="Type de scan à effectuer")
    scan_parser.add_argument("-o", "--output", help="Fichier de sortie pour les résultats")
    scan_parser.add_argument("--pretty", action="store_true", help="Affichage amélioré des résultats")
    
    # Sous-commande pour l'exploitation
    exploit_parser = subparsers.add_parser("exploit", help="Exploitation de vulnérabilités")
    exploit_parser.add_argument("-t", "--target", required=True, help="Domaine ou IP cible")
    exploit_parser.add_argument("--vuln", help="Vulnérabilité spécifique à exploiter")
    exploit_parser.add_argument("-o", "--output", help="Fichier de sortie pour les résultats")
    exploit_parser.add_argument("--pretty", action="store_true", help="Affichage amélioré des résultats")
    
    # Sous-commande pour le lancement complet
    full_parser = subparsers.add_parser("full", help="Exécution complète (reconnaissance, scan et exploitation)")
    full_parser.add_argument("-t", "--target", required=True, help="Domaine ou IP cible")
    full_parser.add_argument("-o", "--output", help="Fichier de sortie pour les résultats")
    full_parser.add_argument("--pretty", action="store_true", help="Affichage amélioré des résultats")
    
    # Sous-commande pour le mode debug
    subparsers.add_parser("debug", help="Mode débogage pour diagnostiquer et réparer les problèmes")
    
    # Analyse des arguments
    args = parser.parse_args()
    
    # Créer l'interface utilisateur si nécessaire
    ui = ConsoleUI(verbose=True) if args.interactive or getattr(args, 'pretty', False) else None

    # Mode interactif
    if args.interactive:
        # Préparer les fonctions à passer à l'interface
        core_functions = {
            "passive_recon": passive_recon,
            "active_recon": active_recon, 
            "vulnerability_scan": vulnerability_scan,
            "exploit_vulnerabilities": exploit_vulnerabilities,
            "generate_report": generate_report
        }
        
        # Lancer l'interface interactive
        ui.run_interactive_mode(core_functions, config)
        return
    
    # Si aucun argument n'est fourni, afficher l'aide
    if not args.command:
        parser.print_help()
        sys.exit(1)
        
    # Vérifier si le mode debug est demandé
    if args.command == "debug":
        debug_mode()
        return
        
    # Traitement des commandes
    if args.command == "passive":
        results = passive_recon(args.target, config)
        if ui:  # Affichage amélioré si --pretty est fourni
            ui.display_scan_results(results, "passive_recon")
        report_path = generate_report(results, args.output, "passive_recon")
        logger.info(f"Rapport généré: {report_path}")
        
    elif args.command == "active":
        results = active_recon(args.target, args.ports, config)
        if ui:  # Affichage amélioré si --pretty est fourni
            ui.display_scan_results(results, "active_recon")
        report_path = generate_report(results, args.output, "active_recon")
        logger.info(f"Rapport généré: {report_path}")
        
    elif args.command == "scan":
        results = vulnerability_scan(args.target, args.type, config)
        if ui:  # Affichage amélioré si --pretty est fourni
            ui.display_scan_results(results, "vulnerability_scan")
        report_path = generate_report(results, args.output, "vulnerability_scan")
        logger.info(f"Rapport généré: {report_path}")
        
    elif args.command == "exploit":
        results = exploit_vulnerabilities(args.target, args.vuln, config)
        if ui:  # Affichage amélioré si --pretty est fourni
            ui.display_scan_results(results, "exploitation")
        report_path = generate_report(results, args.output, "exploitation")
        logger.info(f"Rapport généré: {report_path}")
        
    elif args.command == "full":
        logger.info("Démarrage du processus complet sur %s", args.target)
        
        logger.info("Étape 1: Reconnaissance passive...")
        recon_passive_results = passive_recon(args.target, config)
        if ui:
            ui.display_scan_results(recon_passive_results, "passive_recon")
        
        logger.info("Étape 2: Reconnaissance active...")
        recon_active_results = active_recon(args.target, "1-1000", config)
        if ui:
            ui.display_scan_results(recon_active_results, "active_recon")
        
        logger.info("Étape 3: Scan de vulnérabilités...")
        scan_results = vulnerability_scan(args.target, "full", config)
        if ui:
            ui.display_scan_results(scan_results, "vulnerability_scan")
        
        logger.info("Étape 4: Exploitation...")
        exploit_results = exploit_vulnerabilities(args.target, None, config)
        if ui:
            ui.display_scan_results(exploit_results, "exploitation")
        
        # Assemblage des résultats
        all_results = {
            "passive_recon": recon_passive_results,
            "active_recon": recon_active_results,
            "vulnerability_scan": scan_results,
            "exploitation": exploit_results
        }
        
        # Affichage du résumé complet
        if ui:
            ui.display_scan_results(all_results, "full_process")
            
        report_path = generate_report(all_results, args.output, "full_process")
        logger.info(f"Rapport généré: {report_path}")
        logger.info("Processus complet terminé!")

# Point d'entrée
if __name__ == "__main__":
    main()

# Fonction d'activation automatique de l'environnement virtuel
def __activate_venv():
    import os
    import sys
    from pathlib import Path
    
    # Trouver le chemin de base de l'installation
    script_path = Path(__file__).resolve()
    base_dir = script_path.parent.parent
    
    # Vérifier et activer l'environnement virtuel si nécessaire
    venv_path = base_dir / "venv"
    if venv_path.exists():
        venv_bin = venv_path / "bin"
        if not sys.prefix.startswith(str(venv_path)):
            # L'environnement n'est pas activé, on doit le faire manuellement
            import subprocess
            
            # Réexécuter le script avec l'interpréteur Python de l'environnement virtuel
            python_path = venv_bin / "python"
            os.execv(str(python_path), [str(python_path)] + sys.argv)

# Activer l'environnement virtuel si ce script est exécuté directement
if __name__ == "__main__":
    __activate_venv()
