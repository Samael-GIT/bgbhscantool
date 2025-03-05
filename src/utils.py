#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import logging
import json
import os
import datetime
import xml.etree.ElementTree as ET
from pathlib import Path

# Ajouter les chemins d'importation
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def setup_logging(level="INFO"):
    """
    Configure et retourne un logger.
    
    Args:
        level (str): Niveau de log (DEBUG, INFO, WARNING, ERROR)
        
    Returns:
        logging.Logger: Logger configuré
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    
    # Configuration du format - corriger levelname qui est mal écrit
    logging.basicConfig(
        level=numeric_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    return logging.getLogger(__name__)

def get_base_dir():
    """Retourne le répertoire de base de l'installation."""
    bgbhscan_root = os.environ.get('BGBHSCAN_ROOT')
    if bgbhscan_root:
        return Path(bgbhscan_root)
    return Path(__file__).resolve().parent.parent

def load_config():
    """
    Charge la configuration depuis le fichier tools.json
    
    Returns:
        dict: Configuration chargée ou dictionnaire vide en cas d'erreur
    """
    base_dir = get_base_dir()
    
    # Chercher la configuration dans l'ordre de priorité
    possible_paths = [
        base_dir / "config" / "tools.json",
        Path.home() / ".config" / "bgbhscan" / "config.json",
        Path("/etc/bgbhscan/config.json")
    ]
    
    for config_path in possible_paths:
        try:
            with open(config_path, "r") as f:
                logging.debug(f"Configuration chargée depuis {config_path}")
                return json.load(f)
        except FileNotFoundError:
            continue
        except json.JSONDecodeError:
            logging.error(f"Erreur: Le fichier de configuration {config_path} contient un JSON invalide")
            continue
    
    # Si on arrive ici, aucun fichier n'a été trouvé ou n'était valide
    logging.error("Erreur: Aucun fichier de configuration valide trouvé")
    
    # Créer un fichier de configuration par défaut
    default_config = {
        "version": "1.0.0",
        "logging": {"level": "INFO"},
        "tools": {
            "nmap": {"path": "nmap", "enabled": True},
            "whois": {"path": "whois", "enabled": True},
            "whatweb": {"path": "whatweb", "enabled": True},
        }
    }
    
    # Créer le dossier de configuration s'il n'existe pas
    config_dir = Path(__file__).resolve().parent.parent / "config"
    config_dir.mkdir(parents=True, exist_ok=True)
    
    # Créer le fichier de configuration
    config_path = config_dir / "tools.json"
    try:
        with open(config_path, "w") as f:
            json.dump(default_config, f, indent=4)
        logging.info(f"Fichier de configuration par défaut créé : {config_path}")
    except:
        logging.error("Impossible de créer le fichier de configuration par défaut")
    
    return default_config

def run_command(command):
    """
    Exécute une commande shell et retourne la sortie.
    
    Args:
        command (str): Commande à exécuter
        
    Returns:
        str: Sortie de la commande
    """
    try:
        result = subprocess.run(
            command, 
            shell=True, 
            capture_output=True, 
            text=True, 
            check=False
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        logging.error(f"Erreur lors de l'exécution de la commande: {command}")
        logging.error(f"Détails: {e}")
        return None

def parse_tool_output(output, tool_name):
    """
    Parse la sortie d'un outil en fonction de son format.
    
    Args:
        output (str): Sortie de l'outil
        tool_name (str): Nom de l'outil
        
    Returns:
        dict: Résultats parsés
    """
    if not output:
        return {"error": "Pas de sortie"}
        
    # Traitement en fonction de l'outil
    if tool_name == "nmap":
        try:
            # Analyse XML Nmap
            root = ET.fromstring(output)
            hosts = []
            for host in root.findall(".//host"):
                host_data = {"ports": []}
                
                # Adresse IP
                for addr in host.findall(".//address"):
                    if addr.get("addrtype") == "ipv4":
                        host_data["ip"] = addr.get("addr")
                
                # Ports
                for port in host.findall(".//port"):
                    port_data = {
                        "number": port.get("portid"),
                        "protocol": port.get("protocol"),
                        "state": port.find("state").get("state") if port.find("state") is not None else "unknown"
                    }
                    
                    # Service
                    service = port.find("service")
                    if service is not None:
                        port_data["service"] = {
                            "name": service.get("name"),
                            "product": service.get("product", ""),
                            "version": service.get("version", "")
                        }
                        
                    host_data["ports"].append(port_data)
                
                hosts.append(host_data)
            
            return {"hosts": hosts}
        except Exception as e:
            logging.error(f"Erreur lors du parsing de la sortie Nmap: {e}")
            return {"raw": output}
            
    elif tool_name == "whatweb":
        try:
            return json.loads(output)
        except:
            # Format texte brut
            return {"raw": output}
            
    elif tool_name == "nikto":
        try:
            return json.loads(output)
        except:
            # Format texte brut
            return {"raw": output}
            
    elif tool_name == "whois":
        # Parser WHOIS n'est pas trivial, on retourne le texte brut formatté
        return {"raw": output}
        
    elif tool_name == "dig":
        # Parser la sortie de dig
        lines = output.strip().split('\n')
        records = []
        for line in lines:
            if line.strip():
                records.append(line.strip())
        return {"records": records}
        
    elif tool_name == "theharvester":
        # Retourne le texte brut car le format est complexe
        return {"raw": output}
    
    # Par défaut retourne la sortie brute
    return {"raw": output}

def generate_report(results, output_file=None, report_type="scan"):
    """
    Génère un rapport à partir des résultats.
    
    Args:
        results (dict): Résultats à inclure dans le rapport
        output_file (str): Chemin du fichier de sortie (optionnel)
        report_type (str): Type de rapport
        
    Returns:
        str: Chemin du fichier de rapport
    """
    # Si aucun fichier de sortie n'est spécifié, en créer un
    if not output_file:
        # Créer un répertoire reports dans le répertoire de base
        reports_dir = Path(__file__).resolve().parent.parent / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        output_file = reports_dir / f"{report_type}_{timestamp}.json"
    
    # Vérifier si le chemin existe, sinon créer les dossiers
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Ajouter des métadonnées
    report_data = {
        "metadata": {
            "timestamp": datetime.datetime.now().isoformat(),
            "report_type": report_type,
            "version": "1.0.0"
        },
        "results": results
    }
    
    # Écrire le rapport
    with open(output_path, "w") as f:
        json.dump(report_data, f, indent=4)
    
    logging.info(f"Rapport généré: {output_file}")
    return str(output_file)

def banner():
    """Affiche une bannière stylisée pour l'outil"""
    banner_text = """
    ██████╗  ██████╗ ██████╗ ██╗  ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
    ██╔══██╗██╔════╝ ██╔══██╗██║  ██║██╔════╝██╔════╝██╔══██╗████╗  ██║
    ██████╔╝██║  ███╗██████╔╝███████║███████╗██║     ███████║██╔██╗ ██║
    ██╔══██╗██║   ██║██╔══██╗██╔══██║╚════██║██║     ██╔══██║██║╚██╗██║
    ██████╔╝╚██████╔╝██████╔╝██║  ██║███████║╚██████╗██║  ██║██║ ╚████║
    ╚═════╝  ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
    
    [ BgBhScan - Outil d'automatisation pour Bug Bounty ]
    [ Version 1.0.0                                     ]
    [ Auteur: Samael                                    ]
    """
    print(banner_text)