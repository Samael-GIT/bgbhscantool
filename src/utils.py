#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import logging
import json
import os
import datetime
import xml.etree.ElementTree as ET
from pathlib import Path

def setup_logging(level="INFO"):
    """
    Configure et retourne un logger.
    
    Args:
        level (str): Niveau de log (DEBUG, INFO, WARNING, ERROR)
        
    Returns:
        logging.Logger: Logger configuré
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    
    # Configuration du format
    logging.basicConfig(
        level=numeric_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    return logging.getLogger(__name__)

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
        timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        output_file = f"{report_type}_{timestamp}.json"
    
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
    with open(output_file, "w") as f:
        json.dump(report_data, f, indent=4)
    
    logging.info(f"Rapport généré: {output_file}")
    return output_file

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