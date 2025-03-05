#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import json
import re
import logging
import socket

# Gestion améliorée des importations de modules externes
dns = None
requests = None

# Import avec gestion d'erreurs pour requests
try:
    import requests
except ImportError:
    print("Module 'requests' manquant. Installation recommandée: pip install requests")
    print("Certaines fonctionnalités seront désactivées.")

# Import avec gestion d'erreurs pour dns
try:
    import dns.resolver
except ImportError:
    try:
        # Parfois le module est disponible sous le nom dnspython
        import dnspython as dns
    except ImportError:
        print("Module 'dnspython' manquant. Installation recommandée: pip install dnspython")
        print("La résolution DNS sera limitée aux outils système.")

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# Correction des chemins d'importation pour utils
import sys
import os

# Ajouter les chemins d'importation
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Vérifier que le chemin actuel est dans le chemin pour les importationsn
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)
# Vérifier que le répertoire parent est dans le chemin pour les importations
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

# Importation directe depuis utils plutôt que depuis src.utils ou .utils
try:
    from utils import run_command, parse_tool_output, load_config
except ImportError:
    try:
        # Essayer le chemin absolu si l'importation directe échoue
        from utils import run_command, parse_tool_output, load_config
    except ImportError as e:
        print(f"ERREUR CRITIQUE: Impossible d'importer utils: {e}")
        print(f"Chemin Python actuel: {sys.path}")
        print("Veuillez exécuter 'bgbhscan debug' pour diagnostiquer le problème.")
        sys.exit(1)

logger = logging.getLogger(__name__)

def passive_recon(target, config):
    """
    Effectue la reconnaissance passive sur une cible sans dépendre d'APIs externes.
    
    Args:
        target (str): Domaine ou IP cible
        config (dict): Configuration du programme
        
    Returns:
        dict: Résultats de la reconnaissance passive
    """
    logger.info(f"Démarrage de la reconnaissance passive sur: {target}")
    tools = config.get("tools", {})
    results = {}
    
    # 1. Informations WHOIS
    try:
        if tools.get("whois", {}).get("enabled", True):
            logger.debug("Collecte des informations WHOIS")
            whois_cmd = f"{tools['whois'].get('path', 'whois')} {target}"
            whois_output = run_command(whois_cmd)
            results["whois"] = parse_tool_output(whois_output, "whois")
    except Exception as e:
        logger.error(f"Erreur lors de la collecte WHOIS: {e}")
        results["whois"] = {"error": str(e)}
    
    # 2. DNS Enumeration avec fallback si dnspython n'est pas disponible
    try:
        if tools.get("dig", {}).get("enabled", True):
            logger.debug("Énumération DNS")
            dns_records = {}
            record_types = ['A', 'AAAA', 'NS', 'MX', 'TXT', 'SOA']
            
            for record_type in record_types:
                try:
                    # Essayer d'abord avec dnspython s'il est disponible
                    if dns is not None and hasattr(dns, 'resolver'):
                        answers = dns.resolver.resolve(target, record_type)
                        dns_records[record_type] = [str(answer) for answer in answers]
                    else:
                        # Fallback sur dig si dnspython n'est pas disponible
                        dig_cmd = f"dig +short {target} {record_type}"
                        dig_output = run_command(dig_cmd)
                        if dig_output:
                            dns_records[record_type] = dig_output.strip().split('\n')
                        else:
                            dns_records[record_type] = []
                except Exception:
                    dns_records[record_type] = []
            
            results["dns"] = dns_records
    except Exception as e:
        logger.error(f"Erreur lors de l'énumération DNS: {e}")
        results["dns"] = {"error": str(e)}
    
    # 3. Sous-domaines 
    try:
        logger.debug("Recherche de sous-domains via les certificats SSL")
        subdomains = []
        
        # Méthode 1: Vérification des certificats
        try:
            crt_cmd = f"curl -s 'https://crt.sh/?q=%.{target}&output=json'"
            crt_output = run_command(crt_cmd)
            if crt_output:
                try:
                    crt_data = json.loads(crt_output)
                    for entry in crt_data:
                        name = entry.get("name_value", "")
                        if name and name not in subdomains:
                            subdomains.append(name)
                except json.JSONDecodeError:
                    pass
        except Exception as e:
            logger.error(f"Erreur lors de la recherche via crt.sh: {e}")
        
        # Méthode 2: DNS brute force (pour les noms communs)
        common_subdomains = ["www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", "smtp", "secure"]
        for sub in common_subdomains:
            try:
                hostname = f"{sub}.{target}"
                socket.gethostbyname(hostname)
                subdomains.append(hostname)
            except:
                pass
                
        results["subdomains"] = sorted(list(set(subdomains)))
    except Exception as e:
        logger.error(f"Erreur lors de la recherche de sous-domaines: {e}")
        results["subdomains"] = {"error": str(e)}
    
    return results

def active_recon(target, ports="1-1000", config=None):
    """
    Effectue la reconnaissance active sur une cible.
    
    Args:
        target (str): Domaine ou IP cible
        ports (str): Plages de ports à scanner
        config (dict): Configuration du programme
        
    Returns:
        dict: Résultats de la reconnaissance active
    """
    logger.info(f"Démarrage de la reconnaissance active sur: {target} (ports: {ports})")
    
    # Remplacer load_tools_config() par load_config() ou utiliser le paramètre config
    if config is None:
        config = load_config()
    tools_config = config.get("tools", {})
    
    results = {}
    
    # 1. Scan de ports avec Nmap
    try:
        logger.debug("Lancement du scan de ports avec Nmap")
        nmap_cmd = f"nmap -p {ports} -sV -sC {target} -oX -"
        nmap_output = run_command(nmap_cmd)
        results["port_scan"] = parse_tool_output(nmap_output, "nmap")
    except Exception as e:
        logger.error(f"Erreur lors du scan de ports: {e}")
        results["port_scan"] = {"error": str(e)}
    
    # 2. Découverte des technologies (whatweb ou wappalyzer)
    try:
        if tools_config.get("whatweb", {}).get("path"):
            logger.debug("Détection des technologies avec WhatWeb")
            whatweb_cmd = f"{tools_config['whatweb']['path']} -a 3 {target} --log-json -"
            whatweb_output = run_command(whatweb_cmd)
            results["technologies"] = parse_tool_output(whatweb_output, "whatweb")
    except Exception as e:
        logger.error(f"Erreur lors de la détection des technologies: {e}")
        results["technologies"] = {"error": str(e)}
    
    # 3. Screenshot des pages Web découvertes
    try:
        logger.debug("Capture d'écran des pages web")
        if "http://" not in target and "https://" not in target:
            urls = [f"http://{target}", f"https://{target}"]
        else:
            urls = [target]
            
        screenshots = {}
        for url in urls:
            try:
                # Utilisation de cutycapt ou autre outil si disponible
                if tools_config.get("cutycapt", {}).get("path"):
                    output_file = f"/tmp/{url.replace('://', '_').replace('/', '_')}.png"
                    cutycapt_cmd = f"{tools_config['cutycapt']['path']} --url={url} --out={output_file}"
                    run_command(cutycapt_cmd)
                    screenshots[url] = output_file
            except Exception as e:
                logger.error(f"Erreur lors de la capture d'écran de {url}: {e}")
                
        results["screenshots"] = screenshots
    except Exception as e:
        logger.error(f"Erreur générale lors des captures d'écran: {e}")
        results["screenshots"] = {"error": str(e)}
    
    return results

def vulnerability_scan(target, scan_type="full", config=None):
    """
    Effectue un scan de vulnérabilités sur une cible.
    
    Args:
        target (str): Domaine ou IP cible
        scan_type (str): Type de scan (web, network, full)
        config (dict): Configuration du programme
        
    Returns:
        dict: Résultats du scan de vulnérabilités
    """
    logger.info(f"Démarrage du scan de vulnérabilités sur: {target} (type: {scan_type})")
    
    # Correction: Utilisez directement load_config() au lieu de load_tools_config()
    if config is None:
        config = load_config()
    tools_config = config.get("tools", {})
    
    results = {}
    
    # 1. Scan Web avec Nikto si scan_type est 'web' ou 'full'
    if scan_type in ["web", "full"]:
        try:
            if tools_config.get("nikto", {}).get("path"):
                logger.debug("Lancement du scan Nikto")
                nikto_cmd = f"{tools_config['nikto']['path']} -h {target} -Format json"
                nikto_output = run_command(nikto_cmd)
                results["web_vulnerabilities"] = parse_tool_output(nikto_output, "nikto")
        except Exception as e:
            logger.error(f"Erreur lors du scan Nikto: {e}")
            results["web_vulnerabilities"] = {"error": str(e)}
            
        # 2. Scan avec OWASP ZAP (si disponible)
        try:
            if tools_config.get("zap", {}).get("path"):
                logger.debug("Lancement du scan ZAP")
                zap_cmd = f"{tools_config['zap']['path']} -cmd -quickurl {target} -quickout /tmp/zap_report.json"
                run_command(zap_cmd)
                with open("/tmp/zap_report.json", "r") as f:
                    results["zap_scan"] = json.load(f)
        except Exception as e:
            logger.error(f"Erreur lors du scan ZAP: {e}")
            results["zap_scan"] = {"error": str(e)}
    
    # 3. Scan réseau avec OpenVAS ou Nessus si scan_type est 'network' ou 'full'
    if scan_type in ["network", "full"]:
        try:
            logger.debug("Lancement du scan de vulnérabilités réseau")
            # Ici, on pourrait intégrer OpenVAS ou Nessus via leur API ou CLI
            nmap_vuln_cmd = f"nmap -p- --script vuln {target} -oX -"
            nmap_vuln_output = run_command(nmap_vuln_cmd)
            results["network_vulnerabilities"] = parse_tool_output(nmap_vuln_output, "nmap")
        except Exception as e:
            logger.error(f"Erreur lors du scan de vulnérabilités réseau: {e}")
            results["network_vulnerabilities"] = {"error": str(e)}
    
    # 4. Recherche de failles dans les en-têtes de sécurité
    try:
        logger.debug("Analyse des en-têtes de sécurité")
        if "http://" not in target and "https://" not in target:
            url = f"https://{target}"
        else:
            url = target
            
        if requests:
            response = requests.get(url, timeout=10, verify=False)
            headers = response.headers
            
            security_headers = {
                "X-XSS-Protection": headers.get("X-XSS-Protection"),
                "X-Content-Type-Options": headers.get("X-Content-Type-Options"),
                "Content-Security-Policy": headers.get("Content-Security-Policy"),
                "X-Frame-Options": headers.get("X-Frame-Options"),
                "Strict-Transport-Security": headers.get("Strict-Transport-Security")
            }
        else:
            security_headers = {"error": "Module requests non disponible"}
        
        results["security_headers"] = security_headers
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse des en-têtes de sécurité: {e}")
        results["security_headers"] = {"error": str(e)}
    
    return results

def exploit_vulnerabilities(target, vuln=None, config=None):
    """
    Tente d'exploiter les vulnérabilités découvertes, sans dépendre de Metasploit.
    
    Args:
        target (str): Domaine ou IP cible
        vuln (str): Vulnérabilité spécifique à exploiter
        config (dict): Configuration du programme
        
    Returns:
        dict: Résultats de l'exploitation
    """
    logger.info(f"Démarrage de l'exploitation sur: {target}")
    results = {}
    
    # Si une vulnérabilité spécifique est spécifiée
    if vuln:
        logger.info(f"Tentative d'exploitation de la vulnérabilité: {vuln}")
        
    # Essai de plusieurs vecteurs d'exploitation
    else:
        # 1. SQLi basique
        try:
            logger.debug("Test d'injection SQL basique")
            results["sqli"] = test_sqli(target)
        except Exception as e:
            logger.error(f"Erreur lors du test d'injection SQL: {e}")
            results["sqli"] = {"error": str(e)}
        
        # 2. Test XSS
        try:
            logger.debug("Test de XSS basique")
            results["xss"] = test_xss(target)
        except Exception as e:
            logger.error(f"Erreur lors du test XSS: {e}")
            results["xss"] = {"error": str(e)}
        
        # 3. Test de directory traversal
        try:
            logger.debug("Test de directory traversal")
            results["dir_traversal"] = test_dir_traversal(target)
        except Exception as e:
            logger.error(f"Erreur lors du test de directory traversal: {e}")
            results["dir_traversal"] = {"error": str(e)}
    
    return results

# Fonctions auxiliaires pour l'exploitation
def test_sqli(target):
    """Test simple d'injection SQL"""
    if not requests:
        return {"error": "Module requests non disponible"}
        
    payloads = ["' OR '1'='1", "' OR '1'='1' --", "' UNION SELECT 1,2,3 --"]
    results = {}
    
    # Si le target est une URL complète
    if "http://" in target or "https://" in target:
        url = target
    else:
        url = f"https://{target}"
    
    # Tester chaque payload
    for payload in payloads:
        try:
            test_url = f"{url}?id={payload}"
            response = requests.get(test_url, timeout=10, verify=False)
            
            # Détection de base (très simpliste)
            if "error" in response.text.lower() or "sql" in response.text.lower():
                results[payload] = "Possible SQLi détectée"
            else:
                results[payload] = "Non vulnérable"
        except:
            results[payload] = "Erreur lors du test"
    
    return results

def test_xss(target):
    """Test simple de XSS"""
    if not requests:
        return {"error": "Module requests non disponible"}
        
    payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
    results = {}
    
    # Si le target est une URL complète
    if "http://" in target or "https://" in target:
        url = target
    else:
        url = f"https://{target}"
    
    # Tester chaque payload
    for payload in payloads:
        try:
            test_url = f"{url}?search={payload}"
            response = requests.get(test_url, timeout=10, verify=False)
            
            # Détection de base (très simpliste)
            if payload in response.text:
                results[payload] = "Possible XSS détecté"
            else:
                results[payload] = "Non vulnérable"
        except:
            results[payload] = "Erreur lors du test"
    
    return results

def test_dir_traversal(target):
    """Test simple de directory traversal"""
    if not requests:
        return {"error": "Module requests non disponible"}
        
    payloads = ["../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd", "....//....//....//etc//passwd"]
    results = {}
    
    # Si le target est une URL complète
    if "http://" in target or "https://" in target:
        url = target
    else:
        url = f"https://{target}"
    
    # Tester chaque payload
    for payload in payloads:
        try:
            test_url = f"{url}?file={payload}"
            response = requests.get(test_url, timeout=10, verify=False)
            
            # Détection de base
            if "root:" in response.text or "bin:" in response.text:
                results[payload] = "Possible directory traversal détecté"
            else:
                results[payload] = "Non vulnérable"
        except:
            results[payload] = "Erreur lors du test"
    
    return results
