#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import shutil
import logging
from datetime import datetime
from pathlib import Path

# Couleurs ANSI pour une interface colorée
BLACK = '\033[30m'
RED = '\033[31m'
GREEN = '\033[32m'
YELLOW = '\033[33m'
BLUE = '\033[34m'
MAGENTA = '\033[35m'
CYAN = '\033[36m'
WHITE = '\033[37m'
BRIGHT_BLACK = '\033[90m'
BRIGHT_RED = '\033[91m'
BRIGHT_GREEN = '\033[92m'
BRIGHT_YELLOW = '\033[93m'
BRIGHT_BLUE = '\033[94m'
BRIGHT_MAGENTA = '\033[95m'
BRIGHT_CYAN = '\033[96m'
BRIGHT_WHITE = '\033[97m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'
BLINK = '\033[5m'
REVERSE = '\033[7m'
HIDDEN = '\033[8m'
RESET = '\033[0m'

# Logger pour l'interface utilisateur
logger = logging.getLogger(__name__)

# Effets spéciaux
def bold(text):
    return f"{BOLD}{text}{RESET}"

def underline(text):
    return f"{UNDERLINE}{text}{RESET}"

def blink(text):
    return f"{BLINK}{text}{RESET}"

def colorize(text, color):
    return f"{color}{text}{RESET}"

def multi_style(text, *styles):
    prefix = ''.join(styles)
    return f"{prefix}{text}{RESET}"

# Classe principale pour l'interface utilisateur
class ConsoleUI:
    def __init__(self, verbose=True):
        self.verbose = verbose
        self.terminal_size = shutil.get_terminal_size()
        self.width = self.terminal_size.columns
        self.height = self.terminal_size.lines
        self.logger = logging.getLogger(__name__)
        
    def clear_screen(self):
        """Efface l'écran du terminal."""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def display_banner(self):
        """Affiche une bannière stylisée pour BgBhScan."""
        banner = f"""
{BLUE}╔══════════════════════════════════════════════════════════════════════════════╗{RESET}
{BLUE}║ {BRIGHT_MAGENTA}██████╗  ██████╗ ██████╗ ██╗  ██╗███████╗ ██████╗ █████╗ ███╗   ██╗{BLUE} ║{RESET}
{BLUE}║ {BRIGHT_MAGENTA}██╔══██╗██╔════╝ ██╔══██╗██║  ██║██╔════╝██╔════╝██╔══██╗████╗  ██║{BLUE} ║{RESET}
{BLUE}║ {BRIGHT_MAGENTA}██████╔╝██║  ███╗██████╔╝███████║███████╗██║     ███████║██╔██╗ ██║{BLUE} ║{RESET}
{BLUE}║ {BRIGHT_MAGENTA}██╔══██╗██║   ██║██╔══██╗██╔══██║╚════██║██║     ██╔══██║██║╚██╗██║{BLUE} ║{RESET}
{BLUE}║ {BRIGHT_MAGENTA}██████╔╝╚██████╔╝██████╔╝██║  ██║███████║╚██████╗██║  ██║██║ ╚████║{BLUE} ║{RESET}
{BLUE}║ {BRIGHT_MAGENTA}╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝        {BLUE} ║{RESET}
{BLUE}║                                                                                           ║{RESET}
{BLUE}║{BRIGHT_CYAN} BgBhScan v1.0 - Outil d'automatisation pour Bug Bounty                {BLUE} ║{RESET}
{BLUE}║{BRIGHT_RED}                                                        by 丂卂爪卂乇ㄥ   {BLUE}║{RESET}
{BLUE}╚═══════════════════════════════════════════════════════════════════════════════════════════╝{RESET}
"""
        print(banner)

    def display_menu(self, title, options):
        """Affiche un menu interactif avec des options numérotées."""
        print(f"\n{BRIGHT_GREEN}╔═{RESET} {BOLD}{UNDERLINE}{title}{RESET} {BRIGHT_GREEN}═╗{RESET}")
        
        for i, (option, _) in enumerate(options, 1):
            print(f"{BRIGHT_BLUE}│{RESET} {BRIGHT_WHITE}{i}{RESET}. {option}")
        
        print(f"{BRIGHT_BLUE}│{RESET} {BRIGHT_WHITE}0{RESET}. Retour")
        print(f"{BRIGHT_GREEN}╚{'═' * (len(title) + 4)}╝{RESET}\n")

    def get_user_choice(self, max_choice):
        """Obtient le choix de l'utilisateur avec validation."""
        while True:
            try:
                choice = input(f"{BRIGHT_YELLOW}Votre choix ({BRIGHT_WHITE}0-{max_choice}{BRIGHT_YELLOW}): {RESET}")
                choice = int(choice)
                if 0 <= choice <= max_choice:
                    return choice
                else:
                    print(f"{BRIGHT_RED}Choix invalide. Veuillez entrer un nombre entre 0 et {max_choice}.{RESET}")
            except ValueError:
                print(f"{BRIGHT_RED}Entrée invalide. Veuillez entrer un nombre.{RESET}")

    def display_progress(self, message, progress, total):
        """Affiche une barre de progression stylisée."""
        progress_bar_width = min(40, self.width - 40)
        progress_pct = progress / total if total > 0 else 0
        filled_length = int(progress_bar_width * progress_pct)
        progress_bar = '█' * filled_length + '░' * (progress_bar_width - filled_length)
        
        sys.stdout.write(f"\r{BRIGHT_CYAN}┃ {message}: {BLUE}|{progress_bar}{BLUE}| {GREEN}{progress}/{total} {BRIGHT_YELLOW}({progress_pct:.1%}){RESET}  ")
        sys.stdout.flush()
        
        if progress == total:
            print()  # Nouvelle ligne à la fin
            
    def display_animated_progress(self, message, duration=3):
        """Affiche une animation de chargement pendant une durée spécifiée."""
        animation = "|/-\\"
        start = datetime.now()
        i = 0
        
        while (datetime.now() - start).total_seconds() < duration:
            sys.stdout.write(f"\r{BRIGHT_CYAN}⟳ {message} {BRIGHT_YELLOW}{animation[i % len(animation)]}{RESET}")
            sys.stdout.flush()
            time.sleep(0.1)
            i += 1
            
        sys.stdout.write(f"\r{BRIGHT_GREEN}✓ {message} {BRIGHT_GREEN}terminé!{RESET}" + " " * 20 + "\n")
        sys.stdout.flush()

    def display_task_status(self, task, status, details=None):
        """Affiche le statut d'une tâche avec des icônes colorées."""
        if status == "success":
            icon = f"{BRIGHT_GREEN}✓{RESET}"
        elif status == "warning":
            icon = f"{BRIGHT_YELLOW}⚠{RESET}"
        elif status == "error":
            icon = f"{BRIGHT_RED}✗{RESET}"
        elif status == "info":
            icon = f"{BRIGHT_BLUE}ℹ{RESET}"
        elif status == "pending":
            icon = f"{BRIGHT_CYAN}⟳{RESET}"
        else:
            icon = f"{BRIGHT_WHITE}•{RESET}"
            
        details_str = f" - {details}" if details else ""
        print(f"{icon} {task}{details_str}")

    def display_section_header(self, title):
        """Affiche un en-tête de section avec une bordure colorée."""
        print(f"\n{BRIGHT_BLUE}╔══ {BOLD}{UNDERLINE}{title}{RESET}{BRIGHT_BLUE} {'═' * (self.width - len(title) - 7)}╗{RESET}")

    def display_section_footer(self):
        """Affiche un pied de section avec une bordure colorée."""
        print(f"{BRIGHT_BLUE}╚{'═' * (self.width - 2)}╝{RESET}\n")

    def display_key_value(self, key, value, color_key=BRIGHT_YELLOW, color_value=BRIGHT_WHITE):
        """Affiche une paire clé-valeur formatée et colorée."""
        print(f"{color_key}{key}: {color_value}{value}{RESET}")

    def display_data_table(self, headers, rows, title=None):
        """Affiche un tableau de données formaté avec des couleurs."""
        if title:
            print(f"\n{BRIGHT_GREEN}{BOLD}{title}{RESET}")
            
        # Calculer la largeur de chaque colonne
        col_widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                col_widths[i] = max(col_widths[i], len(str(cell)))
        
        # Entête avec bordures
        header_line = f"{BRIGHT_BLUE}┌" + "┬".join("─" * (w + 2) for w in col_widths) + "┐{RESET}"
        header_text = f"{BRIGHT_BLUE}│" + f"{BRIGHT_BLUE}│{RESET}".join(f" {BRIGHT_CYAN}{h.ljust(w)}{RESET} " for h, w in zip(headers, col_widths)) + f"{BRIGHT_BLUE}│{RESET}"
        separator = f"{BRIGHT_BLUE}├" + "┼".join("─" * (w + 2) for w in col_widths) + "┤{RESET}"
        
        print(header_line)
        print(header_text)
        print(separator)
        
        # Contenu
        for row in rows:
            row_str = f"{BRIGHT_BLUE}│{RESET}"
            for i, (cell, width) in enumerate(zip(row, col_widths)):
                cell_str = str(cell)
                if i == 0:  # Première colonne en jaune
                    row_str += f" {BRIGHT_YELLOW}{cell_str.ljust(width)}{RESET} {BRIGHT_BLUE}│{RESET}"
                else:
                    row_str += f" {BRIGHT_WHITE}{cell_str.ljust(width)}{RESET} {BRIGHT_BLUE}│{RESET}"
            print(row_str)
            
        # Pied de tableau
        footer = f"{BRIGHT_BLUE}└" + "┴".join("─" * (w + 2) for w in col_widths) + "┘{RESET}"
        print(footer)

    def display_scan_results(self, results, scan_type):
        """Affiche les résultats d'un scan de manière structurée et attrayante."""
        if scan_type == "passive_recon":
            self.display_section_header("Résultats de la reconnaissance passive")
            
            # Affichage des informations WHOIS
            if "whois" in results:
                self.display_task_status("Informations WHOIS", "info")
                if isinstance(results["whois"], dict) and "raw" in results["whois"]:
                    whois_data = results["whois"]["raw"].strip().split("\n")
                    for i, line in enumerate(whois_data[:15]):  # Limiter à 15 lignes
                        if ":" in line:
                            key, value = line.split(":", 1)
                            self.display_key_value(f"  {key.strip()}", value.strip())
                    if len(whois_data) > 15:
                        print(f"{BRIGHT_BLUE}  ... {len(whois_data) - 15} lignes supplémentaires ...{RESET}")
            
            # Affichage des enregistrements DNS
            if "dns" in results:
                self.display_task_status("Enregistrements DNS", "info")
                for record_type, records in results["dns"].items():
                    if records:
                        print(f"  {BRIGHT_GREEN}{record_type}{RESET}:")
                        for record in records:
                            print(f"    {BRIGHT_WHITE}•{RESET} {record}")
            
            # Affichage des sous-domaines
            if "subdomains" in results:
                self.display_task_status(f"Sous-domaines ({len(results['subdomains'])})", "info")
                for i, subdomain in enumerate(results['subdomains']):
                    if i < 20:  # Limiter l'affichage initial à 20 sous-domaines
                        print(f"  {BRIGHT_WHITE}•{RESET} {subdomain}")
                    elif i == 20:
                        print(f"  {BRIGHT_BLUE}... {len(results['subdomains']) - 20} sous-domaines supplémentaires ...{RESET}")
                        break
            
            self.display_section_footer()

        elif scan_type == "active_recon":
            self.display_section_header("Résultats de la reconnaissance active")
            
            # Affichage des ports ouverts
            if "port_scan" in results and "hosts" in results["port_scan"]:
                for host in results["port_scan"]["hosts"]:
                    if "ip" in host:
                        self.display_task_status(f"Hôte: {host['ip']}", "info")
                        
                        if "ports" in host and host["ports"]:
                            # Préparer les données pour le tableau
                            headers = ["Port", "Protocol", "État", "Service", "Version"]
                            rows = []
                            
                            for port in host["ports"]:
                                service_name = port.get("service", {}).get("name", "")
                                product = port.get("service", {}).get("product", "")
                                version = port.get("service", {}).get("version", "")
                                
                                service_str = service_name
                                version_str = f"{product} {version}".strip()
                                
                                rows.append([
                                    port.get("number", ""),
                                    port.get("protocol", ""),
                                    port.get("state", ""),
                                    service_str,
                                    version_str
                                ])
                            
                            self.display_data_table(headers, rows, "Ports ouverts")
            
            # Affichage des technologies détectées
            if "technologies" in results:
                self.display_task_status("Technologies détectées", "info")
                if isinstance(results["technologies"], list):
                    for tech in results["technologies"]:
                        if isinstance(tech, dict) and "name" in tech:
                            version = tech.get("version", "")
                            version_str = f" ({version})" if version else ""
                            print(f"  {BRIGHT_WHITE}•{RESET} {tech['name']}{version_str}")
                elif isinstance(results["technologies"], dict) and "raw" in results["technologies"]:
                    print(f"  {results['technologies']['raw']}")
            
            # Affichage des captures d'écran (chemin vers les fichiers)
            if "screenshots" in results:
                self.display_task_status("Captures d'écran", "info")
                for url, path in results["screenshots"].items():
                    print(f"  {BRIGHT_WHITE}•{RESET} {url}: {path}")
            
            self.display_section_footer()

        elif scan_type == "vulnerability_scan":
            self.display_section_header("Résultats du scan de vulnérabilités")
            
            # Affichage des vulnérabilités web
            if "web_vulnerabilities" in results:
                self.display_task_status("Vulnérabilités Web", "info")
                if isinstance(results["web_vulnerabilities"], dict) and "raw" in results["web_vulnerabilities"]:
                    print(f"  {results['web_vulnerabilities']['raw']}")
                elif isinstance(results["web_vulnerabilities"], list):
                    for vuln in results["web_vulnerabilities"]:
                        if isinstance(vuln, dict):
                            vuln_name = vuln.get("name", "Vulnérabilité inconnue")
                            vuln_severity = vuln.get("severity", "?")
                            vuln_desc = vuln.get("description", "")
                            
                            severity_color = BRIGHT_GREEN
                            if vuln_severity in ["high", "critical", "élevée", "critique"]:
                                severity_color = BRIGHT_RED
                            elif vuln_severity in ["medium", "moyenne"]:
                                severity_color = BRIGHT_YELLOW
                                
                            print(f"  {BRIGHT_WHITE}•{RESET} {vuln_name} ({severity_color}{vuln_severity}{RESET})")
                            if vuln_desc:
                                print(f"    {BRIGHT_BLACK}{vuln_desc}{RESET}")
            
            # Affichage des en-têtes de sécurité
            if "security_headers" in results:
                self.display_task_status("En-têtes de sécurité", "info")
                headers_table = []
                for header, value in results["security_headers"].items():
                    status = "✓" if value else "✗"
                    status_color = BRIGHT_GREEN if value else BRIGHT_RED
                    headers_table.append([header, f"{status_color}{status}{RESET}", value or "Non défini"])
                
                self.display_data_table(["En-tête", "État", "Valeur"], headers_table)
                
            self.display_section_footer()

        elif scan_type == "exploitation":
            self.display_section_header("Résultats des tests d'exploitation")
            
            # Affichage des résultats d'injection SQL
            if "sqli" in results:
                self.display_task_status("Tests d'injection SQL", "info")
                for payload, result in results["sqli"].items():
                    if "Possible" in result:
                        status_icon = f"{BRIGHT_RED}⚠{RESET}"
                        result_color = BRIGHT_RED
                    else:
                        status_icon = f"{BRIGHT_GREEN}✓{RESET}"
                        result_color = BRIGHT_GREEN
                    
                    print(f"  {status_icon} Payload: {BRIGHT_YELLOW}{payload}{RESET}")
                    print(f"    Résultat: {result_color}{result}{RESET}")
            
            # Affichage des résultats XSS
            if "xss" in results:
                self.display_task_status("Tests Cross-Site Scripting (XSS)", "info")
                for payload, result in results["xss"].items():
                    if "Possible" in result:
                        status_icon = f"{BRIGHT_RED}⚠{RESET}"
                        result_color = BRIGHT_RED
                    else:
                        status_icon = f"{BRIGHT_GREEN}✓{RESET}"
                        result_color = BRIGHT_GREEN
                    
                    print(f"  {status_icon} Payload: {BRIGHT_YELLOW}{payload}{RESET}")
                    print(f"    Résultat: {result_color}{result}{RESET}")
            
            # Affichage des résultats directory traversal
            if "dir_traversal" in results:
                self.display_task_status("Tests Directory Traversal", "info")
                for payload, result in results["dir_traversal"].items():
                    if "Possible" in result:
                        status_icon = f"{BRIGHT_RED}⚠{RESET}"
                        result_color = BRIGHT_RED
                    else:
                        status_icon = f"{BRIGHT_GREEN}✓{RESET}"
                        result_color = BRIGHT_GREEN
                    
                    print(f"  {status_icon} Payload: {BRIGHT_YELLOW}{payload}{RESET}")
                    print(f"    Résultat: {result_color}{result}{RESET}")
            
            self.display_section_footer()

        elif scan_type == "full_process":
            # Affichage du rapport complet
            self.display_section_header("Rapport d'analyse complet")
            
            print(f"{BRIGHT_CYAN}{BOLD}Résumé des résultats{RESET}")
            print()
            
            # Affichage du nombre de sous-domaines trouvés
            subdomain_count = len(results.get("passive_recon", {}).get("subdomains", []))
            print(f"{BRIGHT_WHITE}Sous-domaines découverts:{RESET} {BRIGHT_YELLOW}{subdomain_count}{RESET}")
            
            # Affichage du nombre de ports ouverts
            port_count = 0
            hosts = results.get("active_recon", {}).get("port_scan", {}).get("hosts", [])
            for host in hosts:
                port_count += len(host.get("ports", []))
            print(f"{BRIGHT_WHITE}Ports ouverts détectés:{RESET} {BRIGHT_YELLOW}{port_count}{RESET}")
            
            # Affichage du nombre de vulnérabilités
            vuln_count = self.count_vulnerabilities(results)
            print(f"{BRIGHT_WHITE}Vulnérabilités potentielles:{RESET} {BRIGHT_RED}{vuln_count}{RESET}")
            
            print()
            print(f"{BRIGHT_WHITE}Pour consulter les détails complets, veuillez consulter le rapport généré.{RESET}")
            
            self.display_section_footer()

    def count_vulnerabilities(self, results):
        """Compte le nombre total de vulnérabilités dans les résultats."""
        count = 0
        
        # Vulnérabilités web
        web_vulns = results.get("vulnerability_scan", {}).get("web_vulnerabilities", [])
        if isinstance(web_vulns, list):
            count += len(web_vulns)
        
        # SQLi
        sqli_results = results.get("exploitation", {}).get("sqli", {})
        if isinstance(sqli_results, dict):
            for result in sqli_results.values():
                if "Possible" in result:
                    count += 1
        
        # XSS
        xss_results = results.get("exploitation", {}).get("xss", {})
        if isinstance(xss_results, dict):
            for result in xss_results.values():
                if "Possible" in result:
                    count += 1
        
        # Directory traversal
        dir_results = results.get("exploitation", {}).get("dir_traversal", {})
        if isinstance(dir_results, dict):
            for result in dir_results.values():
                if "Possible" in result:
                    count += 1
        
        return count

    def interactive_target_selection(self):
        """Interface interactive pour la sélection d'une cible."""
        self.clear_screen()
        self.display_banner()
        print(f"\n{BRIGHT_WHITE}Veuillez spécifier une cible pour l'analyse:{RESET}\n")
        
        target = input(f"{BRIGHT_GREEN}Domaine ou IP cible: {RESET}")
        
        # Validation basique de la cible
        while not target or ' ' in target:
            print(f"{BRIGHT_RED}Erreur: Cible invalide.{RESET}")
            target = input(f"{BRIGHT_GREEN}Domaine ou IP cible: {RESET}")
        
        return target

    def interactive_scan_menu(self, target):
        """Affiche un menu interactif pour sélectionner le type de scan."""
        self.clear_screen()
        self.display_banner()
        
        print(f"\n{BRIGHT_WHITE}Cible sélectionnée:{RESET} {BRIGHT_YELLOW}{target}{RESET}")
        
        options = [
            ("Reconnaissance passive", "passive"),
            ("Reconnaissance active", "active"),
            ("Scan de vulnérabilités", "scan"),
            ("Tests d'exploitation simples", "exploit"),
            ("Analyse complète", "full")
        ]
        
        self.display_menu("Sélectionnez une opération", options)
        choice = self.get_user_choice(len(options))
        
        if choice == 0:
            return None
        
        return options[choice-1][1]

    def interactive_scan_options(self, scan_type, target):
        """Interface pour configurer les options avancées d'un scan."""
        options = {}
        
        if scan_type == "active":
            print(f"\n{BRIGHT_WHITE}Options pour la reconnaissance active:{RESET}")
            ports = input(f"{BRIGHT_GREEN}Plages de ports à scanner (ex: 80,443,8080 ou 1-1000) [1-1000]: {RESET}")
            options["ports"] = ports if ports else "1-1000"
            
        elif scan_type == "scan":
            print(f"\n{BRIGHT_WHITE}Options pour le scan de vulnérabilités:{RESET}")
            
            scan_options = [
                ("Scan web uniquement", "web"),
                ("Scan réseau uniquement", "network"),
                ("Scan complet (web + réseau)", "full")
            ]
            
            self.display_menu("Type de scan", scan_options)
            choice = self.get_user_choice(len(scan_options))
            
            if choice == 0:
                return None
            
            options["type"] = scan_options[choice-1][1]
            
        elif scan_type == "exploit":
            print(f"\n{BRIGHT_WHITE}Options pour les tests d'exploitation:{RESET}")
            
            vuln = input(f"{BRIGHT_GREEN}Vulnérabilité spécifique à tester [laisser vide pour toutes]: {RESET}")
            if vuln:
                options["vuln"] = vuln
        
        return options

    def display_live_progress(self, message, current, total, category=None):
        """Affiche une barre de progression en temps réel avec catégorisation."""
        progress_bar_width = 40
        progress_pct = current / total if total > 0 else 0
        filled_length = int(progress_bar_width * progress_pct)
        fill_char = '■'
        empty_char = '□'
        
        # Couleur en fonction de la catégorie
        color = BRIGHT_GREEN
        if category == "passive":
            color = BRIGHT_BLUE
        elif category == "active":
            color = BRIGHT_CYAN
        elif category == "vuln":
            color = BRIGHT_YELLOW
        elif category == "exploit":
            color = BRIGHT_MAGENTA
            
        progress_bar = f"{color}{fill_char * filled_length}{RESET}{BRIGHT_BLACK}{empty_char * (progress_bar_width - filled_length)}{RESET}"
        
        sys.stdout.write(f"\r{color}┃{RESET} {message}: {progress_bar} {color}{current}/{total}{RESET} ({progress_pct:.1%})  ")
        sys.stdout.flush()
        
        if current == total:
            print()

    def show_countdown(self, seconds, message="Reprise dans"):
        """Affiche un compte à rebours."""
        for i in range(seconds, 0, -1):
            sys.stdout.write(f"\r{message} {BRIGHT_YELLOW}{i}{RESET} secondes...")
            sys.stdout.flush()
            time.sleep(1)
        sys.stdout.write("\r" + " " * (len(message) + 20) + "\r")
        sys.stdout.flush()

    def interactive_report_view(self, report_path):
        """Affiche une interface pour visualiser et exporter le rapport."""
        print(f"\n{BRIGHT_GREEN}Rapport généré avec succès!{RESET}")
        print(f"{BRIGHT_WHITE}Chemin:{RESET} {report_path}")
        
        options = [
            ("Ouvrir le rapport", "open"),
            ("Exporter au format HTML", "html"),
            ("Exporter au format PDF", "pdf"),
            ("Envoyer par email", "email")
        ]
        
        self.display_menu("Options du rapport", options)
        choice = self.get_user_choice(len(options))
        
        if choice == 1:  # Ouvrir le rapport
            return "open"
            os.system(f"xdg-open {report_path} 2>/dev/null || open {report_path} 2>/dev/null || start {report_path} 2>/dev/null")
        elif choice == 2:  # Exporter en HTML
            self.display_animated_progress("Conversion en HTML", 1)
            html_path = report_path.replace('.json', '.html')
            print(f"{BRIGHT_GREEN}Rapport HTML généré:{RESET} {html_path}")
            return "html"
        elif choice == 3:  # Exporter en PDF
            self.display_animated_progress("Conversion en PDF", 2)
            pdf_path = report_path.replace('.json', '.pdf')
            print(f"{BRIGHT_GREEN}Rapport PDF généré:{RESET} {pdf_path}")
            return "pdf"
        
        return None

    def run_interactive_mode(self, core_functions, config):
        """
        Exécute le programme en mode interactif avec une interface utilisateur conviviale.
        
        Args:
            core_functions (dict): Dictionnaire contenant les fonctions principales
            config (dict): Configuration chargée
        """
        # Extraire les fonctions du dictionnaire
        passive_recon = core_functions.get("passive_recon")
        active_recon = core_functions.get("active_recon")
        vulnerability_scan = core_functions.get("vulnerability_scan")
        exploit_vulnerabilities = core_functions.get("exploit_vulnerabilities")
        generate_report = core_functions.get("generate_report")
        
        if not all([passive_recon, active_recon, vulnerability_scan, exploit_vulnerabilities, generate_report]):
            self.display_task_status("Initialisation", "error", "Certaines fonctions essentielles sont manquantes")
            return
        
        # Boucle principale de l'interface
        while True:
            self.clear_screen()
            self.display_banner()
            
            main_options = [
                ("Lancer une analyse", "scan"),
                ("Configuration", "config"),
                ("Consulter les rapports", "reports"),
                ("Aide et documentation", "help"),
                ("Diagnostique et débogage", "debug")
            ]
            
            self.display_menu("Menu Principal", main_options)
            main_choice = self.get_user_choice(len(main_options))
            
            if main_choice == 0:
                break
            
            if main_choice == 1:  # Lancer une analyse
                target = self.interactive_target_selection()
                if not target:
                    continue
                    
                scan_type = self.interactive_scan_menu(target)
                if not scan_type:
                    continue
                
                # Options spécifiques au type de scan
                scan_options = self.interactive_scan_options(scan_type, target)
                if scan_options is None:
                    continue
                    
                # Exécuter le scan approprié
                self.clear_screen()
                self.display_banner()
                self.display_section_header(f"Scan en cours: {scan_type.upper()} sur {target}")
                
                try:
                    results = None
                    report_path = None
                    
                    if scan_type == "passive":
                        self.display_animated_progress(f"Reconnaissance passive sur {target}", 1)
                        results = passive_recon(target, config)
                        self.display_scan_results(results, "passive_recon")
                        report_path = generate_report(results, None, "passive_recon")
                        
                    elif scan_type == "active":
                        ports = scan_options.get("ports", "1-1000")
                        self.display_animated_progress(f"Reconnaissance active sur {target} (ports: {ports})", 1)
                        results = active_recon(target, ports, config)
                        self.display_scan_results(results, "active_recon")
                        report_path = generate_report(results, None, "active_recon")
                        
                    elif scan_type == "scan":
                        scan_subtype = scan_options.get("type", "full")
                        self.display_animated_progress(f"Scan de vulnérabilités sur {target} (type: {scan_subtype})", 2)
                        results = vulnerability_scan(target, scan_subtype, config)
                        self.display_scan_results(results, "vulnerability_scan")
                        report_path = generate_report(results, None, "vulnerability_scan")
                        
                    elif scan_type == "exploit":
                        vuln = scan_options.get("vuln")
                        if vuln:
                            self.display_animated_progress(f"Test d'exploitation sur {target} (vulnérabilité: {vuln})", 1)
                        else:
                            self.display_animated_progress(f"Tests d'exploitation sur {target}", 1)
                        results = exploit_vulnerabilities(target, vuln, config)
                        self.display_scan_results(results, "exploitation")
                        report_path = generate_report(results, None, "exploitation")
                        
                    elif scan_type == "full":
                        self.display_animated_progress(f"Analyse complète sur {target} - Phase 1: Reconnaissance passive", 1)
                        passive_results = passive_recon(target, config)
                        self.display_scan_results(passive_results, "passive_recon")
                        
                        self.display_animated_progress(f"Analyse complète sur {target} - Phase 2: Reconnaissance active", 1)
                        active_results = active_recon(target, "1-1000", config)
                        self.display_scan_results(active_results, "active_recon")
                        
                        self.display_animated_progress(f"Analyse complète sur {target} - Phase 3: Scan de vulnérabilités", 2)
                        vuln_results = vulnerability_scan(target, "full", config)
                        self.display_scan_results(vuln_results, "vulnerability_scan")
                        
                        self.display_animated_progress(f"Analyse complète sur {target} - Phase 4: Tests d'exploitation", 1)
                        exploit_results = exploit_vulnerabilities(target, None, config)
                        self.display_scan_results(exploit_results, "exploitation")
                        
                        # Consolidation des résultats
                        all_results = {
                            "passive_recon": passive_results,
                            "active_recon": active_results,
                            "vulnerability_scan": vuln_results,
                            "exploitation": exploit_results
                        }
                        
                        self.display_scan_results(all_results, "full_process")
                        report_path = generate_report(all_results, None, "full_process")
                    
                    # Options de rapport
                    if report_path:
                        self.interactive_report_view(report_path)
                    
                except Exception as e:
                    self.display_task_status("Erreur pendant l'analyse", "error", str(e))
                    self.logger.error(f"Exception lors de l'exécution de {scan_type}: {e}")
                
                # Pause avant de revenir au menu
                input(f"\n{BRIGHT_YELLOW}Appuyez sur Entrée pour continuer...{RESET}")
            
            elif main_choice == 2:  # Configuration
                self.display_section_header("Configuration")
                # TODO: Ajouter une interface pour modifier la configuration
                print(f"{BRIGHT_YELLOW}Fonctionnalité à venir dans une prochaine version.{RESET}")
                input(f"\n{BRIGHT_YELLOW}Appuyez sur Entrée pour continuer...{RESET}")
            
            elif main_choice == 3:  # Consulter les rapports
                self.display_section_header("Rapports disponibles")
                # TODO: Lister et permettre de consulter les rapports existants
                report_dir = Path(__file__).resolve().parent.parent / "reports"
                reports = list(report_dir.glob("*.json"))
                
                if not reports:
                    print(f"{BRIGHT_YELLOW}Aucun rapport disponible.{RESET}")
                else:
                    print(f"{BRIGHT_WHITE}Rapports trouvés: {len(reports)}{RESET}\n")
                    for i, report in enumerate(reports, 1):
                        print(f"{i}. {BRIGHT_CYAN}{report.name}{RESET} - {report.stat().st_mtime}")
                
                input(f"\n{BRIGHT_YELLOW}Appuyez sur Entrée pour continuer...{RESET}")
            
            elif main_choice == 4:  # Aide et documentation
                self.display_section_header("Aide et Documentation")
                print(f"{BRIGHT_WHITE}BgBhScan - Outil d'automatisation pour Bug Bounty{RESET}\n")
                print("Commandes disponibles:")
                print(f"  {BRIGHT_GREEN}passive{RESET}   - Reconnaissance passive (WHOIS, DNS, sous-domaines)")
                print(f"  {BRIGHT_GREEN}active{RESET}    - Reconnaissance active (scan de ports, technologies)")
                print(f"  {BRIGHT_GREEN}scan{RESET}      - Scan de vulnérabilités (web, réseau)")
                print(f"  {BRIGHT_GREEN}exploit{RESET}   - Tests d'exploitation basiques (SQLi, XSS, etc.)")
                print(f"  {BRIGHT_GREEN}full{RESET}      - Exécution complète de toutes les étapes ci-dessus\n")
                print(f"{BRIGHT_WHITE}Pour plus d'informations, consultez la documentation:{RESET}")
                print("  https://github.com/votre-nom/bgbhscan/docs\n")
                input(f"{BRIGHT_YELLOW}Appuyez sur Entrée pour continuer...{RESET}")
            
            elif main_choice == 5:  # Diagnostique et débogage
                self.display_section_header("Diagnostique et Débogage")
                print(f"{BRIGHT_WHITE}Lancement du mode debug...{RESET}")
                print(f"{BRIGHT_YELLOW}Veuillez patienter...{RESET}")
                time.sleep(1)
                # Si disponible, appel au mode debug externe
                try:
                    from debug import debug_mode
                    debug_mode()
                except ImportError:
                    self.display_task_status("Module de déboggage non trouvé", "error", "debug.py manquant")
                
                input(f"\n{BRIGHT_YELLOW}Appuyez sur Entrée pour continuer...{RESET}")

# Si exécuté directement, afficher une aide simple
if __name__ == "__main__":
    print("Module UI de BgBhScan")
    print("Ce module est conçu pour être importé, pas exécuté directement.")