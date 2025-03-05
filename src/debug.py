#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import platform
import importlib
import subprocess
from pathlib import Path

# Couleurs pour le mode debug
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
BLUE = '\033[94m'
END = '\033[0m'

def success(text):
    """Affiche un message de succès."""
    print(f"{GREEN}✓ {text}{END}")

def warning(text):
    """Affiche un avertissement."""
    print(f"{YELLOW}⚠ {text}{END}")

def error(text):
    """Affiche une erreur."""
    print(f"{RED}✗ {text}{END}")

def info(text):
    """Affiche une information."""
    print(f"ℹ {text}")

def header(text):
    """Affiche un texte d'en-tête formaté."""
    print(f"\n{BLUE}{'='*80}{END}")
    print(f"{BLUE}=== {text} {END}")
    print(f"{BLUE}{'='*80}{END}\n")

# Correction des chemins d'importation pour fonctionner de manière autonome
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)

# Assurons-nous que les bons répertoires sont dans le chemin Python
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

# Fonction pour vérifier si un module est disponible
def check_module_available(module_name):
    """Vérifie si un module est disponible de manière plus fiable."""
    # Méthode 1: Utiliser importlib.util.find_spec
    try:
        spec = importlib.util.find_spec(module_name)
        if spec is not None:
            return True
    except (ImportError, AttributeError, ValueError):
        pass
    
    # Méthode 2: Essayer d'importer le module directement
    try:
        __import__(module_name)
        return True
    except ImportError:
        pass
    
    # Méthode 3: Pour dnspython, vérifier dns.resolver directement
    if module_name == 'dnspython':
        try:
            __import__('dns.resolver')
            return True
        except ImportError:
            pass
    
    # Méthode 4: Vérifier avec pip list pour le module dnspython spécifiquement
    if module_name == 'dnspython':
        try:
            stdout, stderr, returncode = run_cmd("pip list | grep dnspython")
            if returncode == 0 and stdout.strip():
                return True
        except Exception:
            pass
    
    return False

def run_cmd(cmd):
    """Exécute une commande et retourne sa sortie."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=False)
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except Exception as e:
        return None, str(e), -1

def check_python_env():
    """Vérifie l'environnement Python."""
    header("ENVIRONNEMENT PYTHON")
    
    # Version Python
    python_version = platform.python_version()
    if python_version.startswith('3'):
        success(f"Version Python: {python_version}")
    else:
        error(f"Version Python: {python_version} - Python 3.6+ est recommandé")
    
    # Chemins Python
    info(f"PYTHONPATH: {sys.path}")
    
    # Venv actif?
    venv_path = os.environ.get('VIRTUAL_ENV')
    if venv_path:
        success(f"Environnement virtuel actif: {venv_path}")
    else:
        warning("Aucun environnement virtuel n'est activé")
    
    # Vérifier si les modules requis sont installés
    required_modules = ['requests', 'dnspython']
    missing_modules = []
    
    # Vérification spéciale pour dns.resolver
    dns_resolver_available = False
    try:
        import dns.resolver
        dns_resolver_available = True
        success("Module dns.resolver est disponible")
    except ImportError:
        warning("Module dns.resolver n'est pas disponible directement")
    
    # Vérifier les modules individuels
    for module in required_modules:
        is_available = check_module_available(module)
        
        # Exception pour dnspython: si dns.resolver est disponible, considérer dnspython comme installé
        if module == 'dnspython' and dns_resolver_available:
            success(f"Module {module} est installé (via dns.resolver)")
            continue
        
        if is_available:
            success(f"Module {module} est installé")
        else:
            error(f"Module {module} n'est PAS installé")
            missing_modules.append(module)
    
    # Proposer l'installation des modules manquants
    if missing_modules:
        if input(f"Voulez-vous installer les modules manquants? ({', '.join(missing_modules)}) (o/n) ").lower() == 'o':
            header("INSTALLATION DES MODULES")
            
            # Déterminer où installer
            if os.environ.get('VIRTUAL_ENV'):
                info(f"Installation dans l'environnement virtuel actif: {os.environ.get('VIRTUAL_ENV')}")
                pip_cmd = "pip"
            else:
                install_base = Path(__file__).resolve().parent.parent
                venv_path = install_base / "venv"
                if venv_path.exists() and (venv_path / "bin" / "pip").exists():
                    pip_cmd = f"{venv_path}/bin/pip"
                    info(f"Installation dans l'environnement virtuel du projet: {venv_path}")
                else:
                    pip_cmd = "pip"
                    warning("Installation dans l'environnement Python système (pip doit être dans le PATH)")
            
            # Installer chaque module manquant
            for module in missing_modules:
                info(f"Installation de {module}...")
                stdout, stderr, returncode = run_cmd(f"{pip_cmd} install {module}")
                if returncode == 0:
                    success(f"Module {module} installé avec succès")
                else:
                    error(f"Échec de l'installation de {module}")
                    error(stderr)
                    # Vérifier si c'est un problème de permission
                    if "Permission denied" in stderr:
                        info(f"Essai avec sudo...")
                        stdout, stderr, returncode = run_cmd(f"sudo {pip_cmd} install {module}")
                        if returncode == 0:
                            success(f"Module {module} installé avec succès (via sudo)")
                        else:
                            error(f"Échec de l'installation de {module} même avec sudo")

def check_bgbhscan_files():
    """Vérifie les fichiers de BgBhScan."""
    header("FICHIERS BGBHSCAN")
    
    # Chemin de base du projet
    base_dir = Path(__file__).resolve().parent.parent
    info(f"Répertoire de base: {base_dir}")
    
    # Vérifier la présence des fichiers et dossiers principaux
    key_files = [
        base_dir / "src" / "main.py",
        base_dir / "src" / "core.py",
        base_dir / "src" / "utils.py",
        base_dir / "src" / "debug.py",
        base_dir / "requirements.txt",
        base_dir / "config" / "tools.json"
    ]
    
    for file_path in key_files:
        if file_path.exists():
            success(f"Trouvé: {file_path}")
        else:
            error(f"Manquant: {file_path}")
    
    # Vérifier les terminaisons de ligne des fichiers Python
    py_files = list(base_dir.glob("src/*.py"))
    for py_file in py_files:
        try:
            with open(py_file, 'rb') as f:
                content = f.read()
                if b'\r\n' in content:
                    warning(f"Terminaisons de ligne Windows (CRLF) détectées dans {py_file}")
                    
                    # Proposer automatiquement la correction
                    if input("Voulez-vous corriger les terminaisons de ligne? (o/n) ").lower() == 'o':
                        corrected = content.replace(b'\r\n', b'\n')
                        with open(py_file, 'wb') as f_out:
                            f_out.write(corrected)
                        success(f"Terminaisons de ligne corrigées dans {py_file}")
                else:
                    success(f"Terminaisons de ligne correctes dans {py_file}")
        except Exception as e:
            error(f"Erreur lors de la vérification de {py_file}: {e}")

def check_command_symlink():
    """Vérifie le lien symbolique de la commande bgbhscan."""
    header("COMMANDE BGBHSCAN")
    
    # Chercher où se trouve la commande bgbhscan
    stdout, stderr, returncode = run_cmd("which bgbhscan")
    if returncode != 0:
        error("La commande bgbhscan n'est pas trouvée dans le PATH")
        
        # Vérifier dans ~/.local/bin
        local_bin_path = Path.home() / ".local" / "bin" / "bgbhscan"
        if local_bin_path.exists():
            warning(f"bgbhscan trouvé dans {local_bin_path} mais pas dans le PATH")
            
            # Vérifier si ~/.local/bin est dans PATH
            if os.environ.get("PATH") and str(local_bin_path.parent) not in os.environ.get("PATH"):
                warning("~/.local/bin n'est pas dans votre PATH")
                info("Ajoutez-le avec: export PATH=$HOME/.local/bin:$PATH")
                info("Et pour le rendre permanent: echo 'export PATH=$HOME/.local/bin:$PATH' >> ~/.bashrc")
        
        # Suggérer de réinstaller
        warning("Exécutez install.sh pour reconfigurer la commande")
        
        # Proposer de créer le lien
        base_dir = Path(__file__).resolve().parent.parent
        main_script = base_dir / "src" / "main.py"
        
        if main_script.exists() and input("Voulez-vous créer un lien symbolique maintenant? (o/n) ").lower() == 'o':
            # Décider où créer le lien
            link_path = ""
            choice = input("Où créer le lien? 1) /usr/local/bin (nécessite sudo) 2) ~/.local/bin: ")
            if choice == "1":
                link_path = "/usr/local/bin/bgbhscan"
                cmd = f"sudo ln -sf {main_script} {link_path} && sudo chmod +x {main_script}"
            else:
                link_dir = Path.home() / ".local" / "bin"
                link_dir.mkdir(parents=True, exist_ok=True)
                link_path = link_dir / "bgbhscan"
                cmd = f"ln -sf {main_script} {link_path} && chmod +x {main_script}"
            
            stdout, stderr, returncode = run_cmd(cmd)
            if returncode == 0:
                success(f"Lien créé avec succès: {link_path}")
            else:
                error(f"Erreur lors de la création du lien: {stderr}")
    else:
        symlink_path = stdout
        success(f"Commande bgbhscan trouvée: {symlink_path}")
        
        # Vérifier où pointe le lien symbolique
        stdout, stderr, returncode = run_cmd(f"readlink -f {symlink_path}")
        if returncode == 0:
            target_path = stdout
            info(f"Le lien pointe vers: {target_path}")
            
            # Vérifier si le fichier cible existe
            if os.path.exists(target_path):
                success("Le fichier cible existe")
                
                # Vérifier le shebang
                stdout, stderr, returncode = run_cmd(f"head -n 1 {target_path}")
                if "#!/usr/bin/env python3" in stdout:
                    success("Shebang correct dans le fichier cible")
                else:
                    error(f"Shebang incorrect: {stdout}")
                    
                    if input("Voulez-vous corriger le shebang? (o/n) ").lower() == 'o':
                        stdout, stderr, returncode = run_cmd(f"sed -i '1s|^.*$|#!/usr/bin/env python3|' {target_path}")
                        if returncode == 0:
                            success("Shebang corrigé")
                        else:
                            error(f"Impossible de corriger le shebang: {stderr}")
            else:
                error(f"Le fichier cible n'existe pas: {target_path}")
                warning("Le lien symbolique est cassé")
                
                # Proposer de recréer le lien
                if input("Voulez-vous recréer le lien symbolique? (o/n) ").lower() == 'o':
                    base_dir = Path(__file__).resolve().parent.parent
                    main_script = base_dir / "src" / "main.py"
                    
                    if main_script.exists():
                        cmd = f"chmod +x {main_script} && "
                        if os.path.dirname(symlink_path) == "/usr/local/bin":
                            cmd += f"sudo ln -sf {main_script} {symlink_path}"
                        else:
                            cmd += f"ln -sf {main_script} {symlink_path}"
                            
                        stdout, stderr, returncode = run_cmd(cmd)
                        if returncode == 0:
                            success(f"Lien symbolique recréé: {symlink_path} -> {main_script}")
                        else:
                            error(f"Impossible de recréer le lien symbolique: {stderr}")
                    else:
                        error(f"Le script main.py n'existe pas: {main_script}")
        else:
            error(f"Impossible de lire le lien symbolique: {stderr}")

def check_modules_imports():
    """Vérifie les importations de modules."""
    header("VÉRIFICATION DES IMPORTATIONS")
    
    base_dir = Path(__file__).resolve().parent.parent
    src_dir = base_dir / "src"
    
    # Ajouter le répertoire src au chemin Python pour les tests d'importation
    if str(src_dir) not in sys.path:
        sys.path.insert(0, str(src_dir))
    if str(base_dir) not in sys.path:
        sys.path.insert(0, str(base_dir))
    
    modules_to_check = [
        ("core", ["passive_recon", "active_recon", "vulnerability_scan", "exploit_vulnerabilities"]),
        ("utils", ["setup_logging", "generate_report", "banner", "load_config"]),
        ("debug", ["debug_mode", "check_python_env"]),
        ("main", ["main"])
    ]
    
    import_errors = []
    
    for module_name, functions in modules_to_check:
        try:
            module = __import__(module_name)
            success(f"Module {module_name} importé avec succès")
            
            # Vérifier les fonctions
            for func in functions:
                if hasattr(module, func):
                    success(f"  Fonction {func} trouvée dans {module_name}")
                else:
                    error(f"  Fonction {func} manquante dans {module_name}")
                    import_errors.append(f"{module_name}.{func}")
        except ImportError as e:
            error(f"Impossible d'importer {module_name}: {e}")
            import_errors.append(module_name)
            
            # Suggérer des corrections
            if "No module named" in str(e):
                suggestion = f"Assurez-vous que le fichier {module_name}.py est présent dans {src_dir}"
                warning(suggestion)
                
                # Vérifier si le fichier existe
                if (src_dir / f"{module_name}.py").exists():
                    warning(f"Le fichier existe mais n'est pas importable. Problème de PYTHONPATH?")
                    warning(f"PYTHONPATH actuel: {sys.path}")
                    
                    # Tenter une correction en ajoutant ou en imprimant le code
                    info(f"\nPour tester, exécutez:\n")
                    info(f"cd {base_dir}")
                    info(f"PYTHONPATH={base_dir} python3 -c \"import src.{module_name}; print('Import réussi!')\"")
    
    # Si des erreurs d'importation ont été détectées, proposer de corriger
    if import_errors and input("Voulez-vous tenter de corriger les problèmes d'importation? (o/n) ").lower() == 'o':
        fix_common_issues()

def fix_common_issues():
    """Tente de corriger les problèmes courants."""
    header("CORRECTION DES PROBLÈMES COURANTS")
    
    base_dir = Path(__file__).resolve().parent.parent
    
    # 1. Corriger les terminaisons de ligne dans tous les fichiers Python
    info("Correction des terminaisons de ligne...")
    py_files = list(Path(base_dir / "src").glob("*.py"))
    for py_file in py_files:
        try:
            with open(py_file, 'rb') as f:
                content = f.read()
            
            if b'\r\n' in content:
                corrected = content.replace(b'\r\n', b'\n')
                with open(py_file, 'wb') as f_out:
                    f_out.write(corrected)
                success(f"Terminaisons de ligne corrigées dans {py_file}")
        except Exception as e:
            error(f"Erreur lors de la correction de {py_file}: {e}")
    
    # 2. Rendre les scripts exécutables
    info("Application des permissions d'exécution...")
    for py_file in py_files:
        try:
            os.chmod(py_file, 0o755)  # rwxr-xr-x
            success(f"Permissions d'exécution appliquées à {py_file}")
        except Exception as e:
            error(f"Erreur lors de l'application des permissions à {py_file}: {e}")
    
    # 3. Vérifier/corriger les importations dans main.py et core.py
    info("Correction des importations...")
    main_py = base_dir / "src" / "main.py"
    core_py = base_dir / "src" / "core.py"
    utils_py = base_dir / "src" / "utils.py"
    debug_py = base_dir / "src" / "debug.py"
    
    # Fonction pour corriger les importations dans un fichier
    def fix_imports_in_file(file_path):
        if not file_path.exists():
            error(f"Le fichier n'existe pas: {file_path}")
            return
            
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Ajouter le code pour le chemin d'importation si nécessaire
            import_path_code = "\n# Ajouter les chemins d'importation\nimport sys\nimport os\nsys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))\nsys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))\n"
            
            # Corriger les importations problématiques
            fixed_content = content
            
            # Remplacer les importations problématiques
            replacements = [
                ("from utils import", "from utils import"),
                ("from core import", "from core import"),
                ("from debug import", "from debug import"),
                ("from utils import", "from utils import"),
                ("from core import", "from core import"),
                ("from debug import", "from debug import")
            ]
            
            for old, new in replacements:
                if old in fixed_content:
                    fixed_content = fixed_content.replace(old, new)
                    success(f"Remplacé '{old}' par '{new}' dans {file_path.name}")
            
            # Ajouter le code du chemin d'importation si nécessaire
            if "sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))" not in fixed_content:
                # Chercher un bon endroit pour insérer le code
                import_section_end = 0
                lines = fixed_content.split('\n')
                
                # Trouver la fin des imports
                for i, line in enumerate(lines):
                    if line.startswith('import ') or line.startswith('from '):
                        import_section_end = i + 1
                
                # Insérer après le dernier import ou au début s'il n'y en a pas
                if import_section_end > 0:
                    lines.insert(import_section_end, import_path_code)
                    fixed_content = '\n'.join(lines)
                    success(f"Ajouté le code de chemin d'importation dans {file_path.name}")
            
            # Écrire le contenu corrigé si des modifications ont été faites
            if fixed_content != content:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(fixed_content)
                success(f"Fichier sauvegardé avec les corrections: {file_path}")
            else:
                info(f"Aucune correction d'importation nécessaire dans {file_path.name}")
        
        except Exception as e:
            error(f"Erreur lors de la correction de {file_path}: {e}")
    
    # Corriger les importations dans les fichiers principaux
    fix_imports_in_file(main_py)
    fix_imports_in_file(core_py)
    fix_imports_in_file(utils_py)
    fix_imports_in_file(debug_py)
    
    # 4. Recréer le lien symbolique si nécessaire
    info("Vérification du lien symbolique...")
    stdout, stderr, returncode = run_cmd("which bgbhscan")
    if returncode != 0:
        warning("Le lien symbolique bgbhscan n'est pas dans le PATH, tentative de création...")
        
        # Créer dans ~/.local/bin par défaut
        local_bin = Path.home() / ".local" / "bin"
        local_bin.mkdir(parents=True, exist_ok=True)
        link_path = local_bin / "bgbhscan"
        
        cmd = f"chmod +x {main_py} && ln -sf {main_py} {link_path}"
        stdout, stderr, returncode = run_cmd(cmd)
        
        if returncode == 0:
            success(f"Lien symbolique créé: {link_path} -> {main_py}")
            info(f"Assurez-vous que {local_bin} est dans votre PATH")
        else:
            error(f"Impossible de créer le lien symbolique: {stderr}")
    
    success("Corrections terminées!")

def install_dependencies_from_requirements():
    """Installe les dépendances à partir du fichier requirements.txt"""
    header("INSTALLATION DES DÉPENDANCES")
    
    base_dir = Path(__file__).resolve().parent.parent
    req_file = base_dir / "requirements.txt"
    
    if not req_file.exists():
        # Si le fichier requirements.txt n'existe pas, on en crée un avec les dépendances de base
        info(f"Fichier requirements.txt non trouvé, création...")
        with open(req_file, 'w') as f:
            f.write("""# BgBhScan Dependencies

# Core requirements
requests>=2.31.0
dnspython>=2.4.2
beautifulsoup4>=4.12.2
lxml>=4.9.3
pyOpenSSL>=23.2.0
cryptography>=41.0.5
urllib3>=2.0.7

# JSON et parseurs XML
xmltodict>=0.13.0
defusedxml>=0.7.1

# CLI et utilitaires
colorama>=0.4.6
tqdm>=4.66.1
click>=8.1.7

# DNS et réseau
python-whois>=0.8.0
netaddr>=0.9.0
ipaddress>=1.0.23
""")
        success(f"Fichier requirements.txt créé: {req_file}")
    
    # Demander confirmation pour l'installation
    if input(f"Voulez-vous installer toutes les dépendances depuis {req_file}? (o/n) ").lower() == 'o':
        # Déterminer où installer
        if os.environ.get('VIRTUAL_ENV'):
            pip_cmd = "pip"
            env_path = os.environ.get('VIRTUAL_ENV')
        else:
            venv_path = base_dir / "venv"
            if venv_path.exists() and (venv_path / "bin" / "pip").exists():
                pip_cmd = f"{venv_path}/bin/pip"
                env_path = venv_path
            else:
                pip_cmd = "pip"
                env_path = "système Python"
        
        info(f"Installation des dépendances dans: {env_path}")
        stdout, stderr, returncode = run_cmd(f"{pip_cmd} install -r {req_file}")
        
        if returncode == 0:
            success("Dépendances installées avec succès")
        else:
            error(f"Échec de l'installation des dépendances: {stderr}")
            # Essayer avec sudo si nécessaire
            if "Permission denied" in stderr and input("Voulez-vous essayer avec sudo? (o/n) ").lower() == 'o':
                stdout, stderr, returncode = run_cmd(f"sudo {pip_cmd} install -r {req_file}")
                if returncode == 0:
                    success("Dépendances installées avec succès (via sudo)")
                else:
                    error(f"Échec de l'installation des dépendances même avec sudo: {stderr}")

def debug_mode():
    """Mode débogage pour diagnostiquer et résoudre les problèmes."""
    header("BGBHSCAN DEBUG")
    print("Cet outil vous aide à diagnostiquer et résoudre les problèmes de BgBhScan")
    
    # Menu
    while True:
        print("\nOptions disponibles:")
        print("1. Vérifier l'environnement Python")
        print("2. Vérifier les fichiers BgBhScan")
        print("3. Vérifier le lien symbolique de commande")
        print("4. Vérifier les importations de modules")
        print("5. Corriger les problèmes courants")
        print("6. Exécuter toutes les vérifications")
        print("7. Installer les dépendances manquantes")
        print("0. Quitter")
        
        choice = input("\nVotre choix (0-7): ").strip()
        
        if choice == '1':
            check_python_env()
        elif choice == '2':
            check_bgbhscan_files()
        elif choice == '3':
            check_command_symlink()
        elif choice == '4':
            check_modules_imports()
        elif choice == '5':
            fix_common_issues()
        elif choice == '6':
            check_python_env()
            check_bgbhscan_files()
            check_command_symlink()
            check_modules_imports()
            if input("\nVoulez-vous tenter de corriger les problèmes détectés? (o/n) ").lower() == 'o':
                fix_common_issues()
        elif choice == '7':
            install_dependencies_from_requirements()
        elif choice == '0':
            print("Retour au menu principal...")
            return
        else:
            print("Choix invalide, veuillez réessayer.")

# Point d'entrée pour l'utilisation directe du script debug.py
if __name__ == "__main__":
    # Correction des chemins d'importation
    current_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(current_dir)
    
    # Assurons-nous que les bons répertoires sont dans le chemin Python
    if current_dir not in sys.path:
        sys.path.insert(0, current_dir)
    if parent_dir not in sys.path:
        sys.path.insert(0, parent_dir)
        
    debug_mode()
