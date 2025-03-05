#!/bin/bash

# BgBhScan - Script d'installation avec support pour environnements virtuels
# Ce script installe les dépendances Python dans un environnement virtuel

set -e
echo "=== BgBhScan - Installation ==="

# Définir les chemins
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PATH="$SCRIPT_DIR/venv"
MAIN_SCRIPT="$SCRIPT_DIR/src/main.py"

# Permettre l'installation dans n'importe quel répertoire
INSTALL_DIR=${INSTALL_DIR:-"$HOME/.local/share/bgbhscan"}

# Créer le répertoire d'installation s'il n'existe pas
mkdir -p "$INSTALL_DIR"

# Copier les fichiers nécessaires
cp -r "$SCRIPT_DIR/src" "$INSTALL_DIR/"
cp -r "$SCRIPT_DIR/config" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/requirements.txt" "$INSTALL_DIR/"

# Créer l'environnement virtuel dans le nouveau répertoire
VENV_PATH="$INSTALL_DIR/venv"

# Vérifier si Python est installé
if ! command -v python3 &> /dev/null; then
    echo "Python 3 n'est pas installé. Veuillez l'installer avant de continuer."
    exit 1
fi

# Vérifier si pyenv est installé
if command -v pyenv &> /dev/null; then
    echo "pyenv est installé, configuration de l'environnement..."
    
    # Créer l'environnement virtuel avec pyenv si nécessaire
    if [ ! -d "$VENV_PATH" ]; then
        echo "Création d'un environnement virtuel avec pyenv..."
        pyenv virtualenv 3.11.0 bgbhscan-env || echo "Utilisation de la version Python système..."
        pyenv local bgbhscan-env || echo "Impossible de définir l'environnement local, utilisation du système..."
    else
        echo "L'environnement virtuel existe déjà."
    fi
    
    # Installer les dépendances dans l'environnement pyenv
    echo "Installation des dépendances Python dans l'environnement pyenv..."
    pip install -r "$SCRIPT_DIR/requirements.txt"
else
    # Essayer avec venv si pyenv n'est pas disponible
    echo "pyenv n'est pas installé. Tentative d'utilisation de venv..."
    
    # Créer un environnement virtuel standard si nécessaire
    if [ ! -d "$VENV_PATH" ]; then
        echo "Création d'un environnement virtuel avec venv..."
        python3 -m venv "$VENV_PATH"
    fi
    
    # Activer l'environnement virtuel
    source "$VENV_PATH/bin/activate"
    
    # Installer les dépendances
    echo "Installation des dépendances Python dans l'environnement virtuel..."
    pip install -r "$SCRIPT_DIR/requirements.txt"
    
    # Désactiver l'environnement
    deactivate
fi

# Créer les dossiers nécessaires
echo "Préparation de l'environnement..."
mkdir -p "$SCRIPT_DIR/reports"
mkdir -p "$SCRIPT_DIR/config" 2>/dev/null || true

# Créer le fichier de configuration unique
if [ ! -f "$SCRIPT_DIR/config/tools.json" ]; then
    echo "Création du fichier de configuration..."
    cat > "$SCRIPT_DIR/config/tools.json" << 'EOL'
{
    "version": "1.0.0",
    "logging": {
        "level": "INFO",
        "file": "bgbhscan.log"
    },
    "output": {
        "directory": "reports",
        "formats": ["json", "html"]
    },
    "tools": {
        "nmap": {
            "path": "nmap",
            "enabled": true,
            "arguments": "-sV -sC"
        },
        "whois": {
            "path": "whois",
            "enabled": true
        },
        "whatweb": {
            "path": "whatweb",
            "enabled": true,
            "arguments": "-a 3"
        },
        "nikto": {
            "path": "nikto",
            "enabled": true
        },
        "cutycapt": {
            "path": "cutycapt",
            "enabled": true
        },
        "zap": {
            "path": "zap-cli",
            "enabled": false
        }
    },
    "settings": {
        "passive": {
            "timeout": 120,
            "enable_whois": true,
            "enable_dns": true
        },
        "active": {
            "timeout": 300,
            "max_threads": 10,
            "ports_default": "1-1000"
        },
        "vulnerability": {
            "timeout": 600,
            "max_threads": 5
        },
        "proxy": {
            "enable": false,
            "http": "",
            "https": "",
            "socks": ""
        }
    }
}
EOL
fi

# Supprimer l'ancien fichier config.json s'il existe
if [ -f "$SCRIPT_DIR/config/config.json" ]; then
    echo "Suppression de l'ancien fichier config.json..."
    rm -f "$SCRIPT_DIR/config/config.json"
fi

# Rendre les scripts exécutables et ajouter le shebang approprié
echo "Configuration des scripts Python..."
chmod +x "$SCRIPT_DIR/src/main.py"
chmod +x "$SCRIPT_DIR/src/core.py"
chmod +x "$SCRIPT_DIR/src/utils.py"

# Vérifier si le shebang est correct dans le script principal
if ! grep -q "#!/usr/bin/env python3" "$MAIN_SCRIPT"; then
    # Ajouter le shebang au début du fichier
    sed -i '1s/^/#!/usr/bin/env python3\n/' "$MAIN_SCRIPT"
fi

# Ajouter une section d'activation d'environnement au script principal
if ! grep -q "__activate_venv()" "$MAIN_SCRIPT"; then
    cat >> "$MAIN_SCRIPT" << 'EOL'

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
EOL
fi

# Modifier l'installation de la commande
echo "Installation de la commande bgbhscan dans le système..."
mkdir -p "$HOME/.local/bin"

cat > "$HOME/.local/bin/bgbhscan" << EOL
#!/bin/bash
VENV_DIR="$SCRIPT_DIR"
SCRIPT_PATH="\$VENV_DIR/src/main.py"

if [ -f "\$SCRIPT_PATH" ]; then
    export PYTHONPATH="\$VENV_DIR:\$PYTHONPATH"
    cd "\$VENV_DIR"  # Se positionner dans le bon répertoire
    python3 "\$SCRIPT_PATH" "\$@"
else
    echo "Erreur: BgBhScan n'est pas correctement installé dans \$VENV_DIR"
    echo "Veuillez exécuter le script d'installation."
    exit 1
fi
EOL

chmod +x "$HOME/.local/bin/bgbhscan"

echo ""
echo "=== Installation terminée ==="
echo "Vous pouvez maintenant utiliser BgBhScan avec la commande: bgbhscan [commande] -t [cible]"
echo "Exemple: bgbhscan passive -t exemple.com"
