#!/bin/bash

# BgBhScan - Script d'installation avec support pour environnements virtuels
# Ce script installe les dépendances Python dans un environnement virtuel

set -e
echo "=== BgBhScan - Installation ==="

# Vérifier si Python est installé
if ! command -v python3 &> /dev/null; then
    echo "Python 3 n'est pas installé. Veuillez l'installer avant de continuer."
    exit 1
fi

# Définir les chemins
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PATH="$SCRIPT_DIR/venv"

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

# Rendre les scripts exécutables
chmod +x "$SCRIPT_DIR/src/main.py"
chmod +x "$SCRIPT_DIR/src/core.py"
chmod +x "$SCRIPT_DIR/src/utils.py"

# Créer un script d'activation pour faciliter l'utilisation
cat > "$SCRIPT_DIR/run.sh" << 'EOL'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -d "$SCRIPT_DIR/venv" ]; then
    source "$SCRIPT_DIR/venv/bin/activate"
    python3 "$SCRIPT_DIR/src/main.py" "$@"
    deactivate
else
    # Si pyenv est utilisé
    export PYENV_VERSION=bgbhscan-env 2>/dev/null || true
    python3 "$SCRIPT_DIR/src/main.py" "$@"
fi
EOL

chmod +x "$SCRIPT_DIR/run.sh"

echo ""
echo "=== Installation terminée ==="
echo "Pour utiliser BgBhScan:"
echo "1. Soit avec le script d'activation: ./run.sh [commande] -t [cible]"
echo "2. Soit en activant manuellement l'environnement:"
echo "   - Si vous utilisez venv: source $VENV_PATH/bin/activate"
echo "   - Si vous utilisez pyenv: pyenv activate bgbhscan-env"
echo "   Puis exécutez: python3 src/main.py [commande] -t [cible]"
echo ""
echo "Exemple: ./run.sh passive -t exemple.com"
