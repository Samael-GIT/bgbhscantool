#!/bin/bash
VENV_DIR="/home/samael/.venvs/BgBhScan"
SCRIPT_PATH="$VENV_DIR/src/main.py"

if [ -f "$SCRIPT_PATH" ]; then
    export PYTHONPATH="$VENV_DIR:$PYTHONPATH"
    cd "$VENV_DIR"  # Se positionner dans le bon répertoire pour éviter les problèmes d'importation
    python3 "$SCRIPT_PATH" "$@"
else
    echo "Erreur: BgBhScan n'est pas correctement installé dans $VENV_DIR"
    echo "Veuillez exécuter le script d'installation."
    exit 1
fi
