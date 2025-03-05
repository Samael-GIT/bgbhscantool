#!/usr/bin/env python3
import os
import sys
from pathlib import Path

# Trouver le chemin absolu du répertoire src
script_dir = Path(__file__).resolve().parent
src_dir = script_dir / "src"

# Ajouter src au PYTHONPATH
sys.path.insert(0, str(src_dir))
sys.path.insert(0, str(script_dir))

# Importer et exécuter main directement
try:
    from src.main import main
    sys.exit(main())
except ImportError as e:
    print(f"\nERREUR: Impossible d'importer le module principal: {e}")
    print(f"Chemins Python: {sys.path}")
    sys.exit(1)
