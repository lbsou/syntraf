"""Prépare le dossier wheelhouse/ du serveur : les paquets Python des clients, pour toutes leurs plateformes.

La release intégrée du serveur embarque ce dossier ; chaque client se met alors à jour dans son propre venv,
installé hors ligne (sans accès à Internet). À lancer là où Internet est disponible, avant de déployer le serveur :

    python tools/build_wheelhouse.py --python-version 3.11 --platform manylinux2014_x86_64 --platform win_amd64

--python-version : la version de Python des clients (une seule par wheelhouse) ;
--platform       : une ou plusieurs plateformes des clients (Linux x86_64, Linux ARM : manylinux2014_aarch64,
                   Windows : win_amd64).
Sans wheelhouse, une mise à jour qui change les dépendances des clients est refusée (elle ne peut pas les installer).
"""
import argparse
import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--python-version", required=True, help="ex. 3.11")
    parser.add_argument("--platform", action="append", required=True, help="ex. manylinux2014_x86_64, win_amd64")
    parser.add_argument("--requirements", default=os.path.join(ROOT, "requirements_client.txt"))
    parser.add_argument("--output", default=os.path.join(ROOT, "wheelhouse"))
    args = parser.parse_args()

    tmp = args.output + ".tmp"
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(tmp)
    # pip et ses outils de construction : le venv neuf de chaque client en a besoin pour installer le reste
    for platform in args.platform:
        print(f"== {platform}, Python {args.python_version}")
        subprocess.run([sys.executable, "-m", "pip", "download", "--dest", tmp, "--only-binary=:all:",
                        "--platform", platform, "--python-version", args.python_version,
                        "-r", args.requirements, "pip", "setuptools", "wheel"], check=True)
    shutil.rmtree(args.output, ignore_errors=True)
    os.replace(tmp, args.output)
    print(f"{len(os.listdir(args.output))} paquet(s) dans {args.output}")


if __name__ == "__main__":
    main()
