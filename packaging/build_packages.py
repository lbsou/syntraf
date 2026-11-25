#!/usr/bin/env python3
"""Construit les packages d'installation hors ligne de SYNTRAF : un pour le serveur, un pour les sondes, par plateforme.

    python packaging/build_packages.py                         # toutes les plateformes, les deux rôles
    python packaging/build_packages.py --targets linux-x86_64 --roles probe

Chaque archive (dist/syntraf-<rôle>-<version>-<plateforme>.tar.gz, .zip pour Windows) contient tout ce qu'il faut sur
une machine sans accès Internet : un Python portable (python-build-standalone), les dépendances de la plateforme en
wheels, le code (le même découpage que les releases de mise à jour : lib/st_release.py), iperf3v, et un script
d'installation qui crée le service (systemd, OpenRC, launchd, tâche planifiée Windows).

Le package serveur embarque aussi VictoriaMetrics et Grafana, déjà reliés : SYNTRAF écrit dans le VictoriaMetrics local,
qui lit aussi /metrics ; Grafana est provisionné avec la source de données et les tableaux de bord de SYNTRAF
(lib/st_grafana_dashboards.py). Mêmes versions que le lab (lab/config/lab.env).

iperf3v : Linux, un binaire statique (musl) construit ici dans un conteneur Alpine depuis le tag IPERF3V_TAG, valable
sur Debian, RHEL et Alpine ; Windows, la release publiée ; macOS, aucun binaire publié : l'installation utilise
l'iperf3 du système s'il existe. La construction a besoin d'Internet et de Docker (Linux) ; pas l'installation.
"""
import argparse
import hashlib
import io
import os
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lib import st_release  # noqa: E402
from lib.st_global import DefaultValues  # noqa: E402

HERE = Path(__file__).resolve().parent
CACHE = HERE / "cache"
DIST = ROOT / "dist"
PY_VERSION, PY_BUILD = "3.14.10", "20261123"
IPERF3V_TAG = "v3.22.1-v3"
VM_VERSION, GRAFANA_VERSION = "v1.156.0", "13.0.2"

TARGETS = {
    "linux-x86_64": {"python": "x86_64-unknown-linux-gnu", "os": "linux", "iperf": "linux-static",
                     "vm": "linux-amd64", "grafana": "linux-amd64",
                     "platforms": ["manylinux_2_28_x86_64", "manylinux_2_17_x86_64", "manylinux2014_x86_64"]},
    "linux-musl-x86_64": {"python": "x86_64-unknown-linux-musl", "os": "linux", "iperf": "linux-static",
                          "vm": "linux-amd64", "grafana": "linux-amd64-musl",
                          "platforms": ["musllinux_1_2_x86_64", "musllinux_1_1_x86_64"]},
    "windows-x86_64": {"python": "x86_64-pc-windows-msvc", "os": "windows", "iperf": "windows",
                       "vm": "windows-amd64", "grafana": "windows-amd64",
                       "platforms": ["win_amd64"]},
    "macos-arm64": {"python": "aarch64-apple-darwin", "os": "macos", "iperf": "macos",  # iperf3v : macOS 15+
                    "vm": "darwin-arm64", "grafana": "darwin-arm64",
                    "platforms": ["macosx_11_0_arm64", "macosx_10_15_universal2", "macosx_10_9_universal2"]},
    # macOS Intel : pas de cible, cryptography (dépendance) ne publie plus de wheel x86_64 pour macOS
}
ROLES = {"server": {"profile": "full", "requirements": "requirements_server.txt"},
         "probe": {"profile": "client", "requirements": "requirements_client.txt"}}


def fetch(url, name):
    CACHE.mkdir(exist_ok=True)
    path = CACHE / name
    if not path.exists():
        print(f"  téléchargement : {url}")
        tmp = path.with_suffix(".part")
        with urllib.request.urlopen(url, timeout=300) as r, open(tmp, "wb") as f:
            shutil.copyfileobj(r, f)
        tmp.replace(path)
    return path


def python_archive(target):
    triple = TARGETS[target]["python"]
    name = f"cpython-{PY_VERSION}+{PY_BUILD}-{triple}-install_only_stripped.tar.gz"
    return fetch(f"https://github.com/astral-sh/python-build-standalone/releases/download/{PY_BUILD}/{name}", name)


def wheels(target, role):
    """Wheels des dépendances pour la plateforme et le Python cibles (pip download, binaires seulement)."""
    out = CACHE / "wheels" / f"{target}-{role}"
    if out.exists() and any(out.glob("*.whl")):
        return out
    out.mkdir(parents=True, exist_ok=True)
    if "musl" in target:  # pas de wheel musl publié pour tout (zope.interface) : pip wheel dans Alpine, même Python
        print(f"  wheels {target}/{role} (conteneur python:{PY_VERSION.rsplit('.', 1)[0]}-alpine)")
        script = ("set -e; apk add -q build-base libffi-dev >/dev/null; "
                  f"pip wheel --quiet --disable-pip-version-check -w /out -r /src/{ROLES[role]['requirements']}")
        subprocess.run(["docker", "run", "--rm", "-v", f"{ROOT}:/src:ro", "-v", f"{out}:/out",
                        f"python:{PY_VERSION.rsplit('.', 1)[0]}-alpine", "sh", "-c", script], check=True,
                       env=dict(os.environ, MSYS_NO_PATHCONV="1"))
        return out
    cmd = [sys.executable, "-m", "pip", "download", "--disable-pip-version-check", "--quiet", "--dest", str(out),
           "--only-binary=:all:", "--implementation", "cp", "--python-version", PY_VERSION.rsplit(".", 1)[0],
           "-r", str(ROOT / ROLES[role]["requirements"])]
    for p in TARGETS[target]["platforms"]:
        cmd += ["--platform", p]
    print(f"  wheels {target}/{role}")
    subprocess.run(cmd, check=True, cwd=ROOT)
    return out


def iperf3v_linux_static():
    """iperf3v statique (musl) : un seul binaire pour toutes les distributions Linux. Construit dans Alpine."""
    out = CACHE / f"iperf3v-{IPERF3V_TAG}-linux-static"
    if out.exists():
        return out
    script = ("set -e; apk add -q build-base git openssl-dev openssl-libs-static linux-headers; "
              f"git clone -q --depth 1 --branch {IPERF3V_TAG} https://github.com/lbsou/iperf3v.git /b; cd /b; "
              "./configure -q --disable-shared --enable-static-bin >/dev/null; make -s -j$(nproc) >/dev/null; "
              "strip src/iperf3; ./src/iperf3 --version | head -1; cp src/iperf3 /out/iperf3v")
    tmp = CACHE / "iperf3v-build"
    tmp.mkdir(parents=True, exist_ok=True)
    print("  iperf3v statique (conteneur Alpine)")
    subprocess.run(["docker", "run", "--rm", "-v", f"{tmp}:/out", "alpine:3", "sh", "-c", script], check=True,
                   env=dict(os.environ, MSYS_NO_PATHCONV="1"))
    (tmp / "iperf3v").replace(out)
    return out


def iperf3v_asset(name):
    """Fichier de la release iperf3v, vérifié contre son SHA256SUMS (publié par le workflow de release)."""
    base = f"https://github.com/lbsou/iperf3v/releases/download/{IPERF3V_TAG}/"
    path = fetch(base + name, name)
    sums = fetch(base + "SHA256SUMS", f"iperf3v-{IPERF3V_TAG}-SHA256SUMS")
    expected = {line.split()[-1].lstrip("*"): line.split()[0]
                for line in sums.read_text(encoding="ascii").splitlines() if line.strip()}
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if expected.get(name) != actual:
        path.unlink(missing_ok=True)  # téléchargement suivant : depuis la source
        sys.exit(f"{name} : empreinte {actual[:12]}… absente de SHA256SUMS ou différente ({IPERF3V_TAG})")
    return path


def iperf3v_windows():
    return iperf3v_asset(f"iperf3v-{IPERF3V_TAG[1:]}-windows-x86_64.zip")


def iperf3v_macos():
    """Binaire macOS arm64 (OpenSSL lié statiquement, signé ad hoc), construit par la CI d'iperf3v sur macOS 15."""
    return iperf3v_asset(f"iperf3v-{IPERF3V_TAG[1:]}-macos-arm64.tar.gz")


def victoriametrics(target):
    """Archive officielle de VictoriaMetrics (un seul binaire, statique)."""
    plat = TARGETS[target]["vm"]
    ext = "zip" if plat.startswith("windows") else "tar.gz"
    name = f"victoria-metrics-{plat}-{VM_VERSION}.{ext}"
    return fetch(f"https://github.com/VictoriaMetrics/VictoriaMetrics/releases/download/{VM_VERSION}/{name}", name)


def grafana(target):
    """Archive officielle de Grafana OSS (un dossier grafana-<version>/ à la racine)."""
    plat = TARGETS[target]["grafana"]
    ext = "zip" if plat.startswith("windows") else "tar.gz"
    name = f"grafana-{GRAFANA_VERSION}.{plat}.{ext}"
    return fetch(f"https://dl.grafana.com/oss/release/{name}", name)


def dashboards():
    """[(nom de fichier, JSON)] : les tableaux de bord de SYNTRAF, tels que les génère le serveur."""
    import json
    from lib import st_grafana_dashboards
    return [(n, json.dumps(d, ensure_ascii=False, indent=2).encode("utf-8"))
            for n, d in st_grafana_dashboards.all_dashboards()]


class Archive:
    """tar.gz (modes Unix fixés ici : la construction peut se faire sous Windows) ou zip."""

    def __init__(self, path, top):
        self.top, self.zip = top, str(path).endswith(".zip")
        self.f = zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) if self.zip else tarfile.open(path, "w:gz")

    def add_bytes(self, rel, data, mode=0o644):
        name = f"{self.top}/{rel}"
        if self.zip:
            self.f.writestr(name, data)
            return
        info = tarfile.TarInfo(name)
        info.size, info.mode, info.mtime = len(data), mode, 0
        self.f.addfile(info, io.BytesIO(data))

    def add_file(self, rel, path, mode=0o644):
        data = Path(path).read_bytes()
        if rel.endswith(".sh"):  # construit sous Windows : jamais de CRLF dans un script shell
            data = data.replace(bytes([13, 10]), bytes([10]))
        if rel.endswith(".ps1") and not data.startswith(b"\xef\xbb\xbf"):
            data = b"\xef\xbb\xbf" + data  # Windows PowerShell 5.1 lit un script sans BOM en ANSI (accents brisés)
        self.add_bytes(rel, data, mode)

    def close(self):
        self.f.close()


def build(target, role, version):
    t, r = TARGETS[target], ROLES[role]
    top = f"syntraf-{role}-{version}-{target}"
    ext = ".zip" if t["os"] == "windows" else ".tar.gz"
    DIST.mkdir(exist_ok=True)
    path = DIST / (top + ext)
    print(f"{path.name}")
    a = Archive(path, top)
    templates = HERE / "templates"
    if t["os"] == "windows":
        a.add_file("install.ps1", templates / "install.ps1")
        a.add_file("uninstall.ps1", templates / "uninstall.ps1")
    else:
        a.add_file("install.sh", templates / "install.sh", 0o755)
        a.add_file("uninstall.sh", templates / "uninstall.sh", 0o755)
    a.add_file("README.txt", templates / "README.txt")
    a.add_bytes("payload/ROLE", f"{role}\n".encode())
    a.add_bytes("payload/VERSION", f"{version}\n".encode())
    a.add_bytes("payload/TARGET", f"{target}\n".encode())
    a.add_file("payload/python.tar.gz", python_archive(target))
    for whl in sorted(wheels(target, role).glob("*.whl")):
        a.add_file(f"payload/wheels/{whl.name}", whl)
    a.add_file("payload/requirements.txt", ROOT / r["requirements"])
    if role == "server":  # requirements_server.txt inclut requirements_client.txt (-r)
        a.add_file("payload/requirements_client.txt", ROOT / "requirements_client.txt")
    for rel in st_release._included(str(ROOT), r["profile"]):
        a.add_file(f"payload/app/{rel}", ROOT / rel, 0o755 if rel == "syntraf.py" else 0o644)
    if role == "server":  # documentation servie par l'interface (/docs)
        for f in sorted((ROOT / "docs" / "html").rglob("*")):
            if f.is_file():
                a.add_file(f"payload/app/docs/html/{f.relative_to(ROOT / 'docs' / 'html').as_posix()}", f)
    if role == "server":  # VictoriaMetrics + Grafana, reliés à l'installation
        ext = "zip" if t["os"] == "windows" else "tar.gz"
        a.add_file(f"payload/stack/victoria-metrics.{ext}", victoriametrics(target))
        a.add_file(f"payload/stack/grafana.{ext}", grafana(target))
        for name, data in dashboards():
            a.add_bytes(f"payload/grafana-dashboards/{name}", data)
    if t["iperf"] == "linux-static":
        a.add_file("payload/bin/iperf3v", iperf3v_linux_static(), 0o755)
    elif t["iperf"] == "windows":
        with zipfile.ZipFile(iperf3v_windows()) as z:
            for n in z.namelist():
                if not n.endswith("/") and n.lower().endswith((".exe", ".dll")):
                    a.add_bytes(f"payload/bin/{Path(n).name}", z.read(n))
    elif t["iperf"] == "macos":
        with tarfile.open(iperf3v_macos()) as z:
            binary = next(m for m in z.getmembers() if m.isfile() and m.name.endswith("/bin/iperf3v"))
            a.add_bytes("payload/bin/iperf3v", z.extractfile(binary).read(), 0o755)
    a.close()
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    with open(DIST / "SHA256SUMS", "a", encoding="ascii") as f:
        f.write(f"{digest}  {path.name}\n")
    return path


def server_release(version):
    """Release du code du serveur pour la mise à jour depuis GitHub (lib/st_github_update.py) : l'archive, son
    manifeste et la signature du manifeste par la clé du projet (tools/release_key.py). Sans clé : non signée, et
    les serveurs installés ne la proposeront pas."""
    import shutil as _shutil
    from lib import st_github_update
    info = st_release.build(str(ROOT), str(CACHE / "server-release"), version, "full")
    name = f"syntraf-server-code-{version}.tar.gz"  # sans « + » : GitHub renomme ces fichiers joints
    _shutil.copyfile(info["path"], DIST / name)
    manifest = st_github_update.manifest_bytes({"version": version, "id": info["id"], "file": name,
                                                "sha256": info["sha256"], "size": info["size"], "profile": "full"})
    (DIST / f"syntraf-release-{version}.json").write_bytes(manifest)
    sys.path.insert(0, str(ROOT / "tools"))
    import release_key
    if release_key.key_path().is_file():
        sig = st_github_update.sign(manifest, release_key.load_private())
        (DIST / f"syntraf-release-{version}.json.sig").write_text(sig + "\n", encoding="ascii")
        print(f"{name} : signée")
    else:
        print(f"ATTENTION : {name} NON SIGNÉE (pas de clé {release_key.key_path()}) : les serveurs ne la proposeront pas")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--targets", nargs="*", default=list(TARGETS), choices=list(TARGETS))
    ap.add_argument("--roles", nargs="*", default=list(ROLES), choices=list(ROLES))
    args = ap.parse_args()
    version = DefaultValues.SYNTRAF_VERSION
    if (DIST / "SHA256SUMS").exists():
        (DIST / "SHA256SUMS").unlink()
    for target in args.targets:
        for role in args.roles:
            p = build(target, role, version)
            print(f"  {p.stat().st_size // (1024 * 1024)} Mio")
    if "server" in args.roles:
        server_release(version)
    return 0


if __name__ == "__main__":
    sys.exit(main())
