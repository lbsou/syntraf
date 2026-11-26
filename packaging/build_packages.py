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
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import time
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
PY_VERSION, PY_BUILD = "3.14.10", "20261124"
IPERF3V_TAG = "v3.22.1-v2"  # v3.22.1-v3 (binaire macOS) : quand sa release sera publiée
VM_VERSION, GRAFANA_VERSION = "v1.157.0", "13.3.2"

TARGETS = {
    "linux-x86_64": {"python": "x86_64-unknown-linux-gnu", "os": "linux", "iperf": "linux-static",
                     "vm": "linux-amd64", "grafana": "linux-amd64",
                     "platforms": ["manylinux_2_28_x86_64", "manylinux_2_17_x86_64", "manylinux2014_x86_64"],
                     # Sonde : glibc 2.17 (RHEL/CentOS 7) ; pip prend le premier tag qui convient, un wheel 2_28
                     # (cryptography) exigerait glibc 2.28. Le serveur reste en 2_28 : gevent n'a plus de wheel 2014.
                     "probe_platforms": ["manylinux2014_x86_64", "manylinux_2_17_x86_64"],
                     "glibc": {"probe": "2.17", "server": "2.28"}},
    "linux-musl-x86_64": {"python": "x86_64-unknown-linux-musl", "os": "linux", "iperf": "linux-static",
                          "vm": "linux-amd64", "grafana": "linux-amd64-musl",
                          "platforms": ["musllinux_1_2_x86_64", "musllinux_1_1_x86_64"]},
    "windows-x86_64": {"python": "x86_64-pc-windows-msvc", "os": "windows", "iperf": "windows",
                       "vm": "windows-amd64", "grafana": "windows-amd64",
                       "platforms": ["win_amd64"]},
    "macos-arm64": {"python": "aarch64-apple-darwin", "os": "macos", "iperf": None,  # "macos" avec iperf3v v3.22.1-v3
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


def platforms_of(target, role):
    t = TARGETS[target]
    return t.get(f"{role}_platforms") or t["platforms"]


def wheels(target, role):
    """Wheels des dépendances pour la plateforme et le Python cibles (pip download, binaires seulement)."""
    platforms = platforms_of(target, role)
    out = CACHE / "wheels" / f"{target}-{role}-{platforms[0]}"  # nouvelle plateforme : nouveau cache
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
    for p in platforms:
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


def _verified(path, expected, source):
    """path si son empreinte est celle publiée (source) ; sinon il est retiré du cache et la construction s'arrête."""
    actual = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    if not expected or actual != expected.strip().lower():
        Path(path).unlink(missing_ok=True)  # construction suivante : retéléchargé depuis la source
        sys.exit(f"{Path(path).name} : empreinte {actual[:12]}… différente de celle publiée ({source}) : arrêt")
    return path


def victoriametrics(target):
    """Archive officielle de VictoriaMetrics (un seul binaire, statique), vérifiée contre son *_checksums.txt."""
    plat = TARGETS[target]["vm"]
    ext = "zip" if plat.startswith("windows") else "tar.gz"
    name = f"victoria-metrics-{plat}-{VM_VERSION}.{ext}"
    base = f"https://github.com/VictoriaMetrics/VictoriaMetrics/releases/download/{VM_VERSION}/"
    path = fetch(base + name, name)
    sums_name = f"victoria-metrics-{plat}-{VM_VERSION}_checksums.txt"
    sums = {line.split()[-1]: line.split()[0]
            for line in fetch(base + sums_name, sums_name).read_text(encoding="ascii").splitlines() if line.strip()}
    return _verified(path, sums.get(name), sums_name)


def grafana(target):
    """Archive officielle de Grafana OSS (un dossier grafana-<version>/ à la racine), vérifiée contre son .sha256."""
    plat = TARGETS[target]["grafana"]
    ext = "zip" if plat.startswith("windows") else "tar.gz"
    name = f"grafana-{GRAFANA_VERSION}.{plat}.{ext}"
    url = f"https://dl.grafana.com/oss/release/{name}"
    path = fetch(url, name)
    expected = fetch(url + ".sha256", name + ".sha256").read_text(encoding="ascii").split()
    return _verified(path, expected[0] if expected else None, name + ".sha256")


# ------------------------------------------------------------------------------------------- versions embarquées
# Vérifiées à chaque construction (avertissement) ; la CI hebdomadaire (.github/workflows/bundle-versions.yml) monte
# celles dont la montée est automatique (--bump), construit et installe un package de test, puis ouvre une PR.
# Montée automatique : VictoriaMetrics (v1.x), Grafana dans la même version majeure, Python dans la même 3.x.
# Signalées seulement : une nouvelle majeure de Grafana (provisionnement des tableaux de bord à revalider) et
# iperf3v (notre fork : le binaire macOS dépend de sa release).

def _api(url):
    headers = {"User-Agent": "syntraf-build", "Accept": "application/vnd.github+json"}
    if os.environ.get("GH_TOKEN") and url.startswith("https://api.github.com/"):
        headers["Authorization"] = f"Bearer {os.environ['GH_TOKEN']}"  # CI : limite d'appels plus large
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60) as r:
        return json.loads(r.read())


def _semver(text):
    return tuple(int(n) for n in re.findall(r"\d+", str(text))[:3])


def _release_tags(api, repo):
    return [r["tag_name"] for r in api(f"https://api.github.com/repos/{repo}/releases?per_page=100")
            if not r.get("prerelease") and not r.get("draft")]


def latest_versions(api=_api):
    """{composant: {pinned, latest, auto, behind}} ; auto : la CI peut monter la version seule."""
    def entry(pinned, latest, auto, behind=None):
        return {"pinned": pinned, "latest": latest, "auto": auto,
                "behind": (_semver(latest) > _semver(pinned)) if behind is None else behind}

    out = {}
    vm = [t for t in _release_tags(api, "VictoriaMetrics/VictoriaMetrics") if re.fullmatch(r"v1\.\d+\.\d+", t)]
    out["victoriametrics"] = entry(VM_VERSION, max(vm, key=_semver), True)

    grafana_versions = [t[1:] for t in _release_tags(api, "grafana/grafana") if re.fullmatch(r"v\d+\.\d+\.\d+", t)]
    major = _semver(GRAFANA_VERSION)[0]
    same_major = [v for v in grafana_versions if _semver(v)[0] == major] or [GRAFANA_VERSION]
    out["grafana"] = entry(GRAFANA_VERSION, max(same_major, key=_semver), True)
    newest = max(grafana_versions, key=_semver)
    if _semver(newest)[0] > major:
        out["grafana-major"] = entry(GRAFANA_VERSION, newest, False)

    pbs = api("https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest")
    minor = PY_VERSION.rsplit(".", 1)[0]
    patches = {m.group(1) for a in pbs.get("assets", [])
               for m in [re.match(rf"cpython-({re.escape(minor)}\.\d+)\+", a["name"])] if m}
    if patches:
        best = max(patches, key=_semver)
        newer = (_semver(best), pbs["tag_name"]) > (_semver(PY_VERSION), PY_BUILD)
        out["python"] = entry(f"{PY_VERSION}+{PY_BUILD}", f"{best}+{pbs['tag_name']}", True, newer)

    tag = api("https://api.github.com/repos/lbsou/iperf3v/releases/latest")["tag_name"]
    out["iperf3v"] = entry(IPERF3V_TAG, tag, False, tag != IPERF3V_TAG and _semver(tag) >= _semver(IPERF3V_TAG))

    # Bibliothèque de l'interface (carte en direct) : version lue dans le fichier livré ; signalée seulement, une
    # nouvelle version change l'interface et se valide à la main (rendu de la carte)
    shipped = CYTOSCAPE.read_text(encoding="utf-8", errors="replace") if CYTOSCAPE.exists() else ""
    found = re.search(r'"(3\.\d+\.\d+)"', shipped)
    if found:
        out["cytoscape"] = entry(found.group(1), api("https://registry.npmjs.org/cytoscape/latest")["version"], False)
    return out


NAMES = {"victoriametrics": "VictoriaMetrics", "grafana": "Grafana", "grafana-major": "Grafana (majeure)",
         "python": "Python", "iperf3v": "iperf3v", "cytoscape": "Cytoscape (carte)"}
CYTOSCAPE = ROOT / "lib" / "web_ui_kindafixed2" / "static" / "cytoscape-js" / "cytoscape.min.js"


def bump_text(text, versions):
    """(texte de build_packages.py avec les versions automatiques montées, [changements])"""
    changes = []
    vm, gr, py = versions.get("victoriametrics"), versions.get("grafana"), versions.get("python")
    new_vm = vm["latest"] if vm and vm["auto"] and vm["behind"] else VM_VERSION_IN(text)[0]
    new_gr = gr["latest"] if gr and gr["auto"] and gr["behind"] else VM_VERSION_IN(text)[1]
    for key, item in (("victoriametrics", vm), ("grafana", gr), ("python", py)):
        if item and item["auto"] and item["behind"]:
            changes.append(f"{NAMES[key]} {item['pinned']} → {item['latest']}")
    text = re.sub(r'^VM_VERSION, GRAFANA_VERSION = "[^"]*", "[^"]*"',
                  f'VM_VERSION, GRAFANA_VERSION = "{new_vm}", "{new_gr}"', text, count=1, flags=re.M)
    if py and py["auto"] and py["behind"]:
        version, build = py["latest"].split("+", 1)
        text = re.sub(r'^PY_VERSION, PY_BUILD = "[^"]*", "[^"]*"', f'PY_VERSION, PY_BUILD = "{version}", "{build}"',
                      text, count=1, flags=re.M)
    return text, changes


def VM_VERSION_IN(text):  # noqa: N802 - (VM_VERSION, GRAFANA_VERSION) tels qu'écrits dans text
    m = re.search(r'^VM_VERSION, GRAFANA_VERSION = "([^"]*)", "([^"]*)"', text, flags=re.M)
    return m.groups() if m else (VM_VERSION, GRAFANA_VERSION)


def report_versions(versions):
    """Lignes à afficher : un composant par ligne, « à jour » ou ce qui est disponible."""
    lines = []
    for key, v in versions.items():
        state = "à jour" if not v["behind"] else (
            f"{v['latest']} disponible" + ("" if v["auto"] else " (à valider à la main)"))
        lines.append(f"  {NAMES[key]:<18} {v['pinned']:<20} {state}")
    return lines


def dashboards():
    """[(nom de fichier, JSON)] : les tableaux de bord de SYNTRAF, tels que les génère le serveur."""
    import json
    from lib import st_grafana_dashboards
    return [(n, json.dumps(d, ensure_ascii=False, indent=2).encode("utf-8"))
            for n, d in st_grafana_dashboards.all_dashboards()]


def _commit_time():
    """Date des fichiers de l'archive : celle du dernier commit (reproductible), pas 1970 (tar s'en plaint)."""
    if os.environ.get("SOURCE_DATE_EPOCH"):
        return int(os.environ["SOURCE_DATE_EPOCH"])
    try:
        return int(subprocess.run(["git", "log", "-1", "--format=%ct"], cwd=ROOT, capture_output=True, text=True,
                                  check=True).stdout.strip())
    except (OSError, ValueError, subprocess.CalledProcessError):
        return int(time.time())


MTIME = _commit_time()


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
        info.size, info.mode, info.mtime = len(data), mode, MTIME
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
    if t.get("glibc"):  # vérifiée par install.sh avant de rien installer
        a.add_bytes("payload/GLIBC_MIN", f"{t['glibc'][role]}\n".encode())
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
    ap.add_argument("--check-versions", action="store_true",
                    help="compare les versions embarquées aux dernières publiées (code 1 si une montée automatique attend)")
    ap.add_argument("--bump", action="store_true",
                    help="monte dans ce fichier les versions à montée automatique, affiche les changements")
    args = ap.parse_args()
    if args.check_versions or args.bump:
        versions = latest_versions()
        print("\n".join(report_versions(versions)))
        pending = [k for k, v in versions.items() if v["auto"] and v["behind"]]
        if args.bump:
            with open(__file__, encoding="utf-8", newline="") as f:  # fins de ligne gardées telles quelles
                text, changes = bump_text(f.read(), versions)
            if changes:
                with open(__file__, "w", encoding="utf-8", newline="") as f:
                    f.write(text)
            print("\n".join(f"- {c}" for c in changes) if changes else "rien à monter")
            return 0
        return 1 if pending else 0
    try:  # avertissement seulement : la construction reste possible hors ligne ou si GitHub limite les appels
        behind = [line for line in report_versions(latest_versions()) if "disponible" in line]
        if behind:
            print("ATTENTION : composants embarqués en retard (python packaging/build_packages.py --bump)\n"
                  + "\n".join(behind))
    except Exception as exc:  # noqa: BLE001
        print(f"versions embarquées non vérifiées ({type(exc).__name__}: {exc})")
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
