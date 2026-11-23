"""La sonde légère : la release des clients (sans interface web) démarre sans aucune dépendance du serveur ni les
paquets retirés (pytz, tzlocal, py-cpuinfo, tabulate, fqdn). Tourne dans l'image du lab.
"""
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from lib import st_release as rel  # noqa: E402

try:
    import cryptography  # noqa: F401
    import psutil  # noqa: F401
    import toml  # noqa: F401
except ImportError:
    pytest.skip("dépendances de la sonde absentes (lancer dans l'image du lab)", allow_module_level=True)

REMOVED = ["flask", "gevent", "werkzeug", "influxdb_client", "PIL", "flask_wtf", "flask_login", "flask_sqlalchemy",
           "dotenv", "sqlalchemy", "pytz", "tzlocal", "cpuinfo", "tabulate", "fqdn"]
BLOCKER = f"""
import sys, importlib.abc
class Block(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path=None, target=None):
        if name.split(".")[0] in {REMOVED!r}:
            raise ImportError("blocked: " + name)
sys.meta_path.insert(0, Block())
"""


@pytest.fixture(scope="module")
def package(tmp_path_factory):
    out = tmp_path_factory.mktemp("release")
    info = rel.build(str(ROOT), str(out / "dist"), "0.0-test", profile="client")
    rel.safe_extract(info["path"], str(out / "client"))
    return out / "client", info


def run(directory, code):
    return subprocess.run([sys.executable, "-I", "-c", BLOCKER + code], cwd=directory, capture_output=True, text=True,
                          timeout=120, env={"PATH": "/usr/bin:/bin", "SYNTRAF_BASE_DIR": str(directory)})


def test_the_client_package_is_small(package):
    _, info = package
    assert info["size"] < 400_000, info["size"]


def test_the_client_code_imports_without_server_or_removed_packages(package):
    directory, _ = package
    r = run(directory, "sys.path.insert(0, '.')\n"
                       "from lib.st_global import CompilationOptions\n"
                       "assert CompilationOptions.client_only\n"
                       "import lib.st_process_and_thread, lib.st_mesh, lib.st_iperf, lib.st_iperf3_readlog\n"
                       "import lib.st_updater, lib.st_system_stats, lib.st_clean_close, lib.st_nat\n"
                       "from lib.st_mesh import get_system_infos\n"
                       "i = get_system_infos(); assert i['CPU_MODEL'] is not None and i['TIMEZONE']\n"
                       "print('ok')")
    assert r.returncode == 0 and r.stdout.strip().endswith("ok"), r.stderr[-3000:]


def test_syntraf_starts_from_the_client_package(package):
    directory, _ = package
    r = run(directory, "import runpy; sys.argv = ['syntraf.py', '-h']; sys.path.insert(0, '.')\n"
                       "runpy.run_path('syntraf.py', run_name='__main__')")
    assert r.returncode == 0 and "usage" in r.stdout.lower(), (r.stdout[-1500:], r.stderr[-3000:])


def test_a_server_configuration_is_refused_by_the_client_package(package, tmp_path):
    directory, _ = package
    cfg = tmp_path / "server.toml"
    cfg.write_text('[SERVER]\nBIND_ADDRESS = "0.0.0.0"\nSERVER_PORT = "6531"\n'
                   'MESH_LISTENERS_PORT_RANGE = "15000-15100"\nTOKEN = { t = "secret-token" }\n')
    r = run(directory, f"import runpy; sys.argv = ['syntraf.py', '-c', {str(cfg)!r}, '-l', {str(tmp_path)!r}]\n"
                       "sys.path.insert(0, '.')\nrunpy.run_path('syntraf.py', run_name='__main__')")
    assert "client package" in (r.stdout + r.stderr).lower(), (r.stdout[-1500:], r.stderr[-3000:])


def test_fqdn_check_matches_the_former_package():
    fqdn = pytest.importorskip("fqdn")
    from lib.st_conf_validation import FQDN
    for name in ["syntraf.example.org", "a.b", "localhost", "10.0.0.1", "-bad.example.org", "bad-.example.org",
                 "under_score.example.org", "x" * 64 + ".org", "ok.example.org.", "a..b", "example.123",
                 "xn--bcher-kva.example", ("a" * 60 + ".") * 5 + "org"]:
        assert FQDN(name).is_valid == fqdn.FQDN(name).is_valid, name


def test_a_probe_installed_from_the_repository_needs_the_three_packages_only():
    """Première installation d'une sonde : le dépôt complet (avec l'interface web), sans les paquets du serveur."""
    r = run(ROOT, "sys.path.insert(0, '.')\n"
                  "from lib.st_global import CompilationOptions\n"
                  "assert CompilationOptions.client_only\n"
                  "import lib.st_process_and_thread, lib.st_mesh, lib.st_iperf, lib.st_iperf3_readlog\n"
                  "print('ok')")
    assert r.returncode == 0 and r.stdout.strip().endswith("ok"), r.stderr[-3000:]
