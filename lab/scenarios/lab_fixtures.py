"""Fixtures des scénarios du lab (plugin pytest chargé par conftest.py)."""
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lablib import docker, faults, health, topology  # noqa: E402

POST_HEAL_HEALTHY_S = 60
RESTART_HEALTHY_S = 180


@pytest.fixture(scope="session")
def metrics():
    return health.metrics_client()


@pytest.fixture(scope="session")
def lab_up(metrics):
    """Le lab doit être démarré (labctl up) ; on attend seulement qu'il soit sain."""
    r = docker.compose(["ps", "--status", "running", "-q"], check=False)
    if len([line for line in r.stdout.splitlines() if line.strip()]) < 7:
        pytest.fail("lab non démarré : lancer `python lab/labctl.py up` d'abord")
    health.wait_healthy(metrics, timeout_s=RESTART_HEALTHY_S)
    return True


def restart_syntraf() -> None:
    """Recrée serveur et clients (VictoriaMetrics et Grafana restent en place)."""
    faults.heal_all()
    docker.compose(["up", "-d", "--force-recreate", "--no-deps", *topology.SYNTRAF_NODES], timeout=600)


@pytest.fixture(autouse=True)
def fault_guard(request, metrics):
    """Après chaque scénario : retirer toute panne, puis exiger le retour à l'état sain.

    Si SYNTRAF ne redevient pas sain en 60 s, il est redémarré pour que le scénario
    suivant parte d'un état propre ; le rapport le signale (propriété lab_restarted).
    """
    yield
    faults.heal_all()
    try:
        health.wait_healthy(metrics, timeout_s=POST_HEAL_HEALTHY_S)
    except TimeoutError:
        request.node.user_properties.append(("lab_restarted", True))
        restart_syntraf()
        health.wait_healthy(metrics, timeout_s=RESTART_HEALTHY_S)


@dataclass
class Window:
    start: datetime | None = None
    stop: datetime | None = None

    def mark_start(self) -> datetime:
        self.start = datetime.now(timezone.utc)
        return self.start

    def mark_stop(self) -> datetime:
        self.stop = datetime.now(timezone.utc)
        return self.stop


@pytest.fixture
def window() -> Window:
    return Window()


def wait_until(t: datetime) -> None:
    """Dort jusqu'à l'instant UTC t (sans effet s'il est passé)."""
    delay = (t - datetime.now(timezone.utc)).total_seconds()
    if delay > 0:
        time.sleep(delay)
