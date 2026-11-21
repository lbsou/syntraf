import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lablib import docker, health  # noqa: E402


@pytest.fixture(scope="session")
def metrics():
    return health.metrics_client()


@pytest.fixture(scope="session")
def lab_up(metrics):
    """Le lab doit être démarré (labctl up) ; on attend seulement qu'il soit sain."""
    r = docker.compose(["ps", "--status", "running", "-q"], check=False)
    if len([line for line in r.stdout.splitlines() if line.strip()]) < 7:
        pytest.fail("lab non démarré : lancer `python lab/labctl.py up` d'abord")
    health.wait_healthy(metrics, timeout_s=180)
    return True
