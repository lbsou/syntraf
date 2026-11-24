"""Redémarrages, mises à jour et retours arrière (lib/st_lifecycle.py) : repères dans Grafana."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from lib import st_lifecycle as lc  # noqa: E402


def test_an_installed_update_a_rollback_and_a_reconnection_are_events():
    prev = {"status": "DISCONNECTED", "release": "0.45+aaa", "update_failed": None}
    new = {"release": "0.45+bbb", "update_failed": None}
    assert [e[0] for e in lc.events("P1", prev, new)] == ["PROBE_RECONNECTED", "PROBE_UPDATED"]
    rolled = lc.events("P1", {"status": "CONNECTED", "release": "0.45+aaa", "update_failed": None},
                       {"release": "0.45+aaa", "update_failed": "0.45+ccc"})
    assert rolled[0][0] == "PROBE_ROLLED_BACK" and "0.45+ccc" in rolled[0][1] and "0.45+aaa" in rolled[0][1]
    # premier contact depuis le démarrage du serveur : rien (sinon une rafale de repères à chaque redémarrage)
    assert lc.events("P1", {"status": "UNKNOWN", "release": None, "update_failed": None},
                     {"release": "0.45+aaa", "update_failed": None}) == []
    # un retour arrière déjà connu n'est pas répété à chaque reconnexion
    assert lc.events("P1", {"status": "CONNECTED", "release": "0.45+aaa", "update_failed": "0.45+ccc"},
                     {"release": "0.45+aaa", "update_failed": "0.45+ccc"}) == []


def test_events_are_written_once_then_forgotten():
    written = []
    lc.record("SERVER_STARTED", "server", "SYNTRAF server 0.45 started")
    lc.flush(written.extend)
    lc.flush(written.extend)
    assert len(written) == 1 and written[0]["measurement"] == "SYNTRAF_LIFECYCLE"
    assert written[0]["tags"]["EVENT"] == "SERVER_STARTED" and written[0]["fields"] == {"EVENT": 1}
