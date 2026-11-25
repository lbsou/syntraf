"""Envoi des mesures en attente par lots (lib/st_mesh.py client_send_metrics).

Un arriéré entier envoyé en un seul message (jusqu'à 86 400 mesures après une coupure de la base) faisait tomber le
serveur et VictoriaMetrics faute de mémoire, et ne passait jamais sur un lien lent (délai du canal de contrôle
dépassé, reconnexion, nouvel essai du même message géant)."""
import collections
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import lib.st_process_and_thread  # noqa: E402,F401 - charge st_mesh dans l'ordre du serveur
from lib import st_mesh  # noqa: E402
from lib.st_global import DefaultValues  # noqa: E402


def queue(n):
    return collections.OrderedDict((f"k{i}", {"measurement": "m", "i": i}) for i in range(n))


def run(monkeypatch, pending, answer="OK"):
    sent = []
    monkeypatch.setattr(st_mesh, "sock_send", lambda conn, payload, command: sent.append((command, list(payload))))
    monkeypatch.setattr(st_mesh, "sock_rcv", lambda conn, *a, **k: {"COMMAND": "SAVE_METRIC_RESPONSE", "PAYLOAD": answer})
    st_mesh.client_send_metrics({"CLIENT": {"SERVER": "s", "SERVER_PORT": "1"}}, object(), pending)
    return sent


def test_a_large_backlog_leaves_in_batches(monkeypatch):
    size = DefaultValues.CLIENT_METRICS_PER_MESSAGE
    pending = queue(size * 2 + 7)
    sent = run(monkeypatch, pending)
    assert len(sent) == 1 and sent[0][0] == "SAVE_METRIC" and len(sent[0][1]) == size
    assert len(pending) == size + 7 and "k0" not in pending and f"k{size}" in pending  # les plus anciennes d'abord


def test_a_refused_batch_stays_in_the_queue(monkeypatch):
    pending = queue(DefaultValues.CLIENT_METRICS_PER_MESSAGE + 1)
    run(monkeypatch, pending, answer="NOK")
    assert len(pending) == DefaultValues.CLIENT_METRICS_PER_MESSAGE + 1


def test_a_small_queue_leaves_whole(monkeypatch):
    pending = queue(5)
    sent = run(monkeypatch, pending)
    assert len(sent[0][1]) == 5 and not pending


def test_a_batch_fits_well_within_the_message_limit():
    from lib import st_channel_guard
    assert DefaultValues.CLIENT_METRICS_PER_MESSAGE * 2048 < st_channel_guard.MAX_MESSAGE_BYTES  # ~2 Kio par mesure au plus
