"""Journaux des clients transmis au serveur, rétention et recherche (lib/st_log_forward.py, lib/st_log_store.py,
lib/st_log_search.py). Modules sans dépendance : tournent dans lab/.venv.
"""
import logging
import os
import sys
import time
from datetime import timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from lib import st_log_forward as fwd  # noqa: E402
from lib import st_log_search as search  # noqa: E402
from lib import st_log_store as store  # noqa: E402

LINE = " 2026-11-21 23:45:00+0000 - WARNING - st_mesh (handle,1008) - SOCKET TIMEOUT: 172.30.0.32\n"


# ---------------------------------------------------------------------------------- client : tampon borné

def make_logger(handler):
    logger = logging.getLogger(f"syntraf.test.{id(handler)}")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    logger.addHandler(handler)
    return logger


def test_buffer_keeps_formatted_lines_at_or_above_the_level():
    h = fwd.ForwardHandler(capacity=10, level=logging.INFO)
    log = make_logger(h)
    log.debug("noise")
    log.warning("disk almost full")
    lines, dropped = h.drain(100)
    assert len(lines) == 1 and " - WARNING - " in lines[0] and "disk almost full" in lines[0]
    assert dropped == 0 and h.drain(100) == ([], 0)


def test_buffer_is_bounded_and_counts_what_it_dropped():
    h = fwd.ForwardHandler(capacity=3, level=logging.INFO)
    log = make_logger(h)
    for i in range(5):
        log.info(f"line {i}")
    lines, dropped = h.drain(100)
    assert [l.rsplit(" - ", 1)[1] for l in lines] == ["line 2", "line 3", "line 4"]
    assert dropped == 2


def test_drain_sends_in_batches_and_keeps_the_rest():
    h = fwd.ForwardHandler(capacity=10, level=logging.INFO)
    log = make_logger(h)
    for i in range(5):
        log.info(f"line {i}")
    assert len(h.drain(2)[0]) == 2
    assert len(h.drain(10)[0]) == 3


def test_level_can_change_at_runtime():
    h = fwd.ForwardHandler(capacity=10, level=logging.INFO)
    log = make_logger(h)
    h.set_level_name("ERROR")
    log.warning("not forwarded")
    log.error("forwarded")
    assert len(h.drain(10)[0]) == 1


def test_timestamps_carry_their_utc_offset():
    h = fwd.ForwardHandler(capacity=10, level=logging.INFO)
    make_logger(h).info("x")
    stamp = h.drain(10)[0][0].strip().split(" - ")[0]
    assert search.parse_time(stamp).utcoffset() is not None and stamp[-5] in "+-"


# ---------------------------------------------------------------------------------- serveur : stockage

def test_client_lines_are_written_per_client(tmp_path):
    store.append(str(tmp_path), "LAB_C2", [LINE], dropped=0, max_bytes=10_000, backups=2)
    assert (tmp_path / "clients" / "LAB_C2" / "syntraf.log").read_text() == LINE


def test_lines_dropped_by_the_client_are_recorded(tmp_path):
    store.append(str(tmp_path), "LAB_C2", [LINE], dropped=7, max_bytes=10_000, backups=2)
    text = (tmp_path / "clients" / "LAB_C2" / "syntraf.log").read_text()
    assert "7 log line(s) dropped by the client" in text


def test_client_files_rotate_by_size(tmp_path):
    for _ in range(30):
        store.append(str(tmp_path), "LAB_C2", [LINE], dropped=0, max_bytes=500, backups=2)
    files = sorted(os.listdir(tmp_path / "clients" / "LAB_C2"))
    assert files == ["syntraf.log", "syntraf.log.1", "syntraf.log.2"]


def test_unsafe_client_names_are_refused(tmp_path):
    store.append(str(tmp_path), "../../etc", [LINE], dropped=0, max_bytes=500, backups=2)
    assert not (tmp_path / "clients").exists() or os.listdir(tmp_path / "clients") == []


def test_files_older_than_the_retention_are_purged(tmp_path):
    store.append(str(tmp_path), "LAB_C2", [LINE], dropped=0, max_bytes=500, backups=2)
    old = tmp_path / "clients" / "LAB_C2" / "syntraf.log.1"
    old.write_text(LINE)
    past = time.time() - 10 * 86400
    os.utime(old, (past, past))
    removed = store.purge_older_than(str(tmp_path), days=7)
    assert removed == [str(old)] and not old.exists()
    assert (tmp_path / "clients" / "LAB_C2" / "syntraf.log").exists()  # le fichier courant n'est jamais supprimé


# ---------------------------------------------------------------------------------- recherche

def write(path, lines):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(lines))


def corpus(tmp_path):
    # Les lignes sans décalage (ancien format) sont à l'heure du serveur qui les a écrites : UTC dans le lab.
    search.LOCAL_TZ = timezone.utc
    write(tmp_path / "syntraf.log", [
        " 2026-11-21 23:40:00+0000 - INFO - pywsgi (write,1353) - 172.30.0.1 GET /home.html 200\n",
        " 2026-11-21 23:41:00+0000 - ERROR - st_mesh (handle,1050) - CLIENT: 172.30.0.32 DISCONNECTED\n",
        " 2026-11-21 23:42:00 - WARNING - st_victoriametrics (_set_status,1) - DATABASE 'VM' IS NOW OFFLINE\n",
    ])
    write(tmp_path / "clients" / "LAB_C2" / "syntraf.log", [
        " 2026-11-21 18:43:00-0500 - WARNING - st_outage (record,89) - LAB_C3__TO__LAB_C2 - OUTAGE\n",
        "Traceback (most recent call last):\n",
        "  File x, line 1\n",
        " 2026-11-21 23:44:00+0000 - INFO - st_mesh (client,1) - CONNECTED TO SERVER\n",
    ])


def test_nodes_are_the_server_and_each_client_with_logs(tmp_path):
    corpus(tmp_path)
    assert search.nodes(str(tmp_path)) == ["server", "LAB_C2"]


def test_entries_are_parsed_with_node_type_and_timezone(tmp_path):
    corpus(tmp_path)
    entries = search.search(str(tmp_path))
    assert [e["node"] for e in entries] == ["LAB_C2", "LAB_C2", "server", "server", "server"]  # récent d'abord
    outage = next(e for e in entries if "OUTAGE" in e["message"])
    assert outage["type"] == "measurement" and outage["time"] == "2026-11-21T23:43:00+00:00"
    assert next(e for e in entries if "GET /home" in e["message"])["type"] == "webui"


def test_continuation_lines_stay_with_their_entry(tmp_path):
    corpus(tmp_path)
    outage = next(e for e in search.search(str(tmp_path)) if "OUTAGE" in e["message"])
    assert "Traceback" in outage["detail"] and "File x" in outage["detail"]


def test_filters_combine_node_type_level_keywords_and_time(tmp_path):
    corpus(tmp_path)
    d = str(tmp_path)
    assert [e["node"] for e in search.search(d, nodes=["server"], types=["control"])] == ["server"]
    assert len(search.search(d, level="WARNING")) == 3
    assert len(search.search(d, query="disconnected 172.30.0.32")) == 1          # tous les mots, sans casse
    assert len(search.search(d, query='"is now offline"')) == 1                 # expression exacte
    assert len(search.search(d, query="-pywsgi", nodes=["server"])) == 2         # exclusion
    since = search.parse_time("2026-11-21 23:41:30+0000")
    assert len(search.search(d, since=since)) == 3


def test_limit_keeps_the_most_recent(tmp_path):
    corpus(tmp_path)
    entries = search.search(str(tmp_path), limit=2)
    assert [e["message"].split()[0] for e in entries] == ["CONNECTED", "LAB_C3__TO__LAB_C2"]
