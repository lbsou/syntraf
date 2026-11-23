"""Qualité perçue (lib/st_quality.py) : MOS de la voix selon le modèle E (UIT-T G.107, forme simplifiée) et rafales
de pertes (épisodes, ratio de rafale à la manière de la BurstR de G.113, à la granularité de l'intervalle)."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from lib import st_quality as q  # noqa: E402


# ------------------------------------------------------------------------------------------------ MOS

def test_a_clean_g711_path_scores_like_toll_quality():
    r, mos = q.mos(loss_pct=0, jitter_ms=0)
    assert 92 < r <= 93.2 and 4.3 <= mos <= 4.42


def test_loss_lowers_the_score_and_a_dead_path_scores_one():
    _, clean = q.mos(0, 1)
    _, lossy = q.mos(5, 1)
    _, bad = q.mos(20, 1)
    assert clean > lossy > bad
    assert q.mos(100, 0)[1] == 1.0


def test_jitter_and_latency_lower_the_score():
    assert q.mos(0, 40)[1] < q.mos(0, 2)[1]
    assert q.mos(0, 2, latency_ms=300)[1] < q.mos(0, 2)[1]


def test_g729_starts_lower_and_tolerates_loss_differently():
    assert q.mos(0, 0, codec="G729")[1] < q.mos(0, 0, codec="G711")[1]
    assert q.CODECS["G729"]["Ie"] == 11 and q.CODECS["G711"]["Bpl"] == 25.1


def test_bursty_loss_hurts_more_than_random_loss():
    assert q.mos(3, 2, burst_ratio=3)[1] < q.mos(3, 2, burst_ratio=1)[1]


def test_unknown_codec_falls_back_to_g711():
    assert q.mos(1, 1, codec="NOPE") == q.mos(1, 1, codec="G711")


def test_mos_is_added_to_a_measurement_point():
    point = {"measurement": "SYNTRAF", "tags": {"MESH_GROUP": "G"},
             "fields": {"RX_PCT_LOSS": 2.0, "RX_JITTER": 3.0, "RX_BITRATE": 87.0}}
    q.add_mos(point, "OPUS")
    assert 3.5 < point["fields"]["RX_MOS"] < 4.5 and "RX_R_FACTOR" in point["fields"]
    assert point["tags"]["CODEC"] == "OPUS"


# --------------------------------------------------------------------------------------------- rafales

def test_loss_episodes():
    s = [0, 0, 5, 10, 0, 0, 0, 3, 0, 50, 60, 70, 0]
    assert q.episodes(s) == [2, 1, 3]


def test_burst_metrics_of_clustered_losses():
    clustered = [0] * 50 + [30] * 6 + [0] * 50 + [25] * 6 + [0] * 8
    m = q.burst_metrics(clustered, interval_s=1)
    assert m["EPISODES"] == 2 and m["LONGEST_S"] == 6
    assert m["BURST_RATIO"] > 3 and m["HEAVY_SHARE"] == pytest.approx(100)


def test_steady_random_loss_is_not_a_burst():
    """5 % de pertes au hasard à 57 paquets/s : presque chaque seconde perd un paquet, sans rafale pour autant."""
    steady = [5.3, 3.5, 7.0, 1.7, 5.2, 8.8, 3.4, 5.4, 0, 7.1, 3.6, 5.3] * 10
    m = q.burst_metrics(steady, interval_s=1)
    assert m["EPISODES"] == 0 and m["LONGEST_S"] == 0 and m["LOSS_PCT"] > 4


def test_isolated_bad_seconds_are_short_random_bursts():
    scattered = ([3] * 9 + [15]) * 12
    m = q.burst_metrics(scattered, interval_s=1)
    assert m["EPISODES"] == 12 and m["LONGEST_S"] == 1
    assert m["BURST_RATIO"] == pytest.approx(1, abs=0.15) and m["HEAVY_SHARE"] == 0


def test_no_loss_has_no_burst():
    m = q.burst_metrics([0] * 30, interval_s=1)
    assert m == {"EPISODES": 0, "LONGEST_S": 0, "BURST_RATIO": 0.0, "HEAVY_SHARE": 0.0, "LOSS_PCT": 0.0}


def test_bursts_are_published_from_victoriametrics():
    class FakeVm:
        def query_range(self, query, start, end, step):
            assert "SYNTRAF_RX_PCT_LOSS" in query
            vals = [0] * 50 + [30] * 6 + [0] * 40
            return [{"metric": {"CLIENT": "A", "SERVER": "B", "MESH_GROUP": "G", "UID": "A__TO__B__ON__DSCP0"},
                     "values": [[1000 + i, str(v)] for i, v in enumerate(vals)]}]

    written = []
    q.publish_bursts(FakeVm(), written.extend, now=2000)
    fields = {k for p in written for k in p["fields"]}
    assert {"EPISODES", "LONGEST_S", "BURST_RATIO", "HEAVY_SHARE"} <= fields
    assert written[0]["measurement"] == "SYNTRAF_LOSS_BURST" and written[0]["tags"]["CLIENT"] == "A"


# ----------------------------------------------------------------------------------- codec par mesh group

CONFIG = {"IPERF3_PROFILE": [{"UID": "VOICE", "CODEC": "G729"}, {"UID": "DATA"}],
          "MESH_GROUP": [{"UID": "G_VOICE", "IPERF3_PROFILE": "VOICE"}, {"UID": "G_DATA", "IPERF3_PROFILE": "DATA"},
                         {"UID": "G_PLAIN"}]}


def test_each_mesh_group_gets_the_codec_of_its_profile_or_g711():
    assert q.codec_by_group(CONFIG) == {"G_VOICE": "G729", "G_DATA": "G711", "G_PLAIN": "G711"}


def test_measurements_received_by_the_server_get_their_mos():
    points = [{"measurement": "SYNTRAF", "tags": {"MESH_GROUP": "G_VOICE"},
               "fields": {"RX_PCT_LOSS": 0.0, "RX_JITTER": 1.0}},
              {"measurement": "SYNTRAF_FLOW", "tags": {}, "fields": {"EXPECTED": 1}}]
    q.enrich(points, CONFIG)
    assert points[0]["tags"]["CODEC"] == "G729" and points[0]["fields"]["RX_MOS"] < 4.2
    assert "RX_MOS" not in points[1]["fields"]
