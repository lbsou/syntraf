from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse

from lablib import vm

EXPORT = (
    '{"metric":{"__name__":"SYNTRAF_RX_PCT_LOSS","UID":"A__TO__B__ON__DSCP0"},'
    '"values":[100,0],"timestamps":[1795176002500,1795176001000]}\n'
    '{"metric":{"__name__":"SYNTRAF_RX_PCT_LOSS","UID":"A__TO__B__ON__DSCP0","MESH_GROUP":"X"},'
    '"values":[5],"timestamps":[1795176003000]}\n'
)


def test_parse_export_sorts_and_converts_ms():
    rows = vm.parse_export(EXPORT)
    assert rows == [
        (datetime(2026, 11, 20, 12, 0, 1, tzinfo=timezone.utc), 0.0),
        (datetime(2026, 11, 20, 12, 0, 2, 500000, tzinfo=timezone.utc), 100.0),
        (datetime(2026, 11, 20, 12, 0, 3, tzinfo=timezone.utc), 5.0),
    ]


def test_parse_export_empty():
    assert vm.parse_export("") == []


def test_export_url_matches_metric_and_uid():
    url = vm.export_url("http://127.0.0.1:18428", "A__TO__B__ON__DSCP0", "RX_PCT_LOSS",
                        datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc),
                        datetime(2026, 11, 20, 12, 1, tzinfo=timezone.utc))
    u = urlparse(url)
    assert u.path == "/api/v1/export"
    q = parse_qs(u.query)
    assert q["match[]"] == ['{__name__="SYNTRAF_RX_PCT_LOSS",UID="A__TO__B__ON__DSCP0"}']
    assert q["start"] == ["1795176000"] and q["end"] == ["1795176060"]
