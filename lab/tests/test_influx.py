from datetime import datetime, timezone

from lablib import influx

SAMPLE_CSV = (
    "#datatype,string,long,dateTime:RFC3339,dateTime:RFC3339,dateTime:RFC3339,double,string,string,string\r\n"
    "#group,false,false,true,true,false,false,true,true,true\r\n"
    "#default,_result,,,,,,,,\r\n"
    ",result,table,_start,_stop,_time,_value,_field,_measurement,UID\r\n"
    ",,0,2026-11-20T12:00:00Z,2026-11-20T12:01:00Z,2026-11-20T12:00:01Z,0,RX_PCT_LOSS,SYNTRAF,LAB_C1__TO__LAB_C2__ON__DSCP0\r\n"
    ",,0,2026-11-20T12:00:00Z,2026-11-20T12:01:00Z,2026-11-20T12:00:02.5Z,100,RX_PCT_LOSS,SYNTRAF,LAB_C1__TO__LAB_C2__ON__DSCP0\r\n"
    "\r\n"
)


def test_parse_flux_csv_returns_utc_tuples():
    rows = influx.parse_csv(SAMPLE_CSV)
    assert rows[0] == (datetime(2026, 11, 20, 12, 0, 1, tzinfo=timezone.utc), 0.0)
    assert rows[1] == (datetime(2026, 11, 20, 12, 0, 2, 500000, tzinfo=timezone.utc), 100.0)
    assert len(rows) == 2


def test_parse_empty_response():
    assert influx.parse_csv("\r\n") == []


def test_query_builds_flux_with_uid_and_field():
    q = influx.build_query("SYNTRAF", "LAB_C1__TO__LAB_C2__ON__DSCP0", "RX_PCT_LOSS",
                           datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc),
                           datetime(2026, 11, 20, 12, 1, tzinfo=timezone.utc))
    assert 'from(bucket: "SYNTRAF")' in q
    assert "range(start: 2026-11-20T12:00:00Z, stop: 2026-11-20T12:01:00Z)" in q
    assert 'r.UID == "LAB_C1__TO__LAB_C2__ON__DSCP0"' in q
    assert 'r._field == "RX_PCT_LOSS"' in q
    assert 'r._measurement == "SYNTRAF"' in q
