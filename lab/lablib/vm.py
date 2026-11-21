"""Lecture de VictoriaMetrics (points bruts via /api/v1/export), sans dépendance externe."""
import json
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

METRIC_PREFIX = "SYNTRAF_"


def export_url(base: str, flow_uid: str, field: str, start: datetime, stop: datetime) -> str:
    match = f'{{__name__="{METRIC_PREFIX}{field}",UID="{flow_uid}"}}'
    query = urllib.parse.urlencode({"match[]": match, "start": int(start.timestamp()), "end": int(stop.timestamp())})
    return f"{base.rstrip('/')}/api/v1/export?{query}"


def parse_export(text: str) -> list[tuple[datetime, float]]:
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        series = json.loads(line)
        for v, ts in zip(series["values"], series["timestamps"]):
            rows.append((datetime.fromtimestamp(ts / 1000, tz=timezone.utc), float(v)))
    rows.sort(key=lambda r: r[0])
    return rows


class Client:
    def __init__(self, url: str):
        self.url = url.rstrip("/")

    def points(self, flow_uid: str, start: datetime, stop: datetime, field: str = "RX_PCT_LOSS") -> list[tuple[datetime, float]]:
        with urllib.request.urlopen(export_url(self.url, flow_uid, field, start, stop), timeout=30) as resp:
            return parse_export(resp.read().decode())

    def last_point_time(self, flow_uid: str, lookback_s: int = 3600) -> datetime | None:
        now = datetime.now(timezone.utc)
        pts = self.points(flow_uid, now - timedelta(seconds=lookback_s), now + timedelta(seconds=5))
        return pts[-1][0] if pts else None

    def ping(self) -> bool:
        try:
            with urllib.request.urlopen(f"{self.url}/health", timeout=5) as resp:
                return resp.status == 200
        except (urllib.error.URLError, OSError):
            return False
