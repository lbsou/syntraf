"""Lecture d'InfluxDB 2 via l'API HTTP (Flux), sans dépendance externe."""
import csv
import io
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

MEASUREMENT = "SYNTRAF"


def _rfc3339(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_time(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)


def build_query(bucket: str, flow_uid: str, field: str, start: datetime, stop: datetime) -> str:
    return (
        f'from(bucket: "{bucket}")\n'
        f"  |> range(start: {_rfc3339(start)}, stop: {_rfc3339(stop)})\n"
        f'  |> filter(fn: (r) => r._measurement == "{MEASUREMENT}" and r.UID == "{flow_uid}" and r._field == "{field}")\n'
        f'  |> keep(columns: ["_time", "_value"])\n'
        f'  |> sort(columns: ["_time"])\n'
    )


def parse_csv(text: str) -> list[tuple[datetime, float]]:
    rows = []
    header = None
    for rec in csv.reader(io.StringIO(text)):
        if not rec or all(c == "" for c in rec):
            header = None
            continue
        if rec[0].startswith("#"):
            continue
        if header is None:
            header = rec
            continue
        d = dict(zip(header, rec))
        rows.append((_parse_time(d["_time"]), float(d["_value"])))
    return rows


class Client:
    def __init__(self, url: str, token: str, org: str, bucket: str):
        self.url = url.rstrip("/")
        self.token = token
        self.org = org
        self.bucket = bucket

    def _query(self, flux: str) -> str:
        req = urllib.request.Request(
            f"{self.url}/api/v2/query?org={urllib.request.quote(self.org)}",
            data=flux.encode(),
            headers={"Authorization": f"Token {self.token}",
                     "Content-Type": "application/vnd.flux",
                     "Accept": "application/csv"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode()

    def points(self, flow_uid: str, start: datetime, stop: datetime, field: str = "RX_PCT_LOSS") -> list[tuple[datetime, float]]:
        return parse_csv(self._query(build_query(self.bucket, flow_uid, field, start, stop)))

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
