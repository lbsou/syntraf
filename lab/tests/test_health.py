import subprocess

from lablib import health

PS_SAMPLE = """\
    1 Ss      1   1024 /sbin/docker-init -- /entrypoint.sh
    7 Sl     37  51200 python /app/syntraf.py -c /etc/syntraf/config.toml -l /logs
   40 S       1   3000 /usr/local/bin/iperf3 -s -i 1 -p 15001
   41 S       1   3100 /usr/local/bin/iperf3 -u -c 172.30.0.32 -t 0
   42 Z       1      0 [iperf3] <defunct>
   50 R       1    900 ps -eo pid=,stat=,nlwp=,rss=,args=
"""


def fake_exec(monkeypatch, stdout):
    calls = []

    def _exec(service, cmd, check=True, timeout=60):
        calls.append((service, cmd))
        return subprocess.CompletedProcess(cmd, 0, stdout=stdout, stderr="")

    monkeypatch.setattr(health.docker, "exec_", _exec)
    return calls


def test_snapshot_parses_ps_output(monkeypatch):
    calls = fake_exec(monkeypatch, PS_SAMPLE)
    s = health.snapshot("c1")
    assert (s.iperf3_count, s.zombies, s.threads, s.rss_kb) == (2, 1, 37, 51200)
    assert calls[0][0] == "c1"


def test_snapshot_without_syntraf_process(monkeypatch):
    fake_exec(monkeypatch, "    1 Ss 1 1024 /sbin/docker-init\n")
    s = health.snapshot("c1")
    assert (s.iperf3_count, s.zombies, s.threads, s.rss_kb) == (0, 0, 0, 0)


def test_read_env_parses_lab_env(tmp_path):
    f = tmp_path / "lab.env"
    f.write_text("# commentaire\nA=1\nINFLUX_TOKEN=abc=def\n\n")
    assert health.read_env(f) == {"A": "1", "INFLUX_TOKEN": "abc=def"}


def test_stale_flows_lists_missing_and_old(monkeypatch):
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)

    class FakeInflux:
        def last_point_time(self, flow):
            return {"A": now, "B": now - timedelta(seconds=30)}.get(flow)

    assert health.stale_flows(FakeInflux(), ["A", "B", "C"], max_age_s=3) == ["B", "C"]
