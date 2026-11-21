import json
import subprocess

from lablib import docker


def capture(monkeypatch, stdout=""):
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, stdout=stdout, stderr="")

    monkeypatch.setattr(docker.subprocess, "run", fake_run)
    return calls


def test_compose_adds_project_file_and_env(monkeypatch):
    calls = capture(monkeypatch)
    docker.compose(["ps"])
    args = calls[0]
    assert args[:4] == ["docker", "compose", "-p", "syntraf-lab"]
    assert args[4] == "-f" and args[5].replace("\\", "/").endswith("lab/docker-compose.yml")
    assert args[6] == "--env-file" and args[7].replace("\\", "/").endswith("lab/config/lab.env")
    assert args[-1] == "ps"


def test_exec_targets_prefixed_container(monkeypatch):
    calls = capture(monkeypatch)
    docker.exec_("c2", ["tc", "qdisc", "show"])
    assert calls[0] == ["docker", "exec", "syntraf-lab-c2", "tc", "qdisc", "show"]


def test_inspect_state_parses_networks_and_pause(monkeypatch):
    payload = [{"State": {"Running": True, "Paused": False, "StartedAt": "2026-11-21T15:32:27Z"},
                "NetworkSettings": {"Networks": {"syntraf_lab": {"IPAddress": "172.30.0.33"}}}}]
    capture(monkeypatch, stdout=json.dumps(payload))
    assert docker.inspect_state("c3") == {"running": True, "paused": False, "started_at": "2026-11-21T15:32:27Z",
                                          "networks": {"syntraf_lab": "172.30.0.33"}}
