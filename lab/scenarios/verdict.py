"""Plugin pytest : verdicts des scénarios face à la liste des échecs connus, et rapport.

Verdicts :
  passed         réussi
  known_failure  échec listé dans known_failures.txt (bogue connu de SYNTRAF)
  regression     échec non listé
  fixed          test listé qui réussit désormais (à retirer de la liste)

Le code de sortie n'est non nul que s'il y a au moins une régression.
"""
from datetime import datetime
from pathlib import Path

import pytest

DEFAULT_KNOWN = Path(__file__).resolve().parent / "known_failures.txt"


def pytest_addoption(parser):
    g = parser.getgroup("verdict")
    g.addoption("--known-failures", default=str(DEFAULT_KNOWN), help="fichier des échecs connus")
    g.addoption("--report-dir", default=None, help="dossier où écrire summary.md")


def load_known(path: Path) -> dict[str, str]:
    known = {}
    if not path.is_file():
        return known
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        nodeid, _, reason = line.partition("|")
        known[nodeid.strip()] = reason.strip()
    return known


class Verdicts:
    def __init__(self, config):
        self.known = load_known(Path(config.getoption("--known-failures")))
        rd = config.getoption("--report-dir")
        self.report_dir = Path(rd) if rd else None
        self.outcomes: dict[str, str] = {}
        self.details: dict[str, str] = {}
        self.props: dict[str, list] = {}
        self.started = datetime.now()

    @pytest.hookimpl
    def pytest_runtest_logreport(self, report):
        nid = report.nodeid
        if report.failed:
            self.outcomes[nid] = "failed"
            text = report.longreprtext.strip().splitlines()
            self.details[nid] = "\n".join(text[-15:])
        elif report.when == "call" and nid not in self.outcomes:
            self.outcomes[nid] = "skipped" if report.skipped else "passed"
        elif report.when == "setup" and report.skipped:
            self.outcomes.setdefault(nid, "skipped")
        if report.user_properties:
            self.props.setdefault(nid, []).extend(report.user_properties)

    def classify(self) -> dict[str, str]:
        out = {}
        for nid, outcome in self.outcomes.items():
            listed = nid in self.known
            if outcome == "failed":
                out[nid] = "known_failure" if listed else "regression"
            elif outcome == "passed":
                out[nid] = "fixed" if listed else "passed"
            else:
                out[nid] = outcome
        return out

    @pytest.hookimpl(trylast=True)
    def pytest_sessionfinish(self, session, exitstatus):
        verdicts = self.classify()
        regressions = [n for n, v in verdicts.items() if v == "regression"]
        if self.outcomes and exitstatus in (0, 1):
            session.exitstatus = 1 if regressions else 0
        if self.report_dir:
            self.report_dir.mkdir(parents=True, exist_ok=True)
            (self.report_dir / "summary.md").write_text(self.render(verdicts), encoding="utf-8")

    def render(self, verdicts: dict[str, str]) -> str:
        counts = {}
        for v in verdicts.values():
            counts[v] = counts.get(v, 0) + 1
        lines = [f"# Rapport des scénarios — {self.started:%Y-%m-%d %H:%M}", "",
                 "| Verdict | Nombre |", "|---|---|"]
        lines += [f"| {k} | {n} |" for k, n in sorted(counts.items())]
        lines += ["", "| Scénario | Verdict | Note |", "|---|---|---|"]
        for nid, v in verdicts.items():
            note = self.known.get(nid, "")
            if any(k == "lab_restarted" and val for k, val in self.props.get(nid, [])):
                note = (note + " ; " if note else "") + "lab redémarré après ce scénario"
            lines.append(f"| `{nid}` | {v} | {note} |")
        failed = [n for n, v in verdicts.items() if v in ("regression", "known_failure")]
        if failed:
            lines += ["", "## Détails des échecs", ""]
            for nid in failed:
                lines += [f"### `{nid}` ({verdicts[nid]})", "", "```", self.details.get(nid, ""), "```", ""]
        return "\n".join(lines) + "\n"


def pytest_configure(config):
    config.pluginmanager.register(Verdicts(config), "verdicts")
