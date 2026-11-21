"""Vérifications partagées par les scénarios."""
from datetime import datetime
from typing import Callable

from . import series

REAL_MEASURE_MAX_LOSS = 50.0  # au-delà, le point peut être une perte à 100 % générée par SYNTRAF


def value_coverage(points: list[tuple[datetime, float]], start: datetime, stop: datetime,
                   pred: Callable[[float], bool], interval_s: float = 1) -> float:
    return series.coverage([t for t, v in points if pred(v)], start, stop, interval_s)


def not_recovered(metrics, flows: list[str], since: datetime, until: datetime) -> list[str]:
    """Flux sans aucune vraie mesure (pertes < 50 %) entre since et until."""
    out = []
    for f in flows:
        if not any(v < REAL_MEASURE_MAX_LOSS for _t, v in metrics.points(f, since, until)):
            out.append(f)
    return out


def within_pct(value: float, reference: float, pct: float) -> bool:
    if reference == 0:
        return value == 0
    return abs(value - reference) <= abs(reference) * pct / 100


def assert_no_problems(problems: dict) -> None:
    """Échoue en affichant tous les écarts (pytest tronque les grands dictionnaires)."""
    if problems:
        from pprint import pformat
        raise AssertionError(f"{len(problems)} écart(s) :\n{pformat(problems, width=120)}")
