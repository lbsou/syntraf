"""Analyse de séries temporelles de mesures : trous, couverture, moyenne."""
from datetime import datetime, timedelta


def gaps(times: list[datetime], start: datetime, stop: datetime, max_gap_s: float) -> list[tuple[datetime, datetime]]:
    """Intervalles de plus de max_gap_s sans point, bords de fenêtre compris."""
    inside = sorted(t for t in times if start <= t <= stop)
    marks = [start] + inside + [stop]
    out = []
    for a, b in zip(marks, marks[1:]):
        if (b - a).total_seconds() > max_gap_s:
            out.append((a, b))
    return out


def coverage(times: list[datetime], start: datetime, stop: datetime, interval_s: float) -> float:
    """Fraction (0–1) des intervalles de la fenêtre contenant au moins un point."""
    total = int((stop - start).total_seconds() // interval_s)
    if total <= 0:
        return 0.0
    filled = set()
    for t in times:
        if start <= t < stop:
            filled.add(int((t - start).total_seconds() // interval_s))
    return len(filled) / total


def mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0
