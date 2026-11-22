"""Garde-fous de capacité : ce qu'une configuration générée demande aux clients et à la base, comparé aux limites.

Une limite stricte n'est violée que si le changement aggrave l'indicateur concerné : une installation déjà au-delà
peut toujours être modifiée sans grossir. Le seuil d'alerte n'empêche rien : il exige une confirmation explicite.
Module sans dépendance externe.
"""
DEFAULTS = {"MAX_FLOWS_PER_CLIENT": 50, "MAX_TOTAL_FLOWS": 2000, "FLOW_ALERT_ADDED": 100, "FLOW_ALERT_RATIO": 2.0}
MESSAGES = {
    "MAX_FLOWS_PER_CLIENT": "An integer of 1 or more: measurement flows per client in each direction",
    "MAX_TOTAL_FLOWS": "An integer of 1 or more: measurement flows in total",
    "FLOW_ALERT_ADDED": "An integer of 1 or more: flows added by one change before asking for confirmation",
    "FLOW_ALERT_RATIO": "A number of 1 or more: growth factor of the total before asking for confirmation "
                        "(counted once the total exceeds the flows-added threshold)",
}
_UNITS = {"K": 1e3, "M": 1e6, "G": 1e9}


def _bps(value):
    text = str(value or "0").strip().upper()
    try:
        return float(text[:-1]) * _UNITS[text[-1]] if text and text[-1] in _UNITS else float(text)
    except ValueError:
        return 0.0


def limits(server):
    """Limites de la section SERVER, avec leurs valeurs par défaut."""
    out = {}
    for key, default in DEFAULTS.items():
        try:
            out[key] = type(default)(server.get(key, default))
        except (TypeError, ValueError):
            out[key] = default
    return out


def limit_errors(values):
    errors = {}
    for key, default in DEFAULTS.items():
        text = str(values.get(key, "") or "").strip()
        if not text:
            continue
        try:
            ok = type(default)(text) >= 1
        except ValueError:
            ok = False
        if not ok:
            errors[key] = MESSAGES[key]
    return errors


def measure(generated):
    """Flux (connecteurs), listeners, processus iperf3 et débit sortant par client ; total et points par seconde."""
    clients, total, points = {}, 0, 0.0
    for uid, cfg in (generated or {}).items():
        connectors = (cfg or {}).get("CONNECTORS") or {}
        listeners = (cfg or {}).get("LISTENERS") or {}
        clients[uid] = {"connectors": len(connectors), "listeners": len(listeners),
                        "processes": len(connectors) + len(listeners),
                        "kbps_out": sum(_bps(c.get("BANDWIDTH")) for c in connectors.values()) / 1000}
        total += len(connectors)
        points += sum(1 / max(int(c.get("INTERVAL") or 1), 1) for c in connectors.values())
    return {"total_flows": total, "points_per_s": round(points, 1), "clients": clients}


def _flows(entry):
    return max(entry["connectors"], entry["listeners"]) if entry else 0


def assess(before, after, lim):
    """Compare avant et après : violations des limites strictes (si aggravées) et alerte (confirmation requise)."""
    violations = []
    for uid, entry in after["clients"].items():
        flows, was = _flows(entry), _flows(before["clients"].get(uid))
        if flows > lim["MAX_FLOWS_PER_CLIENT"] and flows > was:
            violations.append(f"{uid} would have {flows} flows in each direction ({entry['processes']} iperf3 "
                              f"processes), above the limit of {lim['MAX_FLOWS_PER_CLIENT']} per client")
    if after["total_flows"] > lim["MAX_TOTAL_FLOWS"] and after["total_flows"] > before["total_flows"]:
        violations.append(f"{after['total_flows']} flows in total, above the limit of {lim['MAX_TOTAL_FLOWS']}")
    added = after["total_flows"] - before["total_flows"]
    reasons = []
    if added > lim["FLOW_ALERT_ADDED"]:
        reasons.append(f"{added} flows added (alert above {lim['FLOW_ALERT_ADDED']})")
    # Facteur de croissance : seulement au-delà du seuil « flux ajoutés » (2 → 6 flux sur une petite installation
    # triplerait le total sans rien d'inquiétant)
    if (added > 0 and before["total_flows"] and after["total_flows"] > lim["FLOW_ALERT_ADDED"]
            and after["total_flows"] / before["total_flows"] > lim["FLOW_ALERT_RATIO"]):
        reasons.append(f"total multiplied by {after['total_flows'] / before['total_flows']:.1f} "
                       f"(alert above {lim['FLOW_ALERT_RATIO']:g})")
    busiest = max(after["clients"], key=lambda u: after["clients"][u]["processes"], default=None)
    return {"before": before, "after": after, "added_flows": added, "busiest": busiest, "violations": violations,
            "alert": bool(reasons) and not violations, "alert_reason": "; ".join(reasons), "limits": lim}
