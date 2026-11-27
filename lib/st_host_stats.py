"""Charge du poste de chaque sonde : CPU, mémoire, carte réseau.

La sonde mesure son poste en continu (lib/st_system_stats.py) et l'envoie au serveur sur le canal de contrôle
(SAVE_STATS_METRIC). Le serveur en garde la dernière valeur par sonde ; elle est publiée sur /metrics (historisée par
VictoriaMetrics, tableaux de bord Grafana) et affichée sur la carte en direct, pour relier une perte à un poste
surchargé.

Bibliothèque standard uniquement.
"""
import math
import time

MAX_AGE_S = 60  # au-delà, la valeur n'est plus celle du moment : ni publiée, ni affichée
FIELDS = ("cpu_pct", "cpu_busiest_core_pct", "mem_used_pct", "nic_rx_bps", "nic_tx_bps", "nic_speed_mbps",
          "nic_rx_pct", "nic_tx_pct")


def _pct(value):
    """Un pourcentage borné à [0, 100], ou None (absent, texte d'erreur de la sonde, NaN)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        return None
    return round(min(100.0, max(0.0, float(value))), 1)


def _positive(value):
    """Un nombre positif (débit, vitesse de carte), ou None."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        return None
    return value


def from_payload(payload) -> dict:
    """Valeurs d'un SAVE_STATS_METRIC.

    Sondes 0.45.42 et plus : cpu_pct (moyenne des cœurs), débit réel de la carte (nic_rx_bps, nic_tx_bps) et son
    débit nominal (nic_speed_mbps, None si le système l'ignore : la part en % est alors inconnue, pas 0).
    Toutes versions : cpu_pct_usage (cœur le plus chargé), if_pct_usage_rx/tx (part du débit de la carte, 0 quand il
    est inconnu, mesurée sur 0,1 s)."""
    p = payload if isinstance(payload, dict) else {}
    free = _pct(p.get("mem_pct_free"))
    rx, tx, speed = _positive(p.get("nic_rx_bps")), _positive(p.get("nic_tx_bps")), _positive(p.get("nic_speed_mbps")) or None
    if "nic_rx_bps" in p:  # sonde récente : la part se déduit du débit réel, et reste inconnue sans débit de carte
        rx_pct = _pct(rx / (speed * 1e6) * 100) if rx is not None and speed else None
        tx_pct = _pct(tx / (speed * 1e6) * 100) if tx is not None and speed else None
    else:
        rx_pct, tx_pct = _pct(p.get("if_pct_usage_rx")), _pct(p.get("if_pct_usage_tx"))
    nic = p.get("nic")
    return {"cpu_pct": _pct(p.get("cpu_pct")),
            "cpu_busiest_core_pct": _pct(p.get("cpu_pct_usage")),
            "mem_used_pct": None if free is None else round(100.0 - free, 1),
            "nic_rx_bps": None if rx is None else int(rx), "nic_tx_bps": None if tx is None else int(tx),
            "nic_speed_mbps": speed, "nic_rx_pct": rx_pct, "nic_tx_pct": tx_pct,
            "nic": str(nic)[:64] if isinstance(nic, str) and nic else None}


def record(obj_client, payload, now=None):
    """Retient la dernière charge reçue de cette sonde (heure du serveur : l'horloge de la sonde peut dériver)."""
    obj_client.host_stats = dict(from_payload(payload), at=time.time() if now is None else now)


def latest(obj_client, now=None, max_age=MAX_AGE_S):
    """Dernière charge de la sonde si elle est connectée et la valeur récente : {champ: valeur, age_s} ; sinon None."""
    if obj_client is None or not str(getattr(obj_client, "status", "")).startswith("CONNECTED"):
        return None
    stats = getattr(obj_client, "host_stats", None)
    if not stats:
        return None
    age = (time.time() if now is None else now) - stats.get("at", 0)
    if age > max_age:
        return None
    values = {k: stats.get(k) for k in FIELDS}
    if all(v is None for v in values.values()):
        return None
    return dict(values, nic=stats.get("nic"), age_s=round(max(0.0, age), 1))
