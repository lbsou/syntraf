"""Connexions au canal de contrôle coupées avant toute authentification.

Une sonde qui ne reconnaît pas la clé du serveur (serveur réinstallé : nouvelle clé, la sonde a mémorisé l'ancienne)
raccroche juste après la poignée de main TLS, sans rien envoyer, puis recommence toutes les 10 s. Le serveur ne
voyait que « CONNECTION RESET BY PEER » ; aucune demande d'inscription n'apparaissait. Répété depuis une même
adresse, c'est signalé : dans le journal (avec la marche à suivre) et dans l'interface (Configuration › Clients).
"""
import datetime as dt
import threading

WINDOW_S = 600        # coupures comptées sur les 10 dernières minutes
MIN_DROPS = 3         # en dessous : une coupure réseau ordinaire
WARN_EVERY_S = 600    # journal : au plus une fois toutes les 10 minutes par adresse


def _iso(t):
    return dt.datetime.fromtimestamp(t, dt.timezone.utc).isoformat(timespec="seconds")


def hint(ip):
    return (f"{ip} CONNECTS AND HANGS UP BEFORE AUTHENTICATING, AGAIN AND AGAIN: IF IT IS A SYNTRAF PROBE, IT DOES "
            f"NOT RECOGNIZE THIS SERVER'S KEY (SERVER REINSTALLED?). ON THE PROBE, RUN ITS INSTALLER AGAIN WITH "
            f"--server AND --token (THE TOKEN OF THIS SERVER), OR DELETE syntraf_server_pin NEXT TO ITS CONFIGURATION "
            f"AND RESTART IT")


class PreauthDrops:
    def __init__(self):
        self.lock = threading.Lock()
        self.by_ip = {}

    def record(self, ip, now):
        """Une connexion de ip coupée avant authentification ; True s'il faut l'écrire dans le journal."""
        with self.lock:
            r = self.by_ip.setdefault(ip, {"times": [], "warned": None})
            r["times"] = [t for t in r["times"] if now - t <= WINDOW_S] + [now]
            if len(r["times"]) < MIN_DROPS:
                return False
            if r["warned"] is None or now - r["warned"] >= WARN_EVERY_S:
                r["warned"] = now
                return True
            return False

    def forget(self, ip):
        """L'adresse s'est identifiée (accepté, refusé ou en attente) : ce n'est plus ce problème."""
        with self.lock:
            self.by_ip.pop(ip, None)

    def recent(self, now):
        with self.lock:
            out = []
            for ip, r in self.by_ip.items():
                times = [t for t in r["times"] if now - t <= WINDOW_S]
                if len(times) >= MIN_DROPS:
                    out.append({"IP_ADDRESS": ip, "ATTEMPTS": len(times), "FIRST_SEEN": _iso(times[0]),
                                "LAST_SEEN": _iso(times[-1])})
            return sorted(out, key=lambda r: r["LAST_SEEN"], reverse=True)


DROPS = PreauthDrops()
