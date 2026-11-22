"""Côté client : les lignes de journal à transmettre au serveur.

Un handler de logging garde les lignes formatées dans un tampon borné ; la boucle de contrôle du client les envoie
au serveur par lots (SAVE_LOGS). Si le serveur est injoignable longtemps, les plus anciennes lignes sont
abandonnées et comptées : le client ne bloque jamais et sa mémoire reste bornée.
"""
import collections
import logging
import threading

LOG_FORMAT = " %(asctime)s - %(levelname)s - %(module)s (%(funcName)s,%(lineno)d) - %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S%z"  # avec le décalage horaire : l'heure se lit sans ambiguïté sur le serveur
DEFAULT_CAPACITY = 5000
DEFAULT_LEVEL = "INFO"
BATCH = 500


class ForwardHandler(logging.Handler):
    def __init__(self, capacity=DEFAULT_CAPACITY, level=logging.INFO):
        super().__init__(level)
        self.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))
        self._lines = collections.deque(maxlen=capacity)
        self._dropped = 0
        self._lock_buffer = threading.Lock()

    def emit(self, record):
        try:
            line = self.format(record)
        except Exception:  # noqa: BLE001 - un message mal formé ne doit pas casser l'application
            return
        with self._lock_buffer:
            if len(self._lines) == self._lines.maxlen:
                self._dropped += 1
            self._lines.append(line)

    def drain(self, max_lines=BATCH):
        """(lignes, nombre de lignes abandonnées depuis le dernier envoi) ; vide le tampon de ces lignes."""
        with self._lock_buffer:
            lines = [self._lines.popleft() for _ in range(min(max_lines, len(self._lines)))]
            dropped, self._dropped = self._dropped, 0
        return lines, dropped

    def set_level_name(self, name):
        level = logging.getLevelName(str(name or DEFAULT_LEVEL).upper())
        self.setLevel(level if isinstance(level, int) else logging.INFO)


HANDLER = None


def install(level_name=DEFAULT_LEVEL, logger_name="syntraf"):
    """Branche (une seule fois) le handler de transmission sur le logger de SYNTRAF ; renvoie le handler."""
    global HANDLER
    if HANDLER is None:
        HANDLER = ForwardHandler()
        logging.getLogger(logger_name).addHandler(HANDLER)
    HANDLER.set_level_name(level_name)
    return HANDLER
