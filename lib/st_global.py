# BUILTIN IMPORT
import datetime as _dt
import os
import pathlib
import logging

log = logging.getLogger("syntraf." + __name__)


def local_timezone_name():
    """Nom du fuseau horaire local (affichage) : TZ, sinon /etc/localtime (Linux), sinon le nom court du système."""
    tz = os.environ.get("TZ", "").lstrip(":")
    if tz:
        return tz
    try:
        target = os.path.realpath("/etc/localtime")
        if "zoneinfo/" in target:
            return target.split("zoneinfo/", 1)[1]
    except OSError:
        pass
    try:
        with open("/etc/timezone", encoding="utf-8") as f:
            name = f.read().strip()
            if name:
                return name
    except OSError:
        pass
    return _dt.datetime.now().astimezone().tzname() or "UTC"


SERVER_PACKAGES = ("flask", "gevent", "influxdb_client")


def _available(name):
    try:
        import importlib.util
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def missing_server_parts():
    """Ce qui manque pour faire tourner un serveur : l'interface web (absente de la release des sondes) ou les
    paquets du serveur (une sonde installée depuis le dépôt n'a que requirements_client.txt)."""
    missing = [] if (pathlib.Path(__file__).parent / "web_ui_kindafixed2").is_dir() else ["web interface"]
    return missing + [name for name in SERVER_PACKAGES if not _available(name)]


class CompilationOptions:
    # Sonde légère : sans l'interface web ou sans les paquets du serveur (Flask, gevent, client InfluxDB), ce qui
    # n'est utile qu'au serveur n'est pas importé.
    client_only = bool(missing_server_parts())


class DefaultValues:
    # GLOBAL
    SYNTRAF_VERSION = "0.45.27"
    SYNTRAF_ROOT_DIR = pathlib.Path(__file__).parent.parent.absolute()  # code de la version qui tourne
    # Données (clés, état) : dans l'installation en place, même quand une release installée à distance tourne
    # (st_updater la désigne par SYNTRAF_BASE_DIR) ; sinon l'identité du client changerait à chaque mise à jour.
    SYNTRAF_DATA_DIR = pathlib.Path(os.environ.get("SYNTRAF_BASE_DIR") or SYNTRAF_ROOT_DIR).absolute()
    SYNTRAF_PID_FILE = os.path.join(SYNTRAF_DATA_DIR, 'syntraf.pid')
    SYNTRAF_PROC_DIR = os.path.join(SYNTRAF_DATA_DIR, "proc")

    TIMEZONE = local_timezone_name()

    # DATABASE
    DEFAULT_INFLUXDB_USE_SSL = True
    DEFAULT_WRITE_QUEUE_BUFFER_DEPTH = 86_400
    DEFAULT_DB_CONNECTION_POOL_MAXSIZE = 100
    DEFAULT_FORWARD_METRIC_TO_SERVER = True
    DEFAULT_INFLUXDB_DB_MODE = "OSS"

    # CONTROL CHANNEL
    DEFAULT_SERVER_POOL_SIZE = 1_000
    DEFAULT_SERVER_X509_SELFSIGNED_DIRECTORY = os.path.join(SYNTRAF_DATA_DIR, "crypto",
                                                            "SERVER_X509_SELFSIGNED_DIRECTORY")
    DEFAULT_CLIENT_X509_SELFSIGNED_DIRECTORY = os.path.join(SYNTRAF_DATA_DIR, "crypto",
                                                            "CLIENT_X509_SELFSIGNED_DIRECTORY")
    DEFAULT_WEBUI_X509_SELFSIGNED_DIRECTORY = os.path.join(SYNTRAF_DATA_DIR, "crypto", "WEBUI_X509_SELFSIGNED_DIRECTORY")
    DEFAULT_SERVER_PORT = "6531"
    DEFAULT_KEY_SIZE = 2_048
    DEFAULT_CLIENT_METRICS_QUEUE_SIZE = 86_400
    # Mesures par message SAVE_METRIC : un arriéré part par lots (un message de 86 400 mesures faisait tomber le serveur
    # et VictoriaMetrics faute de mémoire, et ne passait pas un lien lent dans le délai du canal de contrôle)
    CLIENT_METRICS_PER_MESSAGE = 2_000
    DEFAULT_CLIENT_METRICS_UPDATE_FREQUENCY = 1
    CONTROL_CHANNEL_HEARTBEAT = 1
    # A peer silent for this long is considered gone (the client sends a heartbeat every second)
    CONTROL_CHANNEL_TIMEOUT = 15
    CONTROL_CHANNEL_CONNECT_TIMEOUT = 5
    # A disconnected dynamic-IP client's IP is forgotten only if it is not back within this delay (seconds)
    DYNAMIC_IP_FORGET_GRACE = 60

    # WEBUI
    DEFAULT_WEBUI_UPLOAD_BG_FOLDER = "uploaded_background"
    DEFAULT_WEBUI_ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    DEFAULT_WEBUI_PORT = 5000

    # IPERF3
    DEFAULT_DSCP = "0"
    DEFAULT_PACKET_SIZE = 32
    DEFAULT_INTERVAL = "1"
    DEFAULT_BANDWIDTH = "100k"
    DEFAULT_PORT_RANGE = "15000-16000"
    DEFAULT_IPERF3_RSA_KEY_DIRECTORY = os.path.join(SYNTRAF_DATA_DIR, "crypto", "rsa_key_iperf3")
    #DEFAULT_IPERF3_TEMP_DIRECTORY = os.path.join(SYNTRAF_ROOT_DIR, "iperf3_temp")
    DEFAULT_IPERF3_TIME_SKEW_THRESHOLD = "10"

    # Timeout for control connection setup (ms)
    # Secondes (GLOBAL.IPERF3_CONNECT_TIMEOUT, 1 à 60) ; 1 s faisait échouer les liens à pertes (SYN retransmis après 1 s)
    DEFAULT_IPERF3_CONNECT_TIMEOUT = "5"
    # Latence aller-retour entre sondes (TWAMP-Light, lib/st_twamp.py) : réflecteur UDP sur ce port
    DEFAULT_LATENCY = True
    DEFAULT_LATENCY_PORT = "8620"
    DEFAULT_IPERF3_AUTH = True

    # Restart idle server after # seconds in case it got stuck
    DEFAULT_IPERF3_SERVER_IDLE_TIMEOUT = "300"

    # Handle one client connection then exit
    DEFAULT_IPERF3_SERVER_ONE_OFF = True

    # Set timeout for receiving data during active tests (ms)
    DEFAULT_IPERF3_RCV_TIMEOUT = "5000"

    # LOGGING
    DEFAULT_LOG_MAX_SIZE_PER_FILE_MB = 20  # Mo (était 20 485 760 : des fichiers de ~20 To avant rotation)
    DEFAULT_LOG_LEVEL_INT = 20  # logging.INFO
    DEFAULT_LOG_LEVEL = "INFO"
    DEFAULT_LOG_TO = "file"
    DEFAULT_LOG_FILENAME = "syntraf.log"
    DEFAULT_LOG_FILE_TO_KEEP = 2
    DEFAULT_LOG_PURGE_ON_START = False

    # SERVER_MAX_CONNECTION = 50
