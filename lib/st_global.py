# BUILTIN IMPORT
import os
import pathlib
import logging

log = logging.getLogger("syntraf." + __name__)

try:
    from tzlocal import get_localzone
except Exception as ex:
    print("MISSING MODULE: no module named 'tzlocal'")
    exit()


# Will impact the requirement of modules
class CompilationOptions:
    client_only = False


class DefaultValues:
    # GLOBAL
    SYNTRAF_VERSION = "0.45"
    SYNTRAF_ROOT_DIR = pathlib.Path(__file__).parent.parent.absolute()
    SYNTRAF_PID_FILE = os.path.join(SYNTRAF_ROOT_DIR, 'syntraf.pid')

    try:
        TIMEZONE = str(get_localzone())
    except Exception as exc:
        log.error(f"st_global:{type(exc).__name__}:{exc}", exc_info=True)

    # DATABASE
    DEFAULT_INFLUXDB_USE_SSL = True
    DEFAULT_WRITE_QUEUE_BUFFER_DEPTH = 86_400
    DEFAULT_DB_CONNECTION_POOL_MAXSIZE = 100
    DEFAULT_FORWARD_METRIC_TO_SERVER = True

    # CONTROL CHANNEL
    DEFAULT_SERVER_POOL_SIZE = 1_000
    DEFAULT_SERVER_X509_SELFSIGNED_DIRECTORY = os.path.join(SYNTRAF_ROOT_DIR, "crypto",
                                                            "SERVER_X509_SELFSIGNED_DIRECTORY")
    DEFAULT_CLIENT_X509_SELFSIGNED_DIRECTORY = os.path.join(SYNTRAF_ROOT_DIR, "crypto",
                                                            "CLIENT_X509_SELFSIGNED_DIRECTORY")
    DEFAULT_WEBUI_X509_SELFSIGNED_DIRECTORY = os.path.join(SYNTRAF_ROOT_DIR, "crypto", "WEBUI_X509_SELFSIGNED_DIRECTORY")
    DEFAULT_SERVER_PORT = "6531"
    DEFAULT_KEY_SIZE = 2_048
    DEFAULT_CLIENT_METRICS_QUEUE_SIZE = 86_400
    DEFAULT_CLIENT_METRICS_UPDATE_FREQUENCY = 1
    CONTROL_CHANNEL_HEARTBEAT = 1

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
    DEFAULT_IPERF3_RSA_KEY_DIRECTORY = os.path.join(SYNTRAF_ROOT_DIR, "crypto", "rsa_key_iperf3")
    #DEFAULT_IPERF3_TEMP_DIRECTORY = os.path.join(SYNTRAF_ROOT_DIR, "iperf3_temp")
    DEFAULT_IPERF3_TIME_SKEW_THRESHOLD = "10"

    # Timeout for control connection setup (ms)
    DEFAULT_IPERF3_CONNECT_TIMEOUT = "1000"
    DEFAULT_IPERF3_AUTH = True

    # Restart idle server after # seconds in case it got stuck
    DEFAULT_IPERF3_SERVER_IDLE_TIMEOUT = "300"

    # Handle one client connection then exit
    DEFAULT_IPERF3_SERVER_ONE_OFF = True

    # Set timeout for receiving data during active tests (ms)
    DEFAULT_IPERF3_RCV_TIMEOUT = "5000"

    # LOGGING
    DEFAULT_LOG_MAX_SIZE_PER_FILE_MB = 20_485_760
    DEFAULT_LOG_LEVEL_INT = 20  # logging.INFO
    DEFAULT_LOG_LEVEL = "INFO"
    DEFAULT_LOG_TO = "file"
    DEFAULT_LOG_FILENAME = "syntraf.log"
    DEFAULT_LOG_FILE_TO_KEEP = 2
    DEFAULT_LOG_PURGE_ON_START = False

    # SERVER_MAX_CONNECTION = 50
