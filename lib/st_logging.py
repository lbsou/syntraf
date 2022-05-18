from lib.st_global import DefaultValues
import pathlib
import sys
import logging
import logging.config
import os
log = logging.getLogger(__name__)


# DEBUG < INFO < WARNING < ERROR < CRITICAL
#################################################################################
###  LOGGING INIT
#################################################################################
# Initializing logs
def log_init(results):
    p = pathlib.Path(results.log_dir)
    if p.is_dir():
        st_system_stats = conf_logging("lib.st_system_stats", os.path.join(str(p), "lib.st_system_stats.log"))
        st_webui = conf_logging("lib.st_webui",os.path.join(str(p), "lib.st_webui.log"))
        iperf3_connectors_log = conf_logging("lib.st_iperf3_connectors", os.path.join(str(p), "lib.st_iperf3_connectors.log"))
        iperf3_listeners_log = conf_logging("lib.st_iperf3_listeners", os.path.join(str(p), "lib.st_iperf3_listeners.log"))
        map = conf_logging("lib.map", os.path.join(str(p), "lib.st_map.log"))
        server_log = conf_logging("lib.st_server", os.path.join(str(p), "lib.st_server.log"))
        client_log = conf_logging("lib.st_client", os.path.join(str(p), "lib.st_client.log"))
        st_influxdb = conf_logging("lib.st_influxdb", os.path.join(str(p), "lib.st_influxdb.log"))
        st_crypto = conf_logging("lib.st_crypto", os.path.join(str(p), "lib.st_crypto.log"))
        st_iperf3_readlog = conf_logging("lib.st_iperf3_readlog", os.path.join(str(p), "lib.st_iperf3_readlog.log"))
        st_read_toml = conf_logging("lib.st_read_toml", os.path.join(str(p), "lib.st_read_toml.log"))
        st_logging = conf_logging("lib.st_logging", os.path.join(str(p), "lib.st_logging.log"))
        st_process_and_thread = conf_logging("lib.st_process_and_thread", os.path.join(str(p), "lib.st_process_and_thread.log"))
        st_conf_validation = conf_logging("lib.st_conf_validation", os.path.join(str(p), "lib.st_conf_validation.log"))
        syntraf = conf_logging("__main__", os.path.join(str(p), "syntraf.log"))
        st_covariance = conf_logging("lib.st_covariance", os.path.join(str(p), "lib.st_covariance.log"))
    else:
        print(f"IS LOG DIR {p.absolute()} EXIST : NO")
        sys.exit()


def set_log_level(config):
    try:
        for name in logging.root.manager.loggerDict:
            logger = logging.getLogger(name)

            # Setting LOGLEVEL
            if "LOG_LEVEL" in config['GLOBAL']:
                    if config['GLOBAL']['LOG_LEVEL'].lower() in ["debug", "info", "warning", "error", "critical"]:
                        if config['GLOBAL']['LOG_LEVEL'].lower() == "critical":
                            logger.setLevel(logging.CRITICAL)
                        elif config['GLOBAL']['LOG_LEVEL'].lower() == "error":
                            logger.setLevel(logging.ERROR)
                        elif config['GLOBAL']['LOG_LEVEL'].lower() == "warning":
                            logger.setLevel(logging.WARNING)
                        elif config['GLOBAL']['LOG_LEVEL'].lower() == "info":
                            logger.setLevel(logging.INFO)
                        elif config['GLOBAL']['LOG_LEVEL'].lower() == "debug":
                            logger.setLevel(logging.DEBUG)
                    else:
                        log.info(
                            f"LOGLEVEL '{config['GLOBAL']['LOG_LEVEL']}' NOT VALID, APPLYING DEFAULT '{DefaultValues.DEFAULT_LOG_LEVEL}' TO LOGGER '{name}'")
                        logger.setLevel(DefaultValues.DEFAULT_LOG_LEVEL)
            else:
                log.info(f"LOGLEVEL NOT DEFINED, APPLYING DEFAULT '{DefaultValues.DEFAULT_LOG_LEVEL}' TO LOGGER '{name}'")
                logger.setLevel(DefaultValues.DEFAULT_LOG_LEVEL)

    except Exception as e:
        log.error(f"main:loglevel:{type(e).__name__}:{e}")
        return False

    return True


#################################################################################
###  LOGGING CONFIG
#################################################################################
def conf_logging(name, log_file):
    # OCD display
    padding = (25-len(name)) * " "
    logging.config.dictConfig({
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            f'formatter_for_{name}': {'format': ' %(asctime)s - ' + name.upper() + padding + ' - %(levelname)s - %(message)s',
                                      'datefmt': '%Y-%m-%d %H:%M:%S'}
        },
        'handlers': {
            f'console_for_{name}': {
                'level': 'DEBUG',
                'class': 'logging.StreamHandler',
                'formatter': f'formatter_for_{name}',
                'stream': 'ext://sys.stdout'
            },
            f'file_for_{name}': {
                'level': 'DEBUG',
                'class': 'logging.handlers.RotatingFileHandler',
                'formatter': f'formatter_for_{name}',
                'filename': log_file,
                'maxBytes': DefaultValues.DEFAULT_LOGGING_MAX_SIZE_PER_FILE,
                'backupCount': 1
            }
        },
        'loggers': {
            name: {
                'level': logging.DEBUG,
                'handlers': [f'console_for_{name}', f'file_for_{name}']
            }
        }
    })
    return logging.getLogger(name)
