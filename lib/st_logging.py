from lib.st_global import DefaultValues
import pathlib
import sys
import logging
import logging.config
import os

log = logging.getLogger("syntraf." + __name__)


# DEBUG < INFO < WARNING < ERROR < CRITICAL
#################################################################################
###  LOGGING INIT
#################################################################################

# Initializing logs
def log_init(results, config={}):
    logto = DefaultValues.DEFAULT_LOG_TO
    level = DefaultValues.DEFAULT_LOG_LEVEL
    level_int = DefaultValues.DEFAULT_LOG_LEVEL_INT
    logmaxsizeperfile = DefaultValues.DEFAULT_LOG_MAX_SIZE_PER_FILE_MB * 1024 * 1024
    logfiletokeep = DefaultValues.DEFAULT_LOG_FILE_TO_KEEP

    # Setting LOG DESTINATION
    if "LOG_TO" in config['GLOBAL']:
        if isinstance(config['GLOBAL']['LOG_TO'], str):
            if config['GLOBAL']['LOG_TO'].lower() in ["stdout", "file", "all"]:
                logto = config['GLOBAL']['LOG_TO'].lower()
            else:
                log.info(f"LOG_TO NOT DEFINED, APPLYING DEFAULT '{DefaultValues.DEFAULT_LOG_TO}'")
        else:
            log.error(f"LOG_LEVEL IS NOT A STRING, PLEASE FIX THE CONFIGURATION FILE. MAYBE ADD QUOTE?")
            sys.exit()
    else:
        log.info(f"LOG_TO NOT DEFINED, APPLYING DEFAULT '{DefaultValues.DEFAULT_LOG_TO}'")

    # Setting LOG LEVEL
    if "LOG_LEVEL" in config['GLOBAL']:
        if isinstance(config['GLOBAL']['LOG_LEVEL'], str):
            if config['GLOBAL']['LOG_LEVEL'].lower() in ["debug", "info", "warning", "error", "critical"]:
                level = config['GLOBAL']['LOG_LEVEL'].lower()
            else:
                log.info(f"LOG_LEVEL NOT DEFINED, APPLYING DEFAULT '{DefaultValues.DEFAULT_LOG_LEVEL}'")
        else:
            log.error(f"LOG_LEVEL IS NOT A STRING, PLEASE FIX THE CONFIGURATION FILE. MAYBE ADD QUOTE?")
            sys.exit()
    else:
        log.info(f"LOG_LEVEL NOT DEFINED, APPLYING DEFAULT '{DefaultValues.DEFAULT_LOG_LEVEL}'")

    if config['GLOBAL']['LOG_LEVEL'].lower() == "critical":
        level_int = logging.CRITICAL
    elif config['GLOBAL']['LOG_LEVEL'].lower() == "error":
        level_int = logging.ERROR
    elif config['GLOBAL']['LOG_LEVEL'].lower() == "warning":
        level_int = logging.WARNING
    elif config['GLOBAL']['LOG_LEVEL'].lower() == "info":
        level_int = logging.INFO
    elif config['GLOBAL']['LOG_LEVEL'].lower() == "debug":
        level_int = logging.DEBUG

    # Setting LOG_MAX_SIZE_PER_FILE_MB
    if "LOG_MAX_SIZE_PER_FILE_MB" in config['GLOBAL']:
        if isinstance(config['GLOBAL']['LOG_MAX_SIZE_PER_FILE_MB'], str):
            if config['GLOBAL']['LOG_MAX_SIZE_PER_FILE_MB'].isdigit():
                if 1 <= int(config['GLOBAL']['LOG_MAX_SIZE_PER_FILE_MB']) <= 100:
                    logmaxsizeperfile = int(config['GLOBAL']['LOG_MAX_SIZE_PER_FILE_MB'])  * 1024 * 1024
                else:
                    log.info(
                        f"LOG_MAX_SIZE_PER_FILE_MB NOT DEFINED, APPLYING DEFAULT '{DefaultValues.DEFAULT_LOG_MAX_SIZE_PER_FILE_MB}'")
            else:
                log.error(f"LOG_MAX_SIZE_PER_FILE_MB IS NOT AN INT, PLEASE FIX THE CONFIGURATION FILE.")
                sys.exit()
        else:
            log.error(f"LOG_MAX_SIZE_PER_FILE_MB IS NOT AN INT, PLEASE FIX THE CONFIGURATION FILE.")
            sys.exit()
    else:
        log.info(
            f"LOG_MAX_SIZE_PER_FILE_MB NOT DEFINED, APPLYING DEFAULT '{DefaultValues.DEFAULT_LOG_MAX_SIZE_PER_FILE_MB}'")

    # Setting LOG_FILE_TO_KEEP
    if "LOG_FILE_TO_KEEP" in config['GLOBAL']:
        if isinstance(config['GLOBAL']['LOG_FILE_TO_KEEP'], str):
            if config['GLOBAL']['LOG_FILE_TO_KEEP'].isdigit():
                if 1 <= int(config['GLOBAL']['LOG_FILE_TO_KEEP']) <= 50:
                    logfiletokeep = int(config['GLOBAL']['LOG_FILE_TO_KEEP'])
                else:
                    log.info(f"LOG_FILE_TO_KEEP NOT DEFINED, APPLYING DEFAULT '{DefaultValues.DEFAULT_LOG_FILE_TO_KEEP}'")
            else:
                log.error(f"LOG_FILE_TO_KEEP IS NOT AN INT, PLEASE FIX THE CONFIGURATION FILE.")
                sys.exit()
        else:
            log.error(f"LOG_FILE_TO_KEEP IS NOT AN INT, PLEASE FIX THE CONFIGURATION FILE.")
            sys.exit()
    else:
        log.info(
            f"LOG_FILE_TO_KEEP NOT DEFINED, APPLYING DEFAULT '{DefaultValues.DEFAULT_LOG_FILE_TO_KEEP}'")

    p = pathlib.Path(results.log_dir)
    if p.is_dir():
        log_file = os.path.join(str(p), DefaultValues.DEFAULT_LOG_FILENAME)
    else:
        print(f"IS LOG DIR {p.absolute()} EXIST : NO")
        sys.exit()

    syntraf = conf_logging("syntraf", log_file, level, level_int, logto, logmaxsizeperfile, logfiletokeep)
    log.debug(f"LOG LEVEL IS SET TO '{level.upper()}', with a maximum size per file of {config['GLOBAL']['LOG_MAX_SIZE_PER_FILE_MB']}MB and maximum of {logfiletokeep} file on rotation")

# def set_log_level(config):
#     try:
#         for name in logging.root.manager.loggerDict:
#             logger = logging.getLogger(name)
#
#             log.info(f"LOG_TO SET TO '{config['GLOBAL']['LOG_TO'].lower()}', APPLYING VALUE TO LOGGER '{name}'")
#
#             # Setting LOGLEVEL
#             if "LOG_LEVEL" in config['GLOBAL']:
#                     if config['GLOBAL']['LOG_LEVEL'].lower() in ["debug", "info", "warning", "error", "critical"]:
#                         if config['GLOBAL']['LOG_LEVEL'].lower() == "critical":
#                             logger.setLevel(logging.CRITICAL)
#                         elif config['GLOBAL']['LOG_LEVEL'].lower() == "error":
#                             logger.setLevel(logging.ERROR)
#                         elif config['GLOBAL']['LOG_LEVEL'].lower() == "warning":
#                             logger.setLevel(logging.WARNING)
#                         elif config['GLOBAL']['LOG_LEVEL'].lower() == "info":
#                             logger.setLevel(logging.INFO)
#                         elif config['GLOBAL']['LOG_LEVEL'].lower() == "debug":
#                             logger.setLevel(logging.DEBUG)
#                     else:
#                         log.info(
#                             f"LOGLEVEL '{config['GLOBAL']['LOG_LEVEL']}' NOT VALID, APPLYING DEFAULT '{DefaultValues.DEFAULT_LOG_LEVEL}' TO LOGGER '{name}'")
#                         logger.setLevel(DefaultValues.DEFAULT_LOG_LEVEL)
#             else:
#                 log.info(f"LOGLEVEL NOT DEFINED, APPLYING DEFAULT '{DefaultValues.DEFAULT_LOG_LEVEL}' TO LOGGER '{name}'")
#                 logger.setLevel(DefaultValues.DEFAULT_LOG_LEVEL)
#
#     except Exception as e:
#         log.error(f"main:loglevel:{type(e).__name__}:{e}")
#         return False
#
#     return True

#################################################################################
###  LOGGING CONFIG
#################################################################################
def conf_logging(name, log_file, level, level_int, logto, logmaxsizeperfile, logfiletokeep):
    # OCD display
    padding = (25 - len(name)) * " "

    log_dict_config = {}
    log_dict_config['version'] = 1
    log_dict_config['disable_existing_loggers'] = False
    log_dict_config['formatters'] = {
        f'formatter_for_{name}': {
            'format': ' %(asctime)s - %(levelname)s - ' + '%(module)s (%(funcName)s,%(lineno)d) - %(message)s',
            'datefmt': '%Y-%m-%d %H:%M:%S'}
    }
    log_dict_config['handlers'] = {
        f'console_for_{name}': {
            'level': f'{level.upper()}',
            'class': 'logging.StreamHandler',
            'formatter': f'formatter_for_{name}',
            'stream': 'ext://sys.stdout'
        },
        f'file_for_{name}': {
            'level': f'{level.upper()}',
            'class': 'logging.handlers.RotatingFileHandler',
            'formatter': f'formatter_for_{name}',
            'filename': log_file,
            'maxBytes': logmaxsizeperfile,
            'backupCount': logfiletokeep
        }
    }

    if logto == "all":
        log_dict_config['loggers'] = {
            name: {
                'level': level_int,
                'handlers': [f'console_for_{name}', f'file_for_{name}']
            }}
    elif logto == "file":
        log_dict_config['loggers'] = {
            name: {
                'level': level_int,
                'handlers': [f'file_for_{name}']
            }}
    elif logto == "stdout":
        log_dict_config['loggers'] = {
            name: {
                'level': level_int,
                'handlers': [f'console_for_{name}']
            }}

    logging.config.dictConfig(log_dict_config)

    return logging.getLogger(name)
