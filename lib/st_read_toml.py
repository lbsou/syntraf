from lib.st_global import DefaultValues
from lib.st_logging import *
import pathlib
import toml
import logging
import sys
log = logging.getLogger(__name__)


#################################################################################
### READ CONFIG FILE
#################################################################################
def read_conf(config_file):
    p = pathlib.Path(config_file)
    if not p.is_file():
        log.error(f"IS CONFIG FILE {p.absolute()} EXIST : NO")
        return False, None

    # Reading TOML config file
    try:
        config = toml.load(p, _dict=dict)

    except toml.TomlDecodeError as err:
        log.error(f"IS CONFIG FILE {p.absolute()} DECODING SUCCESSFUL : NO")
        log.error(f"{err}")
        return False, None
    except TypeError as err:
        log.error(f"IS CONFIG FILE {p.absolute()} DECODING SUCCESSFUL : NO")
        log.error(f"{err}")
        return False, None
    return True, config


#################################################################################
### READ TOML
#################################################################################
def read_toml(config_file_path):
    p = pathlib.Path(config_file_path)
    if not p.is_file():
        log.error(f"UNABLE TO OPEN '{p.absolute()}', FILE DOES NOT EXIST")
        return False
    try:
        config = toml.load(p, _dict=dict)
    except toml.TomlDecodeError as err:
        log.error(f"DECODING OF FILE '{p.absolute()}' FAILED")
        log.error(f"{err}")
        return False
    except TypeError as err:
        log.error(f"DECODING OF FILE '{p.absolute()}' FAILED")
        log.error(f"{err}")
        return False
    return config


#################################################################################
### WRITE TOML
#################################################################################
def write_toml(config, config_file_path):
    p = pathlib.Path(config_file_path)
    if not p.is_file():
        log.error(f"UNABLE TO OPEN '{p.absolute()}', FILE DOES NOT EXIST")
        return False
    try:
        with open(p, "w") as toml_file:
            toml.dump(config, toml_file)
    except TypeError as err:
        log.error(f"AN ERROR OCCURED WHILE WRITING CONFIG TO FILE '{p.absolute()}'")
        log.error(f"{err}")
        return False
    return True