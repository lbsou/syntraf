from lib.st_global import DefaultValues
from lib.st_logging import *
import pathlib
import toml
import logging
import sys
log = logging.getLogger("syntraf." + __name__)


#################################################################################
### NORMALIZE PEM KEY STRINGS
#################################################################################
def normalize_pem_string(value):
    """
    Clean up PEM key strings that may have been saved as bytes representation.
    Converts strings like "b'-----BEGIN...\\n...-----END...\\n'" to proper PEM format.
    """
    if not isinstance(value, str):
        return value

    # Check if it's a bytes representation string
    if value.startswith("b'") and value.endswith("'"):
        # Remove b' prefix and trailing '
        value = value[2:-1]
        # Replace escaped newlines with actual newlines
        value = value.replace('\\n', '\n')
    elif value.startswith('b"') and value.endswith('"'):
        # Handle double-quoted variant
        value = value[2:-1]
        value = value.replace('\\n', '\n')

    return value


def normalize_config_keys(config):
    """
    Walk through config and normalize any PEM key strings.
    """
    # Keys that should be normalized
    pem_keys = {'PUBLIC_KEY', 'RSA_KEY_LISTENERS', 'RSA_KEY_CONNECTORS',
                'SERVER_X509_PRIVATE_KEY_CONTENT', 'SERVER_X509_CERTIFICATE_CONTENT',
                'CLIENT_X509_PRIVATE_KEY_CONTENT', 'CLIENT_X509_CERTIFICATE_CONTENT'}

    def normalize_dict(d):
        for key, value in d.items():
            if isinstance(value, dict):
                normalize_dict(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        normalize_dict(item)
            elif key in pem_keys and isinstance(value, str):
                d[key] = normalize_pem_string(value)

    if isinstance(config, dict):
        normalize_dict(config)

    return config


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
        # Normalize any PEM key strings that may have bytes representation
        config = normalize_config_keys(config)

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
        # Normalize any PEM key strings that may have bytes representation
        config = normalize_config_keys(config)
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