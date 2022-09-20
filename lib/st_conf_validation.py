# SYNTRAF GLOBAL IMPORT
from lib.st_global import CompilationOptions, DefaultValues
from lib.st_crypto import *
from lib.st_read_toml import *
from lib.st_influxdb import *
from lib.st_obj_mesh import *
from lib.st_map import *

# SYNTRAF SERVER IMPORT
if not CompilationOptions.client_only:
    from collections import defaultdict

# BUILTIN IMPORT
import pathlib
import subprocess
import socket
import re
import logging
import os

# PACKAGE IMPORT
import pytz
import psutil

log = logging.getLogger("syntraf." + __name__)

var_cfg_default_bind_arg = ("", "")
var_cfg_default_bind_add = "*"


#################################################################################
### GLOBAL FUNCTION THAT IS USED TO READ THE CONFIG AND CALL THE APPROPRIATE VALIDATION FUNCTIONS
#################################################################################
def validate_config(parameters, reload=False):
    # Initialization of this dict, as it is only returned when this is a server instance
    _dict_by_group_of_generated_tuple_for_map = {}
    '''
        Validation order :  config_validation_server
                            config_validation_client
                            config_validation_connectors
                            config_validation_listeners
                            config_validation_database
                            config_validation_global
                            config_validation_webui
    '''

    # READING CONFIG FILE
    bool_conf_valid, config = read_conf(parameters.config_file)

    # Before logging anything, set the loglevel. There is a default to INFO if nothing is set (or wrong config) in the config file. (see st_global.py for default config)
    #set_log_level(config)

    if not bool_conf_valid:
        return False, None, None, None
    else:
        log.debug(f"IS CONFIG FILE '{parameters.config_file.upper()}' DECODING SUCCESSFUL : YES")

    # Validation of the server config
    _dict_by_node_generated_config = None

    if "SERVER" in config:
        ok, _dict_by_node_generated_config, _dict_by_group_of_generated_tuple_for_map = config_validation_server(config, parameters)
        if not ok:
            log.error(f"VALIDATION OF SERVER CONFIG FAILED")
            return False, None, None, None
        else:
            log.debug(f"VALIDATION OF SERVER CONFIG SUCCESSFUL!")

    # If this config is in a mesh as a client, do not parse the rest of the config.
    in_a_mesh = False

    # Validation of the client config
    if 'CLIENT' in config:
        if not isinstance(config['CLIENT'], dict):
            log.error(f"IS 'CLIENT' CONFIGURATION CONTAIN PARAMETERS : NO)")
            return False, None, None, None
        else:
            if not config_validation_client(config, parameters):
                log.error(f"VALIDATION OF CLIENT CONFIG FAILED")
                return False, None, None, None
            else:
                log.debug(f"VALIDATION OF CLIENT CONFIG SUCCESSFUL!")
                in_a_mesh = True
    else:
        log.debug(f"IS 'CLIENT' CONFIGURATION DEFINED : NO")
        #return False, None, None

    if not in_a_mesh:
        # Validation of the connectors config
        if 'CONNECTORS' in config:
            for connector_dict_key in config['CONNECTORS']:
                if not config_validation_connectors(config, connector_dict_key):
                    log.error(f"VALIDATION OF CONNECTORS CONFIG FAILED")
                    return False, None, None, None
                else:
                    log.debug(f"VALIDATION OF CONNECTORS CONFIG SUCCESSFUL!")

        # Validation of the listeners config
        if 'LISTENERS' in config:
            for listeners_dict_key in config['LISTENERS']:
                if not config_validation_listeners(config, listeners_dict_key, reload):
                    log.error(f"VALIDATION OF LISTENERS CONFIG FAILED")
                    return False, None, None, None
                else:
                    log.debug(f"VALIDATION OF LISTENERS CONFIG SUCCESSFUL!")
    else:
        log.debug(
            f"THIS IS A MESH CLIENT, SKIPPING LISTENERS AND CONNECTORS CONFIG")
        if 'LISTENERS' in config:
            del (config['LISTENERS'])
        if 'CONNECTORS' in config:
            del (config['CONNECTORS'])

    # Validation of the global config
    if 'GLOBAL' in config:
        if not config_validation_global(config):
            log.error(f"VALIDATION OF GLOBAL CONFIG FAILED")
            return False, None, None, None
        else:
            log.debug(f"VALIDATION OF GLOBAL CONFIG SUCCESSFUL!")
    else:
        log.error(f"NO CLAUSE [GLOBAL] FOUND")
        return False, None, None, None

    if 'SERVER' in config:
        bool_database_config_valid = test_database_connection(config)
        if not bool_database_config_valid:
            return False, None, None, None

    # Validation of the WEBUI config
    #if 'WEBUI' in config and 'SERVER' in config:
    if 'SERVER' in config:
        if not config_validation_certificate(config, "WEBUI", parameters):
            log.error(f"VALIDATION OF WEBUI CONFIG FAILED")
            return False, None, None, None
        else:
            log.debug(f"VALIDATION OF WEBUI CONFIG SUCCESSFUL!")
    #else:
     #   # Not a mandatory config
    #    log.debug(f"NO CLAUSE [WEBUI] FOUND")

    return True, config, _dict_by_node_generated_config, _dict_by_group_of_generated_tuple_for_map


def config_validation_certificate(_config, type_of_service, parameters):
    cert_path = os.path.join(DefaultValues.SYNTRAF_ROOT_DIR, "crypto", f'{type_of_service.upper()}_X509_SELFSIGNED_DIRECTORY')
    private_key_path = os.path.join(cert_path,)
    certificate_path = os.path.join(cert_path,)

    # Do we have explicit cert provided by user?
    if type_of_service.upper() in _config:
        if (not config_file_exist_info(_config, type_of_service.upper(), f'{type_of_service.upper()}_X509_CERTIFICATE', server_log) or
                not config_file_exist_info(_config, type_of_service.upper(), f'{type_of_service.upper()}_X509_PRIVATE_KEY', server_log)):
            log.debug(f"IS THERE VALID X509 CERTIFICATE INFO GIVEN FOR {type_of_service.upper()} ({type_of_service.upper()}_X509_CERTIFICATE, {type_of_service.upper()}_X509_PRIVATE_KEY) : NO, TRYING TO FALLBACK ON SELF-SIGNED CERTIFICATE.")
        else:
            return True
    else:
        log.debug(f"IS THERE VALID X509 CERTIFICATE INFO GIVEN FOR {type_of_service.upper()} ({type_of_service.upper()}_X509_CERTIFICATE, {type_of_service.upper()}_X509_PRIVATE_KEY) : NO, TRYING TO FALLBACK ON SELF-SIGNED CERTIFICATE.")

    # Self Signed
    _config[type_of_service.upper()] = {}
    _config[type_of_service.upper()]['SERVER_X509_SELFSIGNED'] = "YES"

    ss_valid_directory = False

    # If directory does not exist, create it. If an error like permission denied, return False to terminate SYNTRAF
    pl_path = pathlib.Path(cert_path)
    if not pl_path.is_dir():
        if is_dir_create_on_fail(cert_path, f"{type_of_service.upper()}_X509_SELFSIGNED_DIRECTORY"):
            ss_valid_directory = True
        else:
            log.error(f"UNABLE TO CREATE {type_of_service.upper()}_X509_SELFSIGNED_DIRECTORY")
            return False

    # We should have a directory by now, check if we already have the files in it
    if file_exist("private_key_" + type_of_service.lower() + ".pem") and file_exist("certificate_" + type_of_service.lower() + ".pem"):
        return True
    else:
        gen_cert(server_log, cert_path, type_of_service.lower(), parameters, _config, type_of_service)


    #if not ss_valid_directory:
    #    if not isinstance(_config[type_of_service.upper()], dict):
    #        _config[type_of_service.upper()] = {}
    #    _config[type_of_service.upper()][f'{type_of_service.upper()}_X509_SELFSIGNED_DIRECTORY'] = eval(f"DefaultValues.DEFAULT_{type_of_service.upper()}_X509_SELFSIGNED_DIRECTORY")


   #     if not is_dir_create_on_fail(_config[type_of_service.upper()][f'{type_of_service.upper()}_X509_SELFSIGNED_DIRECTORY'], f"{type_of_service.upper()}_X509_SELFSIGNED_DIRECTORY"):
   #         return False
   #     else:
    #        ss_valid_directory = True


    return True


def test_database_connection(config):
    # Validation of the database config
    if 'DATABASE' in config:
        if not config_validation_database(config):
            log.error(f"VALIDATION OF DATABASE CONFIG FAILED")
            return False
        else:
            log.debug(f"VALIDATION OF DATABASE CONFIG SUCCESSFUL!")
    else:
        log.info(f"NO CLAUSE [DATABASE] FOUND")

    # # testing database config
    # try:
    #     for database in config['DATABASE']:
    #         test_db = InfluxObj(config, database['DB_UID'])
    #         if test_db.status == "FAIL":
    #             log.error(
    #                 f"DATABASE INITIALIZATION OF '{database['DB_UID']}' FAILED")
    #             return False
    #         else:
    #             log.debug(
    #                 f"DATABASE INITIALIZATION OF '{database['DB_UID']}' : OK")
    #         test_db.__del__()
    # except Exception as exc:
    #     log.error(f"DATABASE INITIALIZATION OF '{database['DB_UID']}' FAILED")
    #     return False
    return True


#################################################################################
### VALIDATE THE CONNECTORS IN THE CONFIG FILE
#################################################################################
def config_validation_connectors(_config, connector_dict_key):
    try:
        if "DESTINATION_ADDRESS" in _config['CONNECTORS'][connector_dict_key]:
            log.debug(f"IS DESTINATION_ADDRESS DECLARED IN CONFIG FILE : YES")
            if not is_ip_or_hostname_valid(_config['CONNECTORS'][connector_dict_key]['DESTINATION_ADDRESS'],
                                           "DESTINATION_ADDRESS"):
                return False
        else:
            log.error(f"IS DESTINATION_ADDRESS DECLARED IN CONFIG FILE : NO")
            return False

        if "PORT" in _config['CONNECTORS'][connector_dict_key]:
            log.debug(f"IS PORT DECLARED IN CONFIG FILE : YES")
            if not is_port_valid(_config['CONNECTORS'][connector_dict_key]['PORT'], "PORT"):
                return False
        else:
            log.error(f"IS PORT DECLARED IN CONFIG FILE : NO")
            return False

        # DSCP
        if "DSCP" in _config['CONNECTORS'][connector_dict_key]:
            if not validate_dscp(_config['CONNECTORS'][connector_dict_key]['TOS']):
                _config['CONNECTORS'][connector_dict_key]['DSCP'] = DefaultValues.DEFAULT_DSCP
                log.warning(
                    f"DSCP PARAMETER INVALID: APPLYING DEFAULT OF '{DefaultValues.DEFAULT_DSCP}'")
        else:
            _config['CONNECTORS'][connector_dict_key]['DSCP'] = DefaultValues.DEFAULT_DSCP
            log.warning(
                f"DSCP PARAMETER NOT FOUND: APPLYING DEFAULT OF '{DefaultValues.DEFAULT_DSCP}'")

        # PACKET_SIZE
        if "PACKET_SIZE" in _config['CONNECTORS'][connector_dict_key]:
            if not validate_packet_size(_config['CONNECTORS'][connector_dict_key]['PACKET_SIZE']):
                _config['CONNECTORS'][connector_dict_key]['PACKET_SIZE'] = DefaultValues.DEFAULT_PACKET_SIZE
                log.warning(
                    f"PACKET_SIZE PARAMETER INVALID: APPLYING DEFAULT OF '{DefaultValues.DEFAULT_PACKET_SIZE}'")
        else:
            _config['CONNECTORS'][connector_dict_key]['PACKET_SIZE'] = DefaultValues.DEFAULT_PACKET_SIZE
            log.warning(
                f"PACKET_SIZE PARAMETER NOT FOUND: APPLYING DEFAULT OF '{DefaultValues.DEFAULT_PACKET_SIZE}'")

        # BANDWIDTH
        if "BANDWIDTH" in _config['CONNECTORS'][connector_dict_key]:
            log.debug(f"IS BANDWIDTH DECLARED IN CONFIG FILE : YES")
            if validate_bandwidth(_config['CONNECTORS'][connector_dict_key]['BANDWIDTH']) >= 0:
                log.debug(
                    f"IS BANDWIDTH '{_config['CONNECTORS'][connector_dict_key]['BANDWIDTH']}' VALID : YES")
            else:
                _config['CONNECTORS'][connector_dict_key]['BANDWIDTH'] = DefaultValues.DEFAULT_BANDWIDTH
                log.warning(
                    f"BANDWIDTH PARAMETER INVALID: APPLYING DEFAULT OF '{DefaultValues.DEFAULT_BANDWIDTH}'")
        else:
            _config['CONNECTORS'][connector_dict_key]['BANDWIDTH'] = DefaultValues.DEFAULT_BANDWIDTH
            log.warning(
                f"BANDWIDTH PARAMETER NOT FOUND: APPLYING DEFAULT OF '100K'")

    except Exception as exc:
        log.error(f"config_validation_connectors:{type(exc).__name__}:{exc}", exc_info=True)

    return True


#################################################################################
### VALIDATE THE PACKET_SIZE
#################################################################################
def validate_packet_size(packet_size):
    if packet_size.isdigit():
        if 16 <= int(packet_size) <= 65507:
            log.debug(f"IS PACKET_SIZE '{packet_size}' VALID : YES")
            return True
        else:
            log.error(f"IS PACKET_SIZE '{packet_size}' VALID : NO")
            log.error(
                f"PACKET_SIZE VALUE SHOULD BE AN INTEGER BETWEEN 16 and 65507 bytes")
            return False
    else:
        log.error(f"IS PACKET_SIZE '{packet_size}' VALID : NO")
        log.error(
            f"PACKET_SIZE VALUE SHOULD BE AN INTEGER BETWEEN 16 and 65507 bytes")
        return False


#################################################################################
### VALIDATE THE DSCP (Differentiated Services Code Point)
#################################################################################
def validate_dscp(dscp):
    if dscp.isdigit():
        if 0 <= int(dscp) <= 63:
            log.debug(
                f"IS DSCP VALUE '{dscp}' VALID : YES")
            return True
        else:
            log.error(
                f"IS DSCP VALUE '{dscp}' VALID : NO")
            log.error(
                f"DSCP VALUE SHOULD BE AN INTEGER BETWEEN 0 and 63")
            return False
    else:
        log.error(
            f"IS DSCP VALUE '{dscp}' VALID : NO")
        log.error(
            f"DSCP VALUE SHOULD BE AN INTEGER BETWEEN 0 and 63")
        return False


#################################################################################
### VALIDATE THE BANDWIDTH AND RETURN TRUE IF OK
#################################################################################
def validate_bandwidth(bandwidth):
    data = "0"
    multiplier = 1

    try:
        # Check if bandwidth contain something first
        if bandwidth:
            # If end with K, extract what precede, multiplier is 1000
            if bandwidth[-1].lower() == "k":
                multiplier = 1000
                data = bandwidth[0:-1]

            # If end with M, extract what precede, then multiply it by 1000**2 to get bits
            elif bandwidth[-1].lower() == "m":
                multiplier = 1000000
                data = bandwidth[0:-1]

            else:
                data = bandwidth

            try:
                float(data)
                return float(data) * multiplier
            except ValueError:
                return -1

        else:
            return -1

    except Exception as exc:
        log.error(f"validate_bandwidth:{type(exc).__name__}:{exc}", exc_info=True)
        return -1


#################################################################################
### VALIDATE THE LISTENERS IN THE CONFIG FILE [DEPRECATED, REPLACED BY AUTOMATIC CONFIG GENERATION]
#################################################################################
def config_validation_listeners(_config, listener_dict_key, reload=False):
    # TODO : Validation of listener key
    # listener_dict_key

    try:
        # TODO AMÉLIORER LA VALIDATION
        if 'CLIENT_PARAM_DSCP' not in _config['LISTENERS'][listener_dict_key]:
            _config['LISTENERS'][listener_dict_key]['CLIENT_PARAM_DSCP'] = "0"

        # validation description client et serveur
        if not _config['LISTENERS'][listener_dict_key]['DESCRIPTION_CLIENT'] or not \
                _config['LISTENERS'][listener_dict_key]['DESCRIPTION_SERVER']:
            log.error(
                f"IS DESCRIPTION_CLIENT AND DESCRIPTION_SERVER DECLARED IN CONFIG FILE : NO")
            return False
        else:
            log.debug(
                f"IS DESCRIPTION_CLIENT AND DESCRIPTION_SERVER DECLARED IN CONFIG FILE : YES")
            if len(_config['LISTENERS'][listener_dict_key]['DESCRIPTION_CLIENT']) <= 50 and len(
                    _config['LISTENERS'][listener_dict_key]['DESCRIPTION_SERVER']) <= 50:
                log.debug(
                    f"IS LEN OF DESCRIPTION_CLIENT AND DESCRIPTION_SERVER <= 50 CHAR : YES")
            else:
                log.error(
                    f"IS LEN OF DESCRIPTION_CLIENT AND DESCRIPTION_SERVER <= 50 CHAR : NO")
                return False

        # Validation BIND_ADDRESS, MUST BE A LOCAL IP
        #local_IP = [netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr'] for iface in netifaces.interfaces() if
        #            netifaces.AF_INET in netifaces.ifaddresses(iface)]

        #print(psutil.net_if_addrs())



        # global var_cfg_default_bind_add
        # # DO WE HAVE A BIND ADDRESS DEFINED?
        # if "BIND_ADDRESS" in _config['LISTENERS'][listener_dict_key]:
        #     # YES, IF ALL INTERFACE DEFINED, VALIDATE ALL, ELSE VALIDATE ONLY THE ONE SPECIFIED
        #     if _config['LISTENERS'][listener_dict_key]['BIND_ADDRESS'] == "*":
        #         for ip in local_IP:
        #             if not reload:
        #                 if not is_port_available(ip, _config['LISTENERS'][listener_dict_key]['PORT']):
        #                     log.error(
        #                         f"IS PORT {_config['LISTENERS'][listener_dict_key]['PORT']} AVAILABLE ON ALL INTERFACES : NO")
        #                     return False
        #     # If we are not reloading, check if port is available
        #     elif not reload:
        #         if not is_port_available(_config['LISTENERS'][listener_dict_key]['BIND_ADDRESS'],
        #                                  _config['LISTENERS'][listener_dict_key]['PORT']):
        #             return False
        #     else:
        #         log.debug(
        #             f"IS BIND_ADDRESS {_config['LISTENERS'][listener_dict_key]['BIND_ADDRESS']} IN LOCAL INTERFACES : YES")
        #         var_cfg_default_bind_add = _config['LISTENERS'][listener_dict_key]['BIND_ADDRESS']
        # # WE SHOULD USE THE DEFAULT "*"
        # else:
        #     _config['LISTENERS'][listener_dict_key]['BIND_ADDRESS'] = var_cfg_default_bind_add
        #     for ip in local_IP:
        #         if not reload:
        #             if not is_port_available(ip, _config['LISTENERS'][listener_dict_key]['PORT']):
        #                 return False

        # VALIDATING INTERVAL
        if "INTERVAL" in _config['LISTENERS'][listener_dict_key]:
            if not validate_interval(_config['LISTENERS'][listener_dict_key]['INTERVAL']):
                _config['LISTENERS'][listener_dict_key]['INTERVAL'] = DefaultValues.DEFAULT_INTERVAL
                log.warning(
                    f"INTERVAL PARAMETER INVALID: APPLYING DEFAULT OF '{DefaultValues.DEFAULT_INTERVAL}'")
        else:
            _config['LISTENERS'][listener_dict_key]['INTERVAL'] = DefaultValues.DEFAULT_INTERVAL
            log.warning(
                f"BANDWIDTH PARAMETER NOT FOUND: APPLYING DEFAULT OF '{DefaultValues.DEFAULT_INTERVAL}'")

        return True

    except KeyError as exc:
        log.error(f"config_validation_listeners:{type(exc).__name__}:{exc}", exc_info=True)
    except Exception as exc:
        log.error(f"config_validation_listeners:{type(exc).__name__}:{exc}", exc_info=True)


#################################################################################
### VALIDATE INTERVAL
#################################################################################
def validate_interval(interval):
    try:
        if float(interval) < 1 or float(interval) > 60:
            log.debug(f"IS INTERVAL {interval} >= 1 AND <= 60 : NO")
            return False
        else:
            log.debug(f"IS INTERVAL {interval} >= 1 AND <= 60 : YES")
            return True
    except Exception as exc:
        log.error(f"validate_interval:{type(exc).__name__}:{exc}", exc_info=True)
        return False


def config_validation_database(_config):
    if 'DATABASE' in _config:
        for database in _config['DATABASE']:
            if 'DB_UID' in database:
                log.debug(f"IS DB_UID DECLARED : YES")
                if validate_uid(database['DB_UID']):
                    log.debug(f"IS DB_UID '{database['DB_UID']}' VALID : YES")
                else:
                    log.error(f"IS DB_UID '{database['DB_UID']}' VALID : NO")
                    return False
            else:
                log.error(f"IS DB_UID DECLARED IN CONFIG FILE : NO")
                return False

            if 'DB_SERVER_USE_SSL' in database:
                log.debug(
                    f"IS DB_SERVER_USE_SSL DECLARED FOR DATABASE '{database['DB_UID']}' : YES")
            else:
                log.warning(
                    f"IS DB_SERVER_USE_SSL DECLARED FOR DATABASE '{database['DB_UID']}' : NO, APPLYING DEFAULT: {DefaultValues.DEFAULT_INFLUXDB_USE_SSL}")
                database['DB_SERVER_USE_SSL'] = DefaultValues.DEFAULT_INFLUXDB_USE_SSL

            if database['DB_ENGINE'].upper() == "INFLUXDB2":
                log.debug(
                    f"IS DB_ENGINE '{database['DB_ENGINE'].upper()}' VALID FOR DATABASE '{database['DB_UID']}' : YES")
            else:
                log.error(
                    f"IS DB_ENGINE '{database['DB_ENGINE'].upper()}' VALID FOR DATABASE '{database['DB_UID']}' : NO")
                return False

            if 'DB_TOKEN' in database:
                log.debug(
                    f"IS DB_TOKEN DECLARED FOR DATABASE '{database['DB_UID']}' : YES")
            else:
                log.debug(
                    f"IS DB_TOKEN DECLARED FOR DATABASE '{database['DB_UID']}' : NO")
                return False

            if 'DB_ORG' in database:
                log.debug(
                    f"IS DB_ORG DECLARED FOR DATABASE '{database['DB_UID']}' : YES")
            else:
                log.debug(
                    f"IS DB_ORG DECLARED FOR DATABASE '{database['DB_UID']}' : NO")
                return False

            if 'DB_BUCKET' in database:
                log.debug(
                    f"IS DB_BUCKET DECLARED FOR DATABASE '{database['DB_UID']}' : YES")
            else:
                log.debug(
                    f"IS DB_BUCKET DECLARED FOR DATABASE '{database['DB_UID']}' : NO")
                return False

            if 'DB_USE_WEB_PROXY' in database:
                log.debug(
                    f"IS DB_USE_WEB_PROXY FOR DATABASE '{database['DB_UID']}' : YES")

                if re.findall(r'http?.:\/\/.*:.*', database['DB_USE_WEB_PROXY']):
                    log.debug(
                        f"IS DB_USE_WEB_PROXY '{database['DB_USE_WEB_PROXY']}' VALID FOR DATABASE '{database['DB_UID']}' : YES")
                else:
                    log.debug(
                        f"IS DB_USE_WEB_PROXY '{database['DB_USE_WEB_PROXY']}' VALID FOR DATABASE '{database['DB_UID']}' : NO")
                    return False

            # validation du port de la base de données
            if database['DB_PORT']:
                log.debug(
                    f"IS DB_PORT DECLARED FOR DATABASE '{database['DB_UID']}' : YES")

                if is_port_valid(database['DB_PORT'], "DB_PORT"):
                    log.debug(
                        f"IS DB_PORT '{database['DB_PORT']}' VALID FOR DATABASE '{database['DB_UID']}' : YES")
                else:
                    log.error(
                        f"IS DB_PORT '{database['DB_PORT']}' VALID FOR DATABASE '{database['DB_UID']}' : NO")
                    return False
            else:
                log.error(
                    f"IS DB_PORT DECLARED FOR DATABASE '{database['DB_UID']}' : NO")
                return False

            if 'DB_CONNECTION_POOL_MAXSIZE' in database:
                if database['DB_CONNECTION_POOL_MAXSIZE'].isdigit():
                    if 1 <= int(database['DB_CONNECTION_POOL_MAXSIZE']) <= 100000:
                        log.debug(
                            f"IS DB_CONNECTION_POOL_MAXSIZE '{database['DB_CONNECTION_POOL_MAXSIZE']}' VALID : YES")
                    else:
                        log.debug(
                            f"IS DB_CONNECTION_POOL_MAXSIZE '{database['DB_CONNECTION_POOL_MAXSIZE']}' BETWEEN 1 and 100000 : NO, APPLYING DEFAULT OF '{DefaultValues.DEFAULT_DB_CONNECTION_POOL_MAXSIZE}'")
                        database['DB_CONNECTION_POOL_MAXSIZE'] = DefaultValues.DEFAULT_DB_CONNECTION_POOL_MAXSIZE
                else:
                    log.debug(f"IS DB_CONNECTION_POOL_MAXSIZE '{database['DB_CONNECTION_POOL_MAXSIZE']}' VALID : NO, APPLYING DEFAULT OF '{DefaultValues.DEFAULT_DB_CONNECTION_POOL_MAXSIZE}'")
                    database['DB_CONNECTION_POOL_MAXSIZE'] = DefaultValues.DEFAULT_DB_CONNECTION_POOL_MAXSIZE
            else:
                log.debug(f"IS DB_CONNECTION_POOL_MAXSIZE DECLARED FOR DATABASE '{database['DB_UID']}' : NO, APPLYING DEFAULT OF '{DefaultValues.DEFAULT_DB_CONNECTION_POOL_MAXSIZE}'")
                database['DB_CONNECTION_POOL_MAXSIZE'] = DefaultValues.DEFAULT_DB_CONNECTION_POOL_MAXSIZE
    else:
        log.error(f"IS THERE AT LEAST ONE DATABASE DEFINED : NO")
        return False

    return True


#################################################################################
### VALIDATE THE GLOBAL PART OF THE CONFIG FILE
#################################################################################
def config_validation_global(_config):
    try:
        # validating WATCHDOG_CHECK_RATE
        if "WATCHDOG_CHECK_RATE" in _config['GLOBAL']:
            log.debug(f"IS WATCHDOG_CHECK_RATE DECLARED IN CONFIG FILE : YES")
            if _config['GLOBAL']['WATCHDOG_CHECK_RATE'].isdigit():
                if 1 <= int(_config['GLOBAL']['WATCHDOG_CHECK_RATE']) <= 86400:
                    log.debug(
                        f"IS A WATCHDOG_CHECK_RATE OF '{_config['GLOBAL']['WATCHDOG_CHECK_RATE'].upper()} seconds' VALID : YES")
                else:
                    log.error(
                        f"IS A WATCHDOG_CHECK_RATE OF '{_config['GLOBAL']['WATCHDOG_CHECK_RATE'].upper()} seconds' VALID : NO")
                    return False
            else:
                log.error(
                    f"IS A WATCHDOG_CHECK_RATE OF '{_config['GLOBAL']['WATCHDOG_CHECK_RATE'].upper()} seconds' VALID : NO")
                return False
        else:
            log.debug(
                f"IS WATCHDOG_CHECK_RATE DECLARED IN CONFIG FILE : NO, USING DEFAULT (10sec)")
            _config['GLOBAL']['WATCHDOG_CHECK_RATE'] = "10"

        # validation du binaire iperf3
        if 'IPERF3_BINARY_PATH' in _config['GLOBAL']:
            if _config['GLOBAL']['IPERF3_BINARY_PATH'] == "DISABLE":
                return True
            elif not _config['GLOBAL']['IPERF3_BINARY_PATH'] == "":
                iperf3_file = pathlib.Path(_config['GLOBAL']['IPERF3_BINARY_PATH'])
                if not iperf3_file.is_file():
                    log.error(
                        f"DOES IPERF BINARY {_config['GLOBAL']['IPERF3_BINARY_PATH']} EXIST : NO")
                    return False
                else:
                    log.debug(f"DOES IPERF BINARY {_config['GLOBAL']['IPERF3_BINARY_PATH']} EXIST : YES")
                    if not is_iperf3_support_timestamp(_config, _config['GLOBAL']['IPERF3_BINARY_PATH']):
                        return False
                    if not is_iperf3_support_ssl(_config, _config['GLOBAL']['IPERF3_BINARY_PATH']):
                        return False
                    if not is_iperf3_support_skew_threshold(_config, _config['GLOBAL']['IPERF3_BINARY_PATH']):
                        return False

            # Variable exist but is empty
            else:
                del _config['GLOBAL']['IPERF3_BINARY_PATH']
                if not detect_iperf3_path(_config):
                    log.error(f"NO IPERF BINARY FOUND")
                    return False

        else:
            if not detect_iperf3_path(_config):
                log.error(f"NO IPERF BINARY FOUND")
                return False

        # validating directory for RSA keypair
        if 'IPERF3_RSA_KEY_DIRECTORY' in _config['GLOBAL']:
            if len(_config['GLOBAL']['IPERF3_RSA_KEY_DIRECTORY']) <= 0:
                _config['GLOBAL']['IPERF3_RSA_KEY_DIRECTORY'] = DefaultValues.DEFAULT_IPERF3_RSA_KEY_DIRECTORY

            # If directory does not exist, create it. If an error like permission denied, return False to terminate SYNTRAF
            if not is_dir_create_on_fail(_config['GLOBAL']['IPERF3_RSA_KEY_DIRECTORY'], "IPERF3_RSA_KEY_DIRECTORY"):
                return False
        else:
            log.warning(f"IS IPERF3_RSA_KEY_DIRECTORY DEFINED: NO, APPLYING DEFAULT: '{DefaultValues.DEFAULT_IPERF3_RSA_KEY_DIRECTORY}'")
            _config['GLOBAL']['IPERF3_RSA_KEY_DIRECTORY'] = DefaultValues.DEFAULT_IPERF3_RSA_KEY_DIRECTORY

            # If directory does not exist, create it. If an error like permission denied, return False to terminate SYNTRAF
            if not is_dir_create_on_fail(_config['GLOBAL']['IPERF3_RSA_KEY_DIRECTORY'], "IPERF3_RSA_KEY_DIRECTORY"):
                return False

        # validating directory for iperf3 logs
        if 'IPERF3_TEMP_DIRECTORY' in _config['GLOBAL']:
            if len(_config['GLOBAL']['IPERF3_TEMP_DIRECTORY']) <= 0:
                _config['GLOBAL']['IPERF3_TEMP_DIRECTORY'] = DefaultValues.DEFAULT_IPERF3_TEMP_DIRECTORY

            # If directory does not exist, create it. If an error like permission denied, return False to terminate SYNTRAF
            if not is_dir_create_on_fail(_config['GLOBAL']['IPERF3_TEMP_DIRECTORY'], "IPERF3_TEMP_DIRECTORY"):
                return False

        else:
            log.warning(f"IS IPERF3_TEMP_DIRECTORY DEFINED : NO, APPLYING DEFAULT: '{DefaultValues.DEFAULT_IPERF3_TEMP_DIRECTORY}'")

            _config['GLOBAL']['IPERF3_TEMP_DIRECTORY'] = DefaultValues.DEFAULT_IPERF3_TEMP_DIRECTORY

            # If directory does not exist, create it. If an error like permission denied, return False to terminate SYNTRAF
            if not is_dir_create_on_fail(_config['GLOBAL']['IPERF3_TEMP_DIRECTORY'], "IPERF3_TEMP_DIRECTORY"):
                return False

        # When authenticating (credentials + rsa), iperf3 will refuse a connection between two host with a time skew bigger than 10 seconds. iperf3 have a parameter to change this threshold
        if 'IPERF3_TIME_SKEW_THRESHOLD' in _config['GLOBAL']:
            if _config['GLOBAL']['IPERF3_TIME_SKEW_THRESHOLD'].isdigit():
                if not (int(_config['GLOBAL']['IPERF3_TIME_SKEW_THRESHOLD']) >= 1 and int(
                        _config['GLOBAL']['IPERF3_TIME_SKEW_THRESHOLD']) <= 86400):
                    log.warning(
                        f"IS IPERF3_TIME_SKEW_THRESHOLD VALID : NO, APPLYING DEFAULT '{DefaultValues.DEFAULT_IPERF3_TIME_SKEW_THRESHOLD}'")
                    _config['GLOBAL'][
                        'IPERF3_TIME_SKEW_THRESHOLD'] = DefaultValues.DEFAULT_IPERF3_TIME_SKEW_THRESHOLD
        else:
            log.warning(
                f"IS IPERF3_TIME_SKEW_THRESHOLD VALID : NO, APPLYING DEFAULT '{DefaultValues.DEFAULT_IPERF3_TIME_SKEW_THRESHOLD}'")
            _config['GLOBAL'][
                'IPERF3_TIME_SKEW_THRESHOLD'] = DefaultValues.DEFAULT_IPERF3_TIME_SKEW_THRESHOLD

    except Exception as exc:
        log.error(f"config_validation_global:{type(exc).__name__}:{exc}", exc_info=True)
        return False

    return True


def is_dir_create_on_fail(str_path, str_key):
    pl_path = pathlib.Path(str_path)
    try:
        if not pl_path.is_dir():
            log.debug(f"DOES {str_key}: '{str_path}' EXIST : NO, ATTEMPTING TO CREATE IT...")
            pathlib.Path(str_path).mkdir(parents=True, exist_ok=True)
            log.debug(f"'{str_path}' CREATION COMPLETED")
        else:
            log.debug(f"DOES {str_key}: '{str_path}' EXIST : YES")
    except OSError:
        log.error(f"AN ERROR OCCURRED WHILE CREATING DIRECTORY '{str_path}'")
        return False
    return True


#################################################################################
### DETECT IPERF BINARY
#################################################################################
def detect_iperf3_path(_config):
    log.warning(f"IPERF3_BINARY_PATH NOT DEFINED IN CONFIG FILE. SWITCHING TO DETECT MODE.")
    # TRY TO FIND iperf3 in the PATH
    path = os.environ['PATH']
    # Windows use ;, Linux use :
    path = path.replace(":", ";")
    lst_path = path.split(";")
    for path in lst_path:
        p = pathlib.Path(path + "\\iperf3.exe")
        if p.is_file():
            if is_iperf3_support_timestamp(_config, str(p)) and is_iperf3_support_ssl(_config, str(p)) and is_iperf3_support_skew_threshold(_config, str(p)):
                _config['GLOBAL']['IPERF3_BINARY_PATH'] = str(p)
                break
        p = pathlib.Path(path + "/iperf3")
        if p.is_file():
            if is_iperf3_support_timestamp(_config, str(p)) and is_iperf3_support_ssl(_config, str(p)) and is_iperf3_support_skew_threshold(_config, str(p)):
                _config['GLOBAL']['IPERF3_BINARY_PATH'] = str(p)
                break

        if 'IPERF3_BINARY_PATH' not in _config['GLOBAL']:
            log.warning(
                f"IPERF3 BINARY DETECTION FAILED")
            return False
        else:
            log.info(f"FOUND AN IPERF BINARY {_config['GLOBAL']['IPERF3_BINARY_PATH']} IN THE PATH!")


#################################################################################
### VALIDATE THE CLIENT PART OF THE CONFIG FILE
#################################################################################
def config_validation_client(_config, parameters):
    # CLIENT UID
    if 'CLIENT_UID' in _config['CLIENT']:
        if not validate_uid(_config['CLIENT']['CLIENT_UID']):
            log.error(f"IS 'CLIENT' UID VALUE '{_config['CLIENT']['CLIENT_UID']}' VALID : NO, (ONLY A-Za-z0-9_- ALLOWED)")
            return False
    else:
        log.error(
            f"IS 'CLIENT_UID' SPECIFIED IN THE CLIENT CONFIGURATION : NO")
        return False

    # SERVER IP
    if 'SERVER' in _config['CLIENT']:
        if not is_ip_or_hostname_valid(_config['CLIENT']['SERVER'], "SERVER"):
            return False
    else:
        log.error(
            f"IS SERVER SPECIFIED IN CLIENT CONFIGURATION : NO")
        return False

    # SERVER PORT
    if 'SERVER_PORT' in _config['CLIENT']:
        if not is_port_valid(_config['CLIENT']['SERVER_PORT'], "SERVER_PORT"):
            return False
    else:
        log.info(
            f"IS SERVER_PORT SPECIFIED IN CLIENT CONFIGURATION : NO")
        log.info(
            f"APPLYING DEFAULT OF '{DefaultValues.DEFAULT_SERVER_PORT}' FOR SERVER_PORT")
        _config['CLIENT']['SERVER_PORT'] = DefaultValues.DEFAULT_SERVER_PORT

    # TOKEN
    if 'TOKEN' in _config['CLIENT']:
        if not 5 <= len(_config['CLIENT']['TOKEN']) <= 255:
            log.error(
                f"IS TOKEN '{_config['CLIENT']['TOKEN']}' VALID : NO")
            log.error(
                f"TOKEN MUST BE BETWEEN 5 AND 255 CHARACTER INCLUSIVELY")
            return False
    else:
        log.error(
            f"IS TOKEN SPECIFIED IN CLIENT CONFIGURATION : NO")
        return False

    # LOCAL IP
    apply_default = False
    if 'MESH_LOCAL_IP' in _config['CLIENT']:
        if not is_ip_or_hostname_valid(_config['CLIENT']['MESH_LOCAL_IP'], "MESH_LOCAL_IP"):
            apply_default = True
    else:
        apply_default = True

    if apply_default:
        log.warning(
            f"APPLYING MESH_LOCAL_IP DEFAULT '0.0.0.0' ; LISTENING ON ALL INTERFACES.")
        _config['CLIENT']['MESH_LOCAL_IP'] = "0.0.0.0"

    # # Do we need to forward metrics to server?
    # if 'FORWARD_METRICS_TO_SERVER' in _config['CLIENT']:
    #     if not isinstance(_config['CLIENT']['FORWARD_METRICS_TO_SERVER'], bool):
    #         log.warning(
    #             f"IS 'FORWARD_METRICS_TO_SERVER' VALUE VALID : NO, APPLYING DEFAULT '{DefaultValues.DEFAULT_FORWARD_METRIC_TO_SERVER}'")
    #         _config['CLIENT']['FORWARD_METRICS_TO_SERVER'] = DefaultValues.DEFAULT_FORWARD_METRIC_TO_SERVER
    # else:
    #
    #     _config['CLIENT']['FORWARD_METRICS_TO_SERVER'] = DefaultValues.DEFAULT_FORWARD_METRIC_TO_SERVER

    if not config_validation_certificate(_config, "CLIENT", parameters):
        return False

    return True


#################################################################################
### VALIDATE THE SERVER PART OF THE CONFIG FILE
#################################################################################
def config_validation_server(_config, parameters):

    # Validating the IP address of the mesh server

    # if 'SERVER' in _config['SERVER']:
    #     if not is_ip_or_hostname_valid(_config['SERVER']['BIND_ADDRESS'], "SERVER"):
    #         return False, None, None
    # else:
    #     log.error(
    #         f"IS SERVER SPECIFIED IN SERVER CONFIGURATION : NO")
    #     return False, None, None

    # Validating the list of mesh token
    if 'TOKEN' in _config['SERVER']:
        for token in _config['SERVER']['TOKEN']:
            # Token must be between 5 and 255 char long
            if not 5 <= len(_config['SERVER']['TOKEN'][token]) <= 255:
                log.error(
                    f"IS TOKEN '{_config['SERVER']['TOKEN'][token]}' VALID : NO")
                log.error(
                    f"TOKEN MUST BE BETWEEN 5 AND 255 CHARACTER INCLUSIVELY")
                return False, None, None
            else:
                log.debug(
                    f"IS TOKEN '{_config['SERVER']['TOKEN'][token]}' VALID : YES")
    else:
        log.error(
            f"IS TOKEN SPECIFIED IN SERVER CONFIGURATION : NO")
        return False, None, None

    if 'SERVER_PORT' in _config['SERVER']:
        if not is_port_valid(_config['SERVER']['SERVER_PORT'], "SERVER_PORT"):
            return False, None, None
    else:
        log.info(
            f"IS SERVER_PORT SPECIFIED IN SERVER CONFIGURATION : NO, APPLYING DEFAULT: '{DefaultValues.DEFAULT_SERVER_PORT}'")
        _config['SERVER']['SERVER_PORT'] = DefaultValues.DEFAULT_SERVER_PORT

    if 'MESH_LISTENERS_PORT_RANGE' in _config['SERVER']:
        # Does it look like a range?
        x = re.findall(r"^(\d*-\d*)$", _config['SERVER']['MESH_LISTENERS_PORT_RANGE'])
        if not x:
            return False, None, None

        port = _config['SERVER']['MESH_LISTENERS_PORT_RANGE'].split("-")
        if not (is_port_valid(port[0], "MESH_LISTENERS_PORT_RANGE") and is_port_valid(port[1],
                                                                                      "MESH_LISTENERS_PORT_RANGE")):
            return False, None, None

        if port[1] <= port[0]:
            log.error(
                f"IS MESH_LISTENERS_PORT_RANGE BEGINNING SMALLER THAN THE END : NO")
            return False, None, None
    else:
        log.info(
            f"IS MESH_LISTENERS_PORT_RANGE SPECIFIED IN SERVER CONFIGURATION : NO, APPLYING DEFAULT: '{DefaultValues.DEFAULT_PORT_RANGE}'")
        _config['SERVER']['MESH_LISTENERS_PORT_RANGE'] = DefaultValues.DEFAULT_PORT_RANGE

    if not config_validation_certificate(_config, "SERVER", parameters):
        return False, None, None

    # Validating SERVER_CLIENT
    if 'SERVER_CLIENT' in _config:
        # UID must be unique
        arr_uid_unique = []
        for server_client in _config['SERVER_CLIENT']:
            arr_uid_unique.append(server_client['UID'])

        if len(arr_uid_unique) == len(set(arr_uid_unique)):
            log.debug(f"ALL 'SERVER_CLIENT' UID's UNIQUE : YES")
        else:
            log.error(f"ALL 'SERVER_CLIENT' UID's UNIQUE : NO")
            return False, None, None

        for server_client in _config['SERVER_CLIENT']:
            # Validate UID
            if 'UID' in server_client:
                if not validate_uid(server_client['UID']):
                    log.error(
                        f"IS 'SERVER_CLIENT' UID VALUE '{server_client['UID']}' VALID : NO    (ONLY A-Za-z0-9_- ALLOWED)")
                    return False, None, None
                else:
                    log.debug(
                        f"IS 'SERVER_CLIENT' UID VALUE '{server_client['UID']}' VALID : YES")
            else:
                log.error(
                    f"IS 'SERVER_CLIENT' UID VALUE VALID : PARAMETER NOT FOUND")
                return False, None, None

            # Validate IP
            if 'IP_ADDRESS' in server_client:
                if not validate_ipv4(server_client['IP_ADDRESS']):
                    log.error(
                        f"IS 'SERVER_CLIENT' IP_ADDRESS VALUE '{server_client['IP_ADDRESS']}' VALID FOR SERVER_CLIENT '{server_client['UID']}': NO")
                    return False, None, None
                else:
                    log.debug(
                        f"IS 'SERVER_CLIENT' IP_ADDRESS VALUE '{server_client['IP_ADDRESS']}' VALID FOR SERVER_CLIENT '{server_client['UID']}' : YES")
            else:
                log.error(
                    f"IS 'SERVER_CLIENT' IP_ADDRESS VALUE VALID FOR SERVER_CLIENT '{server_client['UID']}': PARAMETER NOT FOUND")
                return False, None, None

            # Validate MESH_GROUP UID LIST
            if 'MESH_GROUP_UID_LIST' in server_client:
                if not validate_mesh_group_uid_list(server_client, _config):
                    log.error(
                        f"IS 'SERVER_CLIENT' MESH_GROUP_UID_LIST VALUE VALID FOR SERVER_CLIENT '{server_client['UID']}' : NO")
                    return False, None, None
                else:
                    log.debug(
                        f"IS 'SERVER_CLIENT' MESH_GROUP_UID_LIST VALUE '{server_client['MESH_GROUP_UID_LIST']}' VALID FOR SERVER_CLIENT '{server_client['UID']}' : YES")
            else:
                log.debug(
                    f"IS 'SERVER_CLIENT' MESH_GROUP_UID_LIST VALUE VALID FOR SERVER_CLIENT '{server_client['UID']}' : PARAMETER NOT FOUND")

            # Validate OVERRIDE_DST_NODE_IP
            if 'OVERRIDE_DST_NODE_IP' in server_client:
                if not validate_override_dst_node_ip(server_client, _config):
                    log.error(
                        f"IS 'SERVER_CLIENT' OVERRIDE_DST_NODE_IP VALUE VALID FOR SERVER_CLIENT '{server_client['UID']}' : NO")
                    return False, None, None
                else:
                    log.debug(
                        f"IS 'SERVER_CLIENT' OVERRIDE_DST_NODE_IP VALUE '{server_client['OVERRIDE_DST_NODE_IP']}' VALID FOR SERVER_CLIENT '{server_client['UID']}' : YES")
            else:
                log.debug(
                    f"IS 'SERVER_CLIENT' OVERRIDE_DST_NODE_IP VALUE VALID FOR SERVER_CLIENT '{server_client['UID']}' : PARAMETER NOT FOUND")

            # Validate MESH_GROUP UID LIST
            if 'P2P_GROUP_UID_LIST' in server_client:
                if not validate_p2p_group_uid_list(server_client, _config):
                    log.error(
                        f"IS 'SERVER_CLIENT' P2P_GROUP_UID_LIST VALUE VALID FOR SERVER_CLIENT '{server_client['UID']}' : NO")
                    return False, None, None
                else:
                    log.debug(
                        f"IS 'SERVER_CLIENT' P2P_GROUP_UID_LIST VALUE '{server_client['MESH_GROUP_UID_LIST']}' VALID FOR SERVER_CLIENT '{server_client['UID']}' : YES")
            else:
                log.debug(
                    f"IS 'SERVER_CLIENT' P2P_GROUP_UID_LIST VALUE VALID FOR SERVER_CLIENT '{server_client['UID']}' : PARAMETER NOT FOUND")


            # Validate MAX_BANDWIDTH (optional parameter)
            if 'MAX_BANDWIDTH' in server_client:
                if not validate_bandwidth(server_client['MAX_BANDWIDTH']) >= 0:
                    log.error(
                        f"IS 'SERVER_CLIENT' MAX_BANDWIDTH VALUE VALID FOR SERVER_CLIENT '{server_client['UID']}' : NO")
                    return False, None, None
                else:
                    log.debug(
                        f"IS 'SERVER_CLIENT' MAX_BANDWIDTH VALUE '{server_client['MAX_BANDWIDTH']}' VALID FOR SERVER_CLIENT '{server_client['UID']}' : YES")

        # Validate EXCLUDED_CLIENT_DICT (optional parameter)
        # Validating after all server_client configuration because it need all the UID, and if a server_client config is wrong, it would crash.
        for server_client in _config['SERVER_CLIENT']:
            if 'EXCLUDED_CLIENT_UID' in server_client:
                if not validate_excluded_client(server_client, _config):
                    log.error(
                        f"IS 'SERVER_CLIENT' EXCLUDED_CLIENT_UID VALUE VALID FOR SERVER_CLIENT '{server_client['UID']}' : NO")
                    return False, None, None
                else:
                    log.debug(
                        f"IS 'SERVER_CLIENT' EXCLUDED_CLIENT_UID VALUE VALID FOR SERVER_CLIENT '{server_client['UID']}' : YES")

    # Validating MESH_GROUP AND GENERATING CONFIG
    if 'MESH_GROUP' in _config:
        if validate_group(_config, "MESH_GROUP"):
            # As a mesh server, this SYNTRAF must generate the client configuration for each nodes
            if 'SERVER_CLIENT' in _config:
                _dict_by_node_generated_config, _dict_by_group_of_generated_tuple_for_map = generate_client_config_mesh(_config)
            else:
                return True, {}, {}
        else:
            log.error(f"ARE ALL 'MESH_GROUP' VALID : NO")
            return False, None, None
    else:
        log.error(f"NO 'MESH_GROUP' FOUND!")
        #return False, None, None

    # Validating P2P AND GENERATING CONFIG
    if 'P2P_GROUP' in _config:
        if validate_group(_config, "P2P_GROUP"):
            pass
            # As a mesh server, this SYNTRAF must generate the client configuration for each nodes
            generate_client_config_p2p(_config)
        else:
            log.error(f"ARE ALL 'P2P_GROUP' VALID : NO")
            return False, None, None
    else:
        log.info(f"NO 'P2P_GROUP' FOUND!")
        #return False, None, None

    return True, _dict_by_node_generated_config, _dict_by_group_of_generated_tuple_for_map


#################################################################################
### Validation of a EXCLUDED_CLIENT_DICT
#################################################################################
def validate_excluded_client(server_client, _config):
    # Create a collection of all mesh client and associated group pairs
    coll_server_client = defaultdict(list)
    for client in _config['SERVER_CLIENT']:
        for group in client['MESH_GROUP_UID_LIST']:
            coll_server_client[group].append(client['UID'])

    found = False
    for excluded_group, excluded_client_array in server_client['EXCLUDED_CLIENT_UID'].items():
        for client in excluded_client_array:
            found = False
            try:
                if client in coll_server_client[excluded_group]:
                    found = True
            except Exception as exc:
                found = False

        if not found:
            return False

    return True


#################################################################################
### Validation of a P2P_GROUP_UID
#################################################################################
def validate_p2p_group_uid_list(server_client, _config):
    # Create a list of valid p2p_group
    list_p2p_group = []
    for p2p_group in _config['P2P_GROUP']:
        list_p2p_group.append(p2p_group['UID'])

    # Create a list of valid server_client
    list_server_client = []
    for server_client in _config['SERVER_CLIENT']:
        list_server_client.append(server_client['UID'])

    # Create a list of valid server_client
    for server_client in _config['SERVER_CLIENT']:
        if 'P2P_GROUP_UID_LIST' in server_client:
            p2p_group_uid_list = server_client['P2P_GROUP_UID_LIST']
            for p2p_group_peer_item in p2p_group_uid_list:
                if not p2p_group_peer_item['GROUP'] in list_p2p_group:
                    log.error(f"IS {p2p_group_peer_item['GROUP']} GROUP IN P2P_GROUP_UID_LIST IN SERVER_CLIENT '{server_client['UID']}' EXIST : NO")
                    return False
                elif not p2p_group_peer_item['PEER'] in list_server_client:
                    log.error(f"IS {p2p_group_peer_item['PEER']} A VALID CLIENT IN SERVER_CLIENT '{server_client['UID']}' : NO")
                    return False
                else:
                    log.debug(
                        f"IS P2P_GROUP_UID_LIST '{server_client['P2P_GROUP_UID_LIST']}' IN SERVER_CLIENT '{server_client['UID']}' VALID : YES")

    return True

#################################################################################
### Validation of a MESH_GROUP_UID
#################################################################################
def validate_mesh_group_uid_list(server_client, _config):
    # Create a list of valid mesh_group
    list_mesh_group = []
    for mesh_group in _config['MESH_GROUP']:
        list_mesh_group.append(mesh_group['UID'])

    for mesh_group_uid in server_client['MESH_GROUP_UID_LIST']:
        if not mesh_group_uid in list_mesh_group:
            log.error(
                f"IS {mesh_group_uid} GROUP IN MESH_GROUP_UID_LIST IN SERVER_CLIENT '{server_client['UID']}' EXIST : NO")
            return False
        else:
            log.debug(
                f"IS {mesh_group_uid} GROUP IN MESH_GROUP_UID_LIST IN SERVER_CLIENT '{server_client['UID']}' EXIST : YES")

    return True


#################################################################################
### Validation of a MESH_GROUP_UID
### All the nodes specified must exists
### The format of the IP address specified must be valid
### exemple : {'CENTOS8-VM': '10.2.0.201', 'LAB3-VM': '10.2.0.201'}
#################################################################################
def validate_override_dst_node_ip(server_client, _config):
    validation_ok = True

    #validation of the IP's
    for ip in server_client['OVERRIDE_DST_NODE_IP'].values():
        if not is_ip_or_hostname_valid(ip, "CLIENT_IP"):
            log.error(
                f"IS '{ip}' A VALID IP ADDRESS IN OVERRIDE_DST_NODE_IP IN SERVER_CLIENT '{server_client['UID']}' : NO")
            validation_ok = False
        else:
            log.debug(
                f"IS '{ip}' A VALID IP ADDRESS IN OVERRIDE_DST_NODE_IP IN SERVER_CLIENT '{server_client['UID']}' : YES")

    # validation of the client's UID
    for override_ip_client_uid in server_client['OVERRIDE_DST_NODE_IP']:
        found = False
        for server_client in _config['SERVER_CLIENT']:
            if server_client['UID'] == override_ip_client_uid:
                found = True
        if not found:
            log.error(f"IS {override_ip_client_uid} CLIENT UID IN OVERRIDE_DST_NODE_IP IN SERVER_CLIENT '{server_client['UID']}' EXIST : NO")
            validation_ok = False
        else:
            log.debug(
                f"IS {override_ip_client_uid} CLIENT UID IN OVERRIDE_DST_NODE_IP IN SERVER_CLIENT '{server_client['UID']}' EXIST : YES")
    return validation_ok

#################################################################################
### Validation of an IP Adresse (ipv4)
#################################################################################
def validate_ipv4(ip):
    return bool(re.match(r'^((\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])\.){3}(\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])$', ip))


#################################################################################
### Validation of a UID
#################################################################################
def validate_uid(uid):
    regex_allowed_char = re.compile(r'^[A-Za-z0-9_-]+$')
    return bool(regex_allowed_char.search(uid))


#################################################################################
### Validation of MESH_GROUP
#################################################################################
def validate_group(_config, group_type):
    for group in _config[group_type]:

        # Validation of the UID, mandatory config and must be A-Za-z0-9_-
        if 'UID' in group:
            if not validate_uid(group['UID']):
                log.error(
                    f"IS UID VALUE '{group['UID']}' VALID : NO    (ONLY A-Za-z0-9_- ALLOWED)")
                return False

        # Validation of the BANDWIDTH
        if 'BANDWIDTH' in group:
            if not validate_bandwidth(group['BANDWIDTH']) >= 0:
                log.error(
                    f"IS BANDWIDTH VALUE '{group['BANDWIDTH']}' VALID FOR SERVER GROUP '{group['UID']}' : NO")
                return False

        # Validation of the TOS
        if 'DSCP' in group:
            if not validate_dscp(group['DSCP']):
                group['DSCP'] = DefaultValues.DEFAULT_DSCP
                log.warning(
                    f"DSCP PARAMETER INVALID FOR SERVER GROUP '{group['UID']}': APPLYING DEFAULT OF {DefaultValues.DEFAULT_DSCP}")
        else:
            group['DSCP'] = DefaultValues.DEFAULT_DSCP
            log.warning(
                f"DSCP PARAMETER NOT FOUND FOR SERVER GROUP '{group['UID']}': APPLYING DEFAULT OF {DefaultValues.DEFAULT_DSCP}")

        # Validation of the PACKET_SIZE
        if "PACKET_SIZE" in group:
            if not validate_packet_size(group['PACKET_SIZE']):
                group['PACKET_SIZE'] = DefaultValues.DEFAULT_PACKET_SIZE
                log.warning(
                    f"PACKET_SIZE PARAMETER INVALID FOR SERVER GROUP '{group['UID']}': APPLYING DEFAULT OF '{DefaultValues.DEFAULT_PACKET_SIZE}'")
        else:
            group['PACKET_SIZE'] = DefaultValues.DEFAULT_PACKET_SIZE
            log.warning(
                f"PACKET_SIZE PARAMETER NOT FOUND FOR SERVER GROUP '{group['UID']}': APPLYING DEFAULT OF '{DefaultValues.DEFAULT_PACKET_SIZE}'")

        # VALIDATING INTERVAL
        if "INTERVAL" in group:
            if not validate_interval(group['INTERVAL']):
                group['INTERVAL'] = DefaultValues.DEFAULT_INTERVAL
                log.warning(
                    f"INTERVAL PARAMETER INVALID FOR SERVER GROUP '{group['UID']}': APPLYING DEFAULT OF '{DefaultValues.DEFAULT_INTERVAL}'")
        else:
            group['INTERVAL'] = DefaultValues.DEFAULT_INTERVAL
            log.warning(
                f"BANDWIDTH PARAMETER NOT FOUND FOR SERVER GROUP '{group['UID']}': APPLYING DEFAULT OF '{DefaultValues.DEFAULT_INTERVAL}'")

    return True



#################################################################################
### Generate the client configs (p2p part)
#################################################################################
def generate_client_config_p2p(_config):
    pass


#################################################################################
### Generate the client configs (mesh part)
#################################################################################
def generate_client_config_mesh(_config, _dict_by_node_generated_config={}):
    dict_obj_connectors = {}
    dict_obj_listeners = {}
    _list_generated_pair_uid = []
    _dict_port_ref = {}
    _list_tuple_for_map_gen = []
    _dict_by_group_of_generated_tuple_for_map = {}

    # Populating the port_ref for each client
    listeners_ports = list(map(int, _config['SERVER']['MESH_LISTENERS_PORT_RANGE'].split('-')))
    for client in _config['SERVER_CLIENT']:
        _dict_port_ref[client['UID']] = listeners_ports

    # iterate over all mesh_group and generate config for every client
    for mesh_group in _config['MESH_GROUP']:
        # This list is use to fill a dictionnary (_dict_by_group_of_generated_tuple_for_map) in which the keys are the mesh_group. We need to reinitalize it at each loop so that it contain only the nodes of the current group
        _list_tuple_for_map_gen = []

        # Loop over all client
        for client in _config['SERVER_CLIENT']:

            # if the current client is member of the current mesh_group
            if mesh_group['UID'] in client['MESH_GROUP_UID_LIST']:

                # Loop over all mesh client
                for client2 in _config['SERVER_CLIENT']:
                    # if the current client is member of the current mesh_group
                    if mesh_group['UID'] in client2['MESH_GROUP_UID_LIST']:

                        # process all client2 if it's not the current client. The goal is to generate connectors and listeners to all nodes in the mesh_group except current client.
                        if not client2['UID'] == client['UID']:

                            pair_UID_1 = mesh_group['UID'] + "_" + client['UID'] + "_" + client2['UID']
                            pair_UID_2 = mesh_group['UID'] + "_" + client2['UID'] + "_" + client['UID']

                            # Check if this pair has not already been done
                            if not pair_UID_1 in _list_generated_pair_uid and not pair_UID_2 in _list_generated_pair_uid:

                                # Adding pair UID so that we don't process the same pair when the loop stumble upon the other client2 as client1
                                _list_generated_pair_uid.append(pair_UID_1)
                                _list_generated_pair_uid.append(pair_UID_2)

                                # Apply partial mesh configuration
                                # When one of the two client has the other in his INCLUDE_ONLY_CLIENT_UID for the current group
                                if not client.get('INCLUDE_ONLY_CLIENT_UID', None) is None or not client2.get('INCLUDE_ONLY_CLIENT_UID', None) is None:
                                    if mesh_group['UID'] in client.get('INCLUDE_ONLY_CLIENT_UID', []) or mesh_group['UID'] in client2.get('INCLUDE_ONLY_CLIENT_UID', []):
                                        if not client2['UID'] in client.get('INCLUDE_ONLY_CLIENT_UID', {}).get(mesh_group['UID'], []) and not client['UID'] in client2.get('INCLUDE_ONLY_CLIENT_UID', {}).get(mesh_group['UID'], []):
                                            continue

                                else:
                                    if 'EXCLUDED_CLIENT_UID' in client:
                                        if mesh_group['UID'] in client['EXCLUDED_CLIENT_UID']:
                                            if client2['UID'] in client['EXCLUDED_CLIENT_UID'][mesh_group['UID']]:
                                                continue

                                    if 'EXCLUDED_CLIENT_UID' in client2:
                                        if mesh_group['UID'] in client2['EXCLUDED_CLIENT_UID']:
                                            if client['UID'] in client2['EXCLUDED_CLIENT_UID'][mesh_group['UID']]:
                                                continue

                                # Once we excluded the node, we can create the dict that will be use to generate the map
                                _list_tuple_for_map_gen.append((client['UID'], client2['UID']))
                                _list_tuple_for_map_gen.append((client2['UID'], client['UID']))

                                # obtain a free port for the listeners
                                listener_client1_port = find_free_port(_dict_port_ref, client['UID'])
                                listener_client2_port = find_free_port(_dict_port_ref, client2['UID'])

                                client_ip = client['IP_ADDRESS']
                                client2_ip = client2['IP_ADDRESS']

                                if 'OVERRIDE_DST_NODE_IP' in client:
                                    for k, v in client['OVERRIDE_DST_NODE_IP'].items():
                                        if k == client2['UID']:
                                            client2_ip = v

                                if 'OVERRIDE_DST_NODE_IP' in client2:
                                    for k, v in client2['OVERRIDE_DST_NODE_IP'].items():
                                        if k == client['UID']:
                                            client_ip = v


                                # add the listeners and connectors of the current pair
                                obj_listener_client_listener = st_obj_mesh(syntraf_instance_type="LISTENER",
                                                                                UID_CLIENT=client2['UID'],
                                                                                UID_SERVER=client['UID'],
                                                                                PORT=listener_client1_port,
                                                                                INTERVAL=mesh_group['INTERVAL'],
                                                                                BIND_ADDRESS=client['IP_ADDRESS'],
                                                                                CLIENT_PARAM_DSCP=mesh_group['DSCP'],
                                                                                MESH_GROUP=mesh_group['UID'],
                                                                                CLIENT_PARAM_PACKET_SIZE=mesh_group[
                                                                                    'PACKET_SIZE'])

                                obj_connector_client_connector = st_obj_mesh(syntraf_instance_type="CONNECTOR",
                                                                                UID_CLIENT=client['UID'],
                                                                                UID_SERVER=client2['UID'],
                                                                                DESTINATION_ADDRESS=client2_ip,
                                                                                PORT=listener_client2_port,
                                                                                BANDWIDTH=mesh_group['BANDWIDTH'],
                                                                                DSCP=mesh_group['DSCP'],
                                                                                MESH_GROUP=mesh_group['UID'],
                                                                                PACKET_SIZE=mesh_group['PACKET_SIZE'])

                                obj_listener_client2_listener = st_obj_mesh(syntraf_instance_type="LISTENER",
                                                                                UID_CLIENT=client['UID'],
                                                                                UID_SERVER=client2['UID'],
                                                                                PORT=listener_client2_port,
                                                                                INTERVAL=mesh_group['INTERVAL'],
                                                                                BIND_ADDRESS=client2['IP_ADDRESS'],
                                                                                CLIENT_PARAM_DSCP=mesh_group['DSCP'],
                                                                                MESH_GROUP=mesh_group['UID'],
                                                                                CLIENT_PARAM_PACKET_SIZE=mesh_group[
                                                                                 'PACKET_SIZE'])

                                obj_connector_client2_connector = st_obj_mesh(syntraf_instance_type="CONNECTOR",
                                                                                UID_CLIENT=client2['UID'],
                                                                                UID_SERVER=client['UID'],
                                                                                DESTINATION_ADDRESS=client_ip,
                                                                                PORT=listener_client1_port,
                                                                                BANDWIDTH=mesh_group['BANDWIDTH'],
                                                                                DSCP=mesh_group['DSCP'],
                                                                                MESH_GROUP=mesh_group['UID'],
                                                                                PACKET_SIZE=mesh_group['PACKET_SIZE'])

                                # Creating array inside dictionary before appending the objects
                                if not client['UID'] in dict_obj_listeners:
                                    dict_obj_listeners[client['UID']] = []
                                if not client['UID'] in dict_obj_connectors:
                                    dict_obj_connectors[client['UID']] = []
                                if not client2['UID'] in dict_obj_listeners:
                                    dict_obj_listeners[client2['UID']] = []
                                if not client2['UID'] in dict_obj_connectors:
                                    dict_obj_connectors[client2['UID']] = []

                                # Adding listeners and connectors
                                dict_obj_listeners[client['UID']].append(obj_listener_client_listener)
                                dict_obj_listeners[client2['UID']].append(obj_listener_client2_listener)
                                dict_obj_connectors[client['UID']].append(obj_connector_client_connector)
                                dict_obj_connectors[client2['UID']].append(obj_connector_client2_connector)

        _dict_by_group_of_generated_tuple_for_map[mesh_group['UID']] = _list_tuple_for_map_gen

    # We must validate if the MAX_BANDWIDTH clause is respected for each client
    for m_client in _config['SERVER_CLIENT']:
        if 'MAX_BANDWIDTH' in m_client:
            sum_bandwidth = 0
            for l in dict_obj_connectors[m_client['UID']]:
                sum_bandwidth += validate_bandwidth(l.bandwidth)
            max_bandwidth = validate_bandwidth(m_client['MAX_BANDWIDTH'])
            if sum_bandwidth > max_bandwidth:
                log.error(f"MAX_BANDWIDTH '{max_bandwidth}' FOR CLIENT '{m_client['UID']}' EXCEEDED. ONE WAY SUM IS '{sum_bandwidth}'.")
                sys.exit()

    # Now, we need to add the final dictionary wrapping "LISTENER" and "CONNECTOR" by node
    # For doing that, we need to create a dictionary for each node and insert the listeners and connectors in it

    for k, v in dict_obj_listeners.items():
        _dict_by_node_generated_config[k] = {}
        _dict_by_node_generated_config[k]['LISTENERS'] = {}
        for obj in v:
            _dict_by_node_generated_config[k]['LISTENERS'][obj.theindexname()] = obj.asdict()

    for k, v in dict_obj_connectors.items():
        if k not in _dict_by_node_generated_config:
            _dict_by_node_generated_config[k] = {}
        _dict_by_node_generated_config[k]['CONNECTORS'] = {}
        for obj in v:
            _dict_by_node_generated_config[k]['CONNECTORS'][obj.theindexname()] = obj.asdict()

    return _dict_by_node_generated_config, _dict_by_group_of_generated_tuple_for_map


#################################################################################
### Use the "port_ref" key of provided dictionary, associated with a
### UID to remove a port from the available list and return that port.
#################################################################################
def find_free_port(_dict_port_ref, uid):
    assigned_port = 0
    for key, port_ref in _dict_port_ref.items():
        if key == uid:
            if (port_ref[1] - port_ref[0]) >= 1:
                assigned_port = port_ref[1]
                port_ref[1] -= 1
            else:
                log.error(
                    f"Port exhaustion encountered when generating client configuration. Please expand the MESH_LISTENERS_PORT_RANGE value.")
                return assigned_port

    return assigned_port


def config_file_exist_info(_config, group, key, log):
    if key in _config[group]:

        if not len(_config[group][key]) <= 0:

            if file_exist(_config[group][key]):
                log.debug(
                    f"IS '{key}' SPECIFIED FILE '{_config[group][key]}' EXIST : YES")
            else:
                log.debug(
                    f"IS '{key}' SPECIFIED FILE '{_config[group][key]}' EXIST : NO")
                return False
        else:
            log.debug(
                f"IS '{key}' SPECIFIED FILE '{_config[group][key]}' EXIST : NO")
            return False
    else:
        return False
    return True


#################################################################################
### RETURN TRUE IF FILE EXIST
### USED BY config_file_exist()
#################################################################################
def file_exist(path):
    file = pathlib.Path(path)
    if not file.exists():
        return False
    return True


#################################################################################
### RETURN TRUE IF IPERF SUPPORT TIMESTAMP
#################################################################################
def is_iperf3_support_skew_threshold(_config, iperf_bin_path):
    args = (iperf_bin_path, "-h")
    # Some version of iperf3 output help to stderr, merging both
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    if not "--time-skew-threshold" in result.stdout.decode('utf-8'):
        log.error(f"DOES IPERF BINARY {_config['GLOBAL']['IPERF3_BINARY_PATH']} SUPPORT TIME SKEW THRESHOLD (--time-skew-threshold) : NO")
        return False
    else:
        log.debug(
            f"DOES IPERF BINARY {iperf_bin_path} SUPPORT TIME SKEW THRESHOLD (--time-skew-threshold) : YES")
        return True


#################################################################################
### RETURN TRUE IF IPERF SUPPORT TIMESTAMP
#################################################################################
def is_iperf3_support_timestamp(_config, iperf_bin_path):
    args = (iperf_bin_path, "-h")
    # Some version of iperf3 output help to stderr, merging both
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    if not "--timestamps" in result.stdout.decode('utf-8'):
        log.error(
            f"DOES IPERF BINARY {_config['GLOBAL']['IPERF3_BINARY_PATH']} SUPPORT TIMESTAMP (--timestamps) : NO")
        log.error("See : https://github.com/esnet/iperf/issues/909")
        return False
    else:
        log.debug(
            f"DOES IPERF BINARY {iperf_bin_path} SUPPORT TIMESTAMP (--timestamps) : YES")
        return True


#################################################################################
### RETURN TRUE IF IPERF BUILT WITH SSL
#################################################################################
def is_iperf3_support_ssl(_config, iperf_bin_path):
    args = (iperf_bin_path, "-h")
    # Some version of iperf3 output help to stderr, merging both
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    if not "--rsa-private-key-path" in result.stdout.decode('utf-8'):
        log.error(
            f"DOES IPERF BINARY {_config['GLOBAL']['IPERF3_BINARY_PATH']} SUPPORT AUTHENTICATION (--rsa-private-key-path, --authorized-users-path, --rsa-public-key-path) : NO")
        return False
    else:
        log.debug(
            f"DOES IPERF BINARY {iperf_bin_path} SUPPORT AUTHENTICATION (--rsa-private-key-path, --authorized-users-path, --rsa-public-key-path) : YES")
        return True


#################################################################################
### RETURN FALSE IF PORT IS ALREADY TAKEN FOR THE SPECIFIED IP
#################################################################################
def is_port_available(ip, port):
    # validation du port qui sera utilisé
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.1)
    location = (ip, int(port))
    result = sock.connect_ex(location)

    if result == 0:
        log.error(
            f"IS PORT {port} ALREADY IN USE: YES")
        return False
    else:
        log.debug(
            f"IS PORT {port} ON {ip} ALREADY IN USE: NO")

    sock.close()
    return True


#################################################################################
### VALIDATE IF STRING IS IP OR VALID HOSTNAME
#################################################################################
def is_ip_or_hostname_valid(ip_host, config_name):
    retval = False

    if not ip_host:
        return False

    x = re.findall(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ip_host)
    if not x:
        # validation DNS
        log.debug(
            f"IS {config_name} '{ip_host}' MATCH IP ADDRESS REGEX : NO, MAYBE A HOSTNAME?")
        retval = False
        try:
            x = re.findall(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", str(socket.gethostbyname(ip_host)))
            if x:
                log.debug(
                    f"IS {config_name} '{ip_host}' RESOLVE TO A VALID IP : YES")
                retval = True
            else:
                log.error(
                    f"IS {config_name} '{ip_host}' RESOLVE TO A VALID IP : NO")
                retval = False
        except Exception as exc:
            log.error(
                f"IS {config_name} '{ip_host}' RESOLVE TO A VALID IP : NO")
            retval = False
    else:
        log.debug(f"IS {config_name} '{ip_host}' A VALID IP : YES")
        retval = True

    return retval


#################################################################################
### VALIDATE IF STRING IS A VALID PORT NUMBER
#################################################################################
def is_port_valid(port, config_name):
    try:
        if port.isdigit():
            if not (1 <= int(port) <= 65534):
                log.error(
                    f"IS {config_name} '{port}' >= 1 AND <= 65534 : NO")
                return False
            else:
                log.debug(
                    f"IS {config_name} '{port}' >= 1 AND <= 65534 : YES")
        else:
            log.error(f"IS {config_name} '{port}' AN INTEGER : NO")
            return False

    except Exception as exc:
        log.error(f"is_port_valid:{type(exc).__name__}:{exc}", exc_info=True)

    return True
