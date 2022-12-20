# SYNTRAF GLOBAL IMPORT
from lib.st_crypto import *
from lib.st_struct import cl_ifreq
from lib.st_read_toml import read_conf
from lib.st_conf_validation import valid_dir_rsa_keypair, valid_dir_logs
from lib.st_process_and_thread import *
from tabulate import tabulate
# SYNTRAF SERVER IMPORT
if not CompilationOptions.client_only:
    # from gevent import monkey
    # monkey.patch_all()
    # from gevent import socket
    import socket
    # from gevent.server import StreamServer
    from gevent.pool import Pool
    from lib.st_influxdb import *  # import ssl after monkey patch because of urllib3

from lib.st_conf_validation import generate_client_config_mesh

# BUILTIN IMPORT
from socketserver import TCPServer, ThreadingMixIn, StreamRequestHandler
import logging
import sys
import time
import threading
import json
from json import JSONEncoder
import select
from lib import st_struct
import platform
import traceback
import pathlib
import os
import inspect
import os.path
import re
import struct
from datetime import datetime
from copy import copy, deepcopy
from ctypes import *

# To detect if the NIC is wireless or ethernet
if sys.platform == "linux":
    import fcntl
elif sys.platform == "win32":
    pass
elif sys.platform == "darwin":
    pass

# PACKAGE IMPORT
import ssl  # import ssl after monkey patch
import json
import pytz
from cpuinfo import get_cpu_info
import psutil

server_log = logging.getLogger("syntraf." + "lib.st_server")
client_log = logging.getLogger("syntraf." + "lib.st_client")


class cc_client:
    _status = "UNKNOWN"
    _status_since = "UNKNOWN"
    _status_explanation = "UNKNOWN"
    _bool_dynamic_client = False
    _client_uid = "UNKNOWN"
    _ip_address = ""
    _tcp_port = "UNKNOWN"
    _system_stats = {}
    _system_infos = {}
    _clock_skew_in_seconds = -1
    _syntraf_version = ""
    _thread_status = {}

    def __init__(self, status, status_since, status_explanation, bool_dynamic_client, client_uid, tcp_port=0,
                 ip_address=""):
        self._status = status
        self._status_since = status_since
        self._status_explanation = status_explanation
        self._bool_dynamic_client = bool_dynamic_client
        self._client_uid = client_uid
        self._ip_address = ip_address
        self._tcp_port = tcp_port

    # make it serializable so it can be returned by the WEBAPI
    def asjson(self):
        o_dict = self.__dict__
        j_dump = {}
        j_dump['status'] = self._status
        j_dump['status_since'] = self._status_since
        j_dump['status_explanation'] = self._status_explanation
        j_dump['bool_dynamic_client'] = self._bool_dynamic_client
        j_dump['client_uid'] = self._client_uid
        j_dump['ip_address'] = self._ip_address
        j_dump['clock_skew_in_seconds'] = self._clock_skew_in_seconds
        j_dump['syntraf_version'] = self._syntraf_version

        # Not connected client
        if '_system_stats' in o_dict:
            j_dump['system_stats'] = o_dict['_system_stats']

        # Not connected client
        if '_system_infos' in o_dict:
            j_dump['system_infos'] = o_dict['_system_infos']

        # Not connected client
        if '_thread_status' in o_dict:
            j_dump['thread_status'] = o_dict['_thread_status']

        return json.dumps(j_dump)

    def asdict(self):
        return {"STATUS": self.status, "STATUS_SINCE": self.status_since, "STATUS_EXPLANATION": self.status_explanation,
                "CLIENT_UID": self.client_uid, "IP_ADDRESS": self.ip_address, "TCP_PORT": self.tcp_port,
                "CLOCK_SKEW": self.clock_skew_in_seconds, "SYNTRAF_VERSION": self.syntraf_version}

    def get_thread_status(self):
        return self._thread_status

    def set_thread_status(self, value):
        self._thread_status = value

    def get_system_infos(self):
        return self._system_infos

    def set_system_infos(self, value):
        self._system_infos = value

    def get_syntraf_version(self):
        return self._syntraf_version

    def set_syntraf_version(self, value):
        self._syntraf_version = value

    def get_clock_skew_in_seconds(self):
        return self._clock_skew_in_seconds

    def set_clock_skew_in_seconds(self, value):
        self._clock_skew_in_seconds = value

    def get_system_stats(self):
        return self._system_stats

    def set_system_stats(self, value):
        self._system_stats = value

    def get_status_since(self):
        return self._status_since

    def set_status_since(self, value):
        self._status_since = value

    def get_status_explanation(self):
        return self._status_explanation

    def set_status_explanation(self, value):
        self._status_explanation = value

    def get_bool_dynamic_client(self):
        return self._bool_dynamic_client

    def set_bool_dynamic_client(self, value):
        self._bool_dynamic_client = value

    def get_status(self):
        return self._status

    def set_status(self, value):
        self._status = value

    def get_client_uid(self):
        return self._client_uid

    def set_client_uid(self, value):
        self._client_uid = value

    def get_ip_address(self):
        return self._ip_address

    def set_ip_address(self, value):
        self._ip_address = value

    def get_tcp_port(self):
        return self._tcp_port

    def set_tcp_port(self, value):
        self._tcp_port = value

    status = property(get_status, set_status)
    status_since = property(get_status_since, set_status_since)
    status_explanation = property(get_status_explanation, set_status_explanation)
    bool_dynamic_client = property(get_bool_dynamic_client, set_bool_dynamic_client)
    client_uid = property(get_client_uid, set_client_uid)
    ip_address = property(get_ip_address, set_ip_address)
    tcp_port = property(get_tcp_port, set_tcp_port)
    system_stats = property(get_system_stats, set_system_stats)
    system_infos = property(get_system_infos, set_system_infos)
    clock_skew_in_seconds = property(get_clock_skew_in_seconds, set_clock_skew_in_seconds)
    syntraf_version = property(get_syntraf_version, set_syntraf_version)


#################################################################################
###  SOCKET RCV
#################################################################################
def sock_rcv(sckt):
    try:
        # Waiting for a size in binary (long addressed on 4bytes)
        size = sckt.recv(4)
        if not size: return None

        # Unpacking the 4 bytes to get the size
        # https://docs.python.org/3/library/struct.html
        size_decoded = struct.unpack(">l", size)[0]

        bytes_left = size_decoded
        data = b''
        while bytes_left >= 1:
            data = data + sckt.recv(bytes_left)
            bytes_left = size_decoded - len(data)

        result = json.loads(data)
        return result

    except Exception as exc:
        raise exc


#################################################################################
###  SOCKET SENDALL
#################################################################################
def sock_send(sckt, payload, command):
    try:
        encoded_payload = json.dumps({'COMMAND': command, 'PAYLOAD': payload}, ensure_ascii=False, default=str).encode(
            "utf-8")
        data_size = struct.pack(">l", len(encoded_payload))

        sckt.sendall(data_size)
        sckt.sendall(encoded_payload)
        return True

    except Exception as exc:
        raise exc


def get_system_infos():
    uname = platform.uname()
    python_version = platform.python_version()
    cpu_infos = get_cpu_info()
    cpu_brand = cpu_infos['brand_raw']
    cpu_frequency = cpu_infos['hz_advertised_friendly']
    cpu_count_logical = psutil.cpu_count(logical=True)
    cpu_count_physical = psutil.cpu_count(logical=False)
    memory_mb_physical = round(psutil.virtual_memory().total / 1024 / 1024)
    boot_time = datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
    system_infos = {'SYSTEM': uname.system, 'NODE_NAME': uname.node, 'RELEASE': uname.release, 'VERSION': uname.version,
                    'PROCESSOR': uname.processor, 'PYTHON_VERSION': python_version, 'CPU_LOGICAL': cpu_count_logical,
                    'CPU_PHYSICAL': cpu_count_physical, 'MEMORY_MB': memory_mb_physical, 'BOOT_TIME': boot_time,
                    'CPU_FREQUENCY': cpu_frequency, 'CPU_MODEL': cpu_brand, 'TIMEZONE': DefaultValues.TIMEZONE}
    return system_infos


def client_sck_init(_config):
    ssl_conn = None
    try:

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        set_tcp_ka(s, client_log)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        # Validating if certificate hostname match
        context.check_hostname = False

        # We ask for the server certificate
        context.verify_mode = ssl.CERT_NONE

        # Wrapping the socket
        ssl_conn = context.wrap_socket(s, server_side=False, do_handshake_on_connect=True)

        client_log.info(f"TRYING TO CONNECT TO : {_config['CLIENT']['SERVER']}:{_config['CLIENT']['SERVER_PORT']}")

        # CONNECT
        ssl_conn.connect((_config['CLIENT']['SERVER'], int(_config['CLIENT']['SERVER_PORT'])))
        client_log.info(f"CONNECTED TO : {_config['CLIENT']['SERVER']}:{_config['CLIENT']['SERVER_PORT']}")

    except (ConnectionRefusedError, ConnectionResetError) as exc:
        client_log.error(
            f"ERROR CONNECTING TO {_config['CLIENT']['SERVER']}:{_config['CLIENT']['SERVER_PORT']} : CONNECTION REFUSED")
        sys.exit()
    except OSError as exc:
        # Network is unreachable
        if exc.errno == 101:
            client_log.error(
                f"ERROR CONNECTING TO {_config['CLIENT']['SERVER']}:{_config['CLIENT']['SERVER_PORT']} : NETWORK UNREACHABLE")
            sys.exit()
    except Exception as exc:
        client_log.error(f"client:{type(exc).__name__}:{exc}", exc_info=True)
        sys.exit()

    if ssl_conn is None:
        sys.exit()
    else:
        return ssl_conn


def client_connect_utime(_config):
    try:
        dt = datetime.now()
        timezone = pytz.timezone(DefaultValues.TIMEZONE)
        dt_tz = timezone.localize(dt)
        client_utime = dt_tz.astimezone(pytz.timezone("UTC")).timestamp()
        return client_utime
    except Exception as exc:
        raise exc


def client_detect_type_if():
    pass
    # ifreq = struct.pack('16sh', 'wlan0', 0)
    # flags = struct.unpack('16sh', fcntl.ioctl(sockfd, SIOCGIFFLAGS, ifreq))[1]
    # ifreq.ifr_name = c_char_p("wlp4s0".encode('utf-8'))
    # "wlp4s0".encode('utf-8')
    # ifreq.ifr_name = create_string_buffer(b"wlp4s0", IFNAMSIZ)

    # ss = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # IFNAMSIZ = 16
    # SIOCGIWNAME = 0x8B01
    # ifreq = st_struct.cl_ifreq()
    #
    # ifreq.ifr_name = b"wlp4s0"
    # ifreq.ifr_slave = b"wlp4s0"
    # print(b"wlp4s0".hex())
    #
    # if sys.platform == "linux":
    #     try:
    #         info = fcntl.ioctl(ss, SIOCGIWNAME, ifreq)
    #         print(info)
    #         print("wireless")
    #     except Exception as exc:
    #         print(exc)
    #         print("not wireless")


def client_send_auth(_config, client_utime, ssl_conn):
    try:
        # Sending TOKEN and UID for authentication, timestamp and version
        client_log.debug(f"SENDING GREETING PAYLOAD TO SERVER")
        payload_greetings = {'TOKEN': _config['CLIENT']['TOKEN'], 'CLIENT_UID': _config['CLIENT']['CLIENT_UID'],
                             'TIMESTAMP': client_utime, 'SYNTRAF_CLIENT_VERSION': DefaultValues.SYNTRAF_VERSION,
                             'PUBLIC_KEY': _config['CLIENT']['PUBLIC_KEY']}

        sock_send(ssl_conn, payload_greetings, "AUTH")
        received_data = sock_rcv(ssl_conn)

        if not received_data is None:
            if received_data['COMMAND'] == "AUTH_FAILED":
                client_log.info(f"AUTHENTICATION FAILED, REASON GIVEN BY SERVER : {received_data['PAYLOAD']}")
                return False
            else:
                client_log.info(f"AUTHENTICATION SUCCESSFULL")
                return True

    except Exception as exc:
        raise exc


def client_receive_configuration(_config, ssl_conn, threads_n_processes, config_file_path, cli_parameters):
    try:
        # If successful, receiving configuration!
        client_log.debug(f"WAITING FOR CONFIGURATION")
        received_data = sock_rcv(ssl_conn)

        # Todo, no received data
        if not received_data is None:
            # If no config for this client
            if received_data['PAYLOAD'] is None:
                client_log.warning(f"THE SERVER DOES NOT HAVE CONFIG FOR THIS NODE FOR NOW")
            else:
                client_log.info(f"NEW CONFIG RECEIVED FROM SERVER")

                # PROJ-A
                # If there is no changes, don't restart!
                read_success, disk_config = read_conf(config_file_path)
                if read_success:
                    update_config(received_data, disk_config)
                    valid_dir_rsa_keypair(disk_config)
                    valid_dir_logs(disk_config)
                    disk_config['GLOBAL']['LOGDIR'] = cli_parameters.log_dir

                    client_log.debug(_config)
                    client_log.debug(disk_config)

                    if disk_config == _config:
                        client_log.debug("SAME SAME SAME SAME")
                    else:
                        client_log.debug("DIFF DIFF DIFF DIFF")


                # got new config, close all listeners and connectors because if the server has restarted, all the credentials has been re-initialized
                client_log.debug(f"CLOSING LISTENERS AND CONNECTORS BEFORE APPLYING NEW CONFIG")
                close_listeners_and_connectors(threads_n_processes)

                # update local config
                client_log.debug(f"UPDATING LOCAL CONFIG WITH CONFIG SENT BY SERVER")
                update_config(received_data, _config)

                # Saving RSA keypair for iperf3 authentication
                client_log.debug(f"SAVING IPERF3 RSA KEYPAIR")
                save_credentials(received_data, _config)

                client_log.info(
                    f"CONFIG WILL LOAD IN LESS THAN {_config['GLOBAL']['WATCHDOG_CHECK_RATE']} seconds (see : WATCHDOG_CHECK_RATE)")
        else:
            client_log.info(f"RECEIVED DATA IS NONE")
    except Exception as exc:
        raise exc


def client_send_system_infos(ssl_conn):
    try:
        client_log.debug(f"SENDING SYSTEM INFOS TO SERVER")
        system_infos = get_system_infos()
        sock_send(ssl_conn, system_infos, "SYSTEM_INFOS")
    except Exception as exc:
        raise exc


def client_send_metrics(_config, ssl_conn, dict_data_to_send_to_server):
    try:
        # If we have some metric to save, send them to the server
        # We send a dictionnary to the server in which the key is a hash of the payload, and the payload are the metrics
        # Ounce we receive a ack, the payload will contain a list of all the hashes that were correctly written to disk.
        # Then we delete those key/value pair in our local dictionnary and print a count of how much of the data sent was written.

        client_log.debug(f"AMOUNT OF METRICS TO SEND TO SERVER: {len(dict_data_to_send_to_server)}")
        if len(dict_data_to_send_to_server) >= 1:
            # we need to extract hash and values as two different list.
            # the server will write as bulk, so once he confirmed everything is written, we can use the list of hash to remove thoses elements from "dict_data_to_send_to_server"
            # We extract the from dictionnary at the same time so that there is no insertion of metrics in between
            dict_data_to_send_to_server_as_array = list(dict_data_to_send_to_server.items())
            keys_of_metrics_to_send_to_server = [x[0] for x in dict_data_to_send_to_server_as_array]
            values_of_metrics_to_send_to_server = [x[1] for x in dict_data_to_send_to_server_as_array]

            sock_send(ssl_conn, values_of_metrics_to_send_to_server, "SAVE_METRIC")
            client_log.debug(
                f"METRICS DICTIONARY SENT WITH {len(values_of_metrics_to_send_to_server)} METRIC(S), WAITING FOR CONFIRMATION")
            received_data = sock_rcv(ssl_conn)
            client_log.debug(
                f"JUST RECEIVED THE FOLLOWING ANSWER FROM THE SERVER : {received_data['COMMAND']}:{received_data['PAYLOAD']}")
            if received_data:
                if received_data['PAYLOAD'] == "OK":
                    client_log.debug((
                        f"SERVER CONFIRMED THAT {len(values_of_metrics_to_send_to_server)} METRIC(S) HAS BEEN WRITEN TO DATABASE"))
                    # removing metrics from local queue as the server has acknowledged having written them to disk
                    for id in keys_of_metrics_to_send_to_server:
                        # if the dict has attain max length define (DEFAULT_WRITE_QUEUE_BUFFER_DEPTH), it is possible the id is no longer there.
                        if id in dict_data_to_send_to_server:
                            dict_data_to_send_to_server.pop(id)

                elif received_data['PAYLOAD'] == "NOK":
                    client_log.error(f"SERVER WAS UNABLE TO WRITE METRICS TO DATABASE")
            else:
                client_log.error(
                    f"CONNECTION TO {_config['CLIENT']['SERVER']}:{_config['CLIENT']['SERVER_PORT']} LOST")
                return False
        return True
    except Exception as exc:
        raise exc


def client_send_heartbeat(ssl_conn):
    try:
        sock_send(ssl_conn, "", "HEARTBEAT")
    except Exception as exc:
        raise exc


def client_send_system_stats(ssl_conn, obj_stats):
    # We send the system stats to the server
    # Custom classes are not serializable, so dumping obj_stats properties into a dict
    try:
        if obj_stats.hasdata:
            sock_send(ssl_conn, obj_stats.as_dict(), "SAVE_STATS_METRIC")
            obj_stats.hasdata = False
            client_log.debug(f"SYSTEM STATS SENT TO SERVER")
        else:
            client_log.debug(f"NO SYSTEM STATS TO SEND TO SERVER")
    except Exception as exc:
        raise exc


def client_awaiting_command(ssl_conn):
    try:
        # We give the chance to the server to send us an action
        #client_log.debug(f"BEFORE ASKING FOR COMMAND TO THE SERVER")
        sock_send(ssl_conn, "", "AWAITING_COMMAND")
        #client_log.debug(f"AFTER ASKING FOR COMMAND TO THE SERVER")

        # Receiving the answer
        #client_log.debug(f"BEFORE RECEIVING COMMAND OR NOP FROM THE SERVER")
        received_data = sock_rcv(ssl_conn)
        #client_log.debug(f"AFTER RECEIVING COMMAND OR NOP FROM THE SERVER")
    except Exception as exc:
        raise exc

    return received_data


def client_command_reconnect(ssl_conn):
    """
    This function is called when a client receive the COMMAND "RECONNECT_CLIENT".
    It close the current socket, then exit the client thread.
    At the next watchdog loop, the client thread will be respawned and the client will reconnect.
    :param ssl_conn: The current ssl socket
    """
    try:
        client_log.info("RECEIVED A REQUEST FROM THE SERVER TO DISCONNECT")
        ssl_conn.shutdown(socket.SHUT_RDWR)
        ssl_conn.close()
        client_log.info("DISCONNECTED")
        sys.exit()
    except Exception as exc:
        raise exc


def client_command_restart(ssl_conn):
    """
    This function is called when a client receive the COMMAND "RESTART_CLIENT".
    It remove the pid lock file, close the current socket and restart the syntraf master process
    It restart differently if it's inside a bundle or not.
    :param ssl_conn: The current ssl socket
    """
    try:
        client_log.info("RECEIVED A REQUEST FROM THE SERVER TO RESTART")

        # shutting down socket
        ssl_conn.shutdown(socket.SHUT_RDWR)
        ssl_conn.close()

        # remove pid file
        pid_file_path = DefaultValues.SYNTRAF_PID_FILE
        pid_file = pathlib.Path(pid_file_path)
        pid_file.unlink()

        # if we are inside a pyinstaller bundle
        if getattr(sys, 'frozen', False):
            os.execv(sys.executable, sys.argv)
        # Windows only for now
        else:
            os.execl(sys.executable, 'python', *sys.argv)
    except Exception as exc:
        raise exc


def client_send_thread_status(ssl_conn, threads_n_processes):
    # We send the threads status to the server
    # Custom classes are not serializable, so dumping st_obj_process_n_thread properties into a dict
    try:
        thread_status = {}
        for thr in threads_n_processes:
            if not thr.syntraf_instance_type == "READ_LOG":
                thread_status[thr.name + thr.syntraf_instance_type] = thr.asjson()

        sock_send(ssl_conn, thread_status, "SAVE_THREAD_STATUS")
        client_log.debug(f"THREAD STATUS SENT TO SERVER")
    except Exception as exc:
        raise exc


def client_command_diffconfig(_config, received_data, threads_n_processes):
    try:
        client_log.info("RECEIVED A REQUEST TO UPDATE LOCAL CONFIG WITH A DIFFCONFIG")

        # A dynamic client just connected, we need to add his IP address to the local config
        if received_data['PAYLOAD']['ELEMENT'] == "CLIENT_IP":
            # In case there was no CONNECTORS associated with that client, there is no IP to update.
            if 'CONNECTORS' in _config:
                for connector_key, connector in _config['CONNECTORS'].items():
                    # If a CONNECTOR config match the client_uid, change the destination_address for the one we just received.
                    # If we receive a valid IP we do not need to restart the connector, the next loop will launch the process for the first time
                    # But if we are setting it to the default IP for dynamic client "0.0.0.0", process_and_thread will not start a CONNECTOR when there is that IP assigned. We will take care to terminate the actual CONNECTOR.
                    if re.match(
                            r"^.{40}_MEMBER_OF_GROUP_.+_CONNECTING_TO_" + received_data['PAYLOAD']['CLIENT_UID'] + "$",
                            connector_key):
                        _config['CONNECTORS'][connector_key]['DESTINATION_ADDRESS'] = received_data['PAYLOAD']['IP_ADDRESS']
                        client_log.info(
                            f"CONNECTOR: '{connector_key}' DESTINATION IP ADDRESS UPDATED WITH '{received_data['PAYLOAD']['IP_ADDRESS']}'")

                        # If we are reverting to unknown dynamic IP client, we should terminate the associated CONNECTOR
                        if received_data['PAYLOAD']['IP_ADDRESS'] == "0.0.0.0":
                            for thr in threads_n_processes:
                                if thr.syntraf_instance_type == "CONNECTOR" and thr.name == connector_key:
                                    client_log.info(
                                        f"CONNECTOR: '{connector_key}' TERMINATED BECAUSE IP ADDRESS IS NOW UNKNOWN (CLIENT IS NOT CONNECTED TO SERVER ANYMORE)'")
                                    thr.close()
                                    terminate_connector(threads_n_processes, connector_key, thr, _config)
    except Exception as exc:
        raise exc


#################################################################################
###  MESH CLIENT SOCKET
#################################################################################
def client(_config, stop_thread, dict_data_to_send_to_server, threads_n_processes, obj_stats, config_file_path, cli_parameters):
    address = "0.0.0.0"
    ssl_conn = None
    try:
        ssl_conn = client_sck_init(_config)
        client_utime = client_connect_utime(_config)
        successful_auth = client_send_auth(_config, client_utime, ssl_conn)

        if not successful_auth:
            ssl_conn.close()
            return

        client_receive_configuration(_config, ssl_conn, threads_n_processes, config_file_path, cli_parameters)
        client_send_system_infos(ssl_conn)

        while True:
            if stop_thread[0]: break

            client_send_heartbeat(ssl_conn)

            client_send_thread_status(ssl_conn, threads_n_processes)

            if not client_send_metrics(_config, ssl_conn, dict_data_to_send_to_server): break

            client_send_system_stats(ssl_conn, obj_stats)

            received_data = client_awaiting_command(ssl_conn)

            if not received_data is None:
                if received_data['COMMAND'] == "RECONNECT_CLIENT":
                    client_command_reconnect(ssl_conn)

                if received_data['COMMAND'] == "RESTART_CLIENT":
                    client_command_restart(ssl_conn)

                # We just received a specific part of the configuration that we should change locally.
                elif received_data['COMMAND'] == "DIFFCONFIG":
                    client_command_diffconfig(_config, received_data, threads_n_processes)

                client_log.debug(f"SLEEPING FOR {DefaultValues.CONTROL_CHANNEL_HEARTBEAT} SECOND(S)")
                time.sleep(DefaultValues.CONTROL_CHANNEL_HEARTBEAT)
                # client_log.debug(f"SLEEP IS OVER")

            else:
                client_log.info(f"RECEIVED DATA IS NONE")

    except socket.timeout as exc:
        client_log.error(f"SOCKET TIMEOUT: {address}: CLOSING CONNECTION")
    except OSError as exc:
        if exc.errno == 32:  # BROKEN PIPE, THE OTHER END HAS GONE AWAY
            client_log.error(f"BROKEN PIPE: {address}: CLOSING CONNECTION")
        # CONNECTION RESET BY PEER
        elif exc.errno == 104:
            client_log.error(f"CONNECTION RESET BY PEER: {address}: CLOSING CONNECTION")
        elif exc.errno == 113:
            client_log.error(f"NO ROUTE TO HOST: {address}: CLOSING CONNECTION")
        # CONNECTION TIMEOUT
        elif exc.errno == 110:
            client_log.error(f"CONNECTION TIMEOUT: {address}: CLOSING CONNECTION")
        # FOR WINDOWS [WinError 10053] #An established connection was aborted by the software in your host machine
        elif exc.errno == 10053:
            client_log.error(f"CONNECTION ABORTED: {address}: CLOSING CONNECTION")
        # FOR WINDOWS [WinError 10054]
        elif exc.errno == 10054:
            client_log.error(f"CONNECTION RESET BY PEER: {address}: CLOSING CONNECTION")
        elif exc.errno == 10057:  # FOR WINDOWS [WinError 10057]
            client_log.error(f"{type(exc).__name__.upper()}:{exc.errno}: {address}: CLOSING CONNECTION")
        elif exc.errno == 8:
            client_log.error(f"INVALID SSL CONNECTION. SERVER PROBABLY TERMINATED THE CONNECTION.")
        else:
            client_log.error(f"UNHANDLE OSError (st_mesh:sock_rcv): {address}:", exc, exc.errno, exc.strerror)
    except json.JSONDecodeError as exc:
        client_log.error(f"JSON DECODING FAILED FOR STRING")
    except ConnectionResetError as exc:
        client_log.error(f"CONNECTION TO {_config['CLIENT']['SERVER']}:{_config['CLIENT']['SERVER_PORT']} LOST")
    except Exception as exc:
        client_log.error(f"client:{type(exc).__name__}:{exc}", exc_info=True)
    finally:
        try:
            ssl_conn.close()
        except Exception as e:
            pass


def validate_clock_skew(_config, received_data, obj_client):
    """
    This function compare the time between the server and the client.
    The objective is to show a warning to the user.
    Unsynchronized client will lead to graph not being aligned and make the comparison difficult.
    Plus, iperf3 with RSA does not like clock skew. There is a workaround by setting IPERF3_TIME_SKEW_THRESHOLD,
    but it's preferable to just sync the clock.
    :param _config: The TOML config file (nested dict)
    :param received_data: The payload we just received from the client containing the systems stats metric
    :param obj_client: The object representing the current client
    """
    dt = datetime.now()
    timezone = pytz.timezone(DefaultValues.TIMEZONE)
    dt_tz = timezone.localize(dt)
    server_utime = dt_tz.astimezone(pytz.timezone("UTC")).timestamp()
    client_utime = received_data['PAYLOAD']['TIMESTAMP']
    clock_skew = server_utime - client_utime
    obj_client.clock_skew_in_seconds = clock_skew
    if abs(clock_skew) > int(_config['GLOBAL']['IPERF3_TIME_SKEW_THRESHOLD']):
        server_log.warning(
            f"CONTEXT: {obj_client.client_uid} - CLOCK SKEW BETWEEN CLIENT AND SERVER IS TOO GREAT '{clock_skew} SECONDS'. WARNING : IF THE SAME SKEW HAPPEN BETWEEN NODES, THE IPERF3 CONTROL CHANNEL WILL FAIL. IF YOU CANNOT TIME SYNC THE NODES, YOU CAN ADJUST THE CLOCK OF THE NODES OR CHANGE THE VAR 'SERVER_IPERF3_TIME_SKEW_THRESHOLD'")


def authenticate_server_client(_config, data, obj_client, sckt):
    valid_token = False
    valid_server_client = False
    ip_addr = sckt.getpeername()[0]
    rejection_explanation = ""

    for description, token in _config['SERVER']['TOKEN'].items():
        if data['PAYLOAD']['TOKEN'] == token:
            valid_token = True

    if is_valid_server_client(_config, data['PAYLOAD']['CLIENT_UID'], sckt):
        valid_server_client = True

    if valid_token and valid_server_client:
        server_log.info(
            f"AUTHENTICATION SUCCESSFUL FROM IP '{ip_addr}' WITH CLIENT_UID '{data['PAYLOAD']['CLIENT_UID']}'")

        # NEW STATUS TRACKING
        obj_client.status = "CONNECTED"
        obj_client.status_since = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

        return True, ""

    elif valid_token and not valid_server_client:
        # Temporary, testing dynamic IP
        server_log.error(
            f"AUTHENTICATION FAILED FROM IP '{ip_addr}' WITH CLIENT UID '{obj_client.client_uid}. CLIENT UID INVALID.")
        rejection_explanation = "UNKNOWN CLIENT"

    elif not valid_token and valid_server_client:
        server_log.error(
            f"AUTHENTICATION FAILED FROM IP '{ip_addr}' WITH CLIENT UID '{obj_client.client_uid}. TOKEN INVALID.")
        rejection_explanation = "INVALID TOKEN"

    elif not valid_token and not valid_server_client:
        server_log.error(
            f"AUTHENTICATION FAILED FROM IP '{ip_addr}' WITH CLIENT UID '{obj_client.client_uid}. CLIENT UID AND TOKEN INVALID.")
        rejection_explanation = "UNKNOWN CLIENT AND INVALID TOKEN"

    return False, rejection_explanation


def send_config(dict_by_node_generated_config, client_uid, sckt, _config):
    bool_we_have_config_for_this_client = False
    try:
        # Now we can send the configuration of this mesh client
        # First, do we have something to send?
        # Then, IF THE IP ADDRESS AND THE UID ARE EQUAL, WE CAN SEND THIS CONFIGURATION!
        if dict_by_node_generated_config:
            for server_client in _config['SERVER_CLIENT']:
                if server_client['UID'] == client_uid:
                    if server_client['UID'] in dict_by_node_generated_config:
                        dict_by_node_generated_config[server_client['UID']]['CLIENT'] = {
                            "RSA_KEY_LISTENERS": _config['SERVER']['RSA_KEY_LISTENERS'].decode(),
                            "RSA_KEY_CONNECTORS": _config['SERVER']['RSA_KEY_CONNECTORS'].decode(),
                            "IPERF3_USERNAME": _config['SERVER']['IPERF3_USERNAME'],
                            "IPERF3_PASSWORD": _config['SERVER']['IPERF3_PASSWORD'],
                            "IPERF3_PASSWORD_HASH": _config['SERVER']['IPERF3_PASSWORD_HASH']}
                        dict_by_node_generated_config[server_client['UID']]['GLOBAL'] = {
                            "IPERF3_TIME_SKEW_THRESHOLD": _config['GLOBAL']['IPERF3_TIME_SKEW_THRESHOLD']}
                        sock_send(sckt, dict_by_node_generated_config[server_client['UID']], "NEWCONFIG")
                        bool_we_have_config_for_this_client = True
    except Exception as exc:
        server_log.error(f"Handler:handle:{type(exc).__name__}:{exc}", exc_info=True)

    return bool_we_have_config_for_this_client


def server_save_metric(obj_client, conn_db, received_data, address, sckt):
    server_log.debug(f"CONTEXT: {obj_client.client_uid} - RECEIVED A COMMAND TO SAVE METRICS")
    try:
        results_of_write_operation_on_multiple_db = []
        for conn in conn_db:
            # TODO, print what is the database we are actually writing to and the result
            server_log.debug(
                f"CONTEXT: {obj_client.client_uid} - SAVING METRICS TO DATABASE '{conn.get_Database_UID()}'")
            results_of_write_operation_on_multiple_db.append(
                conn.save_metrics_to_database_with_buffer(received_data['PAYLOAD'], address, obj_client.client_uid))

        result = "FAIL"
        if "OK" in results_of_write_operation_on_multiple_db and "ERROR" not in results_of_write_operation_on_multiple_db:
            result = "FULL"
        elif "OK" in results_of_write_operation_on_multiple_db and "ERROR" in results_of_write_operation_on_multiple_db:
            result = "PARTIAL"
            server_log.warning(f"SERVER WAS NOT ABLE TO SAVE METRICS TO ALL DATABASES'")

        # For now, if data is written to at least one database, allow the client to empty his cache.
        # In the future, we could get more sophisticated and resend the data to specific database
        if result == "FULL" or result == "PARTIAL":
            server_log.debug(
                f"CONTEXT: {obj_client.client_uid} - {len(received_data['PAYLOAD'])} METRICS FOR CLIENT {obj_client.client_uid} WRITTEN TO DATABASE")
            server_log.debug(f"CONTEXT: {obj_client.client_uid} - SENDING ACK TO CLIENT")
            sock_send(sckt, "OK", "ACK")
            server_log.debug(f"CONTEXT: {obj_client.client_uid} - ACK SENT TO CLIENT")
        else:
            server_log.error(
                f"CONTEXT: {obj_client.client_uid} - UNABLE TO WRITE {len(received_data['PAYLOAD'])} METRICS FOR CLIENT {obj_client.client_uid}")
            sock_send(sckt, "NOK", "ACK")
    except Exception as exc:
        server_log.error(
            f"CONTEXT: {obj_client.client_uid} - UNABLE TO WRITE {len(received_data['PAYLOAD'])} METRICS FOR CLIENT {obj_client.client_uid}")
        sock_send(sckt, "NOK", "ACK")


def server_auth(received_data, obj_client, _config, address, dict_of_commands_for_network_clients, sckt,
                _dict_by_node_generated_config, dict_of_client_pending_acceptance, threads_n_processes):
    obj_client.client_uid = received_data['PAYLOAD']['CLIENT_UID']
    public_key = received_data['PAYLOAD']['PUBLIC_KEY']

    server_log.debug(
        f"CONTEXT: {obj_client.client_uid} - NEW CONNECTION FROM CLIENT_UID : '{obj_client.client_uid}', SOURCE_IP : '{address}'")

    auth_ok = False
    # CHECK IF PUBLIC KEY IS IN THE CONFIG FILE FOR THIS SPECIFIC CLIENT
    for server_client in _config['SERVER_CLIENT']:
        if server_client['UID'] == obj_client.client_uid:
            if 'PUBLIC_KEY' in server_client:
                print("NEW AUTH SUCCESSFUL **************************************")
                auth_ok = True
                pass

    if not auth_ok:
        # add this public key and other interesting informations to a dictionnary that will be use to keep pending acceptation
        dict_of_client_pending_acceptance[obj_client.client_uid] = public_key

    # Authentication, if token is wrong, disconnect
    is_authenticated, rejection_explanation = authenticate_server_client(_config, received_data, obj_client, sckt)

    if is_authenticated:
        obj_client.status = "CONNECTED"
        obj_client.status_explanation = "AUTHENTICATION SUCCESSFUL"
        obj_client.status_since = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

        sock_send(sckt, None, obj_client.status_explanation)

    else:
        obj_client.status = rejection_explanation
        obj_client.status_explanation = "AUTHENTICATION FAILED"
        obj_client.status_since = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

        sock_send(sckt, rejection_explanation, "AUTH_FAILED")

        return False

    for server_client in _config['SERVER_CLIENT']:
        if server_client['UID'] == obj_client.client_uid:

            # If this is a dynamic IP client
            if server_client['IP_ADDRESS'] == "0.0.0.0":

                server_log.debug(
                    f"CONTEXT: {obj_client.client_uid} - THIS CLIENT HAS DYNAMIC IP, UPDATING LOCAL CONFIG AND PUSHING TO OTHER CLIENTS")

                # So that we can track that this is a dynamic client and rollback the ip when disconnection occur.
                obj_client.bool_dynamic_client = True

                # Updating the client object with the ip address he's coming from
                server_client['IP_ADDRESS'] = obj_client.ip_address

                # We need to regenerate the config, we pass the _dict_by_node_generated_config variable to avoid the webui and process_and_thread to continue to use the old memory pointer
                _dict_by_node_generated_config, _dict_by_group_of_generated_tuple_for_map = generate_client_config_mesh(
                    _config, _dict_by_node_generated_config)

                # Telling to every other client to update their config
                for server_client2 in _config['SERVER_CLIENT']:

                    # If there is an existing OVERRIDE_DST_NODE_IP, do not update the config
                    skip_flag = False
                    if 'OVERRIDE_DST_NODE_IP' in server_client2:
                        if server_client2['OVERRIDE_DST_NODE_IP']:
                            for override_ip_client_uid in server_client2['OVERRIDE_DST_NODE_IP']:
                                if override_ip_client_uid == obj_client.client_uid:
                                    skip_flag = True

                    if not skip_flag:
                        # Do not update the client itself
                        if not server_client2['UID'] == obj_client.client_uid:
                            dict_of_commands_for_network_clients[server_client2['UID']] = []
                            dict_of_commands_for_network_clients[server_client2['UID']].append(
                                {"ACTION": "UPDATED_CONFIG", "ELEMENT": "CLIENT_IP",
                                 "CLIENT_UID": obj_client.client_uid, "IP_ADDRESS": obj_client.ip_address})

    # Show an alert in the log when the clock skew is too great
    server_log.debug(f"CONTEXT: {obj_client.client_uid} - STARTING VALIDATION OF CLOCK SKEW")
    validate_clock_skew(_config, received_data, obj_client)
    server_log.debug(f"CONTEXT: {obj_client.client_uid} - VALIDATION OF CLOCK SKEW COMPLETED")

    # Send the config to the client
    server_log.debug(f"CONTEXT: {obj_client.client_uid} - SENDING CONFIG TO THE CLIENT")
    bool_we_have_config_for_this_client = send_config(_dict_by_node_generated_config, obj_client.client_uid, sckt, _config)

    obj_client.syntraf_version = received_data['PAYLOAD']['SYNTRAF_CLIENT_VERSION']

    # No config for this client!
    if not bool_we_have_config_for_this_client:
        sock_send(sckt, None, "NEWCONFIG")
        server_log.info(f"CONTEXT: {obj_client.client_uid} - NO CONFIG FOR THIS CLIENT'")

        obj_client.status = "CONNECTED (PASSIVE)"
        obj_client.status_explanation = "NO CONFIG FOR THIS CLIENT"
        obj_client.status_since = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    return True


def server_save_stats_metric(obj_client, received_data):
    """
    Insert system stats metric we just received from the client into corresponding obj_client.system_stats dictionary
    It will eventually be read by the API for the WEBUI
    It is called everytime the client send stats which should be quite often
    :param obj_client: The object representing the current client
    :param received_data: The payload we just received from the client containing the systems stats metric
    """
    # Make sure that the client system stats history does not get too big
    if len(obj_client.system_stats.setdefault('if_pct_usage_rx', [])) >= 100: obj_client.system_stats[
        'if_pct_usage_rx'].pop(0)
    if len(obj_client.system_stats.setdefault('if_pct_usage_tx', [])) >= 100: obj_client.system_stats[
        'if_pct_usage_tx'].pop(0)
    if len(obj_client.system_stats.setdefault('mem_pct_free', [])) >= 100: obj_client.system_stats['mem_pct_free'].pop(
        0)
    if len(obj_client.system_stats.setdefault('cpu_pct_usage', [])) >= 100: obj_client.system_stats[
        'cpu_pct_usage'].pop(0)

    obj_client.system_stats['if_pct_usage_rx'].append(
        (received_data['PAYLOAD']['timestamp'], received_data['PAYLOAD']['if_pct_usage_rx']))
    obj_client.system_stats['if_pct_usage_tx'].append(
        (received_data['PAYLOAD']['timestamp'], received_data['PAYLOAD']['if_pct_usage_tx']))
    obj_client.system_stats['mem_pct_free'].append(
        (received_data['PAYLOAD']['timestamp'], received_data['PAYLOAD']['mem_pct_free']))
    obj_client.system_stats['cpu_pct_usage'].append(
        (received_data['PAYLOAD']['timestamp'], received_data['PAYLOAD']['cpu_pct_usage']))


def server_awaiting_commands(client_uid, dict_of_commands_for_network_clients, sckt):
    """
    Read a dictionary of pending command and send them to the client
    :param client_uid: The uid of the client we are serving
    :param dict_of_commands_for_network_clients: A dictionary of all the pending command. It's organized by client_uid and each command are a sub dictionnary that contain mandatorily the key "ACTION"
    :param sckt: The current socket connected to the client
    """
    # The client is waiting, if there is no explicit action, send a NOP
    sent_an_action = False
    # Do we have action to send to client?
    if client_uid in dict_of_commands_for_network_clients:
        if len(dict_of_commands_for_network_clients[client_uid]) >= 1:
            for action in dict_of_commands_for_network_clients[client_uid]:
                server_log.info(f"SENDING THE ACTION '{action}' TO THE CLIENT {client_uid}")
                if action['ACTION'] == "RECONNECT_CLIENT":
                    server_log.debug(f"CONTEXT: {client_uid} - SENDING A 'RECONNECT_CLIENT' COMMAND")
                    sock_send(sckt, "", "RECONNECT_CLIENT")
                    server_log.debug(f"CONTEXT: {client_uid} - 'RECONNECT' COMMAND FOR A CLIENT_IP SENT")
                    sent_an_action = True
                    dict_of_commands_for_network_clients[client_uid].remove(action)
                elif action['ACTION'] == "RESTART_CLIENT":
                    server_log.debug(f"CONTEXT: {client_uid} - SENDING A 'RESTART_CLIENT' COMMAND")
                    sock_send(sckt, "", "RESTART_CLIENT")
                    server_log.debug(f"CONTEXT: {client_uid} - 'RESTART_CLIENT' COMMAND FOR A CLIENT_IP SENT")
                    sent_an_action = True
                    dict_of_commands_for_network_clients[client_uid].remove(action)
                elif action['ACTION'] == "UPDATED_CONFIG":
                    if action['ELEMENT'] == "CLIENT_IP":
                        server_log.debug(f"CONTEXT: {client_uid} - SENDING AN 'UPDATE_CONFIG' ACTION FOR A CLIENT_IP")
                        sock_send(sckt, action, "DIFFCONFIG")
                        server_log.debug(f"CONTEXT: {client_uid} - 'UPDATE_CONFIG' COMMAND FOR A CLIENT_IP SENT")
                        sent_an_action = True
                        dict_of_commands_for_network_clients[client_uid].remove(action)

    # The client is waiting for a command, if we don't have any, we should send a NOP to unblock it.
    if not sent_an_action:
        server_log.debug(f"CONTEXT: {client_uid} - SENDING A NOP")
        sock_send(sckt, "", "NOP")
        server_log.debug(f"CONTEXT: {client_uid} - NOP SENT")


def server_save_system_infos(obj_client, received_data):
    """
    Assign the system_infos we just received from the client to the corresponding obj_client. It will eventually be read by the API for the WEBUI
    It is called only one time just after the authentication
    :param obj_client: The object representing the current client
    :param received_data: The payload we just received from the client containing the systems informations
    """
    server_log.debug(f"CONTEXT: {obj_client.client_uid} - RECEIVED A COMMAND TO SAVE SYSTEM INFOS")
    obj_client.system_infos = received_data['PAYLOAD']


def server_forget_dynamic_client_ip(obj_client, _config, dict_of_commands_for_network_clients):
    """
    When a client does not have a static IP configured in the config file, it is assigned with a default "0.0.0.0" IP.
    When then syntraf client thread spawner see this, it will not launch the iperf3 CONNECTOR thread until he receive
    a COMMAND to update the IP to something else. When the client with dynamic IP disconnect, we replace the IP by
    "0.0.0.0" again and inform the other client so that no CONNECTOR are launch for nothing.
    :param obj_client: The object representing the current client
    :param _config: The TOML config file (nested dict)
    :param dict_of_commands_for_network_clients: A dictionary of all the pending command. It's organized by client_uid
    and each command are a sub dictionnary that contain mandatorily the key "ACTION"
    """
    # Rollback ip_address to the default
    if obj_client.bool_dynamic_client:
        for server_client in _config['SERVER_CLIENT']:
            if server_client['UID'] == obj_client.client_uid:
                server_client['IP_ADDRESS'] = "0.0.0.0"

        # Telling every client to update their config, as this client is gone and his real IP is no longer kown for sure.
        # It will trigger on the client, a termination of the running CONNECTORS associated with that IP and prevent it from restarting because "0.0.0.0" is use as a condition in
        # process_and_thread to not launch a CONNECTOR
        for server_client in _config['SERVER_CLIENT']:

            # If there is an existing OVERRIDE_DST_NODE_IP, do not update the IP
            skip_flag = False
            if 'OVERRIDE_DST_NODE_IP' in server_client:
                if server_client['OVERRIDE_DST_NODE_IP']:
                    for override_ip_client_uid in server_client['OVERRIDE_DST_NODE_IP']:
                        if override_ip_client_uid == obj_client.client_uid:
                            skip_flag = True

            if not skip_flag:
                # Make sure we are not updating the dynamic client itself
                if not obj_client.client_uid == server_client['UID']:
                    if not server_client['UID'] in dict_of_commands_for_network_clients:
                        dict_of_commands_for_network_clients[server_client['UID']] = []
                    dict_of_commands_for_network_clients[server_client['UID']].append(
                        {"ACTION": "UPDATED_CONFIG", "ELEMENT": "CLIENT_IP", "CLIENT_UID": obj_client.client_uid,
                         "IP_ADDRESS": "0.0.0.0"})


def server_save_thread_status(obj_client, received_data):
    server_log.debug(f"CONTEXT: {obj_client.client_uid} - RECEIVED A COMMAND TO SAVE THREAD STATUS")
    obj_client.thread_status = received_data['PAYLOAD']


class Handler(StreamRequestHandler):
    def handle(self):
        address = self.client_address
        sckt = self.connection
        _config = self.server._config
        dict_of_commands_for_network_clients = self.server.dict_of_commands_for_network_clients
        dict_of_clients = self.server.dict_of_clients
        conn_db = self.server.conn_db
        _dict_by_node_generated_config = self.server.dict_by_node_generated_config
        dict_of_client_pending_acceptance = self.server.dict_of_client_pending_acceptance
        threads_n_processes = self.server.threads_n_processes

        current_thread = threading.current_thread()
        log.debug(current_thread)

        uid = address[0]
        dict_of_clients[uid] = cc_client(status="CONNECTING", status_since=datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
                                         status_explanation="NOT YET AUTHENTICATED", client_uid="UNKNOWN",
                                         bool_dynamic_client=False, tcp_port=address[1], ip_address=address[0])

        try:
            while True:
                # no need to loop if no server_client
                if "SERVER_CLIENT" in _config:
                    received_data = ""
                    received_data = sock_rcv(sckt)

                    if received_data is None:
                        received_data = sock_rcv(sckt)

                    if received_data is None:
                        server_log.debug(f"CONTEXT: {dict_of_clients[uid].client_uid} - INVALID DATA RECEIVED")
                        dict_of_clients[uid].status_explanation = "CONNECTION RESET BY PEER"
                        server_log.error(f"CONNECTION RESET BY PEER: {dict_of_clients[uid].ip_address}: CLOSING CONNECTION")
                        break
                    else:
                        # Log the command that was received
                        server_log.debug(
                            f"CONTEXT: {dict_of_clients[uid].client_uid} - RECEIVED {received_data['COMMAND']}")

                        if received_data['COMMAND'] == "AUTH":

                            if not server_auth(received_data, dict_of_clients[uid], _config,
                                               dict_of_clients[uid].ip_address, dict_of_commands_for_network_clients, sckt,
                                               _dict_by_node_generated_config, dict_of_client_pending_acceptance, threads_n_processes):
                                return

                            # Now that we know the identity of the client connecting, we can update the dictionary of client objects
                            new_uid = dict_of_clients[uid].client_uid
                            dict_of_clients[new_uid].client_uid = new_uid
                            dict_of_clients[new_uid].status = dict_of_clients[uid].status
                            dict_of_clients[new_uid].bool_dynamic_client = dict_of_clients[uid].bool_dynamic_client
                            dict_of_clients[new_uid].status_since = dict_of_clients[uid].status_since
                            dict_of_clients[new_uid].status_explanation = dict_of_clients[uid].status_explanation
                            dict_of_clients[new_uid].clock_skew_in_seconds = dict_of_clients[uid].clock_skew_in_seconds
                            dict_of_clients[new_uid].syntraf_version = dict_of_clients[uid].syntraf_version
                            dict_of_clients[new_uid].ip_address = address[0]
                            dict_of_clients[new_uid].tcp_port = address[1]
                            dict_of_clients.pop(uid)
                            uid = new_uid

                        elif received_data['COMMAND'] == "SAVE_METRIC":
                            server_save_metric(dict_of_clients[uid], conn_db, received_data,
                                               dict_of_clients[uid].ip_address, sckt)

                        elif received_data['COMMAND'] == "SAVE_STATS_METRIC":
                            server_save_stats_metric(dict_of_clients[uid], received_data)

                        elif received_data['COMMAND'] == "SAVE_THREAD_STATUS":
                            server_save_thread_status(dict_of_clients[uid], received_data)

                        elif received_data['COMMAND'] == "SYSTEM_INFOS":
                            server_save_system_infos(dict_of_clients[uid], received_data)

                        elif received_data['COMMAND'] == "AWAITING_COMMAND":
                            server_awaiting_commands(dict_of_clients[uid].client_uid, dict_of_commands_for_network_clients,
                                                     sckt)

                        elif received_data['COMMAND'] == "HEARTBEAT":
                            pass

                        else:
                            print("UNKNOWN COMMAND:", received_data['COMMAND'])
                else:
                    time.sleep(2)

        except socket.timeout as exc:
            server_log.error(f"SOCKET TIMEOUT: {dict_of_clients[uid].ip_address}: CLOSING CONNECTION")
            dict_of_clients[uid].status_explanation = "SOCKET TIMEOUT"
        except json.JSONDecodeError as exc:
            server_log.error(f"JSON DECODING FAILED FOR STRING")
        except OSError as exc:
            if exc.errno == 32:  # BROKEN PIPE, THE OTHER END HAS GONE AWAY
                dict_of_clients[uid].status_explanation = "BROKEN PIPE"
                server_log.error(f"BROKEN PIPE: {dict_of_clients[uid].ip_address}: CLOSING CONNECTION")
            # CONNECTION RESET BY PEER
            elif exc.errno == 104:
                dict_of_clients[uid].status_explanation = "CONNECTION RESET BY PEER"
                server_log.error(f"CONNECTION RESET BY PEER: {dict_of_clients[uid].ip_address}: CLOSING CONNECTION")
            elif exc.errno == 113:
                dict_of_clients[uid].status_explanation = "NO ROUTE TO HOST"
                server_log.error(f"NO ROUTE TO HOST: {dict_of_clients[uid].ip_address}: CLOSING CONNECTION")
            # CONNECTION TIMEOUT
            elif exc.errno == 110:
                dict_of_clients[uid].status_explanation = "CONNECTION TIMEOUT"
                server_log.error(f"CONNECTION TIMEOUT: {dict_of_clients[uid].ip_address}: CLOSING CONNECTION")
            # FOR WINDOWS [WinError 10053] #An established connection was aborted by the software in your host machine
            elif exc.errno == 10053:
                dict_of_clients[uid].status_explanation = "CONNECTION ABORTED"
                server_log.error(f"CONNECTION ABORTED: {dict_of_clients[uid].ip_address}: CLOSING CONNECTION")
            # FOR WINDOWS [WinError 10054]
            elif exc.errno == 10054:
                dict_of_clients[uid].status_explanation = "CONNECTION RESET BY PEER"
                server_log.error(f"CONNECTION RESET BY PEER: {dict_of_clients[uid].ip_address}: CLOSING CONNECTION")
            elif exc.errno == 10057:  # FOR WINDOWS [WinError 10057]
                dict_of_clients[uid].status_explanation = "SOCKET IS NOT CONNECTED"
                server_log.error(
                    f"{type(exc).__name__.upper()}:{exc.errno}: {dict_of_clients[uid].ip_address}: CLOSING CONNECTION")
            else:
                dict_of_clients[uid].status_explanation = "UNKNOWN OSError"
                server_log.error(f"UNHANDLE OSError (st_mesh:sock_rcv): {dict_of_clients[uid].ip_address}:", exc,
                                 exc.errno, exc.strerror)
        except Exception as exc:
            dict_of_clients[uid].status_explanation = "UNKNOWN"
            server_log.error(f"Handler:handle:{type(exc).__name__}:{exc}", exc_info=True)

        finally:
            # The socket on the other end is probably closed
            server_log.error(f"CLIENT: {dict_of_clients[uid].ip_address} DISCONNECTED")

            try:
                # If this is a dynamic client, once disconnected, we should forget about the ip address
                server_forget_dynamic_client_ip(dict_of_clients[uid], _config, dict_of_commands_for_network_clients)

                # Updating the status
                # We don't want to overwrite a reason for failed authentication, so we overwrite only when the client was connected
                if "CONNECTED" in dict_of_clients[uid].status:
                    dict_of_clients[uid].status = "DISCONNECTED"
                    dict_of_clients[uid].status_since = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

                # Reinitializing stats array so that the sparklines graphes does not appear in the webui
                dict_of_clients[uid].system_stats['if_pct_usage_rx'] = []
                dict_of_clients[uid].system_stats['if_pct_usage_tx'] = []
                dict_of_clients[uid].system_stats['mem_pct_free'] = []
                dict_of_clients[uid].system_stats['cpu_pct_usage'] = []

                sckt.close()

            except Exception as e:
                server_log.error(
                    f"AN ERROR OCCURRED WHILE FREEING RESOURCE FOR THE CLIENT: {dict_of_clients[uid].client_uid}/{dict_of_clients[uid].ip_address}")


class SSL_TCPServer(TCPServer):
    def __init__(self,
                 server_address,
                 RequestHandlerClass,
                 certfile,
                 keyfile,
                 bind_and_activate=True,
                 ssl_version=ssl.PROTOCOL_TLSv1):
        TCPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)
        self.certfile = certfile
        self.keyfile = keyfile
        self.ssl_version = ssl_version


    def get_request(self):
        newsocket, fromaddr = self.socket.accept()
        connstream = ssl.wrap_socket(newsocket,
                                     server_side=True,
                                     certfile=self.certfile,
                                     keyfile=self.keyfile,
                                     #ssl_version=self.ssl_version,
                                     cert_reqs=ssl.CERT_NONE,
                                     do_handshake_on_connect=True)
        return connstream, fromaddr

    def get_config(self):
        return self._config

class SSLnThreadingTCPServer(ThreadingMixIn, SSL_TCPServer):
    # Make sure all the client are close when server is closed
    daemon_threads = True


#################################################################################
###  MESH SERVER SOCKET LISTENER
###  http://www.gevent.org/api/gevent.server.html
###  http://www.gevent.org/api/gevent.baseserver.html#gevent.baseserver.BaseServer
###  https://github.com/veryhappythings/gevent-ssl-example/blob/master/stateful_server.py
###  https://dadruid5.com/2018/07/30/running-a-gevent-streamserver-in-a-thread-for-maximum-control/#:~:text=StreamServer%20Gevent%20maintains%20a%20server%20through%20gevent.server.StreamServer.%20This,pool%20for%20controlling%20the%20number%20of%20connections%20created%3A
###  https://stackoverflow.com/questions/21631799/how-can-i-pass-parameters-to-a-requesthandler
#################################################################################
def server(_config, threads_n_processes, stop_thread, dict_by_node_generated_config, obj_stats, conn_db,
           dict_of_commands_for_network_clients, dict_of_clients, dict_of_client_pending_acceptance):
    # Generating the rsa keypair for iperf3 authentication
    gen_rsa_iperf3(server_log, _config)
    gen_user_pass_iperf3(server_log, _config)
    _config['SERVER']['IPERF3_PASSWORD_HASH'] = gen_iperf3_password_hash(_config['SERVER']['IPERF3_USERNAME'],
                                                                         _config['SERVER']['IPERF3_PASSWORD'])
    server_address = (_config['SERVER']['BIND_ADDRESS'], int(_config['SERVER']['SERVER_PORT']))

    # Avoid "Address already in use" when restarting server
    TCPServer.allow_reuse_address = True

    try:
        # Validating if we need to wrap the socket with legit cert or self-signed
        self_signed_flag = True
        if 'SERVER_X509_SELFSIGNED' in _config['SERVER']:
            if _config['SERVER']['SERVER_X509_SELFSIGNED'] == "NO":
                self_signed_flag = False
        if not self_signed_flag:
                server_log.debug(f"CONTROL CHANNEL SERVER SOCKET CREATED")
                tcp_server = SSLnThreadingTCPServer(server_address, Handler,
                                                    keyfile=_config['SERVER']['SERVER_X509_PRIVATE_KEY'],
                                                    certfile=_config['SERVER']['SERVER_X509_CERTIFICATE'],
                                                    bind_and_activate=True)

                server_log.debug(
                    f"BINDING CONTROL CHANNEL SERVER SSL SOCKET TO '{_config['SERVER']['BIND_ADDRESS']}:{_config['SERVER']['SERVER_PORT']}' SUCCESSFUL")
                server_log.debug(f"CONTROL CHANNEL SERVER SSL SOCKET LISTENING")
        else:

                server_log.debug(f"CONTROL CHANNEL SERVER SOCKET CREATED")
                tcp_server = SSLnThreadingTCPServer(server_address, Handler,
                                                    keyfile=os.path.join(
                                                        DefaultValues.DEFAULT_SERVER_X509_SELFSIGNED_DIRECTORY,
                                                        "private_key_server.pem"),
                                                    certfile=os.path.join(
                                                        DefaultValues.DEFAULT_SERVER_X509_SELFSIGNED_DIRECTORY,
                                                        "certificate_server.pem"), bind_and_activate=True)

                server_log.debug(
                    f"BINDING CONTROL CHANNEL SERVER SSL SOCKET TO '{_config['SERVER']['BIND_ADDRESS']}:{_config['SERVER']['SERVER_PORT']}' SUCCESSFUL")
                server_log.debug(f"CONTROL CHANNEL SERVER SSL SOCKET LISTENING")

        tcp_server.dict_by_node_generated_config = dict_by_node_generated_config
        tcp_server.conn_db = conn_db
        tcp_server.dict_of_commands_for_network_clients = dict_of_commands_for_network_clients
        tcp_server.dict_of_clients = dict_of_clients
        tcp_server.dict_of_client_pending_acceptance = dict_of_client_pending_acceptance
        tcp_server._config = _config
        tcp_server.threads_n_processes = threads_n_processes
        tcp_server.serve_forever()

    except OSError as msg:
        server_log.error(
            f"UNABLE TO START SERVER ON '{_config['SERVER']['BIND_ADDRESS']}:{_config['SERVER']['SERVER_PORT']}' : {msg}")
        sys.exit()

    except Exception as exc:
        server_log.error(f"server:{type(exc).__name__}:{exc}", exc_info=True)
        print(traceback.format_exc())
        sys.exit()


def set_tcp_ka(sckt, log):
    sckt.settimeout(60)
    """
    Setting socket parameters
    SO_KEEPALIVE: activate keepalive
    TCP_KEEPCNT, Kernel 2.4 : overrides tcp_keepalive_probes
        Gets or sets the number of TCP keep alive probes that will be sent before the connection is terminated. It is illegal to set TCP_KEEPCNT to a value greater than 255. (Starting with Windows 10, version 1703.)
    TCP_KEEPIDLE, Kernel 2.4 : overrides tcp_keepalive_time
        Gets or sets the number of seconds a TCP connection will remain idle before keepalive probes are sent to the remote. (This option is available starting with Windows 10, version 1709.)
    TCP_KEEPINTVL, Kernel 2.4 : overrides tcp_keepalive_intvl
        Gets or sets the number of seconds a TCP connection will wait for a keepalive response before sending another keepalive probe. (This option is available starting with Windows 10, version 1709.)
    SIO_KEEPALIVE_VALS: WINDOWS ONLY
        enables or disables the per-connection setting of the TCP keep-alive option which specifies the TCP keep-alive timeout and interval.
        onoff;
        keepalivetime;
        keepaliveinterval;

    TCP_USER_TIMEOUT (rfc5482), Kernel 2.6.37 :

    https://man7.org/linux/man-pages/man7/tcp.7.html

    """

    # SO_TIMEOUT

    # Platform independent SO_KEEPALIVE
    keepalive_before = sckt.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE)
    sckt.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    keepalive_after = sckt.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE)
    log.debug(f"ENABLING SO_KEEPALIVE ON SOCKET. FROM '{keepalive_before}' to '{keepalive_after}'")

    # # Platform independent TCP_NODELAY
    # nodelay_before = sckt.getsockopt(socket.SOL_SOCKET, socket.TCP_NODELAY)
    # sckt.setsockopt(socket.SOL_SOCKET, socket.TCP_NODELAY, 1)
    # nodelay_after = sckt.getsockopt(socket.SOL_SOCKET, socket.TCP_NODELAY)
    # log.debug(f"ENABLING TCP_NODELAY ON SOCKET. FROM '{nodelay_before}' to '{nodelay_after}'")

    platform = sys.platform

    """
    The following values start the keepalive after 1 second (ka_after_idle_sec) of idleness,
    then sends a keepalive ping once every 2 seconds (ka_interval_sec),
    and closes the connection after 5 failed ping (ka_max_fails), or 10 seconds"
    """
    ka_after_idle_sec = 1
    ka_interval_sec = 2
    ka_max_fails = 5
    tcp_user_timeout = 1
    tcp_buffer = 0

    if platform == "linux":
        ka_after_idle_sec_before = sckt.getsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE)
        ka_interval_sec_before = sckt.getsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL)
        ka_max_fails_before = sckt.getsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT)
        tcp_user_timeout_before = sckt.getsockopt(socket.SOL_SOCKET, socket.TCP_USER_TIMEOUT)
        tcp_buffer_before = sckt.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)

        sckt.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, ka_after_idle_sec)
        sckt.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, ka_interval_sec)
        sckt.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, ka_max_fails)
        sckt.setsockopt(socket.SOL_SOCKET, socket.TCP_USER_TIMEOUT, tcp_user_timeout)
        sckt.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, tcp_buffer)

        ka_after_idle_sec_after = sckt.getsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE)
        ka_interval_sec_after = sckt.getsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL)
        ka_max_fails_after = sckt.getsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT)
        tcp_user_timeout_after = sckt.getsockopt(socket.SOL_SOCKET, socket.TCP_USER_TIMEOUT)
        tcp_buffer_after = sckt.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)

        log.debug(f"MODIFYING SO_SNDBUF ON SOCKET FROM '{tcp_buffer_before}' to '{tcp_buffer_after}'")
        log.debug(
            f"MODIFYING TCP_USER_TIMEOUT ON SOCKET FROM '{tcp_user_timeout_before}' to '{tcp_user_timeout_after}'")
        log.debug(f"MODIFYING TCP_KEEPIDLE ON SOCKET FROM '{ka_after_idle_sec_before}' to '{ka_after_idle_sec_after}'")
        log.debug(f"MODIFYING TCP_KEEPINTVL ON SOCKET FROM '{ka_interval_sec_before}' to '{ka_interval_sec_after}'")
        log.debug(f"MODIFYING TCP_KEEPCNT ON SOCKET FROM '{ka_max_fails_before}' to '{ka_max_fails_after}'")

    # TODO
    elif platform == "darwin":
        pass
        # TCP_CONNECTIONTIMEOUT
        # TCP_RXT_CONNDROPTIME
        #     sends a keepalive ping once every 3 seconds (interval_sec)
        #     """
        #     # scraped from /usr/include, not exported by python's socket module
        #     TCP_KEEPALIVE = 0x10
        #     sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        #     sock.setsockopt(socket.IPPROTO_TCP, TCP_KEEPALIVE, interval_sec)

    elif platform == "win32":
        # Enable TCP socket keepalive with (on/off, keep alive time, keep alive interval)
        log.debug(f"MODIFYING TCP SOCKET PARAMETERS FOR WIN32.")
        log.debug(
            f"BEFORE: TCP_KEEPIDLE --> {sckt.getsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE)}, TCP_KEEPINTVL --> {sckt.getsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL)}, TCP_KEEPCNT --> {sckt.getsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT)}")
        sckt.ioctl(socket.SIO_KEEPALIVE_VALS, (1, ka_after_idle_sec * 1000, ka_interval_sec * 1000))
        log.debug(
            f"AFTER: TCP_KEEPIDLE --> {sckt.getsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE)}, TCP_KEEPINTVL --> {sckt.getsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL)}, TCP_KEEPCNT --> {sckt.getsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT)}")


def close_listeners_and_connectors(threads_n_processes):
    for thr in threads_n_processes:
        if thr.syntraf_instance_type == "LISTENER" or thr.syntraf_instance_type == "CONNECTOR":
            thr.close()
            threads_n_processes.remove(thr)


def update_config(data, _config):
    # Updating config (LISTENERS AND CONNECTORS)
    new_config = {'LISTENERS': data['PAYLOAD']['LISTENERS'], 'CONNECTORS': data['PAYLOAD']['CONNECTORS']}

    # Updating CLIENT and GLOBAL config (must be careful, there is already config in this clause)
    _config['CLIENT']['IPERF3_USERNAME'] = data['PAYLOAD']['CLIENT']['IPERF3_USERNAME']
    _config['CLIENT']['IPERF3_PASSWORD'] = data['PAYLOAD']['CLIENT']['IPERF3_PASSWORD']
    _config['CLIENT']['IPERF3_HASH'] = data['PAYLOAD']['CLIENT']['IPERF3_PASSWORD_HASH']
    _config['GLOBAL']['IPERF3_TIME_SKEW_THRESHOLD'] = data['PAYLOAD']['GLOBAL']['IPERF3_TIME_SKEW_THRESHOLD']
    _config.update(new_config)


def save_credentials(data, _config):
    with open(os.path.join(_config['GLOBAL']['IPERF3_RSA_KEY_DIRECTORY'], 'private_key_iperf_client.pem'), 'wb') as f:
        f.write(data['PAYLOAD']['CLIENT']['RSA_KEY_LISTENERS'].encode())

    with open(os.path.join(_config['GLOBAL']['IPERF3_RSA_KEY_DIRECTORY'], 'public_key_iperf_client.pem'), 'wb') as f:
        f.write(data['PAYLOAD']['CLIENT']['RSA_KEY_CONNECTORS'].encode())

    try:
        with open(os.path.join(_config['GLOBAL']['IPERF3_RSA_KEY_DIRECTORY'], 'credentials.csv'), 'w') as f:
            f.write(_config['CLIENT']['IPERF3_USERNAME'] + "," + _config['CLIENT']['IPERF3_HASH'])

    except Exception as exc:
        server_log.error(
            f"server(): AN ERROR OCCURED WHILE WRITING IPERF3 CREDENTIALS")


def is_valid_server_client(_config, uid, socket):
    for server_client in _config['SERVER_CLIENT']:
        if server_client['UID'] == uid:
            return True
    return False
