# SYNTRAF GLOBAL IMPORT
import lib.st_process_and_thread
from lib.st_crypto import *
from lib.st_struct import cl_ifreq
from lib.st_process_and_thread import *
from lib.st_read_toml import read_conf
from lib.st_conf_validation import valid_dir_rsa_keypair, validate_ipv4
from lib.st_obj_cc_client import cc_client
from lib.st_cc_commands import queue_client_ip_update, next_command, dynamic_client_uids, ForgetScheduler
from lib.st_sockutil import recv_exact, recv_message, ProtocolViolation
from lib import st_channel_guard as guard
from lib import st_identity
from lib.st_files import open_private
from lib.st_config_diff import edges_to_restart, reuse_keys
from lib.st_iperf3_credentials import load_or_create
from lib import st_enrollment, st_log_forward, st_log_store, st_nat, st_release, st_syslog, st_updater
import base64

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

# PACKAGE IMPORT
import ssl  # import ssl after monkey patch
import json
import pytz
from cpuinfo import get_cpu_info
import psutil

server_log = logging.getLogger("syntraf." + "lib.st_server")
client_log = logging.getLogger("syntraf." + "lib.st_client")





#################################################################################
###  SOCKET RCV
#################################################################################
def sock_rcv(sckt, max_bytes=guard.MAX_MESSAGE_BYTES, deadline=None):
    """Message suivant (dict) ; None si la connexion se ferme. Taille bornée (max_bytes) et échéance facultative :
    ProtocolViolation au-delà (voir lib/st_channel_guard.py)."""
    try:
        data = recv_message(sckt, max_bytes, deadline)
        if data is None: return None
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

        valid_ip = False
        while not valid_ip:
            try:
                server_ip_addr = socket.gethostbyname(socket.gethostbyname(_config['CLIENT']['SERVER']))
                if validate_ipv4(server_ip_addr):
                    valid_ip = True
            except socket.gaierror as e:
                if e.errno == socket.EAI_AGAIN:
                    logging.error(f"TEMPORARY FAILURE IN NAME RESOLUTION OF {server_ip_addr}")
            time.sleep(1)

        # CONNECT: short timeout so that a connection attempt started during an outage does not delay the
        # reconnection long after the network is back; then the control channel timeout applies.
        ssl_conn.settimeout(DefaultValues.CONTROL_CHANNEL_CONNECT_TIMEOUT)
        ssl_conn.connect((server_ip_addr, int(_config['CLIENT']['SERVER_PORT'])))
        ssl_conn.settimeout(DefaultValues.CONTROL_CHANNEL_TIMEOUT)
        client_check_server_identity(_config, ssl_conn)

        if server_ip_addr != _config['CLIENT']['SERVER']:
            client_log.info(f"CONNECTED TO : {_config['CLIENT']['SERVER']}({server_ip_addr}):{_config['CLIENT']['SERVER_PORT']}")
        else:
            client_log.info(f"CONNECTED TO : {_config['CLIENT']['SERVER']}:{_config['CLIENT']['SERVER_PORT']}")

    except (ConnectionRefusedError, ConnectionResetError) as exc:
        client_log.warning(
            f"ERROR CONNECTING TO {_config['CLIENT']['SERVER']}:{_config['CLIENT']['SERVER_PORT']} : CONNECTION REFUSED")
        sys.exit()
    except OSError as exc:
        # Any failure (unreachable, connect timeout...) ends this attempt: the watchdog retries shortly.
        # Continuing used to hand back an unconnected socket that then waited for nothing.
        reason = "NETWORK UNREACHABLE" if exc.errno == 101 else f"{type(exc).__name__.upper()}: {exc}"
        client_log.warning(f"ERROR CONNECTING TO {_config['CLIENT']['SERVER']}:{_config['CLIENT']['SERVER_PORT']} : {reason}")
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


_RUNNING_RELEASE = []


def running_release():
    """Release de la version qui tourne : désignée par le superviseur, sinon calculée depuis le code en place."""
    if not _RUNNING_RELEASE:
        rid = os.environ.get(st_updater.ENV_RELEASE)
        if not rid:
            try:
                rid = st_release.release_id(DefaultValues.SYNTRAF_ROOT_DIR, DefaultValues.SYNTRAF_VERSION)
            except OSError:
                rid = DefaultValues.SYNTRAF_VERSION
        _RUNNING_RELEASE.append(rid)
    return _RUNNING_RELEASE[0]


def last_failed_release():
    try:
        failed = st_updater.read_state(str(DefaultValues.SYNTRAF_DATA_DIR))["failed"]
        return failed[-1] if failed else None
    except Exception:  # noqa: BLE001
        return None


def client_confirm_release():
    """La version démarrée a rejoint le serveur et reçu sa config : elle devient définitive (plus de retour arrière)."""
    rid = os.environ.get(st_updater.ENV_RELEASE)
    if rid and st_updater.confirm(str(DefaultValues.SYNTRAF_DATA_DIR), rid):
        client_log.info(f"RELEASE {rid} CONFIRMED")


def client_command_update(_config, ssl_conn, received_data):
    """Télécharge la release annoncée par le serveur (par morceaux), la vérifie, l'installe à côté de la version en
    place, puis demande au superviseur de basculer. Un compte rendu est envoyé au serveur dans tous les cas."""
    info = received_data.get('PAYLOAD') or {}
    rid, expected_sha256, size = info.get('RELEASE'), info.get('SHA256'), int(info.get('SIZE') or 0)
    # Nom sûr (il entre dans des chemins) et signature de la clé du serveur épinglée : sinon rien n'est installé
    if not re.fullmatch(r"[A-Za-z0-9_.+-]{1,80}", str(rid or "")) or ".." in str(rid):
        client_log.error(f"UPDATE REFUSED: INVALID RELEASE NAME {guard.clean(rid)}")
        return
    if not st_identity.verify_release(_config['CLIENT'].get('_SERVER_PUBLIC_PEM', ""), rid, expected_sha256, size,
                                      info.get('SIGNATURE')):
        client_log.error(f"UPDATE TO {rid} REFUSED: THE RELEASE IS NOT SIGNED BY THE PINNED SERVER KEY")
        try:
            sock_send(ssl_conn, {"RELEASE": rid, "STATE": "FAILED", "MESSAGE": "release not signed by the server"},
                      "UPDATE_STATUS")
        except OSError:
            pass
        return
    base = str(DefaultValues.SYNTRAF_DATA_DIR)
    client_log.info(f"UPDATE TO RELEASE {rid} REQUESTED BY THE SERVER")
    path = os.path.join(base, "releases", f"download-{rid}.tar.gz")
    try:
        if not os.environ.get(st_updater.ENV_CHILD):
            raise st_updater.UpdateError("SYNTRAF is not started through its supervisor (syntraf.py run by the "
                                         "service): it cannot switch versions")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        offset = 0
        with open(path, "wb") as f:
            while True:
                sock_send(ssl_conn, {"RELEASE": rid, "OFFSET": offset}, "GET_RELEASE_CHUNK")
                answer = sock_rcv(ssl_conn)
                payload = (answer or {}).get('PAYLOAD') or {}
                if (answer or {}).get('COMMAND') != "RELEASE_CHUNK" or payload.get('ERROR'):
                    raise st_updater.UpdateError(payload.get('ERROR') or "unexpected answer while downloading")
                data = base64.b64decode(payload['DATA'])
                f.write(data)
                offset += len(data)
                if payload.get('EOF') or offset > size:
                    break
        st_updater.stage(base, path, expected_sha256, rid, python=sys.executable, force=bool(info.get('FORCE')))
        sock_send(ssl_conn, {"RELEASE": rid, "STATE": "STAGED", "MESSAGE": "installed, switching"}, "UPDATE_STATUS")
        client_log.info(f"RELEASE {rid} INSTALLED, ASKING THE SUPERVISOR TO SWITCH")
        st_updater.request_restart(base)
    except Exception as exc:
        client_log.error(f"UPDATE TO RELEASE {rid} FAILED: {exc}")
        sock_send(ssl_conn, {"RELEASE": rid, "STATE": "FAILED", "MESSAGE": str(exc)[:500]}, "UPDATE_STATUS")
    finally:
        if os.path.exists(path):
            os.remove(path)


def client_token(_config):
    """Jeton à présenter : le jeton propre remis par le serveur (fichier), sinon le jeton partagé de la config.
    Après un refus du jeton propre, une tentative se fait avec le jeton partagé : si la clé du client est épinglée,
    le serveur l'accepte et lui remet son nouveau jeton (rotation faite pendant son absence)."""
    client = _config['CLIENT']
    path = client.get('_TOKEN_FILE')
    if path and not client.get('_USE_SHARED_TOKEN') and os.path.isfile(path):
        with open(path, encoding="utf-8") as f:
            own = f.read().strip()
        if own:
            return own
    return client['TOKEN']


def client_command_set_token(_config, received_data):
    """Le serveur remet au client son jeton propre : il est gardé dans un fichier lisible par le seul propriétaire."""
    path = _config['CLIENT'].get('_TOKEN_FILE')
    token = (received_data.get('PAYLOAD') or {}).get('TOKEN')
    if not path or not token:
        return
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(token)
    os.replace(tmp, path)
    _config['CLIENT']['_USE_SHARED_TOKEN'] = False
    client_log.info("OWN TOKEN RECEIVED FROM THE SERVER AND SAVED")


SAFE_UID_RE = re.compile(r"^[A-Za-z0-9_-]{4,50}$")


def client_command_set_uid(_config, received_data):
    """Le serveur a renommé ce client : le nouveau nom est gardé dans un fichier (il l'emporte sur CLIENT_UID de la
    configuration au prochain démarrage) et utilisé dès la reconnexion."""
    path = _config['CLIENT'].get('_UID_FILE')
    uid = str((received_data.get('PAYLOAD') or {}).get('UID') or "")
    if not path or not SAFE_UID_RE.match(uid):
        client_log.error(f"INVALID NAME RECEIVED FROM THE SERVER: '{uid}'")
        return False
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(uid)
    os.replace(tmp, path)
    client_log.warning(f"RENAMED BY THE SERVER: '{_config['CLIENT']['CLIENT_UID']}' IS NOW '{uid}'")
    _config['CLIENT']['CLIENT_UID'] = uid
    return True


def client_apply_uid_file(_config):
    """Nom remis par le serveur (renommage) : il remplace CLIENT_UID de la configuration."""
    path = _config['CLIENT'].get('_UID_FILE')
    if not path or not os.path.isfile(path):
        return
    with open(path, encoding="utf-8") as f:
        uid = f.read().strip()
    if SAFE_UID_RE.match(uid) and uid != _config['CLIENT'].get('CLIENT_UID'):
        client_log.warning(f"CLIENT_UID '{uid}' GIVEN BY THE SERVER ({path}) REPLACES "
                           f"'{_config['CLIENT'].get('CLIENT_UID')}' OF THE CONFIGURATION")
        _config['CLIENT']['CLIENT_UID'] = uid


def client_check_server_identity(_config, ssl_conn):
    """Le serveur doit présenter la clé attendue (CLIENT.SERVER_CERT_SHA256, sinon celle épinglée à la première
    connexion) : sinon la connexion est abandonnée avant d'envoyer le moindre jeton (homme du milieu)."""
    der = ssl_conn.getpeercert(binary_form=True)
    pin_file = _config['CLIENT'].get('_SERVER_PIN_FILE') or os.path.join(
        os.path.dirname(os.path.abspath(_config['CLIENT'].get('_TOKEN_FILE') or "x")), "syntraf_server_pin")
    pin = st_identity.ServerPin(pin_file, _config['CLIENT'].get('SERVER_CERT_SHA256', ""))
    try:
        state = pin.check(der)
    except st_identity.IdentityError as exc:
        client_log.error(f"{exc}: NOT THE SYNTRAF SERVER (OR ITS KEY CHANGED: SET CLIENT.SERVER_CERT_SHA256, "
                         f"OR DELETE {pin_file} IF THE CHANGE IS EXPECTED). CONNECTION ABANDONED")
        ssl_conn.close()
        sys.exit()
    fp = st_identity.spki_sha256(der)
    if state == "PINNED":
        client_log.warning(f"SERVER KEY PINNED ON FIRST CONNECTION: {fp} (COMPARE IT WITH THE SERVER PAGE; "
                           f"SET CLIENT.SERVER_CERT_SHA256 TO FIX IT FROM THE START)")
    _config['CLIENT']['_SERVER_FP'] = fp
    _config['CLIENT']['_SERVER_PUBLIC_PEM'] = st_identity.public_key_pem_of_cert(der)


def client_key_proof(_config):
    """Preuve de possession de la clé du client (signature), ou None si sa clé privée est introuvable."""
    path = _config['CLIENT'].get('CLIENT_X509_PRIVATE_KEY')
    fp = _config['CLIENT'].get('_SERVER_FP')
    if not path or not fp or not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as f:
        return st_identity.auth_proof(f.read(), _config['CLIENT']['CLIENT_UID'], fp)


def client_send_auth(_config, client_utime, ssl_conn):
    try:
        # Sending TOKEN and UID for authentication, timestamp and version
        client_log.debug(f"SENDING GREETING PAYLOAD TO SERVER")
        token = client_token(_config)
        used_own_token = token != _config['CLIENT']['TOKEN']
        payload_greetings = {'TOKEN': token, 'CLIENT_UID': _config['CLIENT']['CLIENT_UID'],
                             'TIMESTAMP': client_utime, 'SYNTRAF_CLIENT_VERSION': DefaultValues.SYNTRAF_VERSION,
                             'PUBLIC_KEY': _config['CLIENT']['PUBLIC_KEY'],
                             'SYNTRAF_RELEASE': running_release(), 'UPDATE_FAILED': last_failed_release(),
                             'LOCAL_ADDRESSES': st_nat.local_ipv4_addresses(), 'PROOF': client_key_proof(_config)}

        sock_send(ssl_conn, payload_greetings, "AUTH")
        received_data = sock_rcv(ssl_conn)

        if not received_data is None:
            if received_data['COMMAND'] == "AUTH_FAILED":
                reason = received_data['PAYLOAD']
                if reason == "PENDING APPROVAL":
                    client_log.warning("WAITING FOR AN ADMINISTRATOR TO APPROVE THIS CLIENT ON THE SERVER")
                else:
                    client_log.info(f"AUTHENTICATION FAILED, REASON GIVEN BY SERVER : {reason}")
                # Jeton propre refusé : la prochaine tentative se fera avec le jeton partagé de la config
                _config['CLIENT']['_USE_SHARED_TOKEN'] = used_own_token and reason == "INVALID TOKEN"
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

                # Keep our current key for an identical edge: a connector key contains a hash of the destination IP,
                # which a DIFFCONFIG updates without renaming the key.
                for edge_type in ('LISTENERS', 'CONNECTORS'):
                    received_data['PAYLOAD'][edge_type] = reuse_keys(_config.get(edge_type),
                                                                     received_data['PAYLOAD'][edge_type])

                # PROJ-A
                # If there is no changes, don't restart!
                read_success, disk_config = read_conf(config_file_path)
                if read_success:
                    update_config(received_data, disk_config)
                    valid_dir_rsa_keypair(disk_config)
                    #valid_dir_logs(disk_config)
                    disk_config['GLOBAL']['LOGDIR'] = cli_parameters.log_dir

                    #client_log.debug(_config)
                    #client_log.debug(disk_config)

                    if disk_config == _config:
                        client_log.debug("SAME SAME SAME SAME")
                    else:
                        client_log.debug("DIFF DIFF DIFF DIFF")

                # Stop only the listeners and connectors that changed (all of them if the iperf3 credentials changed
                # with IPERF3_AUTH): a reconnection to the server must not interrupt the measurements.
                new_config = {'LISTENERS': received_data['PAYLOAD']['LISTENERS'],
                              'CONNECTORS': received_data['PAYLOAD']['CONNECTORS'],
                              'CLIENT': {'IPERF3_USERNAME': received_data['PAYLOAD']['CLIENT']['IPERF3_USERNAME'],
                                         'IPERF3_PASSWORD': received_data['PAYLOAD']['CLIENT']['IPERF3_PASSWORD'],
                                         'IPERF3_HASH': received_data['PAYLOAD']['CLIENT']['IPERF3_PASSWORD_HASH']},
                              'GLOBAL': {'IPERF3_AUTH': _config['GLOBAL'].get('IPERF3_AUTH')}}
                listeners_to_stop, connectors_to_stop = edges_to_restart(_config, new_config)
                client_log.info(f"NEW CONFIG: RESTARTING {len(listeners_to_stop)} LISTENER(S) AND {len(connectors_to_stop)} CONNECTOR(S)")
                from lib.st_process_and_thread import terminate_listener_and_childs, terminate_connector_and_childs
                for thr in list(threads_n_processes):
                    if thr.syntraf_instance_type == "LISTENER" and thr.name in listeners_to_stop:
                        thr.close()  # kill first: reading the stderr of a live iperf3 would block
                        terminate_listener_and_childs(threads_n_processes, thr.name, thr, _config)
                    elif thr.syntraf_instance_type == "CONNECTOR" and thr.name in connectors_to_stop:
                        thr.close()
                        terminate_connector_and_childs(threads_n_processes, thr.name, thr, _config)

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
            # We extract the dictionary at the same time so that there is no insertion of metrics in between
            dict_data_to_send_to_server_as_array = list(dict_data_to_send_to_server.items())
            keys_of_metrics_to_send_to_server = [x[0] for x in dict_data_to_send_to_server_as_array]
            values_of_metrics_to_send_to_server = [x[1] for x in dict_data_to_send_to_server_as_array]

            sock_send(ssl_conn, values_of_metrics_to_send_to_server, "SAVE_METRIC")
            client_log.debug(
                f"METRICS DICTIONARY SENT WITH {len(values_of_metrics_to_send_to_server)} METRIC(S), WAITING FOR CONFIRMATION")
            received_data = sock_rcv(ssl_conn)
            if received_data:
                client_log.debug(
                    f"JUST RECEIVED THE FOLLOWING ANSWER FROM THE SERVER : {received_data['COMMAND']}:{received_data['PAYLOAD']}")
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
                # connexion fermée par le serveur (redémarrage...) : les mesures restent en file, renvoyées ensuite
                client_log.warning(
                    f"CONNECTION TO {_config['CLIENT']['SERVER']}:{_config['CLIENT']['SERVER_PORT']} LOST: "
                    f"{len(dict_data_to_send_to_server)} MEASUREMENT(S) KEPT FOR THE NEXT CONNECTION")
                return False
        return True
    except Exception as exc:
        raise exc


def client_send_heartbeat(ssl_conn):
    try:
        sock_send(ssl_conn, "", "HEARTBEAT")
    except Exception as exc:
        raise exc


def client_send_system_stats(ssl_conn, obj_stats, dict_data_to_send_to_server=None):
    # We send the system stats to the server
    # Custom classes are not serializable, so dumping obj_stats properties into a dict
    # metrics_buffer : nombre de mesures en attente d'envoi au serveur (arriéré affiché par la webui du serveur)
    try:
        if obj_stats.hasdata:
            payload = obj_stats.as_dict()
            if dict_data_to_send_to_server is not None:
                payload["metrics_buffer"] = len(dict_data_to_send_to_server)
            sock_send(ssl_conn, payload, "SAVE_STATS_METRIC")
            obj_stats.hasdata = False
            #client_log.debug(f"SYSTEM STATS SENT TO SERVER")
        #else:
            #client_log.debug(f"NO SYSTEM STATS TO SEND TO SERVER")
    except Exception as exc:
        raise exc


def client_send_logs(ssl_conn):
    """Envoie au serveur les lignes de journal en attente (voir st_log_forward), par lots."""
    handler = st_log_forward.HANDLER
    if handler is None:
        return
    lines, dropped = handler.drain()
    if lines or dropped:
        sock_send(ssl_conn, {"LINES": lines, "DROPPED": dropped}, "SAVE_LOGS")


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
        #client_log.debug(f"THREAD STATUS SENT TO SERVER")
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
                                if thr.syntraf_instance_type == "CONNECTOR" and connector_key in thr.name:
                                    client_log.info(f"CONNECTOR: '{connector_key}' TERMINATED BECAUSE IP ADDRESS IS NOW UNKNOWN (CLIENT IS NOT CONNECTED TO SERVER ANYMORE)'")
                                    thr.close()
                                    from lib.st_process_and_thread import terminate_connector_and_childs
                                    terminate_connector_and_childs(threads_n_processes, connector_key, thr, _config)
    except Exception as exc:
        raise exc


# Server side: clients declared without IP (set when the server starts), and the delayed forgetting of their IP
DYNAMIC_UIDS = set()
DYNAMIC_IP_FORGET = ForgetScheduler()


#################################################################################
###  MESH CLIENT SOCKET
#################################################################################
def client(_config, stop_thread, dict_data_to_send_to_server, threads_n_processes, obj_stats, config_file_path, cli_parameters):

    address = "0.0.0.0"
    ssl_conn = None
    # Jeton propre remis par le serveur : à côté du fichier de configuration
    _config['CLIENT'].setdefault('_TOKEN_FILE', os.path.join(os.path.dirname(os.path.abspath(config_file_path)),
                                                             "syntraf_client_token"))
    _config['CLIENT'].setdefault('_UID_FILE', os.path.join(os.path.dirname(os.path.abspath(config_file_path)),
                                                           "syntraf_client_uid"))
    _config['CLIENT'].setdefault('_SERVER_PIN_FILE', os.path.join(os.path.dirname(os.path.abspath(config_file_path)),
                                                                  "syntraf_server_pin"))
    client_apply_uid_file(_config)
    try:
        ssl_conn = client_sck_init(_config)
        client_utime = client_connect_utime(_config)
        successful_auth = client_send_auth(_config, client_utime, ssl_conn)

        if not successful_auth:
            ssl_conn.close()
            return

        client_receive_configuration(_config, ssl_conn, threads_n_processes, config_file_path, cli_parameters)
        client_confirm_release()
        client_send_system_infos(ssl_conn)

        current_obj_process_n_thread = None
        while not current_obj_process_n_thread:
            if stop_thread[0]: break
            current_obj_process_n_thread = lib.st_process_and_thread.get_obj_process_n_thread(threads_n_processes, "CLIENT")
            time.sleep(1)

        while True:
            # Update last activity
            current_obj_process_n_thread.last_activity = datetime.now()

            if stop_thread[0]: break

            client_send_heartbeat(ssl_conn)

            client_send_thread_status(ssl_conn, threads_n_processes)

            if not client_send_metrics(_config, ssl_conn, dict_data_to_send_to_server): break

            client_send_system_stats(ssl_conn, obj_stats, dict_data_to_send_to_server)

            client_send_logs(ssl_conn)

            received_data = client_awaiting_command(ssl_conn)

            if not received_data is None:
                if received_data['COMMAND'] == "RECONNECT_CLIENT":
                    client_command_reconnect(ssl_conn)

                if received_data['COMMAND'] == "RESTART_CLIENT":
                    client_command_restart(ssl_conn)

                elif received_data['COMMAND'] == "SET_TOKEN":
                    client_command_set_token(_config, received_data)

                elif received_data['COMMAND'] == "SET_UID":
                    if client_command_set_uid(_config, received_data):
                        client_command_reconnect(ssl_conn)  # se représente sous son nouveau nom

                elif received_data['COMMAND'] == "UPDATE":
                    client_command_update(_config, ssl_conn, received_data)

                # We just received a specific part of the configuration that we should change locally.
                elif received_data['COMMAND'] == "DIFFCONFIG":
                    client_command_diffconfig(_config, received_data, threads_n_processes)

                #client_log.debug(f"SLEEPING FOR {DefaultValues.CONTROL_CHANNEL_HEARTBEAT} SECOND(S)")
                time.sleep(DefaultValues.CONTROL_CHANNEL_HEARTBEAT)
                # client_log.debug(f"SLEEP IS OVER")

            else:
                client_log.info(f"RECEIVED DATA IS NONE")

    except socket.timeout as exc:
        client_log.error(f"SOCKET TIMEOUT: {address}: CLOSING CONNECTION")
    except OSError as exc:
        if exc.errno == 32:  # BROKEN PIPE, THE OTHER END HAS GONE AWAY
            client_log.warning(f"BROKEN PIPE: {address}: CLOSING CONNECTION")
        # CONNECTION RESET BY PEER
        elif exc.errno == 104:
            client_log.warning(f"CONNECTION RESET BY PEER: {address}: CLOSING CONNECTION")
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
            client_log.warning(f"CONNECTION RESET BY PEER: {address}: CLOSING CONNECTION")
        elif exc.errno == 10057:  # FOR WINDOWS [WinError 10057]
            client_log.error(f"{type(exc).__name__.upper()}:{exc.errno}: {address}: CLOSING CONNECTION")
        elif exc.errno == 8:
            client_log.error(f"INVALID SSL CONNECTION. SERVER PROBABLY TERMINATED THE CONNECTION.")
        else:
            client_log.error(f"UNHANDLED OSError (st_mesh:client): {address}: {type(exc).__name__}: {exc} (errno {exc.errno})")
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


_KEY_PROOF_NONCES = st_identity.NonceCache()
_SERVER_IDENTITY = {}
_SERVER_CONFIG = {}  # configuration du serveur, posée à son démarrage (signature des releases)
_UNPROVEN_WARNED = set()


def server_identity(_config=None):
    """(empreinte, clé privée PEM) du certificat du canal de contrôle, lus une fois."""
    if not _SERVER_IDENTITY:
        srv = (_config or _SERVER_CONFIG.get('config') or {}).get('SERVER', {})
        with open(srv['SERVER_X509_CERTIFICATE'], "rb") as f:
            _SERVER_IDENTITY['fp'] = st_identity.spki_sha256(st_identity.pem_to_der(f.read()))
        with open(srv['SERVER_X509_PRIVATE_KEY'], encoding="utf-8") as f:
            _SERVER_IDENTITY['key'] = f.read()
    return _SERVER_IDENTITY['fp'], _SERVER_IDENTITY['key']


def server_sign_release(_config, update):
    try:
        _, key = server_identity(_config)
        return st_identity.sign_release(key, update.get("RELEASE"), update.get("SHA256"), update.get("SIZE") or 0)
    except Exception as exc:  # noqa: BLE001 - sans signature, le client refusera la release : signalé ici
        server_log.error(f"UNABLE TO SIGN RELEASE {update.get('RELEASE')}: {type(exc).__name__}: {exc}")
        return ""


def server_check_key_proof(_config, payload, decision):
    """Le client prouve qu'il détient la clé qu'il présente (signature liée à ce serveur, horodatée, à usage
    unique). Absente : client d'une version antérieure, accepté avec un avertissement, sauf si
    SERVER.REQUIRE_KEY_PROOF l'exige. Invalide : refusé."""
    proof = payload.get('PROOF')
    uid = str(payload.get('CLIENT_UID') or "")
    if proof:
        try:
            fp, _ = server_identity(_config)
        except Exception as exc:  # noqa: BLE001
            server_log.error(f"UNABLE TO READ THE CONTROL CERTIFICATE TO CHECK KEY PROOFS: {exc}")
            return decision
        if st_identity.check_auth_proof(payload.get('PUBLIC_KEY') or "", uid, fp, proof, _KEY_PROOF_NONCES):
            return decision
        return st_enrollment.Decision(False, "INVALID KEY PROOF", None)
    if _config.get('SERVER', {}).get('REQUIRE_KEY_PROOF'):
        return st_enrollment.Decision(False, "KEY PROOF REQUIRED (UPDATE THE CLIENT)", None)
    if uid not in _UNPROVEN_WARNED:
        _UNPROVEN_WARNED.add(uid)
        server_log.warning(f"CONTEXT: {guard.clean(uid)} - DOES NOT PROVE IT HOLDS ITS KEY (OLDER CLIENT): UPDATE IT, "
                           f"THEN ENABLE SERVER.REQUIRE_KEY_PROOF")
    return decision


def authenticate_server_client(_config, data, obj_client, sckt, enrollment=None, dict_of_commands_for_network_clients=None):
    """Décide de l'admission d'un client (voir st_enrollment.authorize) : clé épinglée, jeton propre, jetons partagés,
    demandes en attente. Remet son jeton propre à un client épinglé qui s'est présenté avec un jeton partagé."""
    ip_addr = sckt.getpeername()[0]
    payload = data['PAYLOAD']
    obj_client.public_key_sha256 = st_enrollment.fingerprint(payload.get('PUBLIC_KEY'))
    obj_client.public_key = payload.get('PUBLIC_KEY')
    obj_client.release_id = payload.get('SYNTRAF_RELEASE')
    obj_client.update_failed = payload.get('UPDATE_FAILED')
    obj_client.nat_detected = st_nat.nat_detected(ip_addr, payload.get('LOCAL_ADDRESSES'))
    decision = st_enrollment.authorize(_config, payload, ip_addr,
                                       enrollment if isinstance(enrollment, st_enrollment.Enrollment) else None)
    if decision.accepted:
        decision = server_check_key_proof(_config, payload, decision)
    if decision.accepted and decision.rename_to:
        # Client renommé pendant son absence : admis sous son nouveau nom, qu'on lui remet
        server_log.warning(f"CONTEXT: {decision.rename_to} - PRESENTED ITS PREVIOUS NAME '{guard.clean(payload['CLIENT_UID'])}': "
                           f"GIVING IT ITS NEW NAME")
        payload['CLIENT_UID'] = decision.rename_to
        obj_client.client_uid = decision.rename_to
        if dict_of_commands_for_network_clients is not None:
            dict_of_commands_for_network_clients.setdefault(decision.rename_to, []).append(
                {"ACTION": "SET_UID", "UID": decision.rename_to})
    if decision.accepted:
        server_log.info(f"AUTHENTICATION SUCCESSFUL FROM IP '{ip_addr}' WITH CLIENT_UID '{payload['CLIENT_UID']}'")
        obj_client.status = "CONNECTED"
        obj_client.status_since = datetime.now()
        if decision.deliver_token and dict_of_commands_for_network_clients is not None:
            server_log.info(f"CONTEXT: {payload['CLIENT_UID']} - HANDING OVER ITS OWN TOKEN")
            dict_of_commands_for_network_clients.setdefault(payload['CLIENT_UID'], []).append(
                {"ACTION": "SET_TOKEN", "TOKEN": decision.deliver_token})
        return True, ""
    level = server_log.warning if decision.reason == "PENDING APPROVAL" else server_log.error
    level(f"AUTHENTICATION REFUSED FROM IP '{ip_addr}' WITH CLIENT UID '{guard.clean(obj_client.client_uid)}': {decision.reason}")
    return False, decision.reason


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
                            "IPERF3_TIME_SKEW_THRESHOLD": _config['GLOBAL']['IPERF3_TIME_SKEW_THRESHOLD'],
                            "LOG_FORWARD_LEVEL": _config['GLOBAL'].get('LOG_FORWARD_LEVEL', st_log_forward.DEFAULT_LEVEL)}
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
        f"CONTEXT: {guard.clean(obj_client.client_uid)} - NEW CONNECTION, SOURCE_IP : '{address}'")

    # Admission : clé épinglée, jeton propre ou partagé, demande en attente (dict_of_client_pending_acceptance est
    # l'objet st_enrollment.Enrollment du serveur)
    is_authenticated, rejection_explanation = authenticate_server_client(
        _config, received_data, obj_client, sckt, dict_of_client_pending_acceptance, dict_of_commands_for_network_clients)

    if is_authenticated:
        obj_client.status = "CONNECTED"
        obj_client.status_explanation = "AUTHENTICATION SUCCESSFUL"
        obj_client.status_since = datetime.now()

        sock_send(sckt, None, obj_client.status_explanation)

    else:
        obj_client.status = rejection_explanation
        obj_client.status_explanation = "AUTHENTICATION FAILED"
        obj_client.status_since = datetime.now()

        sock_send(sckt, rejection_explanation, "AUTH_FAILED")

        return False

    for server_client in _config['SERVER_CLIENT']:
        if server_client['UID'] == obj_client.client_uid:

            # If this is a dynamic IP client (declared without IP; its IP may still be known from a recent connection)
            if server_client['UID'] in DYNAMIC_UIDS:
                # So that we can track that this is a dynamic client and rollback the ip when disconnection occur.
                obj_client.bool_dynamic_client = True
                # Back before its IP was forgotten: the other clients kept their connectors, nothing to announce
                DYNAMIC_IP_FORGET.cancel(obj_client.client_uid)
                if server_client['IP_ADDRESS'] == obj_client.ip_address:
                    break

                server_log.debug(
                    f"CONTEXT: {obj_client.client_uid} - THIS CLIENT HAS DYNAMIC IP, UPDATING LOCAL CONFIG AND PUSHING TO OTHER CLIENTS")

                # Updating the client object with the ip address he's coming from
                server_client['IP_ADDRESS'] = obj_client.ip_address

                # We need to regenerate the config, we pass the _dict_by_node_generated_config variable to avoid the webui and process_and_thread to continue to use the old memory pointer
                _dict_by_node_generated_config, _dict_by_group_of_generated_tuple_for_map = generate_client_config_mesh(
                    _config, _dict_by_node_generated_config)

                # Telling to every other client to update their config. The update is appended to their
                # pending commands, never replacing them: another dynamic client may have just been announced.
                queue_client_ip_update(_config, dict_of_commands_for_network_clients, obj_client.client_uid,
                                       obj_client.ip_address)

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
        obj_client.status_since = datetime.now()

    return True


def server_save_stats_metric(obj_client, received_data):
    """
    Insert system stats metric we just received from the client into corresponding obj_client.system_stats dictionary
    It will eventually be read by the API for the WEBUI
    It is called everytime the client send stats which should be quite often
    :param obj_client: The object representing the current client
    :param received_data: The payload we just received from the client containing the systems stats metric
    """
    # Mesures en attente d'envoi chez le client (None : client d'une version qui ne le rapporte pas)
    obj_client.metrics_buffer = received_data['PAYLOAD'].get('metrics_buffer')

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


RELEASE_CHUNK_BYTES = 256 * 1024


def server_send_release_chunk(sckt, payload):
    """Morceau de la release intégrée du serveur (la seule qu'il distribue)."""
    try:
        info = st_release.builtin(DefaultValues.SYNTRAF_ROOT_DIR, DefaultValues.SYNTRAF_DATA_DIR,
                                  DefaultValues.SYNTRAF_VERSION)
        if payload.get('RELEASE') != info['id']:
            sock_send(sckt, {"ERROR": f"this server distributes release {info['id']} only"}, "RELEASE_CHUNK")
            return
        offset = int(payload.get('OFFSET') or 0)
        with open(info['path'], "rb") as f:
            f.seek(offset)
            data = f.read(RELEASE_CHUNK_BYTES)
        sock_send(sckt, {"OFFSET": offset, "DATA": base64.b64encode(data).decode(),
                         "EOF": offset + len(data) >= info['size']}, "RELEASE_CHUNK")
    except Exception as exc:
        server_log.error(f"server_send_release_chunk:{type(exc).__name__}:{exc}")
        sock_send(sckt, {"ERROR": "the server could not read its release"}, "RELEASE_CHUNK")


def server_save_update_status(obj_client, payload):
    obj_client.update_status = dict(payload, AT=datetime.now().astimezone().isoformat(timespec="seconds"))
    log_fn = server_log.error if payload.get('STATE') == "FAILED" else server_log.info
    log_fn(f"CONTEXT: {obj_client.client_uid} - UPDATE TO {guard.clean(payload.get('RELEASE'))}: "
           f"{guard.clean(payload.get('STATE'))} {guard.clean(payload.get('MESSAGE', ''), 400)}")


_LAST_LOG_PURGE = [0.0]


def server_save_logs(_config, client_uid, received_data):
    """Écrit les lignes de journal reçues d'un client sous LOGDIR/clients/<UID>/ (rotation comme les journaux du
    serveur) ; au plus une fois par heure, supprime les fichiers plus vieux que LOG_RETENTION_DAYS."""
    g = _config.get('GLOBAL', {})
    try:
        max_bytes = int(g.get('LOG_MAX_SIZE_PER_FILE_MB', DefaultValues.DEFAULT_LOG_MAX_SIZE_PER_FILE_MB)) * 1024 * 1024
        backups = int(g.get('LOG_FILE_TO_KEEP', DefaultValues.DEFAULT_LOG_FILE_TO_KEEP))
        payload = received_data.get('PAYLOAD') or {}
        # une ligne reçue sur plusieurs lignes ne peut pas forger d'entrée : ses suites sont décalées
        raw = payload.get('LINES') if isinstance(payload.get('LINES'), list) else []
        lines = "".join(st_log_store.contained(line) for line in raw).splitlines()
        st_log_store.append(g.get('LOGDIR', ''), client_uid, lines, int(payload.get('DROPPED') or 0),
                            max_bytes, backups)
        st_syslog.FORWARDER.forward_client_lines(client_uid, lines)
        if g.get('LOG_RETENTION_DAYS') and time.time() - _LAST_LOG_PURGE[0] > 3600:
            _LAST_LOG_PURGE[0] = time.time()
            removed = st_log_store.purge_older_than(g.get('LOGDIR', ''), int(g['LOG_RETENTION_DAYS']))
            if removed:
                server_log.info(f"LOG RETENTION: {len(removed)} FILE(S) OLDER THAN {g['LOG_RETENTION_DAYS']} DAYS REMOVED")
    except Exception as exc:
        server_log.error(f"server_save_logs:{type(exc).__name__}:{exc}")


def server_awaiting_commands(client_uid, dict_of_commands_for_network_clients, sckt):
    """
    Read a dictionary of pending command and send them to the client
    :param client_uid: The uid of the client we are serving
    :param dict_of_commands_for_network_clients: A dictionary of all the pending command. It's organized by client_uid and each command are a sub dictionnary that contain mandatorily the key "ACTION"
    :param sckt: The current socket connected to the client
    """
    # The client reads exactly one answer per AWAITING_COMMAND: hand out at most one action, the oldest.
    # The others stay queued for the next polls.
    sent_an_action = False
    action = next_command(dict_of_commands_for_network_clients, client_uid)
    if action is not None:
        server_log.info(f"SENDING THE ACTION '{action['ACTION']}' TO THE CLIENT {client_uid}")  # jamais le contenu (jeton)
        if action['ACTION'] == "RECONNECT_CLIENT":
            sock_send(sckt, "", "RECONNECT_CLIENT")
            sent_an_action = True
        elif action['ACTION'] == "RESTART_CLIENT":
            sock_send(sckt, "", "RESTART_CLIENT")
            sent_an_action = True
        elif action['ACTION'] == "UPDATE":
            update = {k: action[k] for k in ("RELEASE", "SHA256", "SIZE", "FORCE") if k in action}
            update["SIGNATURE"] = server_sign_release(None, update)
            sock_send(sckt, update, "UPDATE")
            sent_an_action = True
        elif action['ACTION'] == "SET_TOKEN":
            sock_send(sckt, {"TOKEN": action['TOKEN']}, "SET_TOKEN")
            sent_an_action = True
        elif action['ACTION'] == "SET_UID":
            sock_send(sckt, {"UID": action['UID']}, "SET_UID")
            sent_an_action = True
        elif action['ACTION'] == "UPDATED_CONFIG" and action.get('ELEMENT') == "CLIENT_IP":
            sock_send(sckt, action, "DIFFCONFIG")
            sent_an_action = True
        else:
            server_log.warning(f"CONTEXT: {client_uid} - UNKNOWN ACTION DROPPED: {guard.clean(action.get('ACTION'))}")

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
        queue_client_ip_update(_config, dict_of_commands_for_network_clients, obj_client.client_uid, "0.0.0.0")


def server_save_thread_status(obj_client, received_data):
    server_log.debug(f"CONTEXT: {obj_client.client_uid} - RECEIVED A COMMAND TO SAVE THREAD STATUS")
    obj_client.thread_status = received_data['PAYLOAD']


class Handler(StreamRequestHandler):
    def handle(self):
        address = self.client_address
        sckt = self.connection
        _config = self.server._config

        threading.current_thread().name = f"CONTROL CHANNEL CLIENT:{address}"

        dict_of_commands_for_network_clients = self.server.dict_of_commands_for_network_clients
        dict_of_clients = self.server.dict_of_clients
        conn_db = self.server.conn_db
        _dict_by_node_generated_config = self.server.dict_by_node_generated_config
        dict_of_client_pending_acceptance = self.server.dict_of_client_pending_acceptance
        threads_n_processes = self.server.threads_n_processes

        current_thread = threading.current_thread()
        log.debug(current_thread)

        uid = address[0]
        dict_of_clients[uid] = cc_client(status="CONNECTING", status_since=datetime.now(),
                                         status_explanation="NOT YET AUTHENTICATED", client_uid="UNKNOWN",
                                         bool_dynamic_client=False, tcp_port=address[1], ip_address=address[0])

        # Avant une authentification réussie : AUTH seulement, message court, avant l'échéance
        authenticated = False
        auth_deadline = time.monotonic() + guard.AUTH_DEADLINE_S
        try:
            sckt.settimeout(guard.AUTH_DEADLINE_S)
            sckt.do_handshake()
            set_tcp_ka(sckt, server_log)  # rétablit le délai de lecture normal
            while True:
                # no need to loop if no server_client
                if "SERVER_CLIENT" in _config:
                    limit = guard.max_message_bytes(authenticated)
                    deadline = None if authenticated else auth_deadline
                    received_data = sock_rcv(sckt, limit, deadline)

                    if received_data is None:
                        received_data = sock_rcv(sckt, limit, deadline)

                    if received_data is None:
                        server_log.debug(f"CONTEXT: {dict_of_clients[uid].client_uid} - INVALID DATA RECEIVED")
                        dict_of_clients[uid].status_explanation = "CONNECTION RESET BY PEER"
                        server_log.warning(f"CONNECTION RESET BY PEER: {dict_of_clients[uid].ip_address}: CLOSING CONNECTION")
                        break
                    else:
                        # Log the command that was received
                        command = received_data.get('COMMAND') if isinstance(received_data, dict) else None
                        server_log.debug(
                            f"CONTEXT: {dict_of_clients[uid].client_uid} - RECEIVED {guard.clean(command)}")
                        if not guard.allowed(command, authenticated):
                            server_log.warning(f"{dict_of_clients[uid].ip_address}: COMMAND {guard.clean(command)} "
                                               f"BEFORE AUTHENTICATION: CLOSING CONNECTION")
                            dict_of_clients[uid].status_explanation = "COMMAND BEFORE AUTHENTICATION"
                            break

                        if received_data['COMMAND'] == "AUTH":

                            if not server_auth(received_data, dict_of_clients[uid], _config,
                                               dict_of_clients[uid].ip_address, dict_of_commands_for_network_clients, sckt,
                                               _dict_by_node_generated_config, dict_of_client_pending_acceptance, threads_n_processes):
                                return

                            # Now that we know the identity of the client connecting, we can update the dictionary of client objects
                            new_uid = dict_of_clients[uid].client_uid
                            if new_uid not in dict_of_clients:
                                # Déclaré depuis le démarrage (page Clients, approbation, renommage)
                                dict_of_clients[new_uid] = cc_client(status="UNKNOWN", status_since=datetime.now(),
                                                                     status_explanation="NEVER CONNECTED",
                                                                     client_uid=new_uid, bool_dynamic_client=False)
                            dict_of_clients[new_uid].client_uid = new_uid
                            dict_of_clients[new_uid].status = dict_of_clients[uid].status
                            dict_of_clients[new_uid].bool_dynamic_client = dict_of_clients[uid].bool_dynamic_client
                            dict_of_clients[new_uid].status_since = dict_of_clients[uid].status_since
                            dict_of_clients[new_uid].status_explanation = dict_of_clients[uid].status_explanation
                            dict_of_clients[new_uid].clock_skew_in_seconds = dict_of_clients[uid].clock_skew_in_seconds
                            dict_of_clients[new_uid].syntraf_version = dict_of_clients[uid].syntraf_version
                            # clé présentée à l'authentification : nécessaire pour l'épingler (Secure)
                            dict_of_clients[new_uid].public_key = dict_of_clients[uid].public_key
                            dict_of_clients[new_uid].public_key_sha256 = dict_of_clients[uid].public_key_sha256
                            dict_of_clients[new_uid].release_id = dict_of_clients[uid].release_id
                            dict_of_clients[new_uid].update_failed = dict_of_clients[uid].update_failed
                            dict_of_clients[new_uid].nat_detected = getattr(dict_of_clients[uid], "nat_detected", None)
                            dict_of_clients[new_uid].ip_address = address[0]
                            dict_of_clients[new_uid].tcp_port = address[1]
                            dict_of_clients.pop(uid)
                            uid = new_uid
                            authenticated = True

                        elif received_data['COMMAND'] == "SAVE_METRIC":
                            # Un client n'écrit que ce qu'il mesure (étiquette SERVER = son nom)
                            kept, dropped = guard.authorized_points(received_data.get('PAYLOAD'),
                                                                    dict_of_clients[uid].client_uid)
                            if dropped:
                                server_log.warning(f"CONTEXT: {dict_of_clients[uid].client_uid} - {dropped} POINT(S) "
                                                   f"REJECTED: NOT MEASURED BY THIS CLIENT")
                            received_data['PAYLOAD'] = kept
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

                        elif received_data['COMMAND'] == "GET_RELEASE_CHUNK":
                            server_send_release_chunk(sckt, received_data.get('PAYLOAD') or {})

                        elif received_data['COMMAND'] == "UPDATE_STATUS":
                            server_save_update_status(dict_of_clients[uid], received_data.get('PAYLOAD') or {})

                        elif received_data['COMMAND'] == "SAVE_LOGS":
                            server_save_logs(_config, dict_of_clients[uid].client_uid, received_data)

                        elif received_data['COMMAND'] == "HEARTBEAT":
                            pass

                        else:
                            print("UNKNOWN COMMAND:", received_data['COMMAND'])
                else:
                    time.sleep(2)

        except ProtocolViolation as exc:
            dict_of_clients[uid].status_explanation = "PROTOCOL VIOLATION"
            server_log.warning(f"{dict_of_clients[uid].ip_address}: {exc}"
                               f"{'' if authenticated else ' BEFORE AUTHENTICATION'}: CLOSING CONNECTION")
        except socket.timeout as exc:
            server_log.warning(f"SOCKET TIMEOUT: {dict_of_clients[uid].ip_address}: CLOSING CONNECTION")
            dict_of_clients[uid].status_explanation = "SOCKET TIMEOUT"
        except json.JSONDecodeError as exc:
            server_log.error(f"JSON DECODING FAILED FOR STRING")
        except OSError as exc:
            if exc.errno == 32:  # BROKEN PIPE, THE OTHER END HAS GONE AWAY
                dict_of_clients[uid].status_explanation = "BROKEN PIPE"
                server_log.warning(f"BROKEN PIPE: {dict_of_clients[uid].ip_address}: CLOSING CONNECTION")
            # CONNECTION RESET BY PEER
            elif exc.errno == 104:
                dict_of_clients[uid].status_explanation = "CONNECTION RESET BY PEER"
                server_log.warning(f"CONNECTION RESET BY PEER: {dict_of_clients[uid].ip_address}: CLOSING CONNECTION")
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
                server_log.warning(f"CONNECTION RESET BY PEER: {dict_of_clients[uid].ip_address}: CLOSING CONNECTION")
            elif exc.errno == 10057:  # FOR WINDOWS [WinError 10057]
                dict_of_clients[uid].status_explanation = "SOCKET IS NOT CONNECTED"
                server_log.error(
                    f"{type(exc).__name__.upper()}:{exc.errno}: {dict_of_clients[uid].ip_address}: CLOSING CONNECTION")
            else:
                dict_of_clients[uid].status_explanation = "UNKNOWN OSError"
                # e.g. a TLS handshake that failed because the client vanished in the middle of it
                server_log.error(f"UNHANDLED OSError (st_mesh:handle): {dict_of_clients[uid].ip_address}: "
                                 f"{type(exc).__name__}: {exc} (errno {exc.errno})")
        except Exception as exc:
            dict_of_clients[uid].status_explanation = "UNKNOWN"
            server_log.error(f"Handler:handle:{type(exc).__name__}:{exc}", exc_info=True)

        finally:
            # The socket on the other end is probably closed
            server_log.warning(f"CLIENT: {dict_of_clients[uid].ip_address} DISCONNECTED")

            try:
                # If this is a dynamic client, forget its ip address, but only if it has not come back within the
                # grace delay: after a short outage it is usually back with the same IP, and the other clients'
                # connectors resume by themselves.
                if dict_of_clients[uid].bool_dynamic_client:
                    obj_gone, token = dict_of_clients[uid], DYNAMIC_IP_FORGET.schedule(dict_of_clients[uid].client_uid)

                    def forget_if_not_back(obj_gone=obj_gone, token=token):
                        if DYNAMIC_IP_FORGET.should_forget(obj_gone.client_uid, token):
                            server_log.info(f"CONTEXT: {obj_gone.client_uid} - NOT BACK AFTER {DefaultValues.DYNAMIC_IP_FORGET_GRACE} S, FORGETTING ITS IP")
                            server_forget_dynamic_client_ip(obj_gone, _config, dict_of_commands_for_network_clients)

                    timer = threading.Timer(DefaultValues.DYNAMIC_IP_FORGET_GRACE, forget_if_not_back)
                    timer.daemon = True
                    timer.start()

                # Updating the status
                # We don't want to overwrite a reason for failed authentication, so we overwrite only when the client was connected
                if "CONNECTED" in dict_of_clients[uid].status:
                    dict_of_clients[uid].status = "DISCONNECTED"
                    dict_of_clients[uid].status_since = datetime.now()

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
        self.ssl_version = ssl_version  # conservé pour compatibilité, non utilisé (comme avant)
        # ssl.wrap_socket a été supprimé en Python 3.12 : contexte serveur équivalent
        # (même certificat et clé, aucune vérification du certificat client).
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        self.context.verify_mode = ssl.CERT_NONE


    limiter = guard.ConnectionLimiter()

    def process_request(self, request, client_address):
        # Connexions simultanées limitées, au total et par adresse : au-delà, fermée aussitôt
        if not self.limiter.acquire(client_address[0]):
            server_log.warning(f"{client_address[0]}: TOO MANY CONNECTIONS, REFUSED")
            self.shutdown_request(request)
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.limiter.release(client_address[0])

    def get_request(self):
        newsocket, fromaddr = self.socket.accept()
        # Timeout + keepalive: a client that vanished is detected instead of blocking its thread forever.
        set_tcp_ka(newsocket, server_log)
        # The TLS handshake is done in the client's own thread (Handler.handle): a client stalled in the
        # middle of it must not block the accept loop for every other client.
        connstream = self.context.wrap_socket(newsocket,
                                              server_side=True,
                                              do_handshake_on_connect=False)
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
    global DYNAMIC_UIDS
    _SERVER_CONFIG['config'] = _config
    # Union: if this thread is restarted, the IPs of connected dynamic clients are already filled in _config
    DYNAMIC_UIDS |= dynamic_client_uids(_config)

    # iperf3 authentication: rsa keypair and user/password, kept across server restarts (otherwise every
    # client has to restart all its iperf3 after a server restart)
    def generate_iperf3_credentials():
        gen_rsa_iperf3(server_log, _config)
        gen_user_pass_iperf3(server_log, _config)
        return {"username": _config['SERVER']['IPERF3_USERNAME'], "password": _config['SERVER']['IPERF3_PASSWORD'],
                "private_pem": _config['SERVER']['RSA_KEY_LISTENERS'].decode(),
                "public_pem": _config['SERVER']['RSA_KEY_CONNECTORS'].decode()}

    creds = load_or_create(_config['GLOBAL']['IPERF3_RSA_KEY_DIRECTORY'], generate_iperf3_credentials)
    _config['SERVER']['IPERF3_USERNAME'] = creds['username']
    _config['SERVER']['IPERF3_PASSWORD'] = creds['password']
    _config['SERVER']['RSA_KEY_LISTENERS'] = creds['private_pem'].encode()
    _config['SERVER']['RSA_KEY_CONNECTORS'] = creds['public_pem'].encode()
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


def set_tcp_ka(sckt, log, timeout_s=None):
    sckt.settimeout(DefaultValues.CONTROL_CHANNEL_TIMEOUT if timeout_s is None else timeout_s)
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
    # Unacknowledged data for longer than this (ms) closes the connection: keepalive alone never fires
    # because the client always has data in flight.
    tcp_user_timeout = DefaultValues.CONTROL_CHANNEL_TIMEOUT * 1000

    if platform == "linux":
        ka_after_idle_sec_before = sckt.getsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE)
        ka_interval_sec_before = sckt.getsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL)
        ka_max_fails_before = sckt.getsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT)
        tcp_user_timeout_before = sckt.getsockopt(socket.IPPROTO_TCP, socket.TCP_USER_TIMEOUT)

        sckt.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, ka_after_idle_sec)
        sckt.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, ka_interval_sec)
        sckt.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, ka_max_fails)
        sckt.setsockopt(socket.IPPROTO_TCP, socket.TCP_USER_TIMEOUT, tcp_user_timeout)

        ka_after_idle_sec_after = sckt.getsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE)
        ka_interval_sec_after = sckt.getsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL)
        ka_max_fails_after = sckt.getsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT)
        tcp_user_timeout_after = sckt.getsockopt(socket.IPPROTO_TCP, socket.TCP_USER_TIMEOUT)

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





def update_config(data, _config):
    # Updating config (LISTENERS AND CONNECTORS)
    new_config = {'LISTENERS': data['PAYLOAD']['LISTENERS'], 'CONNECTORS': data['PAYLOAD']['CONNECTORS']}

    # Updating CLIENT and GLOBAL config (must be careful, there is already config in this clause)
    _config['CLIENT']['IPERF3_USERNAME'] = data['PAYLOAD']['CLIENT']['IPERF3_USERNAME']
    _config['CLIENT']['IPERF3_PASSWORD'] = data['PAYLOAD']['CLIENT']['IPERF3_PASSWORD']
    _config['CLIENT']['IPERF3_HASH'] = data['PAYLOAD']['CLIENT']['IPERF3_PASSWORD_HASH']
    _config['GLOBAL']['IPERF3_TIME_SKEW_THRESHOLD'] = data['PAYLOAD']['GLOBAL']['IPERF3_TIME_SKEW_THRESHOLD']
    # Journaux transmis au serveur, à partir du niveau qu'il demande (absent : serveur d'une version antérieure)
    if data['PAYLOAD']['GLOBAL'].get('LOG_FORWARD_LEVEL'):
        st_log_forward.install(data['PAYLOAD']['GLOBAL']['LOG_FORWARD_LEVEL'])
    _config.update(new_config)


def save_credentials(data, _config):
    with open_private(os.path.join(_config['GLOBAL']['IPERF3_RSA_KEY_DIRECTORY'], 'private_key_iperf_client.pem'), 'wb') as f:
        f.write(data['PAYLOAD']['CLIENT']['RSA_KEY_LISTENERS'].encode())

    with open(os.path.join(_config['GLOBAL']['IPERF3_RSA_KEY_DIRECTORY'], 'public_key_iperf_client.pem'), 'wb') as f:
        f.write(data['PAYLOAD']['CLIENT']['RSA_KEY_CONNECTORS'].encode())

    try:
        with open_private(os.path.join(_config['GLOBAL']['IPERF3_RSA_KEY_DIRECTORY'], 'credentials.csv'), 'w') as f:
            f.write(_config['CLIENT']['IPERF3_USERNAME'] + "," + _config['CLIENT']['IPERF3_HASH'])

    except Exception as exc:
        server_log.error(
            f"server(): AN ERROR OCCURED WHILE WRITING IPERF3 CREDENTIALS")


def is_valid_server_client(_config, uid, socket):
    for server_client in _config['SERVER_CLIENT']:
        if server_client['UID'] == uid:
            return True
    return False
