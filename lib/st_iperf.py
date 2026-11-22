from lib.st_global import DefaultValues
from lib.st_crypto import *
from lib.st_conf_validation import is_port_available, validate_ipv4
from lib.st_global import DefaultValues
from lib.st_process_and_thread import thread_read_log, thread_udp_hole, get_obj_process_n_thread
import subprocess
import sys
import logging
import os
import time
from datetime import datetime
import psutil
import warnings
import socket
import shlex

from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

iperf3_connectors_log = logging.getLogger("syntraf." + "lib.st_iperf3_connectors")
iperf3_listeners_log = logging.getLogger("syntraf." + "lib.st_iperf3_listeners")
HIGH_PRIORITY_CLASS = 0x00000080


# Client derrière un NAT (connecteur bidirectionnel) : le flux de retour arrive sur un port UDP que ce client a ouvert
# en sortie. Un datagramme vide envoyé depuis ce port vers le pair, toutes les KEEPALIVE_INTERVAL_S, garde la
# correspondance NAT ouverte (voir lib/st_nat.py). Avant : la boucle tournait sans rien envoyer (scapy commenté).
def udp_hole_punch(dst_ip, dst_port, iperf3_connector_obj_pnt, connector_key, threads_n_processes, exit_boolean):
    from lib import st_nat

    curr_thread = get_obj_process_n_thread(threads_n_processes, "UDP_HOLE", connector_key)
    curr_thread.packet_sent = 0
    curr_thread.pid = curr_thread.thread_obj.native_id

    # iperf3 démarré, puis port du flux de retour lu dans sa sortie (thread READ_LOG)
    while iperf3_connector_obj_pnt.subproc is None or not iperf3_connector_obj_pnt.bidir_src_port:
        if exit_boolean[0]:
            return
        time.sleep(1)
    iperf3_pid = iperf3_connector_obj_pnt.subproc.pid

    try:
        dst_ip = socket.gethostbyname(dst_ip)
    except OSError as exc:
        iperf3_connectors_log.error(f"UDP_HOLE FOR {connector_key}: CANNOT RESOLVE {dst_ip}: {exc}")
        return

    warned = False
    while not exit_boolean[0]:
        src_port = iperf3_connector_obj_pnt.bidir_src_port
        if not src_port:
            break  # iperf3 redémarre : un nouveau fil sera lancé avec lui
        try:
            st_nat.send_keepalive(iperf3_connector_obj_pnt.bidir_local_addr, src_port, dst_ip, dst_port)
            curr_thread.packet_sent += 1
            curr_thread.last_activity = datetime.now()
            iperf3_connectors_log.debug(f"NAT KEEPALIVE {connector_key}: {src_port} -> {dst_ip}:{dst_port}")
        except OSError as exc:
            if not warned:  # pas de socket brute (Windows, pas de CAP_NET_RAW) : le flux continu suffit souvent
                iperf3_connectors_log.warning(f"NAT KEEPALIVE UNAVAILABLE FOR {connector_key}: {exc}. THE RETURN STREAM "
                                              f"RELIES ON THE NAT KEEPING THE MAPPING WHILE TRAFFIC FLOWS IN")
                warned = True
        for _ in range(st_nat.KEEPALIVE_INTERVAL_S):
            if exit_boolean[0]:
                return
            time.sleep(1)

    iperf3_connectors_log.info(f"UDP_HOLE FOR {connector_key}, IPERF3 PROCESS ID: '{iperf3_pid}' TERMINATED")


#################################################################################
### START AN IPERF3 CLIENT AS CHILD PROCESS
#################################################################################
def iperf3_client(config, connector_key, connector_value, threads_n_processes):
    try:
        iperf3_obj_proc_n_thread = get_obj_process_n_thread(threads_n_processes, "CONNECTOR", connector_key)

        env_var = os.environ
        env_var['IPERF3_PASSWORD'] = config['CLIENT']['IPERF3_PASSWORD']
        # print(_config['CLIENT']['IPERF3_PASSWORD'])
        # DEBUG
        # subprocess.call(shlex.split("echo %IPERF3_PASSWORD%"), shell=True, env=env_var)

        if config['CONNECTORS'][connector_key]['BIDIR']:
            bidir_arg = "--bidir"
            iperf3_connectors_log.debug(f"{connector_key} - BIDIRECTIONAL MODE ACTIVATED")
        else:
            bidir_arg = ""

        valid_ip = False
        ip_address = None
        while not valid_ip:
            try:
                ip_address = socket.gethostbyname(socket.gethostbyname(config['CONNECTORS'][connector_key]['DESTINATION_ADDRESS']))
                if validate_ipv4(ip_address):
                    valid_ip = True
            except socket.gaierror as e:
                if e.errno == socket.EAI_AGAIN:
                    logging.error(f"TEMPORARY FAILURE IN NAME RESOLUTION OF {ip_address}")
            time.sleep(1)

        args = []
        args.append(config['GLOBAL']['IPERF3_BINARY_PATH'])
        args.append("-u")
        args.extend(["-l", config['CONNECTORS'][connector_key]['PACKET_SIZE']])
        args.extend(["-c", ip_address])
        args.extend(["-t", "0"])
        args.extend(["-b", config['CONNECTORS'][connector_key]['BANDWIDTH']])
        args.append("--udp-counters-64bit")
        args.extend(["--connect-timeout=" + DefaultValues.DEFAULT_IPERF3_CONNECT_TIMEOUT])
        args.extend(["--dscp", config['CONNECTORS'][connector_key]['DSCP']])
        args.extend(["--pacing-timer", str(config['CONNECTORS'][connector_key]['PACKET_PACING'])])
        args.extend(["-f", "k"])
        args.extend(["-p", str(config['CONNECTORS'][connector_key]['PORT'])])
        args.append("--timestamps='%F %T '")
        args.extend([bidir_arg, "--forceflush"])

        ''' 
        --cntl-ka[=#/#/#] use control connection TCP keepalive - KEEPIDLE/KEEPINTV/KEEPCNT
        control connection Keepalive period should be larger than retry period (interval * count) 
        TCP_KEEPIDLE = Interval of Keepalive
        TCP_KEEPINTV = Interval of Retry
        TCP_KEEPCNT = Drop connection after that amount of lost keepalive
        '''
        args.append('--cntl-ka=10/1/5')

        if config['GLOBAL']['IPERF3_AUTH']:
            args.append("--username")
            args.append(config['CLIENT']['IPERF3_USERNAME'])
            args.append("--rsa-public-key-path")
            args.append(os.path.join(config['GLOBAL']['IPERF3_RSA_KEY_DIRECTORY'], 'public_key_iperf_client.pem'))

        #if config['CONNECTORS'][connector_key]['BIDIR']:
        #    args.append("--rcv-timeout")
        #    args.append(DefaultValues.DEFAULT_IPERF3_RCV_TIMEOUT)

        arguments = " "
        arguments = arguments.join(args)
        # iperf3_listeners_log.error(arguments)

        #print(_config['CLIENT']['IPERF3_PASSWORD'])

        if config['CONNECTORS'][connector_key]['BIDIR']:
            # Make sure we have udp_hole punching and read_log thread for each bidir connector
            thread_udp_hole(config, connector_key, connector_value, threads_n_processes, iperf3_obj_proc_n_thread)
            time.sleep(2)

        p = subprocess.Popen(args, close_fds=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE, stdin=None, text=True, env=env_var, bufsize=1)
        iperf3_obj_proc_n_thread.subproc = p

        if p.poll() is None:
            iperf3_connectors_log.warning(f"IPERF3 CLIENT FOR CONNECTOR '{connector_key}' STARTED WITH SERVER {config['CONNECTORS'][connector_key]['DESTINATION_ADDRESS']}:{config['CONNECTORS'][connector_key]['PORT']} {arguments}")
        else:
            last_breath = p.communicate()[1]

            explanation = "UNKNOWN"
            if "unable to connect to server: No route to host" in last_breath:
                explanation = "CLIENT FIREWALL"
            iperf3_connectors_log.error(f"UNABLE TO START IPERF3 CLIENT FOR CONNECTOR '{connector_key}' : IPERF3 LAST BREATH : {last_breath}")
            iperf3_connectors_log.error(f"PROBABLE EXPLANATION: {explanation}")
            iperf3_connectors_log.error(f"IPERF3 CLIENT FOR {connector_key} TERMINATED")

    except Exception as exc:
        iperf3_connectors_log.error(f"iperf_client:{type(exc).__name__}:{exc}", exc_info=True)


#################################################################################
### START AN IPERF3 SERVER AS CHILD PROCESS
#################################################################################
def iperf3_server(config, listener_key, listener_value, threads_n_processes):
    iperf3_obj_proc_n_thread = get_obj_process_n_thread(threads_n_processes, "LISTENER", listener_key)

    iperf3_listeners_log.debug(config['LISTENERS'][listener_key]['BIND_ADDRESS'])

    #if is_port_available(config['LISTENERS'][listener_key]['BIND_ADDRESS'], str(config['LISTENERS'][listener_key]['PORT'])):
    try:
        args = []
        args.append(config['GLOBAL']['IPERF3_BINARY_PATH'])
        args.append("-s")
        args.extend(["-i", config['LISTENERS'][listener_key]['INTERVAL']])
        args.extend(["-f", "k"])
        args.append("--forceflush")
        args.extend(["--idle-timeout", DefaultValues.DEFAULT_IPERF3_SERVER_IDLE_TIMEOUT])
        args.extend(["--rcv-timeout", DefaultValues.DEFAULT_IPERF3_RCV_TIMEOUT])
        args.append("--one-off")
        args.extend(["-p", str(config['LISTENERS'][listener_key]['PORT'])])
        args.append("--timestamps='%F %T '")

        ''' 
        --cntl-ka[=#/#/#] use control connection TCP keepalive - KEEPIDLE/KEEPINTV/KEEPCNT
        control connection Keepalive period should be larger than retry period (interval * count) 
        TCP_KEEPIDLE = Interval of Keepalive
        TCP_KEEPINTV = Interval of Retry
        TCP_KEEPCNT = Drop connection after that amount of lost keepalive
        '''
        args.append('--cntl-ka=10/1/5')

        if config['GLOBAL']['IPERF3_AUTH']:
            args.append("--rsa-private-key-path")
            args.append(os.path.join(config['GLOBAL']['IPERF3_RSA_KEY_DIRECTORY'], 'private_key_iperf_client.pem'))
            args.append("--authorized-users-path")
            args.append(os.path.join(config['GLOBAL']['IPERF3_RSA_KEY_DIRECTORY'], 'credentials.csv'))
            args.append("--time-skew-threshold")
            args.append(config['GLOBAL']['IPERF3_TIME_SKEW_THRESHOLD'])
            args.append("--timestamps='%F %T '")

        arguments = " "
        arguments = arguments.join(args)
        # iperf3_listeners_log.error(arguments)

        p = subprocess.Popen(args, close_fds=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE, stdin=None, text=True, bufsize=1)
        iperf3_obj_proc_n_thread.subproc = p

        if p.poll() is None:
            iperf3_listeners_log.warning(f"IPERF3 SERVER FOR LISTENER '{listener_key}' STARTED ON PORT {config['LISTENERS'][listener_key]['PORT']}")
            return p
        else:
            last_breath = p.communicate()[1]
            iperf3_listeners_log.error(f"UNABLE TO START IPERF3 SERVER FOR LISTENER '{listener_key}' : IPERF3 LAST BREATH : {last_breath}")

    except Exception as exc:
        iperf3_listeners_log.error(f"iperf_server:{type(exc).__name__}:{exc}", exc_info=True)
    # else:
    #     iperf3_listeners_log.error(f"iperf_server: port unavailable")
    #     sys.exit()

