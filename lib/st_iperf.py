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
import psutil
import warnings
import socket
import getmac
import shlex

from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
from scapy import all as scapy

iperf3_connectors_log = logging.getLogger("syntraf." + "lib.st_iperf3_connectors")
iperf3_listeners_log = logging.getLogger("syntraf." + "lib.st_iperf3_listeners")
HIGH_PRIORITY_CLASS = 0x00000080


# Find the ephemeral port iperf3 is using for the incoming connection in bidirectional mode then send a packet
# to the other side with the right src and dst port to keep alive the udp hole punch.
def udp_hole_punch(dst_ip, dst_port, iperf3_connector_obj_pnt, connector_key, threads_n_processes, exit_boolean):

    # Wait for iperf3 to start
    while iperf3_connector_obj_pnt.subproc is None:
        if exit_boolean[0]:
            return
        time.sleep(1)
        if iperf3_connector_obj_pnt.subproc:
            break

    iperf3_pid = iperf3_connector_obj_pnt.subproc.pid

    # Find current thread to update packet sent in the st_obj_process_n_thread object
    curr_thread = get_obj_process_n_thread(threads_n_processes, "UDP_HOLE", connector_key)
    curr_thread.packet_sent = 0
    curr_thread.pid = curr_thread.thread_obj.native_id

    # Waiting for the READ_LOG thread to obtain the source port
    while iperf3_connector_obj_pnt.bidir_src_port == 0:
        if exit_boolean[0]:
            return
        iperf3_connectors_log.debug(f"UDP_HOLE_PUNCH FOR {connector_key}, IPERF3 PROCESS ID: '{iperf3_pid}' IS WAITING FOR A PORT:{iperf3_connector_obj_pnt.bidir_src_port}")
        time.sleep(1)

    # Hostname resolution
    valid_ip = False
    while not valid_ip:
        if exit_boolean[0]:
            return
        try:
            dst_ip = socket.gethostbyname(dst_ip)
            if validate_ipv4(dst_ip):
                valid_ip = True
        except socket.gaierror as e:
            if e.errno == socket.EAI_AGAIN:
                iperf3_connectors_log.error(f"TEMPORARY FAILURE IN NAME RESOLUTION OF {dst_ip}")
        time.sleep(1)

    src_ip = iperf3_connector_obj_pnt.bidir_local_addr
    src_port = iperf3_connector_obj_pnt.bidir_src_port
    src_if = ""
    src_mac = ""
    dst_mac = ""

    # In case there is PBR on the server, make sure we are sending the packet out the right interface
    interfaces = psutil.net_if_addrs()

    # We need to figure out what is the out interface so that we can get the mac address
    for iface_key, iface_values in interfaces.items():
        for iface in iface_values:
            if iface.address == src_ip:
                src_if = iface_key

    # Get the MAC of the out_if
    for iface_key, iface_values in interfaces.items():
        if iface_key == src_if:
            for iface in iface_values:
                if iface.family == psutil.AF_LINK:
                    src_mac = iface.address

    if sys.platform == "linux":
        try:
            p = subprocess.check_output(["whereis", "ip"])
            ip_bin = p.decode('utf-8').split()[1]
            if ip_bin:
                cmd = (f"{ip_bin} route get from {src_ip} to {dst_ip} oif {src_if} ipproto udp sport {src_port} dport {dst_port}")
                p = subprocess.check_output(shlex.split(cmd))
                nexthop = p.decode('utf-8').replace("\n", "").split()[4]
                dst_mac = getmac.get_mac_address(None, nexthop)

        except Exception as e:
            iperf3_connectors_log.error(e)
    elif sys.platform == "win32":
        cmd = (f"powershell find-netroute -remoteipaddress {dst_ip} | Select-Object NextHop | Select -ExpandProperty NextHop")
        p = subprocess.check_output(shlex.split(cmd))
        nexthop = p.decode('utf-8')
        dst_mac = getmac.get_mac_address(None, nexthop)

    while True:
        if exit_boolean[0]:
            return

        if iperf3_connector_obj_pnt.bidir_src_port == 0:
            exit_message = "bidir_src_port became 0"
            break
        try:
            curr_thread.packet_sent += 1
            curr_thread.last_activity = datetime.now()
            iperf3_connectors_log.debug(f"SENDING KEEPALIVE WITH SRC:{src_mac}/{src_ip}/{iperf3_connector_obj_pnt.bidir_src_port}, DST:{dst_mac}/{dst_ip}/{dst_port} ON IFACE:{src_if}")
            scapy.sendp(scapy.Ether(src=src_mac, dst=dst_mac) / scapy.IP(src=src_ip, dst=dst_ip) / scapy.UDP(sport=src_port,dport=dst_port) / scapy.Raw(load="KEEPALIVE"), verbose=False, iface=src_if, inter=1, count=1)

        except Exception as ex:
            iperf3_connectors_log.error(ex)

        time.sleep(1)

    iperf3_connectors_log.error(f"UDP_HOLE FOR {connector_key}, IPERF3 PROCESS ID: '{iperf3_pid}' TERMINATED. EXIT MESSAGE: {exit_message}")


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

    if is_port_available(config['LISTENERS'][listener_key]['BIND_ADDRESS'], str(config['LISTENERS'][listener_key]['PORT'])):
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
    else:
        iperf3_listeners_log.error(f"iperf_server: port unavailable")
        sys.exit()

