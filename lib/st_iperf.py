from lib.st_global import DefaultValues
from lib.st_crypto import *
from lib.st_conf_validation import is_port_available, validate_ipv4
from lib.st_global import DefaultValues
import subprocess
import sys
import logging
import os
import re
import time
import psutil
import shlex
import warnings
import socket
import getmac

from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
from scapy import all as scapy

iperf3_connectors_log = logging.getLogger("syntraf." + "lib.st_iperf3_connectors")
iperf3_listeners_log = logging.getLogger("syntraf." + "lib.st_iperf3_listeners")


# Find the ephemeral port iperf3 is using for the incoming connection in bidirectional mode then send a packet
# to the other side with the right src and dst port to keep alive the udp hole punch.
def udp_hole_punch(dst_ip, dst_port, exit_boolean, iperf3_conn_thread, connector):
    exit_message = ""
    iperf3_pid = iperf3_conn_thread.subproc.pid
    # Waiting for the READ_LOG thread to obtain the source port
    while iperf3_conn_thread.bidir_src_port == 0 and not exit_boolean[0]:
        iperf3_connectors_log.debug(f"UDP_HOLE_PUNCH FOR {connector}, IPERF3 PROCESS ID: '{iperf3_pid}' IS WAITING FOR A PORT:{iperf3_conn_thread.bidir_src_port}")
        time.sleep(1)

    # Hostname resolution
    valid_ip = False
    while not valid_ip:
        try:
            dst_ip = socket.gethostbyname(dst_ip)
            if validate_ipv4(dst_ip):
                valid_ip = True
        except socket.gaierror as e:
            if e.errno == socket.EAI_AGAIN:
                iperf3_connectors_log.error(f"TEMPORARY FAILURE IN NAME RESOLUTION OF {dst_ip}")
        time.sleep(1)

    src_ip = iperf3_conn_thread.bidir_local_addr
    src_port = iperf3_conn_thread.bidir_src_port
    src_if = ""
    src_mac = ""
    dst_mac = ""

    # In case there is PBR on the server, make sure we are sending the packet out the right interface
    if not exit_boolean[0]:

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

        cmd = ""
        args = None
        if sys.platform == "linux":
            try:
                cmd = "ip"
                args = (f"ip route get from {src_ip} to {dst_ip} oif {src_if} ipproto udp sport {src_port} dport {dst_port} | awk '{{print $3}}'")
                p = subprocess.check_output(shlex.split(args), shell=True)
                nexthop = p.decode('utf-8')
                dst_mac = getmac.get_mac_address(None, nexthop)
                iperf3_connectors_log.error(dst_mac)
            except Exception as e:
                iperf3_connectors_log.error(f"ERREUR========================={e}")
        elif sys.platform == "win32":
            #p = subprocess.check_output("where powershell")
            cmd = "powershell"
            args = (f"find-netroute -remoteipaddress {dst_ip} | Select-Object NextHop | Select -ExpandProperty NextHop")
            p = subprocess.check_output(cmd + " " + args)
            nexthop = p.decode('utf-8')
            dst_mac = getmac.get_mac_address(None, nexthop)
        else:
            exit_boolean[0] = True

    while not exit_boolean[0]:
        if iperf3_conn_thread.bidir_src_port == 0:
            exit_message = "bidir_src_port became 0"
            break

        try:
            iperf3_connectors_log.debug(f"SENDING KEEPALIVE WITH SRC:{src_mac}/{src_ip}/{iperf3_conn_thread.bidir_src_port}, DST:{dst_mac}/{dst_ip}/{dst_port} ON IFACE:{src_if}")
            scapy.sendp(scapy.Ether(src=src_mac, dst=dst_mac) / scapy.IP(src=src_ip, dst=dst_ip) / scapy.UDP(sport=src_port,dport=dst_port) / scapy.Raw(load="KEEPALIVE"), verbose=False, iface=src_if, inter=1, count=1)
        except Exception as ex:
            iperf3_connectors_log.error(ex)

        time.sleep(1)

    if exit_boolean[0]:
        exit_message = "EXIT BOOLEAN BECAME TRUE, THE CONNECTOR PROBABLY DIED."

    iperf3_connectors_log.error(f"UDP_HOLE FOR {connector}, IPERF3 PROCESS ID: '{iperf3_pid}' TERMINATED. EXIT MESSAGE: {exit_message}")


#################################################################################
### START AN IPERF3 CLIENT AS CHILD PROCESS
#################################################################################
def iperf3_client(connector_dict_key, _config):
    try:
        env_var = os.environ
        env_var['IPERF3_PASSWORD'] = _config['CLIENT']['IPERF3_PASSWORD']
        # print(_config['CLIENT']['IPERF3_PASSWORD'])
        # DEBUG
        # subprocess.call(shlex.split("echo %IPERF3_PASSWORD%"), shell=True, env=env_var)

        if _config['CONNECTORS'][connector_dict_key]['BIDIR']:
            bidir_arg = "--bidir"
            iperf3_connectors_log.debug(f"{connector_dict_key} - BIDIRECTIONAL MODE ACTIVATED")
        else:
            bidir_arg = ""

        valid_ip = False
        while not valid_ip:
            try:
                ip_address = socket.gethostbyname(socket.gethostbyname(_config['CONNECTORS'][connector_dict_key]['DESTINATION_ADDRESS']))
                if validate_ipv4(ip_address):
                    valid_ip = True
            except socket.gaierror as e:
                if e.errno == socket.EAI_AGAIN:
                    logging.error(f"TEMPORARY FAILURE IN NAME RESOLUTION OF {ip_address}")
            time.sleep(1)

        args = (
            _config['GLOBAL']['IPERF3_BINARY_PATH'], "-u", "-l",
            _config['CONNECTORS'][connector_dict_key]['PACKET_SIZE'], "-c",
            ip_address, "-t", "0", "-b",
            _config['CONNECTORS'][connector_dict_key]['BANDWIDTH'],
            "--udp-counters-64bit", "--connect-timeout=" + DefaultValues.DEFAULT_IPERF3_CONNECT_TIMEOUT, "--dscp", _config['CONNECTORS'][connector_dict_key]['DSCP'],
            "--pacing-timer", "12000",
            "--username", _config['CLIENT']['IPERF3_USERNAME'],
            "--rsa-public-key-path", os.path.join(_config['GLOBAL']['IPERF3_RSA_KEY_DIRECTORY'], 'public_key_iperf_client.pem'),
            "--connect-timeout", DefaultValues.DEFAULT_IPERF3_CLIENT_CONNECT_TIMEOUT,
            "--logfile",
            os.path.join(_config['GLOBAL']['IPERF3_TEMP_DIRECTORY'],
                         "syntraf_" + str(_config['CONNECTORS'][connector_dict_key]['PORT']) + "_connector.log"),
            "-f", "k", "-p", str(_config['CONNECTORS'][connector_dict_key]['PORT']), "--timestamps='%F %T '",
            bidir_arg)

        arguments = ""
        for i in args:
            arguments += " " + i

        #print(args)
        #print(_config['CLIENT']['IPERF3_PASSWORD'])

        p = subprocess.Popen(args, close_fds=True, stderr=subprocess.PIPE, stdout=subprocess.DEVNULL, env=env_var)

        #time.sleep(int(DefaultValues.DEFAULT_IPERF3_CONNECT_TIMEOUT)/1000 + 2)

        if p.poll() is None:
            iperf3_connectors_log.warning(f"IPERF3 CLIENT FOR CONNECTOR '{connector_dict_key}' STARTED WITH SERVER {_config['CONNECTORS'][connector_dict_key]['DESTINATION_ADDRESS']}:{_config['CONNECTORS'][connector_dict_key]['PORT']} {arguments}")
            return p
        else:
            #p.stderr.close()
            last_breath = p.communicate()[1].decode('utf-8')

            explanation = "UNKNOWN"
            if "unable to connect to server: No route to host" in last_breath:
                explanation = "CLIENT FIREWALL"
            iperf3_connectors_log.error(f"UNABLE TO START IPERF3 CLIENT FOR CONNECTOR '{connector_dict_key}' : IPERF3 LAST BREATH : {last_breath}")
            iperf3_connectors_log.error(f"PROBABLE EXPLANATION: {explanation}")
            iperf3_connectors_log.error(f"IPERF3 CLIENT FOR {connector_dict_key} TERMINATED")

            return None

    except Exception as exc:
        iperf3_connectors_log.error(f"iperf_client:{type(exc).__name__}:{exc}", exc_info=True)
        return None


#################################################################################
### START AN IPERF3 SERVER AS CHILD PROCESS
#################################################################################
def iperf3_server(listener_dict_key, _config):
    global var_cfg_default_bind_arg

    #if "BIND_ADDRESS" in _config['LISTENERS'][listener_dict_key]:
    #    if not _config['LISTENERS'][listener_dict_key]['BIND_ADDRESS'] == "*":
    #        var_cfg_default_bind_arg = ("-B", _config['LISTENERS'][listener_dict_key]['BIND_ADDRESS'])

    if is_port_available(_config['LISTENERS'][listener_dict_key]['BIND_ADDRESS'], str(_config['LISTENERS'][listener_dict_key]['PORT'])):
        try:
            args = (_config['GLOBAL']['IPERF3_BINARY_PATH'], "-s", "-i", _config['LISTENERS'][listener_dict_key]['INTERVAL'],
                    #var_cfg_default_bind_arg[0], var_cfg_default_bind_arg[1],
                    "--logfile",
                    os.path.join(_config['GLOBAL']['IPERF3_TEMP_DIRECTORY'], "syntraf_" + str(_config['LISTENERS'][listener_dict_key]['PORT']) + "_listener.log"), "-f", "k",
                    "--rsa-private-key-path", os.path.join(_config['GLOBAL']['IPERF3_RSA_KEY_DIRECTORY'], 'private_key_iperf_client.pem'),
                    "--authorized-users-path", os.path.join(_config['GLOBAL']['IPERF3_RSA_KEY_DIRECTORY'], 'credentials.csv'),
                    "--time-skew-threshold", _config['GLOBAL']['IPERF3_TIME_SKEW_THRESHOLD'],
                    "--idle-timeout", DefaultValues.DEFAULT_IPERF3_SERVER_IDLE_TIMEOUT,
                    "--rcv-timeout", DefaultValues.DEFAULT_IPERF3_RCV_TIMEOUT,
                    "--one-off",
                    "-p", str(_config['LISTENERS'][listener_dict_key]['PORT']), "--timestamps='%F %T '")

            arguments = ""
            for i in args:
                arguments += " " + i

            p = subprocess.Popen(args, close_fds=True, stderr=subprocess.PIPE, stdout=subprocess.DEVNULL)
            if p.poll() is None:
                iperf3_listeners_log.warning(
                    f"IPERF3 SERVER FOR LISTENER '{listener_dict_key}' STARTED ON {_config['LISTENERS'][listener_dict_key]['BIND_ADDRESS']}:{_config['LISTENERS'][listener_dict_key]['PORT']}")
                return p
            else:
                iperf3_listeners_log.error(
                    f"UNABLE TO START IPERF3 SERVER FOR LISTENER '{listener_dict_key}'")

        except Exception as exc:
            iperf3_listeners_log.error(f"iperf_server:{type(exc).__name__}:{exc}", exc_info=True)
    else:
        iperf3_listeners_log.error(f"iperf_server: port unavailable")
        sys.exit()
