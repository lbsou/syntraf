from lib.st_global import DefaultValues
from lib.st_crypto import *
from lib.st_conf_validation import is_port_available
from lib.st_global import DefaultValues
import subprocess
import sys
import logging
import os
import time
import psutil
import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
from scapy import all as scapy

iperf3_connectors_log = logging.getLogger("syntraf." + "lib.st_iperf3_connectors")
iperf3_listeners_log = logging.getLogger("syntraf." + "lib.st_iperf3_listeners")


# Find the ephemeral port iperf3 is using for the incoming connection in bidirectional mode then send a packet
# to the other side with the right src and dst port to keep alive the udp hole punch.
def udp_hole_punch(dst_ip, dst_port, iperf3_pid, exit_boolean, iperf_conn_thread):

    # Waiting for the READ_LOG thread to obtain the source port
    while iperf_conn_thread.bidir_src_port == 0:
        time.sleep(1)
        iperf3_connectors_log.error("waiting for a port")

    # two_ports = False
    # lst_udp_port_iperf = []
    # net_conn = psutil.net_connections("udp")
    #
    # while not two_ports:
    #     for con in net_conn:
    #         if con.pid == iperf3_pid:
    #             lst_udp_port_iperf.append(con.laddr[1])
    #     if len(lst_udp_port_iperf) == 2:
    #         two_ports = True
    #     time.sleep(1)

    interfaces = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    while not exit_boolean[0]:
        # Send on all interface, dirty ack
        for if_name, addrs in interfaces.items():
            for if_name2, stats2 in stats.items():
                # Do not try to send on a down interface
                if if_name2 == if_name and if_name2 != "lo":
                    if stats2.isup:
                        try:
                            iperf3_connectors_log.error(f"SCAPY time on {if_name}")
                            iperf3_connectors_log.error(f"SRC:{iperf_conn_thread.bidir_src_port}, DST:{dst_ip}/{dst_port}, IFACE:{if_name}")
                            scapy.sendp(scapy.Ether()/scapy.IP(dst=dst_ip) / scapy.UDP(sport=int(iperf_conn_thread.bidir_src_port), dport=dst_port) / scapy.Raw(load="KEEPALIVE"), verbose=False, iface=if_name, inter=0.1, count=10)
                        except Exception as ex:
                            iperf3_connectors_log.error(ex)
        time.sleep(1)


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

        args = (
            _config['GLOBAL']['IPERF3_BINARY_PATH'], "-u", "-l",
            _config['CONNECTORS'][connector_dict_key]['PACKET_SIZE'], "-c",
            _config['CONNECTORS'][connector_dict_key]['DESTINATION_ADDRESS'], "-t", "0", "-b",
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

        time.sleep(int(DefaultValues.DEFAULT_IPERF3_CONNECT_TIMEOUT)/1000 + 2)

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
