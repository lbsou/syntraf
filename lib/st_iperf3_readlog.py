from lib.st_global import DefaultValues
from lib.st_iperf import *
from lib.st_influxdb import *
import os
import time
import re
import datetime
import pytz
import pathlib
import logging
log = logging.getLogger("syntraf." + __name__)


#################################################################################
### YIELD LINE FROM IPERF3 OUTPUT FILE
#################################################################################
def tail(file, interval, uid_client, uid_server, _config, edge_type, edge_dict_key, dict_data_to_send_to_server, threads_n_processes, exit_boolean, iperf_read_log_thread=None):
    utime_last_event = 0

    try:
        cpt_port_bidir = 0
        while True:
            time.sleep(interval)
            lines = file.read().splitlines()
            file.seek(0)
            file.truncate()

            if exit_boolean[0]:
                yield "exit_boolean_true"

            for line in lines:
                values = line.split(" ")

                if line:
                    if (len(values) >= 20 and ("omitted" not in line) and ("terminated" not in line) and (
                            "Interval" not in line) and ("receiver" not in line) and ("------------" not in line) and (
                            "- - - - - - - - -" not in line)):
                        utime_last_event = time.time()
                        yield line

                    else:
                        log.debug(f"tail():LINE DOES NOT CONTAIN METRICS:{line}")

                        # When we have a bidir connection, iperf will open two port to destination. We want to grab the second source port, as it will allow us to keepalive the udp hole with scapy in another thread.
                        #local 192.168.2.41 port 58743 connected to 192.168.6.100 port 15999
                        #local 192.168.2.41 port 58744 connected to 192.168.6.100 port 15999

                        m_lport = re.search(r"local (?:[0-9]{1,3}.){3}[0-9]{1,3} port (\d{1,10}) connected to (?:[0-9]{1,3}.){3}[0-9]{1,3} port \d{1,10}", line)
                        m_laddr = re.search(r"local ((?:[0-9]{1,3}.){3}[0-9]{1,3}) port \d{1,10} connected to (?:[0-9]{1,3}.){3}[0-9]{1,3} port \d{1,10}", line)

                        # Grab only the port from the second line, which is the RX
                        if m_lport and cpt_port_bidir >= 0 and hasattr(iperf_read_log_thread, 'bidir_src_port'):
                            if cpt_port_bidir == 0:
                                cpt_port_bidir += 1
                            elif cpt_port_bidir == 1:
                                iperf_read_log_thread.bidir_src_port = int(m_lport.groups()[0])
                                iperf_read_log_thread.bidir_local_addr = m_laddr.groups()[0]
                                log.info(f"GOT A SRC_IP AND SRC_PORT FOR UDP_HOLE_PUNCH:{m_laddr.groups()[0]}/{m_lport.groups()[0]}")
                                cpt_port_bidir = -1
                        continue
                else:
                    #NO LINE
                    utime_now = time.time()
                    listener_just_started_or_absent = False

                    # Get the infos of the starttime of the current listener, if it has just started or does not exist, do no log an outage, it's just iperf that is not running.
                    flag_no_thread_found = True
                    for obj_thread_n_process in threads_n_processes:
                        if obj_thread_n_process.name == edge_dict_key and (obj_thread_n_process.syntraf_instance_type == "LISTENER" or obj_thread_n_process.syntraf_instance_type == "CONNECTOR"):
                            flag_no_thread_found = False
                            dt_delta = datetime.datetime.now() - datetime.datetime.strptime(obj_thread_n_process.starttime,
                                                                                            "%d/%m/%Y %H:%M:%S")
                            if dt_delta.total_seconds() <= 60:
                                listener_just_started_or_absent = True

                    if flag_no_thread_found: listener_just_started_or_absent = True

                    '''
                    Iperf3 stop generating events when the connection is lost for too long [how much exactly?], but we still want to report the losses
                    For that, we need to already have received a log in the past (utime_last_event != 0) and the current log file of iperf3 must not yield line (not line)
                    '''
                    #log.debug(f"OUTAGE_MECHANISM DEBUG utime_last_event:{utime_last_event}")
                    #log.debug(f"{utime_last_event}{line}{listener_just_started_or_absent}")

                    if utime_last_event != 0 and not line:
                        log.debug(f"OUTAGE_MECHANISM DEBUG utime_now:{utime_now} utime_last_event:{utime_last_event} utime_now - utime_last_event: {(utime_now - utime_last_event)}")

                        # If iperf3 did not write any events for the double of the interval he's supposed to
                        if (utime_now - utime_last_event) >= (2 * interval):
                            # Save new event to database with 100% loss for every time interval
                            qty_of_event_to_report = (utime_now - utime_last_event) / interval
                            log.warn(
                                f"{edge_dict_key} - SYNTRAF HAS DETECTED AN OUTAGE, {qty_of_event_to_report} EVENTS WHERE LOST. GENERATING 100% LOSSES VALUES.")

                            for utime_generated in range(int(utime_last_event) + interval, int(utime_now), interval):
                                dt_generated = datetime.datetime.fromtimestamp(utime_generated)
                                timezone = pytz.timezone(DefaultValues.TIMEZONE)
                                dt_tz_generated = timezone.localize(dt_generated)
                                timestamp_generated = dt_tz_generated.astimezone(pytz.timezone("UTC"))
                                utime_generated_utc = dt_tz_generated.astimezone(pytz.timezone("UTC")).timestamp()

                                # we could just yield a line, but that would required building a line with the same format as iperf3, it's a hack IMHO, prefer to save directly here.
                                save_to_server([uid_client, uid_server, timestamp_generated, utime_generated_utc, "0", "0", "100"], _config,
                                               edge_type, edge_dict_key, "0", "0", dict_data_to_send_to_server)

                                log.debug(f"WRITING_TO_QUEUE ({len(dict_data_to_send_to_server)}) - {edge_dict_key}")
                                log.debug(f"timestamp:{timestamp_generated}, bitrate: 0, jitter: 0, loss: 100, packet_loss: 0, packet_total: 0")

                            utime_last_event = utime_now
                    continue

    except Exception as exc:
        log.error(f"tail:{type(exc).__name__}:{exc}", exc_info=True)


#################################################################################
###
#################################################################################
def parse_line_to_array(line, _config, edge_dict_key, edge_type, dict_data_to_send_to_server):
    values = line.split(" ")

    try:
        if (len(values) >= 20 and ("omitted" not in line) and ("terminated" not in line) and (
                "Interval" not in line) and ("receiver" not in line) and ("------------" not in line) and (
                "- - - - - - - - -" not in line) and "TX-C" not in line and "TX-S" not in line):
            # When connection is dropped without the management channel being aware of it, iperf3 start to log 0 values
            # NOT OK : ["'2021-04-06", '15:10:12', "'[", '', '6]', '', '10.00-10.44', '', 'sec', '', '0.00', 'Bytes', '', '0.00','Kbits/sec', '', '0.017', 'ms', '', '0/0', '(0%)', '', '\n']
            # OK : ["'2021-04-06", '15:10:04', "'[", '', '6]', '', '', '1.00-2.00', '', '', 'sec', '', '10.6', 'KBytes', '','87.2', 'Kbits/sec', '', '0.011', 'ms', '', '0/50', '(0%)', '', '\n']

            # When using bidir, we get RX and TX. TX is discarded by previous condition, and RX need to be remove from the line for proper parsing
            if "[RX-C]" in line:
                line = line.replace("[RX-C]", "")
            if "[RX-S]" in line:
                line = line.replace("[RX-S]", "")

            # timestamp
            x = re.findall(r"(\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)", line)
            dt = datetime.datetime.strptime(str(x[0]), "%Y-%m-%d %H:%M:%S")
            timezone = pytz.timezone(DefaultValues.TIMEZONE)
            dt_tz = timezone.localize(dt)
            timestamp = dt_tz.astimezone(pytz.timezone("UTC"))
            utime = dt_tz.astimezone(pytz.timezone("UTC")).timestamp()

            # bitrate
            x = re.findall(r"Bytes[ ]+(\d.*\d*) Kbits\/sec", line)
            bitrate = str(x[0])

            # jitter
            x = re.findall(r"\/sec  (.*) ms", line)
            jitter = str(x[0])

            # loss
            x = re.findall(r"\((.*)%\)", line)
            loss = str(x[0])

            # packet_loss
            x = re.findall(r"ms  (.*)\/.*\(", line)
            packet_loss = str(x[0])

            # packet_total
            x = re.findall(r"ms .*\/(.*)\s\(", line)
            packet_total = str(x[0])

            # when 100% packet loss, iperf report 0 for all values except jitter
            # ie: [  5]   4.00-5.00   sec  0.00 Bytes  0.00 bits/sec  0.024 ms  0/0 (0%)
            if bitrate == "0.00" and loss == "0" and packet_loss == "0" and packet_total == "0":
                loss = "100"

            # When we have bidir activated, the server will transmit
            if edge_type == "CONNECTORS":
                save_to_server(
                    [_config['CONNECTORS'][edge_dict_key]['UID_SERVER'],
                     _config['CONNECTORS'][edge_dict_key]['UID_CLIENT'],
                     timestamp, utime, bitrate, jitter,
                     loss], _config, edge_type, edge_dict_key, packet_loss, packet_total, dict_data_to_send_to_server)
                log.debug(f"WRITING_TO_QUEUE ({len(dict_data_to_send_to_server)}) - connector:{edge_dict_key}")
            else:
                save_to_server(
                    [_config['LISTENERS'][edge_dict_key]['UID_CLIENT'],
                     _config['LISTENERS'][edge_dict_key]['UID_SERVER'], timestamp, utime, bitrate, jitter,
                     loss], _config, edge_type, edge_dict_key, packet_loss, packet_total, dict_data_to_send_to_server)
                log.debug(f"WRITING_TO_QUEUE ({len(dict_data_to_send_to_server)}) - listener:{edge_dict_key}")

            log.debug(f"timestamp:{timestamp.strftime('%d/%m/%Y %H:%M:%S')}, bitrate: {bitrate}, jitter: {jitter}, loss: {loss}, packet_loss: {packet_loss}, packet_total: {packet_total}")

    except Exception as exc:
        log.error(f"parse_line_to_array:{type(exc).__name__}:{exc}", exc_info=True)
        return False

    return True


#################################################################################
### FUNCTION TO READ LISTENERS LOGS
#################################################################################
def read_log_listener(listener_dict_key, _config, exit_boolean, dict_data_to_send_to_server, threads_n_processes):
    exit_message = "unknown"
    # Opening file and using generator
    pathlib.Path(os.path.join(_config['GLOBAL']['IPERF3_TEMP_DIRECTORY'], "syntraf_" + str(_config['LISTENERS'][listener_dict_key]['PORT']) + "_listener.log")).touch()
    file = open(
        os.path.join(_config['GLOBAL']['IPERF3_TEMP_DIRECTORY'], "syntraf_" + str(_config['LISTENERS'][listener_dict_key]['PORT']) + "_listener.log"), "r+")

    lines = tail(file, int(_config['LISTENERS'][listener_dict_key]['INTERVAL']), _config['LISTENERS'][listener_dict_key]['UID_CLIENT'], _config['LISTENERS'][listener_dict_key]['UID_SERVER'], _config, "LISTENERS", listener_dict_key, dict_data_to_send_to_server, threads_n_processes, exit_boolean)
    log.info(f"READING LOGS FOR LISTENER {listener_dict_key} FROM {file.name} ")
    try:
        for line in lines:
            if "exit_boolean_true" in line:
                exit_boolean[0] = True
            #log.debug(f"TEMP DEBUG {line}")
            if exit_boolean[0] or not parse_line_to_array(line, _config, listener_dict_key, "LISTENERS", dict_data_to_send_to_server):
                break
    except Exception as exc:
        log.error(f"read_log:{type(exc).__name__}:{exc}", exc_info=True)
    finally:
        file.close()

    if exit_boolean:
        exit_message = "EXIT BOOLEAN BECAME TRUE"

    log.error(f"THREAD READ_LOG FOR {listener_dict_key} TERMINATED. Exit message: {exit_message}")


#################################################################################
### FUNCTION TO READ CONNECTORS LOGS
#################################################################################
def read_log_connector(connector_dict_key, _config, exit_boolean, dict_data_to_send_to_server, threads_n_processes, iperf3_conn_thread):
    exit_message = "unknown"

    # Opening file and using generator
    pathlib.Path(os.path.join(_config['GLOBAL']['IPERF3_TEMP_DIRECTORY'], "syntraf_" + str(_config['CONNECTORS'][connector_dict_key]['PORT']) + "_connector.log")).touch()
    file = open(
        os.path.join(_config['GLOBAL']['IPERF3_TEMP_DIRECTORY'], "syntraf_" + str(_config['CONNECTORS'][connector_dict_key]['PORT']) + "_connector.log"), "r+")

    lines = tail(file, int(_config['CONNECTORS'][connector_dict_key]['INTERVAL']), _config['CONNECTORS'][connector_dict_key]['UID_CLIENT'], _config['CONNECTORS'][connector_dict_key]['UID_SERVER'], _config, "CONNECTORS", connector_dict_key, dict_data_to_send_to_server, threads_n_processes, exit_boolean, iperf3_conn_thread)

    log.info(f"READING LOGS FOR CONNECTOR {connector_dict_key} FROM {file.name} ")
    try:
        for line in lines:
            if "exit_boolean_true" in line:
                exit_boolean[0] = True

            if exit_boolean[0] or not parse_line_to_array(line, _config, connector_dict_key, "CONNECTORS", dict_data_to_send_to_server):
                break

    except Exception as exc:
        log.error(f"read_log:{type(exc).__name__}:{exc}", exc_info=True)
    finally:
        file.close()

    if exit_boolean:
        exit_message = "EXIT BOOLEAN BECAME TRUE. THE CONNECTOR PROBABLY DIED."

    log.error(f"READ_LOG FOR {connector_dict_key} TERMINATED. Exit message: {exit_message}")