from lib.st_global import DefaultValues
from lib.st_process_and_thread import st_obj_process_n_thread
from lib.st_iperf import *
from lib.st_influxdb import *
import time
import re
from datetime import datetime
import pytz
import logging
log = logging.getLogger("syntraf." + __name__)


#################################################################################
### FUNCTION TO READ LOGS
#################################################################################
def read_log(edge_key, edge_type, config, dict_data_to_send_to_server, threads_n_processes, exit_boolean):
    try:
        current_obj_process_n_thread: st_obj_process_n_thread
        current_obj_process_n_thread = get_obj_process_n_thread(threads_n_processes, edge_key, edge_type)

        lines = tail(config, edge_type, edge_key, exit_boolean, threads_n_processes, current_obj_process_n_thread, dict_data_to_send_to_server)
        log.info(f"READING LOGS FOR {edge_type} {edge_key}")

        while True:
            if exit_boolean[0]:
                return
            line = next(lines, None)
            if line:
                if not parse_line(line, config, edge_key, edge_type, dict_data_to_send_to_server, current_obj_process_n_thread):
                    break
            time.sleep(int(config[f"{edge_type}S"][edge_key]['INTERVAL']) / 2)

    except Exception as exc:
        log.error(f"read_log:{type(exc).__name__}:{exc}", exc_info=True)


#################################################################################
### YIELD LINE FROM IPERF3 STDOUT
#################################################################################
def tail(config: {}, edge_type: string, edge_key: string, exit_boolean: [], threads_n_processes: [], current_obj_process_n_thread, dict_data_to_send_to_server: {}):

    try:
        utime_last_event = None
        iperf3_obj_process_n_thread = wait_iperf3(config, edge_type, edge_key, exit_boolean, threads_n_processes)
        current_obj_process_n_thread.iperf3_obj_process_n_thread = iperf3_obj_process_n_thread

        log.debug(f"READLOG THREAD ACQUIRED IPERF3 STDOUT FOR {edge_type} - {iperf3_obj_process_n_thread.name} -  {edge_key}")

        while True:
            if exit_boolean[0]:
                return
            try:
                line = next(iperf3_obj_process_n_thread.subproc.stdout, None)
            # I/O operation on closed file
            except ValueError:
                log.debug("11111111111111111111111111111111111111111111111")
                pass
                # Possible outage
                #utime_last_event = outage_management(config, edge_type, edge_key, utime_last_event, dict_data_to_send_to_server)
            except Exception as exc:
                log.debug("22222222222222222222222222222222222222222222222")
                iperf3_obj_process_n_thread = wait_iperf3(config, edge_type, edge_key, exit_boolean, threads_n_processes)
                current_obj_process_n_thread.iperf3_obj_process_n_thread = iperf3_obj_process_n_thread
                #log.error(f"tail:{type(exc).__name__}:{exc}", exc_info=True)
            else:
                if line:
                    # Transmitter does not include the metrics
                    if "TX-C" in line or "TX-S" in line:
                        continue
                    else:
                        log.debug(f"LINE FROM A {edge_type} : {edge_key} - {line} - {datetime.now()}")
                        utime_last_event = time.time()
                        yield line
            time.sleep(int(config[f"{edge_type}S"][edge_key]['INTERVAL']) / 2)

    except Exception as exc:
        log.error(f"tail:{type(exc).__name__}:{exc}", exc_info=True)


#################################################################################
###
#################################################################################
def parse_line(line: string, _config: {}, edge_key: string, edge_type: string, dict_data_to_send_to_server: {}, current_obj_process_n_thread: st_obj_process_n_thread):
    values = line.split(" ")

    #The edge_type is used not only as reference to the type but also as a key in the config. In config there is an "S", so replacing for the current function and the save_config
    if edge_type == "CONNECTOR":
        edge_type = "CONNECTORS"
        if not _config['CONNECTORS'][edge_key]['BIDIR']:
            return True
    else:
        edge_type = "LISTENERS"

    line = format_line(line)

    try:
        #Grab src port if bidir conection
        if "connected to" in line and "local" in line:
            if edge_key in _config['CONNECTORS']:
                if _config['CONNECTORS'][edge_key]['BIDIR']:
                    grab_bidir_src_port(_config, line, current_obj_process_n_thread.iperf3_obj_process_n_thread)
        elif (len(values) >= 20 and ("omitted" not in line) and ("terminated" not in line) and (
                "Interval" not in line) and ("receiver" not in line) and ("------------" not in line) and (
                "- - - - - - - - -" not in line) and "TX-C" not in line and "TX-S" not in line):
            # When connection is dropped without the management channel being aware of it, iperf3 start to log 0 values
            # NOT OK : ["'2021-04-06", '15:10:12', "'[", '', '6]', '', '10.00-10.44', '', 'sec', '', '0.00', 'Bytes', '', '0.00','Kbits/sec', '', '0.017', 'ms', '', '0/0', '(0%)', '', '\n']
            # OK : ["'2021-04-06", '15:10:04', "'[", '', '6]', '', '', '1.00-2.00', '', '', 'sec', '', '10.6', 'KBytes', '','87.2', 'Kbits/sec', '', '0.011', 'ms', '', '0/50', '(0%)', '', '\n']

            # increment the counter of line read
            if not current_obj_process_n_thread.line_read:
                current_obj_process_n_thread.line_read = 1
            else:
                current_obj_process_n_thread.line_read += 1

            # Update last activity
            current_obj_process_n_thread.last_activity = datetime.now()

            timestamp, utime, bitrate, jitter, loss, packet_loss, packet_total = extract_values_from_iperf3_result_line(line)

            # when 100% packet loss, iperf report 0 for all values except jitter
            # ie: [  5]   4.00-5.00   sec  0.00 Bytes  0.00 bits/sec  0.024 ms  0/0 (0%)
            if bitrate == "0.00" and loss == "0" and packet_loss == "0" and packet_total == "0":
                loss = "100"
                jitter = "0"

            # When we have bidir activated, the server will transmit
            if edge_type == "CONNECTORS":
                save_to_server(
                    [_config['CONNECTORS'][edge_key]['UID_SERVER'],
                     _config['CONNECTORS'][edge_key]['UID_CLIENT'],
                     timestamp, utime, bitrate, jitter,
                     loss], _config, edge_type, edge_key, packet_loss, packet_total, dict_data_to_send_to_server)
                log.debug(f"WRITING_TO_QUEUE ({len(dict_data_to_send_to_server)}) - connector:{edge_key}")
            else:
                save_to_server(
                    [_config['LISTENERS'][edge_key]['UID_CLIENT'],
                     _config['LISTENERS'][edge_key]['UID_SERVER'], timestamp, utime, bitrate, jitter,
                     loss], _config, edge_type, edge_key, packet_loss, packet_total, dict_data_to_send_to_server)
                log.debug(f"WRITING_TO_QUEUE ({len(dict_data_to_send_to_server)}) - listener:{edge_key}")

            log.debug(f"timestamp:{timestamp.strftime('%d/%m/%Y %H:%M:%S')}, bitrate: {bitrate}, jitter: {jitter}, loss: {loss}, packet_loss: {packet_loss}, packet_total: {packet_total}")

        else:
            log.debug(f"tail(): {edge_key} - LINE DOES NOT CONTAIN METRICS:{line}")

    except Exception as exc:
        log.error(f"parse_line:{type(exc).__name__}:{exc}", exc_info=True)
        return False

    return True


# Wait for iperf3 to start
def wait_iperf3(config: {}, edge_type: string, edge_key: string, exit_boolean: [], threads_n_processes: []):

    # find corresponding iperf3 thread
    iperf3_obj_process_n_thread = get_obj_process_n_thread(threads_n_processes, edge_key, edge_type)

    while True:
        if exit_boolean[0]:
            return None
        try:
            if iperf3_obj_process_n_thread.subproc is not None:
                return iperf3_obj_process_n_thread
        except Exception as exc:
            pass
        time.sleep(int(config[f"{edge_type}S"][edge_key]['INTERVAL']) / 2)


def format_line(line: string):
    # When using bidir, we get RX and TX. TX is discarded by previous condition, and RX need to be remove from the line for proper parsing
    if "[RX-C]" in line:
        line = line.replace("[RX-C]", "")
    elif "[RX-S]" in line:
        line = line.replace("[RX-S]", "")
    return line


def extract_values_from_iperf3_result_line(line: string):
    # timestamp
    x = re.findall(r"(\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)", line)
    dt = datetime.strptime(str(x[0]), "%Y-%m-%d %H:%M:%S")
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

    return timestamp, utime, bitrate, jitter, loss, packet_loss, packet_total


def grab_bidir_src_port(_config: {}, line: string, iperf3_obj_process_n_thread: st_obj_process_n_thread):

    # When we have a bidir connection, iperf will open two port to destination. We want to grab the second source port, as it will allow us to keepalive the udp hole with scapy in another thread.
    # local 192.168.2.41 port 58743 connected to 192.168.6.100 port 15999
    # local 192.168.2.41 port 58744 connected to 192.168.6.100 port 15999

    m_lport = re.search(r"local (?:[0-9]{1,3}.){3}[0-9]{1,3} port (\d{1,10}) connected to (?:[0-9]{1,3}.){3}[0-9]{1,3} port \d{1,10}", line)
    m_laddr = re.search(r"local ((?:[0-9]{1,3}.){3}[0-9]{1,3}) port \d{1,10} connected to (?:[0-9]{1,3}.){3}[0-9]{1,3} port \d{1,10}", line)

    # Grab only the port from the second line, which is the RX
    if m_lport and iperf3_obj_process_n_thread.bidir_src_port_cpt >= 0 and hasattr(iperf3_obj_process_n_thread, 'bidir_src_port'):
        if iperf3_obj_process_n_thread.bidir_src_port_cpt == 0:
            iperf3_obj_process_n_thread.bidir_src_port_cpt += 1
        elif iperf3_obj_process_n_thread.bidir_src_port_cpt == 1:
            iperf3_obj_process_n_thread.bidir_src_port = int(m_lport.groups()[0])
            iperf3_obj_process_n_thread.bidir_local_addr = m_laddr.groups()[0]
            log.info(f"GOT A SRC_IP AND SRC_PORT FOR UDP_HOLE_PUNCH:{m_laddr.groups()[0]}/{m_lport.groups()[0]}")
            iperf3_obj_process_n_thread.bidir_src_port_cpt = -1


def outage_management(config: {}, edge_type: string, edge_key: string,  utime_last_event, dict_data_to_send_to_server):
    utime_now = time.time()

    interval = int(config[f"{edge_type}S"][edge_key]['INTERVAL'])
    uid_client = config[f"{edge_type}S"][edge_key]['UID_CLIENT']
    uid_server = config[f"{edge_type}S"][edge_key]['UID_SERVER']

    '''
    When iperf3 stop generating logs, we want to record 100% losses
    For that, we need to already have received a log in the past (utime_last_event != None) and the current log file of iperf3 must not yield line (not line)
    '''
    # log.debug(f"OUTAGE_MECHANISM DEBUG utime_last_event:{utime_last_event}")
    # log.debug(f"{utime_last_event}{line}{listener_just_started_or_absent}")

    log.debug(utime_last_event)
    if utime_last_event:
        log.debug(f"OUTAGE_MECHANISM DEBUG utime_now:{utime_now} utime_last_event:{utime_last_event} utime_now - utime_last_event: {(utime_now - utime_last_event)}")

        # If iperf3 did not write any events for the double of the interval he's supposed to
        if (utime_now - utime_last_event) >= (2 * interval):
            # Save new event to database with 100% loss for every time interval
            qty_of_event_to_report = (utime_now - utime_last_event) / interval
            log.warning(f"{edge_key} - SYNTRAF HAS DETECTED AN OUTAGE, {qty_of_event_to_report} EVENTS WHERE LOST. GENERATING 100% LOSSES VALUES.")

            for utime_generated in range(int(utime_last_event) + interval, int(utime_now), interval):
                dt_generated = datetime.fromtimestamp(utime_generated)
                timezone = pytz.timezone(DefaultValues.TIMEZONE)
                dt_tz_generated = timezone.localize(dt_generated)
                timestamp_generated = dt_tz_generated.astimezone(pytz.timezone("UTC"))
                utime_generated_utc = dt_tz_generated.astimezone(pytz.timezone("UTC")).timestamp()

                # save
                save_to_server([uid_client, uid_server, timestamp_generated, utime_generated_utc, "0", "0", "100"], config, edge_type, edge_key, "0", "0", dict_data_to_send_to_server)

                log.debug(f"WRITING_TO_QUEUE ({len(dict_data_to_send_to_server)}) - {edge_key}")
                log.debug(f"timestamp:{timestamp_generated}, bitrate: 0, jitter: 0, loss: 100, packet_loss: 0, packet_total: 0")

            return utime_now


