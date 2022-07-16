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
log = logging.getLogger(__name__)


#################################################################################
### YIELD LINE OF IPERF LOG AND TRUNCATE IT AFTER
#################################################################################
def tail(file):
    try:
        # seek the end
        file.seek(0, os.SEEK_END)

        while True:
            # reading last line
            line = file.readline()

            # Else, sleep
            if not line:
                time.sleep(0.2)
                continue
            file.seek(0)
            # truncate the line to keep the file empty
            file.truncate()

            yield line
    except Exception as exc:
        log.error(f"tail:{type(exc).__name__}:{exc}", exc_info=True)


#################################################################################
###
#################################################################################
def parse_line_to_array(line, _config, listener_dict_key, conn_db, dict_data_to_send_to_server):
    values = line.split(" ")

    try:
        if (len(values) >= 20 and ("omitted" not in line) and ("terminated" not in line) and (
                "Interval" not in line) and ("receiver" not in line) and ("------------" not in line) and (
                "- - - - - - - - -" not in line)):
            # When connection is dropped without the management channel being aware of it, iperf3 start to log 0 values
            # NOT OK : ["'2021-04-06", '15:10:12', "'[", '', '6]', '', '10.00-10.44', '', 'sec', '', '0.00', 'Bytes', '', '0.00','Kbits/sec', '', '0.017', 'ms', '', '0/0', '(0%)', '', '\n']
            # OK : ["'2021-04-06", '15:10:04', "'[", '', '6]', '', '', '1.00-2.00', '', '', 'sec', '', '10.6', 'KBytes', '','87.2', 'Kbits/sec', '', '0.011', 'ms', '', '0/50', '(0%)', '', '\n']

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
            #if (bitrate == "0.00"):
            #    loss = 100

            # packet_loss
            x = re.findall(r"ms  (.*)\/.*\(", line)
            packet_loss = str(x[0])

            # packet_total
            x = re.findall(r"ms .*\/(.*)\s\(", line)
            packet_total = str(x[0])

            # when 100% packet loss, iperf report 0 for all values except jitter
            # ie: [  5]   4.00-5.00   sec  0.00 Bytes  0.00 bits/sec  0.024 ms  0/0 (0%)
            if bitrate == "0.00" and loss == "0" and packet_loss == "0" and packet_total == "0":
                loss = 100

            if _config['CLIENT']['FORWARD_METRICS_TO_SERVER']:
                save_to_server(
                    [_config['LISTENERS'][listener_dict_key]['UID_CLIENT'],
                     _config['LISTENERS'][listener_dict_key]['UID_SERVER'], timestamp, utime, bitrate, jitter,
                     loss], _config, listener_dict_key, packet_loss, packet_total, dict_data_to_send_to_server)

            log.debug(f"WRITING_TO_QUEUE ({len(dict_data_to_send_to_server)}) - listener:{listener_dict_key}")
            log.debug(f"timestamp:{timestamp.strftime('%d/%m/%Y %H:%M:%S')}, bitrate: {bitrate}, jitter: {jitter}, loss: {loss}, packet_loss: {packet_loss}, packet_total: {packet_total}")

            #elif _config['GLOBAL']['DB_ENGINE'].upper() == "INFLUXDB2":
            #    json_body = generate_json([_config['LISTENERS'][listener_dict_key]['UID_CLIENT'],
            #         _config['LISTENERS'][listener_dict_key]['UID_SERVER'], timestamp, utime, bitrate, jitter, loss], _config, listener_dict_key, packet_loss, packet_total)
            #    for conn in conn_db:
            #        result = conn.save_metrics_to_database_with_buffer(json_body)
            #
            #    log.debug(f"WRITING_TO_INFLUXDB2 - listener:{listener_dict_key},timestamp:{timestamp},utime:{utime},bitrate:{bitrate},jitter:{jitter},loss:{loss},packet_loss:{packet_loss},packet_total:{packet_total}")

    except Exception as exc:
        log.error(f"parse_line_to_array:{type(exc).__name__}:{exc}", exc_info=True)
        return False

    return True


#################################################################################
### FUNCTION USE WITH THREAD TO READ LOGS
#################################################################################
def read_log(listener_dict_key, _config, stop_thread, dict_data_to_send_to_server, conn_db):
    # Opening file and using generator
    pathlib.Path(os.path.join(_config['GLOBAL']['IPERF3_TEMP_DIRECTORY'], "syntraf_" + str(_config['LISTENERS'][listener_dict_key]['PORT']) + ".log")).touch()
    file = open(
        os.path.join(_config['GLOBAL']['IPERF3_TEMP_DIRECTORY'], "syntraf_" + str(_config['LISTENERS'][listener_dict_key]['PORT']) + ".log"), "r+")
    lines = tail(file)
    log.info(f"READING LOGS FOR LISTENER {listener_dict_key} FROM {file.name} ")
    try:
        for line in lines:
            if stop_thread[0] or not parse_line_to_array(line, _config, listener_dict_key, conn_db, dict_data_to_send_to_server):
                break

    except Exception as exc:
        log.error(f"read_log:{type(exc).__name__}:{exc}", exc_info=True)
    finally:
        file.close()
