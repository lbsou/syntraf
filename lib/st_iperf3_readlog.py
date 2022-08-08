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
### YIELD LINE FROM IPERF3 OUTPUT FILE
#################################################################################
def tail(file, interval, uid_client, uid_server, _config, listener_dict_key, dict_data_to_send_to_server, threads_n_processes):
    utime_last_event = 0
    try:
        # seek the end
        file.seek(0, os.SEEK_END)

        while True:
            utime_now = time.time()
            dt_now = datetime.datetime.now()

            # reading last line
            line = file.readline()

            print(threads_n_processes)
            for obj_thread_n_process in threads_n_processes:
                print(obj_thread_n_process.name + "   " + listener_dict_key)
                if obj_thread_n_process.name == listener_dict_key:
                    print("found!")

            '''
            Iperf3 stop generating events when the connection is lost for too long [how much exactly?], but we still want to report the losses
            # For that, we need to already have received a log in the past (utime_last_event != 0) and the current log file of iperf3 must not yield line (not line)
            '''
            log.debug(f"OUTAGE_MECHANISM DEBUG utime_last_event:{utime_last_event}")
            if utime_last_event != 0 and not line:
                log.debug(f"OUTAGE_MECHANISM DEBUG utime_now:{utime_now} utime_last_event:{utime_last_event} utime_now - utime_last_event: {(utime_now - utime_last_event)}")

                # If iperf3 did not write any events for the double of the interval he's supposed to
                if (utime_now - utime_last_event) >= (2 * interval):
                    # Save new event to database with 100% loss for every time interval
                    qty_of_event_to_report = (utime_now - utime_last_event) / interval
                    log.warning(f"listener:{listener_dict_key} - SYNTRAF HAS DETECTED AN OUTAGE, {qty_of_event_to_report} EVENTS WHERE LOST. GENERATING 100% LOSSES VALUES.")

                    for utime_generated in range(int(utime_last_event) + interval, int(utime_now), interval):
                        dt_generated = datetime.datetime.fromtimestamp(utime_generated)
                        timezone = pytz.timezone(DefaultValues.TIMEZONE)
                        dt_tz_generated = timezone.localize(dt_generated)
                        timestamp_generated = dt_tz_generated.astimezone(pytz.timezone("UTC"))
                        utime_generated_utc = dt_tz_generated.astimezone(pytz.timezone("UTC")).timestamp()

                        # we could just yield a line, but that would required building a line with the same format as iperf3, it's a hack IMHO, prefer to save directly here.
                        save_to_server([uid_client, uid_server, timestamp_generated, utime_generated_utc, "0", "0", "100"], _config, listener_dict_key, "0", "0", dict_data_to_send_to_server)
                        log.debug(f"WRITING_TO_QUEUE ({len(dict_data_to_send_to_server)}) - listener:{listener_dict_key}")
                        log.debug(f"timestamp:{timestamp_generated}, bitrate: 0, jitter: 0, loss: 100, packet_loss: 0, packet_total: 0")

                    utime_last_event = utime_now
                else:
                    time.sleep(interval / 2)
                    continue
            # Service has not started receiving stuff yet
            # looped too fast but still inside the no outage interval
            elif not line:
                time.sleep(interval / 2)
                continue
            else:
                utime_last_event = time.time()
                file.seek(0)
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

            if _config['CLIENT']['FORWARD_METRICS_TO_SERVER']:
                save_to_server(
                    [_config['LISTENERS'][listener_dict_key]['UID_CLIENT'],
                     _config['LISTENERS'][listener_dict_key]['UID_SERVER'], timestamp, utime, bitrate, jitter,
                     loss], _config, listener_dict_key, packet_loss, packet_total, dict_data_to_send_to_server)

                log.debug(f"WRITING_TO_QUEUE ({len(dict_data_to_send_to_server)}) - listener:{listener_dict_key}")
                log.debug(f"timestamp:{timestamp.strftime('%d/%m/%Y %H:%M:%S')}, bitrate: {bitrate}, jitter: {jitter}, loss: {loss}, packet_loss: {packet_loss}, packet_total: {packet_total}")
    except Exception as exc:
        log.error(f"parse_line_to_array:{type(exc).__name__}:{exc}", exc_info=True)
        return False

    return True

#################################################################################
### FUNCTION USE WITH THREAD TO READ LOGS
#################################################################################
def read_log(listener_dict_key, _config, stop_thread, dict_data_to_send_to_server, conn_db, threads_n_processes):
    # Opening file and using generator
    pathlib.Path(os.path.join(_config['GLOBAL']['IPERF3_TEMP_DIRECTORY'], "syntraf_" + str(_config['LISTENERS'][listener_dict_key]['PORT']) + ".log")).touch()
    file = open(
        os.path.join(_config['GLOBAL']['IPERF3_TEMP_DIRECTORY'], "syntraf_" + str(_config['LISTENERS'][listener_dict_key]['PORT']) + ".log"), "r+")

    lines = tail(file, int(_config['LISTENERS'][listener_dict_key]['INTERVAL']), _config['LISTENERS'][listener_dict_key]['UID_CLIENT'], _config['LISTENERS'][listener_dict_key]['UID_SERVER'], _config, listener_dict_key, dict_data_to_send_to_server, threads_n_processes)
    log.info(f"READING LOGS FOR LISTENER {listener_dict_key} FROM {file.name} ")
    try:
        for line in lines:
            log.debug(f"TEMP DEBUG {line}")
            if stop_thread[0] or not parse_line_to_array(line, _config, listener_dict_key, conn_db, dict_data_to_send_to_server):
                break

    except Exception as exc:
        log.error(f"read_log:{type(exc).__name__}:{exc}", exc_info=True)
    finally:
        file.close()
