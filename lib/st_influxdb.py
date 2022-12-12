# SYNTRAF GLOBAL IMPORT
from lib.st_global import CompilationOptions, DefaultValues

# SYNTRAF SERVER IMPORT
if not CompilationOptions.client_only:
    from influxdb_client import InfluxDBClient, Point, WritePrecision, WriteOptions
    from influxdb_client.client.write_api import SYNCHRONOUS

# BUILTIN IMPORT
import logging
import queue
import traceback
import hashlib
from datetime import datetime

log = logging.getLogger("syntraf." + __name__)

'''
This class is the object that allow us to write and query the database from all the modules in SYNTRAF
It can use a HTTP proxy, or not.
It maintain a status (self.status) of "OFFLINE" or "ONLINE" that is updated when a write or a query happen along with a timestamp (self.status_time)
I'm still investigating if a buffer is necessary in case of a database outage/unreachable. Because it seem that influxdb client is able to cache some for us..
'''


class InfluxObj(object):
    def __init__(self, _config, database_uid):
        database = {'DB_UID': "UNKNOWN", 'DB_SERVER': "UNKNOWN", 'DB_PORT': "UNKNOWN"}
        prefix = "UNKNOWN"
        self.database_uid = database_uid
        try:
            self.write_queue = queue.Queue(maxsize=DefaultValues.DEFAULT_WRITE_QUEUE_BUFFER_DEPTH)

            for database in _config['DATABASE']:
                if database['DB_UID'] == database_uid:
                    if database['DB_ENGINE'].upper() == "INFLUXDB2":
                        if database['DB_SERVER_USE_SSL']:
                            prefix = "https"
                        else:
                            prefix = "http"

                        if 'DB_USE_WEB_PROXY' in database:
                            self._connection, = InfluxDBClient(
                                url=f"{prefix}://{database['DB_SERVER']}:{database['DB_PORT']}",
                                token=database['DB_TOKEN'],
                                org=database['DB_ORG'],
                                connection_pool_maxsize=int(database['DB_CONNECTION_POOL_MAXSIZE']),
                                proxy=database['DB_USE_WEB_PROXY']),

                        else:
                            self._connection = InfluxDBClient(
                                url=f"{prefix}://{database['DB_SERVER']}:{database['DB_PORT']}",
                                token=database['DB_TOKEN'],
                                org=database['DB_ORG'],
                                connection_pool_maxsize=int(database['DB_CONNECTION_POOL_MAXSIZE']))

                        self.DB_ORG = database['DB_ORG']
                        self.DB_BUCKET = database['DB_BUCKET']
                        self.DB_UID = database_uid
                        self.DB_SERVER = database['DB_SERVER']
                        self.DB_PORT = database['DB_PORT']
                        self.prefix = prefix

                        health = self._connection.health()

                        if health.status == "pass":
                            log.info(
                                f"CONNECTION TO DATABASE '{database['DB_UID']}', '{prefix}://{database['DB_SERVER']}:{database['DB_PORT']}' SUCCESSFUL")
                            self.status = "ONLINE"

                        else:
                            log.error(
                                f"CONNECTION TO DATABASE '{database['DB_UID']}', '{prefix}://{database['DB_SERVER']}:{database['DB_PORT']}' FAILED")
                            self.status = "OFFLINE"
                        self.status_time = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        except Exception as exc:
            # log.error(f"get_connection_influxdb2:{type(exc).__name__}:{exc}", exc_info=True)
            log.error(
                f"CONNECTION TO DATABASE '{database['DB_UID']}', '{prefix}://{database['DB_SERVER']}:{database['DB_PORT']}' FAILED")
            self._connection.__del__()
            self.status = "FAIL"
            self.status_time = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

        self.write_api = self._connection.write_api(write_options=SYNCHRONOUS)
        self.query_api = self._connection.query_api()

    def force_status_check(self):
        health = self._connection.health()

        # The status has changed. Update the status and the status timestamp.
        if self.status == "ONLINE" and health.status == "fail" or self.status == "OFFLINE" and health.status == "pass":

            # Updating status and timestamp
            if health.status == "pass":
                self.status = "ONLINE"
            elif health.status == "fail":
                self.status = "OFFLINE"
            self.status_time = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

            # logging the event
            if self.status == "ONLINE":
                log.info(f"DATABASE '{self.DB_UID}', '{self.prefix}://{self.DB_SERVER}:{self.DB_PORT}' IS NOW {self.status}")
            elif self.status == "OFFLINE":
                log.warning(f"DATABASE '{self.DB_UID}', '{self.prefix}://{self.DB_SERVER}:{self.DB_PORT}' IS NOW {self.status}")

    def save_metrics_to_database_with_buffer(self, payload, address, client_uid):
        try:
            # Batch write
            with self._connection.write_api(write_options=WriteOptions(batch_size=500, flush_interval=10_000, max_retries=0)) as _write_client:
                try:
                    _write_client.write(self.DB_BUCKET, self.DB_ORG, payload)
                except Exception as exc:
                    print(f"server:{type(exc).__name__}:{exc}")
                    print(traceback.format_exc())


            #log.debug(f"{len(payload)} ELEMENTS FROM {client_uid}/{address[0]} HAS BEEN WRITTEN TO DATABASE")

            # If status changed, update status in timestamp
            if not self.status == "ONLINE":
                self.status = "ONLINE"
                self.status_time = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
            return "OK"

        except Exception as exc:
            #log.debug(f"{len(payload)} ELEMENTS FROM {client_uid}/{address[0]} HAS **NOT** BEEN WRITTEN TO DATABASE")
            print(f"server:{type(exc).__name__}:{exc}")
            print(traceback.format_exc())


            # if len(self.write_queue.queue) == DefaultValues.DEFAULT_WRITE_QUEUE_BUFFER_DEPTH: self.write_queue.queue.popleft()
            # self.write_queue.put({"DB_BUCKET": self.DB_BUCKET, "DB_ORG": self.DB_ORG, "JSON_PAYLOAD": JSON_PAYLOAD})

            # If status changed, update status dans timestamp
            if not self.status == "OFFLINE":
                self.status = "OFFLINE"
                self.status_time = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
                log.error(f"UNABLE TO CONNECT TO DATABASE, SETTING DATABASE STATUS TO 'OFFLINE'")

            return "ERROR"

    def __del__(self):
        self._connection.close()

    def get_Database_UID(self):
        return self.database_uid

"""
This function generate a json that we can pass to a influxdb write_api to write metrics in database
"""


def generate_json(values, _config, edge_type, edge_dict_key, packet_loss, packet_total):

    json_body = {
        "measurement": "SYNTRAF",
        "tags": {
            "MESH_GROUP": _config[edge_type][edge_dict_key]['MESH_GROUP'],
#            "CLIENT": _config[edge_type][edge_dict_key]['UID_CLIENT'],
            "CLIENT": values[0],
#            "SERVER": _config[edge_type][edge_dict_key]['UID_SERVER'],
            "SERVER": values[1],
            "UID": f"{values[0]}__TO__{values[1]}__ON__DSCP{_config[edge_type][edge_dict_key]['DSCP']}"
                   #"UID": f"{_config[edge_type][edge_dict_key]['UID_CLIENT']}__TO__{_config[edge_type][edge_dict_key]['UID_SERVER']}__ON__DSCP{_config[edge_type][edge_dict_key]['DSCP']}"
        },
        "time": values[2],
        "fields": {
            "RX_BITRATE": float(values[4]),
            "RX_JITTER": float(values[5]),
            "RX_PCT_LOSS": float(values[6]),
            "RX_PACKET_TOTAL": int(packet_total),
            "RX_PACKET_LOSS": int(packet_loss)
        }
    }

    return json_body


"""
This function generate a json that we can pass to a influxdb write_api to write covariance in database
"""


def generate_json_covariance(pair_a, pair_b, mesh_group, timestamp, covar):
    json_body = {
        "measurement": "SYNTRAF_COVARIANCE",
        "tags": {
            "PAIR_UID_A": pair_a,
            "PAIR_UID_B": pair_b,
            "MESH_GROUP": mesh_group
        },
        "time": timestamp,
        "fields": {
            "COVARIANCE": float(covar)
        }
    }

    return json_body


def save_to_server(values, _config, edge_type, edge_dict_key, packet_loss, packet_total, dict_data_to_send_to_server):
    json_body = generate_json(values, _config, edge_type, edge_dict_key, packet_loss, packet_total)

    try:
        # Make sure that the CLIENT_METRICS_QUEUE does not get too big
        if len(dict_data_to_send_to_server) >= DefaultValues.DEFAULT_CLIENT_METRICS_QUEUE_SIZE:
            dict_data_to_send_to_server.pop(next(iter(dict_data_to_send_to_server)))

        dict_data_to_send_to_server[hashlib.sha1(str(json_body).encode()).hexdigest()] = json_body

    except Exception as exc:
        log.error(f"save_to_server:{type(exc).__name__}:{exc}")
