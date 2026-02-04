# SYNTRAF GLOBAL IMPORT
from lib.st_global import CompilationOptions, DefaultValues

# SYNTRAF SERVER IMPORT
if not CompilationOptions.client_only:
    # InfluxDB 2.x client
    from influxdb_client import InfluxDBClient, Point, WritePrecision, WriteOptions
    from influxdb_client.client.write_api import SYNCHRONOUS

    # InfluxDB 3.x client (optional - may not be installed)
    try:
        from influxdb_client_3 import InfluxDBClient3
        INFLUXDB3_AVAILABLE = True
    except ImportError:
        INFLUXDB3_AVAILABLE = False

# BUILTIN IMPORT
import logging
import queue
import traceback
import hashlib
import requests
from datetime import datetime

log = logging.getLogger("syntraf." + __name__)

'''
This class is the object that allow us to write and query the database from all the modules in SYNTRAF
It can use a HTTP proxy, or not.
It maintain a status (self.status) of "OFFLINE" or "ONLINE" that is updated when a write or a query happen along with a timestamp (self.status_time)
Supports both InfluxDB 2.x and InfluxDB 3.x
'''


class InfluxObj(object):
    def __init__(self, _config, database_uid):
        database = {'DB_UID': "UNKNOWN", 'DB_SERVER': "UNKNOWN", 'DB_PORT': "UNKNOWN"}
        prefix = "UNKNOWN"
        self.database_uid = database_uid
        self.DB_UID = database_uid  # Always set this for WebUI compatibility
        self.db_engine = "UNKNOWN"
        self._connection = None
        self.write_api = None
        self.query_api = None
        self.DB_SERVER = "UNKNOWN"
        self.DB_PORT = "UNKNOWN"
        self.status = "UNKNOWN"
        self.status_time = None
        self.disabled = False  # Track if database is disabled

        try:
            self.write_queue = queue.Queue(maxsize=DefaultValues.DEFAULT_WRITE_QUEUE_BUFFER_DEPTH)

            for database in _config['DATABASE']:
                if database['DB_UID'] == database_uid:
                    self.db_engine = database['DB_ENGINE'].upper()
                    self.disabled = database.get('DISABLED', False)

                    # InfluxDB 2.x
                    if self.db_engine == "INFLUXDB2":
                        self._init_influxdb2(database)

                    # InfluxDB 3.x
                    elif self.db_engine == "INFLUXDB3":
                        self._init_influxdb3(database)

                    # VictoriaMetrics
                    elif self.db_engine == "VICTORIAMETRICS":
                        self._init_victoriametrics(database)

                    else:
                        log.error(f"Unknown database engine: {database['DB_ENGINE']}")
                        self.status = "FAIL"
                        self.status_time = datetime.now()

        except Exception as exc:
            log.error(f"CONNECTION TO DATABASE '{database['DB_UID']}' FAILED: {type(exc).__name__}: {exc}")
            if self._connection:
                try:
                    self._connection.close()
                except:
                    pass
            self.status = "FAIL"
            self.status_time = datetime.now()

    def _init_influxdb2(self, database):
        """Initialize InfluxDB 2.x connection"""
        if database.get('DB_SERVER_USE_SSL', DefaultValues.DEFAULT_INFLUXDB_USE_SSL):
            prefix = "https"
        else:
            prefix = "http"

        connection_params = {
            'url': f"{prefix}://{database['DB_SERVER']}:{database['DB_PORT']}",
            'token': database['DB_TOKEN'],
            'org': database['DB_ORG'],
            'connection_pool_maxsize': int(database.get('DB_CONNECTION_POOL_MAXSIZE', DefaultValues.DEFAULT_DB_CONNECTION_POOL_MAXSIZE))
        }

        if 'DB_USE_WEB_PROXY' in database:
            connection_params['proxy'] = database['DB_USE_WEB_PROXY']

        self._connection = InfluxDBClient(**connection_params)

        self.DB_ORG = database['DB_ORG']
        self.DB_BUCKET = database['DB_BUCKET']
        self.DB_UID = database['DB_UID']
        self.DB_SERVER = database['DB_SERVER']
        self.DB_PORT = database['DB_PORT']
        self.prefix = prefix

        health = self._connection.health()

        if health.status == "pass":
            log.info(f"CONNECTION TO DATABASE '{database['DB_UID']}' (InfluxDB2), '{prefix}://{database['DB_SERVER']}:{database['DB_PORT']}' SUCCESSFUL")
            self.status = "ONLINE"
        else:
            log.error(f"CONNECTION TO DATABASE '{database['DB_UID']}' (InfluxDB2), '{prefix}://{database['DB_SERVER']}:{database['DB_PORT']}' FAILED")
            self.status = "OFFLINE"

        self.status_time = datetime.now()
        self.write_api = self._connection.write_api(write_options=SYNCHRONOUS)
        self.query_api = self._connection.query_api()

    def _init_influxdb3(self, database):
        """Initialize InfluxDB 3.x connection"""
        if not INFLUXDB3_AVAILABLE:
            log.error("InfluxDB 3.x client not installed. Install with: pip install influxdb3-python")
            self.status = "FAIL"
            self.status_time = datetime.now()
            return

        if database.get('DB_SERVER_USE_SSL', DefaultValues.DEFAULT_INFLUXDB_USE_SSL):
            prefix = "https"
        else:
            prefix = "http"

        # InfluxDB 3 uses 'database' instead of 'bucket' and doesn't use 'org'
        # It can use either DB_BUCKET or DB_DATABASE for the database name
        db_name = database.get('DB_DATABASE', database.get('DB_BUCKET', 'syntraf'))

        try:
            self._connection = InfluxDBClient3(
                host=database['DB_SERVER'],
                token=database['DB_TOKEN'],
                database=db_name,
                org=database.get('DB_ORG', ''),  # InfluxDB3 Cloud may still need org
            )

            self.DB_ORG = database.get('DB_ORG', '')
            self.DB_BUCKET = db_name  # For compatibility, store as DB_BUCKET
            self.DB_DATABASE = db_name
            self.DB_UID = database['DB_UID']
            self.DB_SERVER = database['DB_SERVER']
            self.DB_PORT = database.get('DB_PORT', '443')
            self.prefix = prefix

            # Test connection by writing a test point (InfluxDB3 doesn't have health endpoint)
            # We'll consider it online if no exception is raised during init
            log.info(f"CONNECTION TO DATABASE '{database['DB_UID']}' (InfluxDB3), '{prefix}://{database['DB_SERVER']}' SUCCESSFUL")
            self.status = "ONLINE"
            self.status_time = datetime.now()

        except Exception as exc:
            log.error(f"CONNECTION TO DATABASE '{database['DB_UID']}' (InfluxDB3) FAILED: {type(exc).__name__}: {exc}")
            self.status = "FAIL"
            self.status_time = datetime.now()

    def _init_victoriametrics(self, database):
        """Initialize VictoriaMetrics connection"""
        if database.get('DB_SERVER_USE_SSL', False):
            prefix = "https"
        else:
            prefix = "http"

        port = database.get('DB_PORT', '8428')
        self._vm_url = f"{prefix}://{database['DB_SERVER']}:{port}"

        # Optional tenant for VictoriaMetrics cluster multi-tenancy
        self._vm_tenant = database.get('DB_TENANT', None)

        # Optional authentication token
        self._vm_token = database.get('DB_TOKEN', None)

        # Store common attributes for compatibility
        self.DB_UID = database['DB_UID']
        self.DB_SERVER = database['DB_SERVER']
        self.DB_PORT = port
        self.prefix = prefix

        try:
            # Build headers for requests
            self._vm_headers = {'Content-Type': 'text/plain'}
            if self._vm_token:
                self._vm_headers['Authorization'] = f'Bearer {self._vm_token}'

            # Health check
            health_response = requests.get(f"{self._vm_url}/health", headers=self._vm_headers, timeout=10)

            if health_response.status_code == 200:
                log.info(f"CONNECTION TO DATABASE '{database['DB_UID']}' (VictoriaMetrics), '{self._vm_url}' SUCCESSFUL")
                self.status = "ONLINE"
            else:
                log.error(f"CONNECTION TO DATABASE '{database['DB_UID']}' (VictoriaMetrics), '{self._vm_url}' FAILED: HTTP {health_response.status_code}")
                self.status = "OFFLINE"

            self.status_time = datetime.now()

        except Exception as exc:
            log.error(f"CONNECTION TO DATABASE '{database['DB_UID']}' (VictoriaMetrics) FAILED: {type(exc).__name__}: {exc}")
            self.status = "FAIL"
            self.status_time = datetime.now()

    def force_status_check(self):
        """Check the health status of the database connection"""
        try:
            if self.db_engine == "INFLUXDB2":
                health = self._connection.health()
                new_status = "ONLINE" if health.status == "pass" else "OFFLINE"
            elif self.db_engine == "INFLUXDB3":
                # InfluxDB3 doesn't have a health endpoint, try a simple query
                try:
                    # Just check if we can reach the server
                    new_status = "ONLINE"
                except:
                    new_status = "OFFLINE"
            elif self.db_engine == "VICTORIAMETRICS":
                # VictoriaMetrics health check
                try:
                    response = requests.get(f"{self._vm_url}/health", headers=self._vm_headers, timeout=5)
                    new_status = "ONLINE" if response.status_code == 200 else "OFFLINE"
                except:
                    new_status = "OFFLINE"
            else:
                return

            # The status has changed. Update the status and the status timestamp.
            if self.status != new_status:
                self.status = new_status
                self.status_time = datetime.now()

                if self.status == "ONLINE":
                    log.info(f"DATABASE '{self.DB_UID}' IS NOW {self.status}")
                else:
                    log.warning(f"DATABASE '{self.DB_UID}' IS NOW {self.status}")

        except Exception as exc:
            if self.status != "OFFLINE":
                self.status = "OFFLINE"
                self.status_time = datetime.now()
                log.warning(f"DATABASE '{self.DB_UID}' IS NOW OFFLINE: {exc}")

    def save_metrics_to_database_with_buffer(self, payload, address, client_uid):
        """Write metrics to the database"""
        try:
            if self.db_engine == "INFLUXDB2":
                return self._write_influxdb2(payload)
            elif self.db_engine == "INFLUXDB3":
                return self._write_influxdb3(payload)
            elif self.db_engine == "VICTORIAMETRICS":
                return self._write_victoriametrics(payload)
            else:
                log.error(f"Unknown database engine: {self.db_engine}")
                return "ERROR"

        except Exception as exc:
            log.error(f"Database write error: {type(exc).__name__}: {exc}")
            print(traceback.format_exc())

            if self.status != "OFFLINE":
                self.status = "OFFLINE"
                self.status_time = datetime.now()
                log.error(f"UNABLE TO CONNECT TO DATABASE, SETTING DATABASE STATUS TO 'OFFLINE'")

            return "ERROR"

    def _write_influxdb2(self, payload):
        """Write data using InfluxDB 2.x API"""
        with self._connection.write_api(write_options=WriteOptions(batch_size=500, flush_interval=10_000, max_retries=0)) as _write_client:
            try:
                _write_client.write(self.DB_BUCKET, self.DB_ORG, payload)
            except Exception as exc:
                print(f"InfluxDB2 write error: {type(exc).__name__}: {exc}")
                print(traceback.format_exc())
                raise

        if self.status != "ONLINE":
            self.status = "ONLINE"
            self.status_time = datetime.now()
        return "OK"

    def _write_influxdb3(self, payload):
        """Write data using InfluxDB 3.x API"""
        try:
            # InfluxDB3 can accept line protocol or dict/Point format
            # Convert the payload to line protocol format for batch writing
            if isinstance(payload, list):
                for record in payload:
                    self._write_single_record_influxdb3(record)
            else:
                self._write_single_record_influxdb3(payload)

            if self.status != "ONLINE":
                self.status = "ONLINE"
                self.status_time = datetime.now()
            return "OK"

        except Exception as exc:
            print(f"InfluxDB3 write error: {type(exc).__name__}: {exc}")
            print(traceback.format_exc())
            raise

    def _write_single_record_influxdb3(self, record):
        """Write a single record to InfluxDB 3.x"""
        if isinstance(record, dict):
            # Convert dict format to line protocol
            measurement = record.get('measurement', 'SYNTRAF')
            tags = record.get('tags', {})
            fields = record.get('fields', {})
            timestamp = record.get('time')

            # Build line protocol string
            tag_str = ','.join([f"{k}={v}" for k, v in tags.items()])
            field_str = ','.join([f"{k}={self._format_field_value(v)}" for k, v in fields.items()])

            if tag_str:
                line = f"{measurement},{tag_str} {field_str}"
            else:
                line = f"{measurement} {field_str}"

            if timestamp:
                line += f" {timestamp}"

            self._connection.write(record=line, database=self.DB_DATABASE)
        else:
            # Assume it's already in a compatible format
            self._connection.write(record=record, database=self.DB_DATABASE)

    def _format_field_value(self, value):
        """Format a field value for line protocol"""
        if isinstance(value, str):
            return f'"{value}"'
        elif isinstance(value, bool):
            return str(value).lower()
        elif isinstance(value, int):
            return f"{value}i"
        elif isinstance(value, float):
            return str(value)
        else:
            return f'"{str(value)}"'

    def _write_victoriametrics(self, payload):
        """Write data using VictoriaMetrics API (InfluxDB line protocol)"""
        try:
            # Build line protocol data
            lines = []

            if isinstance(payload, list):
                for record in payload:
                    lines.append(self._dict_to_line_protocol(record))
            else:
                lines.append(self._dict_to_line_protocol(payload))

            line_data = '\n'.join(lines)

            # Determine write endpoint
            if self._vm_tenant:
                # Cluster mode with multi-tenancy
                write_url = f"{self._vm_url}/insert/{self._vm_tenant}/influx/write"
            else:
                # Single-node mode
                write_url = f"{self._vm_url}/write"

            # POST the line protocol data
            response = requests.post(
                write_url,
                data=line_data,
                headers=self._vm_headers,
                timeout=30
            )

            if response.status_code not in (200, 204):
                log.error(f"VictoriaMetrics write failed: HTTP {response.status_code} - {response.text}")
                raise Exception(f"VictoriaMetrics write failed: HTTP {response.status_code}")

            if self.status != "ONLINE":
                self.status = "ONLINE"
                self.status_time = datetime.now()
            return "OK"

        except Exception as exc:
            print(f"VictoriaMetrics write error: {type(exc).__name__}: {exc}")
            print(traceback.format_exc())
            raise

    def _dict_to_line_protocol(self, record):
        """Convert a dict record to InfluxDB line protocol format"""
        if isinstance(record, dict):
            measurement = record.get('measurement', 'SYNTRAF')
            tags = record.get('tags', {})
            fields = record.get('fields', {})
            timestamp = record.get('time')

            # Build line protocol string
            tag_str = ','.join([f"{k}={v}" for k, v in tags.items()])
            field_str = ','.join([f"{k}={self._format_field_value(v)}" for k, v in fields.items()])

            if tag_str:
                line = f"{measurement},{tag_str} {field_str}"
            else:
                line = f"{measurement} {field_str}"

            if timestamp:
                # Convert timestamp to nanoseconds for InfluxDB line protocol
                if isinstance(timestamp, str):
                    # Parse ISO format string to datetime
                    try:
                        # Handle ISO format with timezone (e.g., "2026-02-04 02:33:04+00:00")
                        # Replace space with T for fromisoformat compatibility
                        ts_str = timestamp.replace(' ', 'T')
                        dt = datetime.fromisoformat(ts_str)
                        ts_ns = int(dt.timestamp() * 1_000_000_000)
                    except:
                        # Fallback: try to use as-is if it's already numeric
                        try:
                            ts_ns = int(timestamp)
                        except:
                            ts_ns = int(datetime.now().timestamp() * 1_000_000_000)
                elif isinstance(timestamp, datetime):
                    ts_ns = int(timestamp.timestamp() * 1_000_000_000)
                elif isinstance(timestamp, (int, float)):
                    # Assume it's already in seconds or nanoseconds
                    if timestamp > 1e15:  # Already nanoseconds
                        ts_ns = int(timestamp)
                    else:  # Seconds
                        ts_ns = int(timestamp * 1_000_000_000)
                else:
                    ts_ns = int(datetime.now().timestamp() * 1_000_000_000)
                line += f" {ts_ns}"

            return line
        else:
            # Assume it's already in line protocol format
            return str(record)

    def __del__(self):
        if self._connection:
            try:
                self._connection.close()
            except:
                pass

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
            "CLIENT": values[0],
            "SERVER": values[1],
            "UID": f"{values[0]}__TO__{values[1]}__ON__DSCP{_config[edge_type][edge_dict_key]['DSCP']}"
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


def save_to_server(values, config, edge_type, edge_dict_key, packet_loss, packet_total, dict_data_to_send_to_server):
    json_body = generate_json(values, config, edge_type, edge_dict_key, packet_loss, packet_total)

    try:
        # Make sure that the CLIENT_METRICS_QUEUE does not get too big
        if len(dict_data_to_send_to_server) >= DefaultValues.DEFAULT_CLIENT_METRICS_QUEUE_SIZE:
            dict_data_to_send_to_server.pop(next(iter(dict_data_to_send_to_server)))

        dict_data_to_send_to_server[hashlib.sha1(str(json_body).encode()).hexdigest()] = json_body

    except Exception as exc:
        log.error(f"save_to_server:{type(exc).__name__}:{exc}")
