import json

class cc_client:
    _status = "UNKNOWN"
    _status_since = "UNKNOWN"
    _status_explanation = "UNKNOWN"
    _bool_dynamic_client = False
    _client_uid = "UNKNOWN"
    _ip_address = ""
    _tcp_port = "UNKNOWN"
    _system_stats = {}
    _system_infos = {}
    _clock_skew_in_seconds = -1
    _syntraf_version = ""
    _thread_status = {}

    def __init__(self, status, status_since, status_explanation, bool_dynamic_client, client_uid, tcp_port=0,
                 ip_address=""):
        self._status = status
        self._status_since = status_since
        self._status_explanation = status_explanation
        self._bool_dynamic_client = bool_dynamic_client
        self._client_uid = client_uid
        self._ip_address = ip_address
        self._tcp_port = tcp_port

    # make it serializable so it can be returned by the WEBAPI
    def asjson(self):
        o_dict = self.__dict__
        j_dump = {}
        j_dump['status'] = self._status
        j_dump['status_since'] = self._status_since
        j_dump['status_explanation'] = self._status_explanation
        j_dump['bool_dynamic_client'] = self._bool_dynamic_client
        j_dump['client_uid'] = self._client_uid
        j_dump['ip_address'] = self._ip_address
        j_dump['clock_skew_in_seconds'] = self._clock_skew_in_seconds
        j_dump['syntraf_version'] = self._syntraf_version

        # Not connected client
        if '_system_stats' in o_dict:
            j_dump['system_stats'] = o_dict['_system_stats']

        # Not connected client
        if '_system_infos' in o_dict:
            j_dump['system_infos'] = o_dict['_system_infos']

        # Not connected client
        if '_thread_status' in o_dict:
            j_dump['thread_status'] = o_dict['_thread_status']

        return json.dumps(j_dump)

    def asdict(self):
        return {"STATUS": self.status, "STATUS_SINCE": self.status_since, "STATUS_EXPLANATION": self.status_explanation,
                "CLIENT_UID": self.client_uid, "IP_ADDRESS": self.ip_address, "TCP_PORT": self.tcp_port,
                "CLOCK_SKEW": self.clock_skew_in_seconds, "SYNTRAF_VERSION": self.syntraf_version}

    def get_thread_status(self):
        return self._thread_status

    def set_thread_status(self, value):
        self._thread_status = value

    def get_system_infos(self):
        return self._system_infos

    def set_system_infos(self, value):
        self._system_infos = value

    def get_syntraf_version(self):
        return self._syntraf_version

    def set_syntraf_version(self, value):
        self._syntraf_version = value

    def get_clock_skew_in_seconds(self):
        return self._clock_skew_in_seconds

    def set_clock_skew_in_seconds(self, value):
        self._clock_skew_in_seconds = value

    def get_system_stats(self):
        return self._system_stats

    def set_system_stats(self, value):
        self._system_stats = value

    def get_status_since(self):
        return self._status_since

    def set_status_since(self, value):
        self._status_since = value

    def get_status_explanation(self):
        return self._status_explanation

    def set_status_explanation(self, value):
        self._status_explanation = value

    def get_bool_dynamic_client(self):
        return self._bool_dynamic_client

    def set_bool_dynamic_client(self, value):
        self._bool_dynamic_client = value

    def get_status(self):
        return self._status

    def set_status(self, value):
        self._status = value

    def get_client_uid(self):
        return self._client_uid

    def set_client_uid(self, value):
        self._client_uid = value

    def get_ip_address(self):
        return self._ip_address

    def set_ip_address(self, value):
        self._ip_address = value

    def get_tcp_port(self):
        return self._tcp_port

    def set_tcp_port(self, value):
        self._tcp_port = value

    status = property(get_status, set_status)
    status_since = property(get_status_since, set_status_since)
    status_explanation = property(get_status_explanation, set_status_explanation)
    bool_dynamic_client = property(get_bool_dynamic_client, set_bool_dynamic_client)
    client_uid = property(get_client_uid, set_client_uid)
    ip_address = property(get_ip_address, set_ip_address)
    tcp_port = property(get_tcp_port, set_tcp_port)
    system_stats = property(get_system_stats, set_system_stats)
    system_infos = property(get_system_infos, set_system_infos)
    clock_skew_in_seconds = property(get_clock_skew_in_seconds, set_clock_skew_in_seconds)
    syntraf_version = property(get_syntraf_version, set_syntraf_version)