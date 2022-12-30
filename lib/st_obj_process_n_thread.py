from datetime import datetime


class st_obj_process_n_thread:
    def __init__(self, **kwargs):
        if kwargs['syntraf_instance_type'] == "LISTENER" or kwargs['syntraf_instance_type'] == "CONNECTOR":
            self.syntraf_instance_type = kwargs['syntraf_instance_type']
            self.name = kwargs['name']
            self.subproc = kwargs['subproc']
            self.starttime = kwargs['starttime']
            self.last_activity = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
            self.group = kwargs['group']
            self.opposite_side = kwargs['opposite_side']
            self.port = kwargs['port']
            self.pid = self.subproc.pid
            self.bidir_src_port = None
            self.bidir_local_addr = None
            self.line_read = None
            self.packet_sent = None
        elif kwargs['syntraf_instance_type'] == "SERVER" or kwargs['syntraf_instance_type'] == "CLIENT" or \
                kwargs['syntraf_instance_type'] == "SERVER_SOCKET" or kwargs['syntraf_instance_type'] == "READ_LOG" or kwargs['syntraf_instance_type'] == "WEBUI" or kwargs['syntraf_instance_type'] == "COVARIANCE" or kwargs['syntraf_instance_type'] == "STATS" or kwargs['syntraf_instance_type'] == "UDP_HOLE":
            self.syntraf_instance_type = kwargs['syntraf_instance_type']
            self.exit_boolean = kwargs['exit_boolean']
            self.name = kwargs['name']
            self.thread_obj = kwargs['thread_obj']
            self.starttime = kwargs['starttime']
            self.last_activity = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
            self.group = kwargs['group']
            self.opposite_side = kwargs['opposite_side']
            self.port = kwargs['port']
            self.pid = self.thread_obj.native_id
            self.bidir_src_port = None
            self.bidir_local_addr = None
            self.line_read = None
            self.packet_sent = None

        if kwargs['syntraf_instance_type'] == "CONNECTOR":
            self.bidir_src_port = kwargs['bidir_src_port']
            self.bidir_local_addr = kwargs['bidir_local_addr']

    def __str__(self):
        if self.syntraf_instance_type == "CONNECTOR":
            return f"name: {self.name}, syntraf_instance_type: {self.syntraf_instance_type}, pid: {self.pid}, running: {self.getstatus()}, bidir_src_port: {self.bidir_src_port}"
        else:
            return f"name: {self.name}, syntraf_instance_type: {self.syntraf_instance_type}, pid: {self.pid}, running: {self.getstatus()}"

    def asjson(self):
        return {'starttime': self.starttime, 'syntraf_instance_type': self.syntraf_instance_type, 'group': self.group, 'opposite_side': self.opposite_side, 'listener_port': self.port}

    def getstatus(self):
        if hasattr(self, 'subproc'):
            if self.subproc.poll() is None:
                return True
            else:
                return False
        elif hasattr(self, 'thread_obj'):
            return self.thread_obj.is_alive()

    def close(self):
        if hasattr(self, 'subproc'):
            self.subproc.kill()
        elif hasattr(self, 'thread_obj'):
            self.thread_obj.join(0.01)

    def touch_last_activity(self):
        self.last_activity = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

