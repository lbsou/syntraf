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
        elif kwargs['syntraf_instance_type'] == "SERVER" or kwargs['syntraf_instance_type'] == "CLIENT" or \
                kwargs['syntraf_instance_type'] == "SERVER_SOCKET" or kwargs['syntraf_instance_type'] == "READ_LOG" or kwargs['syntraf_instance_type'] == "WEBUI" or kwargs['syntraf_instance_type'] == "COVARIANCE" or kwargs['syntraf_instance_type'] == "STATS":
            self.syntraf_instance_type = kwargs['syntraf_instance_type']
            self.exit_boolean = kwargs['exit_boolean']
            self.name = kwargs['name']
            self.thread_obj = kwargs['thread_obj']
            self.starttime = kwargs['starttime']
            self.last_activity = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
            self.group = kwargs['group']
            self.opposite_side = kwargs['opposite_side']
            self.port = kwargs['port']

    def __str__(self):
        return f"name: {self.name}, syntraf_instance_type:{self.syntraf_instance_type}"

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

