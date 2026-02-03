from datetime import datetime
import time


class st_obj_process_n_thread:
    def __init__(self, **kwargs):
        if len(kwargs) != 0:
            if kwargs['syntraf_instance_type'] == "LISTENER" or kwargs['syntraf_instance_type'] == "CONNECTOR":
                self.syntraf_instance_type = kwargs['syntraf_instance_type']
                self.name = kwargs['name']
                self.subproc = kwargs['subproc']
                self.starttime = kwargs['starttime']
                self.last_activity = datetime.now()
                self.group = kwargs['group']
                self.opposite_side = kwargs['opposite_side']
                self.port = kwargs['port']
                self.bidir_src_port = None
                self.bidir_local_addr = None
                self.bidir_src_port_cpt = 0
                self.line_read = None
                self.packet_sent = None
                # Respawn tracking
                self.respawn_count = 0
                self.last_failure_time = None
                self.current_backoff_delay = 0
                self.consecutive_failures = 0
            elif kwargs['syntraf_instance_type'] == "SERVER" or kwargs['syntraf_instance_type'] == "CLIENT" or \
                    kwargs['syntraf_instance_type'] == "SERVER_SOCKET" or kwargs['syntraf_instance_type'] == "READ_LOG" or kwargs['syntraf_instance_type'] == "WEBUI" or kwargs['syntraf_instance_type'] == "COVARIANCE" or kwargs['syntraf_instance_type'] == "STATS" or kwargs['syntraf_instance_type'] == "UDP_HOLE":
                self.syntraf_instance_type = kwargs['syntraf_instance_type']
                self.exit_boolean = kwargs['exit_boolean']
                self.name = kwargs['name']
                self.thread_obj = kwargs['thread_obj']
                self.starttime = kwargs['starttime']
                self.last_activity = datetime.now()
                self.group = kwargs['group']
                self.opposite_side = kwargs['opposite_side']
                self.port = kwargs['port']
                self.bidir_src_port = None
                self.bidir_src_port_cpt = 0
                self.bidir_local_addr = None
                self.line_read = None
                self.packet_sent = None
                # Respawn tracking
                self.respawn_count = 0
                self.last_failure_time = None
                self.current_backoff_delay = 0
                self.consecutive_failures = 0

            if kwargs['syntraf_instance_type'] == "READ_LOG":
                self.iperf3_obj_process_n_thread = None

            if kwargs['syntraf_instance_type'] == "CONNECTOR":
                self.bidir_src_port = kwargs['bidir_src_port']
                self.bidir_local_addr = kwargs['bidir_local_addr']

    def __str__(self):
        if self.syntraf_instance_type == "CONNECTOR":
            return f"name: {self.name}, syntraf_instance_type: {self.syntraf_instance_type}, running: {self.getstatus()}, bidir_src_port: {self.bidir_src_port}"
        else:
            return f"name: {self.name}, syntraf_instance_type: {self.syntraf_instance_type}, running: {self.getstatus()}"

    def asjson(self):
        return {'starttime': self.starttime, 'syntraf_instance_type': self.syntraf_instance_type, 'group': self.group, 'opposite_side': self.opposite_side, 'listener_port': self.port}

    def getstatus(self):
        if hasattr(self, 'subproc'):
            if self.subproc:
                if self.subproc.poll() is None:
                    return True
                else:
                    return False
            else:
                return False
        elif hasattr(self, 'thread_obj'):
            return self.thread_obj.is_alive()

    def getpid(self):
        if hasattr(self, 'subproc'):
            if self.subproc:
                if self.subproc.poll() is None:
                    return self.subproc.pid
                else:
                    return 0
            else:
                return 0
        elif hasattr(self, 'thread_obj'):
            return self.thread_obj.native_id

    def close(self, graceful_timeout=2.0):
        """Close the process or thread with graceful shutdown attempt."""
        if hasattr(self, 'subproc'):
            if self.subproc and self.subproc.poll() is None:
                # Try SIGTERM first for graceful shutdown
                self.subproc.terminate()
                try:
                    self.subproc.wait(timeout=graceful_timeout)
                except Exception:
                    # Force kill if graceful shutdown fails
                    self.subproc.kill()
                    try:
                        self.subproc.wait(timeout=1.0)
                    except Exception:
                        pass
        elif hasattr(self, 'thread_obj'):
            # Signal thread to exit first (if exit_boolean exists)
            if hasattr(self, 'exit_boolean') and self.exit_boolean:
                if isinstance(self.exit_boolean, list) and len(self.exit_boolean) > 0:
                    self.exit_boolean[0] = True
            # Wait with reasonable timeout
            self.thread_obj.join(timeout=graceful_timeout)

    def touch_last_activity(self):
        self.last_activity = datetime.now()

    def record_failure(self, config=None):
        """Record a failure and calculate next backoff delay."""
        from lib.st_global import DefaultValues

        self.consecutive_failures += 1
        self.respawn_count += 1
        self.last_failure_time = time.time()

        # Get backoff settings from config or defaults
        if config and 'GLOBAL' in config:
            min_delay = config['GLOBAL'].get('RESPAWN_MIN_DELAY', DefaultValues.DEFAULT_RESPAWN_MIN_DELAY)
            max_delay = config['GLOBAL'].get('RESPAWN_MAX_DELAY', DefaultValues.DEFAULT_RESPAWN_MAX_DELAY)
            multiplier = config['GLOBAL'].get('RESPAWN_BACKOFF_MULTIPLIER', DefaultValues.DEFAULT_RESPAWN_BACKOFF_MULTIPLIER)
        else:
            min_delay = DefaultValues.DEFAULT_RESPAWN_MIN_DELAY
            max_delay = DefaultValues.DEFAULT_RESPAWN_MAX_DELAY
            multiplier = DefaultValues.DEFAULT_RESPAWN_BACKOFF_MULTIPLIER

        # Calculate exponential backoff
        self.current_backoff_delay = min(
            min_delay * (multiplier ** (self.consecutive_failures - 1)),
            max_delay
        )
        return self.current_backoff_delay

    def should_respawn(self):
        """Check if enough time has passed since last failure to attempt respawn."""
        if self.last_failure_time is None:
            return True

        elapsed = time.time() - self.last_failure_time
        return elapsed >= self.current_backoff_delay

    def reset_failure_count(self):
        """Reset failure tracking after successful operation."""
        self.consecutive_failures = 0
        self.current_backoff_delay = 0

    def get_backoff_remaining(self):
        """Get remaining time in backoff period."""
        if self.last_failure_time is None:
            return 0
        elapsed = time.time() - self.last_failure_time
        remaining = self.current_backoff_delay - elapsed
        return max(0, remaining)

