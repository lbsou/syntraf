import hashlib

class st_obj_mesh:
    def __init__(self, **kwargs):
        if kwargs['syntraf_instance_type'] == "LISTENER":
            self.syntraf_instance_type = kwargs['syntraf_instance_type']
            self.uid_client = kwargs['UID_CLIENT']
            self.uid_server = kwargs['UID_SERVER']
            self.port = kwargs['PORT']
            self.interval = kwargs['INTERVAL']
            self.bind_address = kwargs['BIND_ADDRESS']
            self.dscp = kwargs['CLIENT_PARAM_DSCP']
            self.packet_size = kwargs['CLIENT_PARAM_PACKET_SIZE']
            self.mesh_group = kwargs['MESH_GROUP']
            self.hash = hashlib.sha1(f"{self.syntraf_instance_type}{self.uid_client}{self.uid_server}{self.port}{self.interval}{self.bind_address}{self.dscp}{self.packet_size}{self.mesh_group}".encode('utf-8')).hexdigest()

        elif kwargs['syntraf_instance_type'] == "CONNECTOR":
            self.uid_client = kwargs['UID_CLIENT']
            self.uid_server = kwargs['UID_SERVER']
            self.syntraf_instance_type = kwargs['syntraf_instance_type']
            self.destination_address = kwargs['DESTINATION_ADDRESS']
            self.port = kwargs['PORT']
            self.bandwidth = kwargs['BANDWIDTH']
            self.dscp = kwargs['DSCP']
            self.packet_size = kwargs['PACKET_SIZE']
            self.mesh_group = kwargs['MESH_GROUP']
            self.hash = hashlib.sha1(f"{self.syntraf_instance_type}{self.uid_client}{self.uid_server}{self.port}{self.destination_address}{self.dscp}{self.packet_size}{self.mesh_group}{self.bandwidth}".encode('utf-8')).hexdigest()

    def __str__(self):
        if self.syntraf_instance_type == "LISTENER":
            return str({self.hash + "_MEMBER_OF_GROUP_" + self.mesh_group + "_SERVING_" + self.uid_client: {'UID_CLIENT': self.uid_client, 'UID_SERVER': self.uid_server, 'PORT': self.port, 'INTERVAL': self.interval, 'BIND_ADDRESS': self.bind_address, 'DSCP': self.dscp, 'PACKET_SIZE': self.packet_size, 'MESH_GROUP': self.mesh_group}})
        elif self.syntraf_instance_type == "CONNECTOR":
            return str({self.hash + "_MEMBER_OF_GROUP_" + self.mesh_group + "_CONNECTING_TO_" + self.uid_server: {'DESTINATION_ADDRESS': self.destination_address, 'PORT': self.port, 'BANDWIDTH': self.bandwidth, 'DSCP': self.dscp, 'PACKET_SIZE': self.packet_size, 'MESH_GROUP': self.mesh_group}})

    def asdict(self):
        if self.syntraf_instance_type == "LISTENER":
            return {'UID_CLIENT': self.uid_client, 'UID_SERVER': self.uid_server, 'PORT': self.port, 'INTERVAL': self.interval, 'BIND_ADDRESS': self.bind_address, 'DSCP': self.dscp, 'PACKET_SIZE': self.packet_size, 'MESH_GROUP': self.mesh_group}
        elif self.syntraf_instance_type == "CONNECTOR":
            return {'UID_CLIENT': self.uid_client, 'UID_SERVER': self.uid_server, 'DESTINATION_ADDRESS': self.destination_address, 'PORT': self.port, 'BANDWIDTH': self.bandwidth, 'DSCP': self.dscp, 'PACKET_SIZE': self.packet_size, 'MESH_GROUP': self.mesh_group}

    def theindexname(self):
        if self.syntraf_instance_type == "LISTENER":
            return self.hash + "_MEMBER_OF_GROUP_" + self.mesh_group + "_SERVING_" + self.uid_client
        elif self.syntraf_instance_type == "CONNECTOR":
            return self.hash + "_MEMBER_OF_GROUP_" + self.mesh_group + "_CONNECTING_TO_" + self.uid_server